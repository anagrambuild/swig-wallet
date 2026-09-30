#![cfg(not(feature = "program_scope_test"))]
//! Exercise reserve refreshes against the Token program bundled in pinned LiteSVM.

mod common;

use common::*;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use litesvm_token::spl_token;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    rent::Rent,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig::error::SwigError;
use swig_interface::{
    AuthorityConfig, ClientAction, CreateSubAccountInstruction, CreateSubAccountV2Instruction,
    SignV2Instruction, SubAccountSignInstruction, SubAccountSignV2Instruction,
};
use swig_state::{
    action::{
        all::All, close_swig_authority::CloseSwigAuthority, program_all::ProgramAll,
        sub_account::SubAccount, sub_account_v2::SubAccountV2Create, token_limit::TokenLimit,
    },
    authority::AuthorityType,
    swig::{
        sub_account_seeds, sub_account_v2_asset_seeds, sub_account_v2_state_seeds,
        swig_wallet_address_seeds, SwigWithRoles,
    },
    SwigAuthenticateError,
};

const INITIAL_AMOUNT: u64 = 1_000_000_000;
const LIMIT: u64 = 1_000_000;
const COMPOSER: Pubkey = Pubkey::from_str_const("BXAu5ZWHnGun2XZjUZ9nqwiZ5dNVmofPGYdMC4rx4qLV");

struct Fixture {
    context: Context,
    authority: Keypair,
    swig: Pubkey,
    wallet: Pubkey,
    source: Pubkey,
    destination: Pubkey,
    old_reserve: u64,
}

impl Fixture {
    fn new() -> Self {
        Self::with_actions(vec![
            ClientAction::ProgramAll(ProgramAll),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: spl_token::native_mint::ID.to_bytes(),
                current_amount: LIMIT,
            }),
        ])
    }

    fn with_actions(actions: Vec<ClientAction>) -> Self {
        let mut context = setup_test_context().unwrap();
        context
            .svm
            .add_program_from_file(COMPOSER, "../target/deploy/test_program_authority.so")
            .unwrap();
        let root = Keypair::new();
        let authority = Keypair::new();
        let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
        let wallet =
            Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id())
                .0;
        add_authority_with_ed25519_root(
            &mut context,
            &swig,
            &root,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: authority.pubkey().as_ref(),
            },
            actions,
        )
        .unwrap();
        let old_reserve = context.svm.get_sysvar::<Rent>().minimum_balance(165);
        let source = Pubkey::new_unique();
        let destination = Pubkey::new_unique();
        for (key, owner, amount) in [
            (source, wallet, INITIAL_AMOUNT),
            (destination, Pubkey::new_unique(), 0),
        ] {
            let token = spl_token::state::Account {
                mint: spl_token::native_mint::ID,
                owner,
                amount,
                state: spl_token::state::AccountState::Initialized,
                is_native: COption::Some(old_reserve),
                ..Default::default()
            };
            let mut data = vec![0; spl_token::state::Account::LEN];
            spl_token::state::Account::pack(token, &mut data).unwrap();
            context
                .svm
                .set_account(
                    key,
                    Account {
                        lamports: amount + old_reserve,
                        data,
                        owner: spl_token::ID,
                        executable: false,
                        rent_epoch: 0,
                    },
                )
                .unwrap();
        }
        Self {
            context,
            authority,
            swig,
            wallet,
            source,
            destination,
            old_reserve,
        }
    }

    fn reduce_rent(&mut self) -> u64 {
        let rent = Rent::with_lamports_per_byte(3_480);
        self.context.svm.set_sysvar(&rent);
        rent.minimum_balance(165)
    }

    fn send(
        &mut self,
        inner: Instruction,
    ) -> Result<TransactionMetadata, Box<FailedTransactionMetadata>> {
        let ix = SignV2Instruction::new_ed25519(
            self.swig,
            self.wallet,
            self.authority.pubkey(),
            inner,
            1,
        )
        .unwrap();
        self.send_instruction(ix)
    }

    fn send_instruction(
        &mut self,
        ix: Instruction,
    ) -> Result<TransactionMetadata, Box<FailedTransactionMetadata>> {
        let message = v0::Message::try_compile(
            &self.context.default_payer.pubkey(),
            &[ix],
            &[],
            self.context.svm.latest_blockhash(),
        )
        .unwrap();
        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[&self.context.default_payer, &self.authority],
        )
        .unwrap();
        self.context.svm.send_transaction(tx).map_err(Box::new)
    }

    fn source_state(&self) -> spl_token::state::Account {
        spl_token::state::Account::unpack(&self.context.svm.get_account(&self.source).unwrap().data)
            .unwrap()
    }

    fn remaining(&self) -> u64 {
        let account = self.context.svm.get_account(&self.swig).unwrap();
        let swig = SwigWithRoles::from_bytes(&account.data).unwrap();
        swig.get_role(1)
            .unwrap()
            .unwrap()
            .get_action::<TokenLimit>(spl_token::native_mint::ID.as_ref())
            .unwrap()
            .unwrap()
            .current_amount
    }

    fn transfer(&self, amount: u64) -> Instruction {
        spl_token::instruction::transfer(
            &spl_token::ID,
            &self.source,
            &self.destination,
            &self.wallet,
            &[],
            amount,
        )
        .unwrap()
    }

    fn sync_and_transfer(&self, amount: u64) -> Instruction {
        let mut data = b"syncxfer".to_vec();
        data.extend_from_slice(&amount.to_le_bytes());
        Instruction {
            program_id: COMPOSER,
            accounts: vec![
                AccountMeta::new(self.source, false),
                AccountMeta::new(self.destination, false),
                AccountMeta::new_readonly(self.wallet, true),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            data,
        }
    }

    fn snapshot(&self) -> [Option<Account>; 4] {
        [self.source, self.destination, self.wallet, self.swig]
            .map(|key| self.context.svm.get_account(&key))
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum SigningPath {
    Limited,
    All,
    SubAccountV1,
    SubAccountV2,
}

#[derive(Clone, Copy)]
enum PersonalWsolAction {
    None,
    Fund(u64),
    Approve,
    SetCloseAuthority,
}

fn dual_reserve_case(
    path: SigningPath,
    vault_is_source: bool,
    rent_increases: bool,
    counterparty_is_signer: bool,
    amount: u64,
    expected_error: Option<u32>,
    personal_action: PersonalWsolAction,
) {
    let mut actions = vec![
        ClientAction::ProgramAll(ProgramAll),
        ClientAction::TokenLimit(TokenLimit {
            token_mint: spl_token::native_mint::ID.to_bytes(),
            current_amount: LIMIT,
        }),
    ];
    match path {
        SigningPath::Limited => {},
        SigningPath::All => actions.push(ClientAction::All(All)),
        SigningPath::SubAccountV1 => {
            actions.push(ClientAction::SubAccount(SubAccount::new_for_creation()));
        },
        SigningPath::SubAccountV2 => {
            actions.push(ClientAction::SubAccountV2Create(SubAccountV2Create));
        },
    }
    let mut fixture = Fixture::with_actions(actions);
    let swig_account = fixture.context.svm.get_account(&fixture.swig).unwrap();
    let swig_id = SwigWithRoles::from_bytes(&swig_account.data)
        .unwrap()
        .state
        .id;
    let mut vault = fixture.wallet;
    let mut sub_state = Pubkey::default();
    match path {
        SigningPath::SubAccountV1 => {
            let (account, bump) = Pubkey::find_program_address(
                &sub_account_seeds(&swig_id, &1u32.to_le_bytes()),
                &program_id(),
            );
            vault = account;
            let create = CreateSubAccountInstruction::new_with_ed25519_authority(
                fixture.swig,
                fixture.authority.pubkey(),
                fixture.context.default_payer.pubkey(),
                account,
                1,
                bump,
            )
            .unwrap();
            fixture.send_instruction(create).unwrap();
        },
        SigningPath::SubAccountV2 => {
            let (state, state_bump) = Pubkey::find_program_address(
                &sub_account_v2_state_seeds(fixture.swig.as_ref(), &0u32.to_le_bytes()),
                &program_id(),
            );
            let (asset, asset_bump) = Pubkey::find_program_address(
                &sub_account_v2_asset_seeds(fixture.swig.as_ref(), &0u32.to_le_bytes()),
                &program_id(),
            );
            vault = asset;
            sub_state = state;
            let create = CreateSubAccountV2Instruction::new_with_ed25519_authority(
                fixture.swig,
                fixture.authority.pubkey(),
                fixture.context.default_payer.pubkey(),
                state,
                asset,
                1,
            )
            .unwrap();
            fixture.send_instruction(create).unwrap();
        },
        _ => {},
    }
    let lower_rent = Rent::with_lamports_per_byte(3_480);
    let (before_rent, after_rent) = if rent_increases {
        (lower_rent, Rent::default())
    } else {
        (Rent::default(), lower_rent)
    };
    let previous_reserve = before_rent.minimum_balance(165);
    let required = after_rent.minimum_balance(165);
    assert_ne!(previous_reserve, required);
    let pool_authority = Pubkey::find_program_address(&[b"pool"], &COMPOSER).0;
    let counterparty = if counterparty_is_signer {
        fixture.authority.pubkey()
    } else {
        pool_authority
    };
    let source_authority = if vault_is_source { vault } else { counterparty };
    let target_authority = if vault_is_source { counterparty } else { vault };
    for (key, owner) in [
        (fixture.source, source_authority),
        (fixture.destination, target_authority),
    ] {
        let mut account = fixture.context.svm.get_account(&key).unwrap();
        let token = spl_token::state::Account {
            mint: spl_token::native_mint::ID,
            owner,
            amount: INITIAL_AMOUNT,
            state: spl_token::state::AccountState::Initialized,
            is_native: COption::Some(previous_reserve),
            ..Default::default()
        };
        spl_token::state::Account::pack(token, &mut account.data).unwrap();
        account.lamports = INITIAL_AMOUNT + previous_reserve;
        fixture.context.svm.set_account(key, account).unwrap();
    }
    fixture.context.svm.set_sysvar(&after_rent);
    let mut data = b"syncboth".to_vec();
    data.extend_from_slice(&amount.to_le_bytes());
    let inner = Instruction {
        program_id: COMPOSER,
        accounts: vec![
            AccountMeta::new(fixture.source, false),
            AccountMeta::new(fixture.destination, false),
            AccountMeta::new_readonly(source_authority, source_authority != pool_authority),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        data,
    };
    let mut instructions = Vec::new();
    let funding = if let PersonalWsolAction::Fund(lamports) = personal_action {
        assert!(vault_is_source && counterparty_is_signer);
        fixture
            .context
            .svm
            .airdrop(&fixture.authority.pubkey(), lamports * 2)
            .unwrap();
        instructions.push(solana_system_interface::instruction::transfer(
            &fixture.authority.pubkey(),
            &fixture.destination,
            lamports,
        ));
        lamports
    } else {
        0
    };
    instructions.push(inner);
    match personal_action {
        PersonalWsolAction::Approve => {
            assert!(vault_is_source && counterparty_is_signer);
            instructions.push(
                spl_token::instruction::approve(
                    &spl_token::ID,
                    &fixture.destination,
                    &Pubkey::new_unique(),
                    &fixture.authority.pubkey(),
                    &[],
                    1,
                )
                .unwrap(),
            );
        },
        PersonalWsolAction::SetCloseAuthority => {
            assert!(vault_is_source && counterparty_is_signer);
            instructions.push(
                spl_token::instruction::set_authority(
                    &spl_token::ID,
                    &fixture.destination,
                    Some(&Pubkey::new_unique()),
                    spl_token::instruction::AuthorityType::CloseAccount,
                    &fixture.authority.pubkey(),
                    &[],
                )
                .unwrap(),
            );
        },
        _ => {},
    }
    let ix = match path {
        SigningPath::Limited | SigningPath::All => SignV2Instruction::new_ed25519_with_signers(
            fixture.swig,
            fixture.wallet,
            fixture.authority.pubkey(),
            {
                assert_eq!(instructions.len(), 1);
                instructions.pop().unwrap()
            },
            1,
            &[fixture.authority.pubkey()],
        )
        .unwrap(),
        SigningPath::SubAccountV1 => SubAccountSignInstruction::new_with_ed25519_authority(
            fixture.swig,
            vault,
            fixture.authority.pubkey(),
            1,
            instructions,
        )
        .unwrap(),
        SigningPath::SubAccountV2 => SubAccountSignV2Instruction::new_with_ed25519_authority(
            fixture.swig,
            sub_state,
            vault,
            fixture.authority.pubkey(),
            1,
            0,
            instructions,
        )
        .unwrap(),
    };
    let before = fixture.snapshot();
    let vault_before = fixture.context.svm.get_account(&vault);
    let sub_state_before = fixture.context.svm.get_account(&sub_state);
    let authority_before = fixture.context.svm.get_account(&fixture.authority.pubkey());
    let result = fixture.send_instruction(ix);
    let metadata = if let Some(error) = expected_error {
        let failure = result.unwrap_err();
        assert_eq!(
            failure.err,
            TransactionError::InstructionError(0, InstructionError::Custom(error))
        );
        assert_eq!(fixture.snapshot(), before);
        assert_eq!(
            fixture.context.svm.get_account(&fixture.authority.pubkey()),
            authority_before
        );
        assert_eq!(fixture.context.svm.get_account(&vault), vault_before);
        assert_eq!(
            fixture.context.svm.get_account(&sub_state),
            sub_state_before
        );
        failure.meta
    } else {
        let metadata = result.unwrap_or_else(|e| {
            panic!(
                "{path:?}, vault source={vault_is_source}, rent increase={rent_increases}: {e:?}"
            )
        });
        for (key, owner, expected_lamports) in [
            (
                fixture.source,
                source_authority,
                INITIAL_AMOUNT + previous_reserve - amount,
            ),
            (
                fixture.destination,
                target_authority,
                INITIAL_AMOUNT + previous_reserve + amount + funding,
            ),
        ] {
            let account = fixture.context.svm.get_account(&key).unwrap();
            let token = spl_token::state::Account::unpack(&account.data).unwrap();
            assert_eq!(account.owner, spl_token::ID);
            assert_eq!(account.lamports, expected_lamports);
            assert_eq!(token.owner, owner);
            assert_eq!(token.is_native, COption::Some(required));
            assert_eq!(token.amount, expected_lamports - required);
            assert_eq!(token.delegate, COption::None);
            assert_eq!(token.delegated_amount, 0);
            assert_eq!(token.close_authority, COption::None);
        }
        if funding != 0 {
            assert_eq!(
                fixture
                    .context
                    .svm
                    .get_account(&fixture.authority.pubkey())
                    .unwrap()
                    .lamports,
                authority_before.unwrap().lamports - funding
            );
        }
        let spent = if path == SigningPath::Limited && vault_is_source {
            amount
        } else {
            0
        };
        assert_eq!(fixture.remaining(), LIMIT - spent);
        metadata
    };
    let token_success = format!("Program {} success", spl_token::ID);
    assert_eq!(
        metadata
            .logs
            .iter()
            .filter(|line| **line == token_success)
            .count(),
        if matches!(
            personal_action,
            PersonalWsolAction::Approve | PersonalWsolAction::SetCloseAuthority
        ) {
            4
        } else {
            3
        },
        "both SyncNative calls and Transfer must succeed before verification: {:?}",
        metadata.logs
    );
}

#[test]
fn sync_native_refreshes_both_reserves_with_vault_as_source_or_target() {
    for path in [
        SigningPath::Limited,
        SigningPath::All,
        SigningPath::SubAccountV1,
        SigningPath::SubAccountV2,
    ] {
        for rent_increases in [false, true] {
            // Vault sends to the outer signer's WSOL account.
            dual_reserve_case(
                path,
                true,
                rent_increases,
                true,
                LIMIT,
                None,
                PersonalWsolAction::None,
            );
            // A swap-program pool sends to the vault's WSOL account.
            dual_reserve_case(
                path,
                false,
                rent_increases,
                false,
                LIMIT,
                None,
                PersonalWsolAction::None,
            );
            // Both reserves may refresh when the outer signer owns the source,
            // provided the CPI does not spend from that personal account.
            dual_reserve_case(
                path,
                false,
                rent_increases,
                true,
                0,
                None,
                PersonalWsolAction::None,
            );
        }
    }
}

#[test]
fn refreshing_both_reserves_does_not_allow_personal_wsol_spending() {
    for path in [
        SigningPath::Limited,
        SigningPath::All,
        SigningPath::SubAccountV1,
        SigningPath::SubAccountV2,
    ] {
        for rent_increases in [false, true] {
            dual_reserve_case(
                path,
                false,
                rent_increases,
                true,
                1,
                Some(SwigError::PermissionDeniedAuthorityExternalAssetChange as u32),
                PersonalWsolAction::None,
            );
        }
    }
}

#[test]
fn refreshing_both_reserves_does_not_increase_the_vault_token_limit() {
    for rent_increases in [false, true] {
        dual_reserve_case(
            SigningPath::Limited,
            true,
            rent_increases,
            true,
            LIMIT + 1,
            Some(SwigAuthenticateError::PermissionDeniedInsufficientBalance as u32),
            PersonalWsolAction::None,
        );
    }
}

#[test]
fn reserve_refresh_does_not_allow_personal_sol_wrapping() {
    for path in [SigningPath::SubAccountV1, SigningPath::SubAccountV2] {
        for rent_increases in [false, true] {
            dual_reserve_case(
                path,
                true,
                rent_increases,
                true,
                LIMIT,
                Some(SwigError::PermissionDeniedAuthorityExternalAssetChange as u32),
                PersonalWsolAction::Fund(LIMIT),
            );
        }
    }
}

#[test]
fn reserve_refresh_keeps_delegate_and_close_authority_immutable() {
    for path in [SigningPath::SubAccountV1, SigningPath::SubAccountV2] {
        for rent_increases in [false, true] {
            for action in [
                PersonalWsolAction::Approve,
                PersonalWsolAction::SetCloseAuthority,
            ] {
                dual_reserve_case(
                    path,
                    true,
                    rent_increases,
                    true,
                    LIMIT,
                    Some(SwigError::PermissionDeniedAuthorityExternalAssetChange as u32),
                    action,
                );
            }
        }
    }
}

#[test]
fn sync_native_refreshes_rent_without_consuming_token_limit() {
    let mut fixture = Fixture::new();
    let lamports = fixture
        .context
        .svm
        .get_account(&fixture.source)
        .unwrap()
        .lamports;
    let required = fixture.reduce_rent();
    assert_ne!(required, fixture.old_reserve);
    let sync = spl_token::instruction::sync_native(&spl_token::ID, &fixture.source).unwrap();
    let result = fixture.send(sync.clone()).unwrap();
    println!("WSOL_SYNC_CU {}", result.compute_units_consumed);
    assert_eq!(fixture.source_state().is_native, COption::Some(required));
    assert_eq!(fixture.source_state().amount, lamports - required);
    assert_eq!(
        fixture
            .context
            .svm
            .get_account(&fixture.source)
            .unwrap()
            .lamports,
        lamports
    );
    assert_eq!(fixture.remaining(), LIMIT);

    fixture.context.svm.expire_blockhash();
    fixture.send(sync).unwrap();
    assert_eq!(fixture.remaining(), LIMIT);
    fixture.send(fixture.transfer(LIMIT)).unwrap();
    assert_eq!(fixture.remaining(), 0);
}

#[test]
fn wsol_transfer_can_retain_a_stale_reserve() {
    let mut fixture = Fixture::new();
    fixture.reduce_rent();
    fixture.send(fixture.transfer(LIMIT)).unwrap();
    assert_eq!(
        fixture.source_state().is_native,
        COption::Some(fixture.old_reserve)
    );
    assert_eq!(fixture.source_state().amount, INITIAL_AMOUNT - LIMIT);
    assert_eq!(fixture.remaining(), 0);
}

#[test]
fn sync_native_and_transfer_in_one_cpi_charge_the_transfer_amount() {
    let mut fixture = Fixture::new();
    let required = fixture.reduce_rent();
    let result = fixture.send(fixture.sync_and_transfer(LIMIT)).unwrap();
    println!("WSOL_SYNC_TRANSFER_CU {}", result.compute_units_consumed);
    assert_eq!(fixture.remaining(), 0);
    assert_eq!(fixture.source_state().is_native, COption::Some(required));
    assert_eq!(
        fixture.source_state().amount,
        INITIAL_AMOUNT + fixture.old_reserve - required - LIMIT
    );
    let destination = fixture
        .context
        .svm
        .get_account(&fixture.destination)
        .unwrap();
    assert_eq!(
        spl_token::state::Account::unpack(&destination.data)
            .unwrap()
            .amount,
        LIMIT
    );
}

fn assert_sync_transfer_rejected(
    mut fixture: Fixture,
    amount: u64,
    expected: SwigAuthenticateError,
) {
    fixture.reduce_rent();
    let before = fixture.snapshot();
    let error = fixture.send(fixture.sync_and_transfer(amount)).unwrap_err();
    // The composer runs SyncNative then Transfer. Both Token CPIs must succeed
    // before Swig rejects the permission debit; p-token omits instruction logs.
    let token_success = format!("Program {} success", spl_token::ID);
    assert_eq!(
        error
            .meta
            .logs
            .iter()
            .filter(|line| **line == token_success)
            .count(),
        2,
        "both Token CPIs must complete: {:?}",
        error.meta.logs
    );
    assert_eq!(
        error.err,
        TransactionError::InstructionError(0, InstructionError::Custom(expected as u32))
    );
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn sync_native_and_over_limit_transfer_roll_back() {
    assert_sync_transfer_rejected(
        Fixture::new(),
        LIMIT + 1,
        SwigAuthenticateError::PermissionDeniedInsufficientBalance,
    );
}

#[test]
fn sync_native_and_transfer_without_token_permission_roll_back() {
    assert_sync_transfer_rejected(
        Fixture::with_actions(vec![ClientAction::ProgramAll(ProgramAll)]),
        1,
        SwigAuthenticateError::PermissionDeniedMissingPermission,
    );
}

#[test]
fn sync_native_rent_increase_does_not_consume_token_limit() {
    let mut fixture = Fixture::new();
    let lamports = fixture
        .context
        .svm
        .get_account(&fixture.source)
        .unwrap()
        .lamports;
    let lower_reserve = fixture.reduce_rent();
    let sync = spl_token::instruction::sync_native(&spl_token::ID, &fixture.source).unwrap();
    fixture.send(sync.clone()).unwrap();
    assert_eq!(
        fixture.source_state().is_native,
        COption::Some(lower_reserve)
    );

    fixture.context.svm.set_sysvar(&Rent::default());
    fixture.context.svm.expire_blockhash();
    fixture.send(sync).unwrap();
    assert_eq!(
        fixture.source_state().is_native,
        COption::Some(fixture.old_reserve)
    );
    assert_eq!(fixture.source_state().amount, INITIAL_AMOUNT);
    assert_eq!(
        fixture
            .context
            .svm
            .get_account(&fixture.source)
            .unwrap()
            .lamports,
        lamports
    );
    assert_eq!(fixture.remaining(), LIMIT);
}

#[test]
fn wsol_close_without_permission_rolls_back() {
    let mut fixture = Fixture::new();
    fixture.reduce_rent();
    let before = fixture.snapshot();
    let close = spl_token::instruction::close_account(
        &spl_token::ID,
        &fixture.source,
        &fixture.wallet,
        &fixture.wallet,
        &[],
    )
    .unwrap();
    let error = fixture.send(close).unwrap_err();
    assert_eq!(
        error.err,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(
                SwigAuthenticateError::PermissionDeniedMissingPermission as u32
            )
        )
    );
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn wsol_close_to_wallet_consumes_full_lamport_limit() {
    let mut fixture = Fixture::with_actions(vec![
        ClientAction::ProgramAll(ProgramAll),
        ClientAction::TokenLimit(TokenLimit {
            token_mint: spl_token::native_mint::ID.to_bytes(),
            current_amount: INITIAL_AMOUNT + Rent::default().minimum_balance(165),
        }),
        ClientAction::CloseSwigAuthority(CloseSwigAuthority),
    ]);
    fixture.reduce_rent();
    let source_lamports = fixture
        .context
        .svm
        .get_account(&fixture.source)
        .unwrap()
        .lamports;
    let wallet_before = fixture
        .context
        .svm
        .get_account(&fixture.wallet)
        .unwrap()
        .lamports;
    let close = spl_token::instruction::close_account(
        &spl_token::ID,
        &fixture.source,
        &fixture.wallet,
        &fixture.wallet,
        &[],
    )
    .unwrap();
    fixture.send(close).unwrap();
    assert_eq!(
        fixture
            .context
            .svm
            .get_account(&fixture.source)
            .map(|account| account.lamports)
            .unwrap_or(0),
        0
    );
    assert_eq!(
        fixture
            .context
            .svm
            .get_account(&fixture.wallet)
            .unwrap()
            .lamports,
        wallet_before + source_lamports
    );
    assert_eq!(fixture.remaining(), 0);
}

#[test]
fn wsol_authority_changes_still_fail_and_roll_back() {
    let mut fixture = Fixture::new();
    fixture.reduce_rent();
    let source_before = fixture.context.svm.get_account(&fixture.source).unwrap();
    let swig_before = fixture.context.svm.get_account(&fixture.swig).unwrap();
    let ix = spl_token::instruction::set_authority(
        &spl_token::ID,
        &fixture.source,
        Some(&Pubkey::new_unique()),
        spl_token::instruction::AuthorityType::AccountOwner,
        &fixture.wallet,
        &[],
    )
    .unwrap();
    let error = fixture.send(ix).unwrap_err();
    assert_eq!(
        error.err,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(SwigError::AccountDataModifiedUnexpectedly as u32)
        )
    );
    assert_eq!(
        fixture.context.svm.get_account(&fixture.source).unwrap(),
        source_before
    );
    assert_eq!(
        fixture.context.svm.get_account(&fixture.swig).unwrap(),
        swig_before
    );
}
