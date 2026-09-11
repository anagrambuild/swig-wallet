#![cfg(not(feature = "program_scope_test"))]
//! Exercise reserve refreshes against the Token program bundled in pinned LiteSVM.

mod common;
#[path = "../src/error.rs"]
mod swig_error;

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
use swig::actions::sign_v2::SignV2Args;
use swig_error::SwigError;
use swig_interface::{compact_instructions, AuthorityConfig, ClientAction, SignV2Instruction};
use swig_state::{
    action::{
        close_swig_authority::CloseSwigAuthority, program_all::ProgramAll, token_limit::TokenLimit,
    },
    authority::AuthorityType,
    swig::{swig_wallet_address_seeds, SwigWithRoles},
    IntoBytes, SwigAuthenticateError,
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
        self.send_sign_instruction(ix)
    }

    fn send_compact_sequence(
        &mut self,
        inner: Vec<Instruction>,
    ) -> Result<TransactionMetadata, Box<FailedTransactionMetadata>> {
        // The interface and SDK wrap each inner instruction separately. Exercise
        // the handler's multi-CPI format using the production compact encoder,
        // retaining the builder's account contract and Ed25519 authority payload.
        let mut ix = SignV2Instruction::new_ed25519(
            self.swig,
            self.wallet,
            self.authority.pubkey(),
            inner[0].clone(),
            1,
        )
        .unwrap();
        let authority_index = *ix.data.last().unwrap();
        let (accounts, instructions) = compact_instructions(self.swig, ix.accounts, inner);
        let payload = instructions.into_bytes();
        let args = SignV2Args::new(1, payload.len() as u16);
        ix.accounts = accounts;
        ix.data = [args.into_bytes().unwrap(), &payload, &[authority_index]].concat();
        self.send_sign_instruction(ix)
    }

    fn send_sign_instruction(
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

    /// Replace the token processor only for controlled failure injection. All
    /// SyncNative and transfer success tests use LiteSVM's actual Token program.
    fn write_source_data(
        &mut self,
        data: &[u8],
    ) -> Result<TransactionMetadata, Box<FailedTransactionMetadata>> {
        let owner = self.context.svm.get_account(&self.source).unwrap().owner;
        self.context
            .svm
            .add_program_from_file(owner, "../target/deploy/test_program_authority.so")
            .unwrap();
        self.send(Instruction {
            program_id: owner,
            accounts: vec![AccountMeta::new(self.source, false)],
            data: [b"writeacc".as_slice(), data].concat(),
        })
    }

    fn assert_data_write_rejected(&mut self, data: &[u8]) {
        let before = self.snapshot();
        let owner = before[0].as_ref().unwrap().owner;
        let error = self.write_source_data(data).unwrap_err();
        assert!(
            error
                .meta
                .logs
                .contains(&format!("Program {owner} success")),
            "the injected mutation must succeed before Swig rejects it: {:?}",
            error.meta.logs
        );
        assert_eq!(
            error.err,
            TransactionError::InstructionError(
                0,
                InstructionError::Custom(SwigError::AccountDataModifiedUnexpectedly as u32)
            )
        );
        assert_eq!(self.snapshot(), before);
    }
}

#[test]
fn non_native_reserve_payloads_remain_immutable() {
    let token_2022 = Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
    for owner in [spl_token::ID, token_2022] {
        let mut fixture = Fixture::new();
        let mut account = fixture.context.svm.get_account(&fixture.source).unwrap();
        account.owner = owner;
        account.data[0..32].copy_from_slice(Pubkey::new_unique().as_ref());
        account.data[109..113].copy_from_slice(&[0; 4]); // COption::None
                                                         // Keep the ignored payload nonzero: capture must not interpret it as WSOL.
        fixture
            .context
            .svm
            .set_account(fixture.source, account.clone())
            .unwrap();
        fixture.write_source_data(&account.data).unwrap();
        assert_eq!(fixture.remaining(), LIMIT);

        account.data[113..121].copy_from_slice(&(fixture.old_reserve - 1).to_le_bytes());
        fixture.assert_data_write_rejected(&account.data);
    }
}

#[test]
fn native_tag_and_metadata_changes_cannot_reclassify_a_snapshot() {
    // The boundaries around both excluded fields remain protected, including
    // the full native option tag and the delegated amount immediately after it.
    for offset in [0, 31, 32, 63, 72, 108, 109, 110, 111, 112, 121, 164] {
        let mut fixture = Fixture::new();
        let mut data = fixture
            .context
            .svm
            .get_account(&fixture.source)
            .unwrap()
            .data;
        data[offset] ^= 1;
        fixture.assert_data_write_rejected(&data);
    }
}

#[test]
fn arbitrary_wsol_reserve_refresh_is_rejected() {
    let mut fixture = Fixture::new();
    fixture.reduce_rent();
    let mut data = fixture
        .context
        .svm
        .get_account(&fixture.source)
        .unwrap()
        .data;
    // Preserve amount + reserve and backing, but choose neither the old reserve
    // nor the current rent minimum.
    data[64..72].copy_from_slice(&(INITIAL_AMOUNT + 1).to_le_bytes());
    data[113..121].copy_from_slice(&(fixture.old_reserve - 1).to_le_bytes());
    fixture.assert_data_write_rejected(&data);
}

#[test]
fn verification_checks_the_original_wsol_backing() {
    let mut fixture = Fixture::new();
    let mut account = fixture.context.svm.get_account(&fixture.source).unwrap();
    let repaired_data = account.data.clone();
    account.data[64..72].copy_from_slice(&(INITIAL_AMOUNT + 1).to_le_bytes());
    fixture
        .context
        .svm
        .set_account(fixture.source, account)
        .unwrap();
    // Snapshotting permits the CPI to run, but repairing the account cannot
    // bypass verification of the captured amount, reserve and lamports.
    fixture.assert_data_write_rejected(&repaired_data);
}

#[test]
fn sync_native_on_an_outer_authoritys_wsol_account_succeeds() {
    let mut fixture = Fixture::new();
    let mut account = fixture.context.svm.get_account(&fixture.source).unwrap();
    account.data[32..64].copy_from_slice(fixture.authority.pubkey().as_ref());
    fixture
        .context
        .svm
        .set_account(fixture.source, account.clone())
        .unwrap();
    let required = fixture.reduce_rent();
    let sync = spl_token::instruction::sync_native(&spl_token::ID, &fixture.source).unwrap();
    fixture.send(sync).unwrap();
    assert_eq!(fixture.source_state().is_native, COption::Some(required));
    assert_eq!(fixture.source_state().amount, account.lamports - required);
    assert_eq!(fixture.remaining(), LIMIT);
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

fn assert_compact_sync_transfers(total: u64) {
    let mut fixture = Fixture::new();
    let required = fixture.reduce_rent();
    let before = fixture.snapshot();
    let instructions = vec![
        spl_token::instruction::sync_native(&spl_token::ID, &fixture.source).unwrap(),
        fixture.transfer(LIMIT / 2),
        fixture.transfer(total - LIMIT / 2),
    ];
    let result = fixture.send_compact_sequence(instructions);
    let metadata = if total <= LIMIT {
        assert_eq!(fixture.remaining(), LIMIT - total);
        assert_eq!(fixture.source_state().is_native, COption::Some(required));
        assert_eq!(
            fixture.source_state().amount,
            INITIAL_AMOUNT + fixture.old_reserve - required - total
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
            total
        );
        result.unwrap()
    } else {
        let error = result.unwrap_err();
        assert_eq!(
            error.err,
            TransactionError::InstructionError(
                0,
                InstructionError::Custom(
                    SwigAuthenticateError::PermissionDeniedInsufficientBalance as u32
                )
            )
        );
        assert_eq!(fixture.snapshot(), before);
        error.meta
    };
    let token_success = format!("Program {} success", spl_token::ID);
    assert_eq!(
        metadata
            .logs
            .iter()
            .filter(|line| **line == token_success)
            .count(),
        3
    );
}

#[test]
fn sync_native_and_separate_compact_transfers_share_one_limit() {
    assert_compact_sync_transfers(LIMIT);
}

#[test]
fn sync_native_and_separate_compact_transfers_over_limit_roll_back() {
    assert_compact_sync_transfers(LIMIT + 1);
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
fn wsol_close_with_permission_returns_lamports_without_consuming_token_limit() {
    let mut fixture = Fixture::with_actions(vec![
        ClientAction::ProgramAll(ProgramAll),
        ClientAction::TokenLimit(TokenLimit {
            token_mint: spl_token::native_mint::ID.to_bytes(),
            current_amount: LIMIT,
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
    assert_eq!(fixture.remaining(), LIMIT);
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
