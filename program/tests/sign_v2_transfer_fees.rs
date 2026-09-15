#![cfg(not(feature = "program_scope_test"))]
//! Transfer-fee compatibility against LiteSVM's real Token-2022 program.

mod common;

use common::*;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use solana_sdk::{
    account::Account,
    instruction::{Instruction, InstructionError},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use spl_token_2022_interface::{
    extension::{
        memo_transfer::{instruction::enable_required_transfer_memos, MemoTransfer},
        transfer_fee::{
            instruction::harvest_withheld_tokens_to_mint, TransferFeeAmount, TransferFeeConfig,
        },
        BaseStateWithExtensions, BaseStateWithExtensionsMut, ExtensionType, StateWithExtensions,
        StateWithExtensionsMut,
    },
    instruction::transfer_checked,
    state::{Account as TokenAccount, AccountState, Mint},
    ID as TOKEN_2022,
};
use swig::error::SwigError;
use swig_interface::{
    AuthorityConfig, ClientAction, CreateSubAccountInstruction, CreateSubAccountV2Instruction,
    SignV2Instruction, SubAccountSignInstruction, SubAccountSignV2Instruction,
};
use swig_state::{
    action::{
        all::All, program_all::ProgramAll, sub_account::SubAccount,
        sub_account_v2::SubAccountV2Create, token_limit::TokenLimit,
    },
    authority::AuthorityType,
    swig::{
        sub_account_seeds, sub_account_v2_asset_seeds, sub_account_v2_state_seeds,
        swig_wallet_address_seeds, SwigWithRoles,
    },
    SwigAuthenticateError,
};

const INITIAL_AMOUNT: u64 = 10_000;
const LIMIT: u64 = 100;

#[derive(Clone, Copy, Debug)]
enum SigningPath {
    Limited,
    All,
    SubAccountV1,
    SubAccountV2,
}

struct Fixture {
    context: Context,
    authority: Keypair,
    swig: Pubkey,
    wallet: Pubkey,
    vault: Pubkey,
    sub_state: Pubkey,
    mint: Pubkey,
    source: Pubkey,
    destination: Pubkey,
    path: SigningPath,
}

impl Fixture {
    fn new(path: SigningPath, personal_destination: bool, fee_bps: u16) -> Self {
        let mut context = setup_test_context().unwrap();
        let root = Keypair::new();
        let authority = Keypair::new();
        let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
        let wallet =
            Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id())
                .0;
        let mint = Pubkey::new_unique();
        let mut actions = vec![
            ClientAction::ProgramAll(ProgramAll),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint.to_bytes(),
                current_amount: LIMIT,
            }),
        ];
        match path {
            SigningPath::Limited => {},
            SigningPath::All => actions.push(ClientAction::All(All)),
            SigningPath::SubAccountV1 => {
                actions.push(ClientAction::SubAccount(SubAccount::new_for_creation()))
            },
            SigningPath::SubAccountV2 => {
                actions.push(ClientAction::SubAccountV2Create(SubAccountV2Create))
            },
        }
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
        let mut fixture = Self {
            context,
            authority,
            swig,
            wallet,
            vault: wallet,
            sub_state: Pubkey::default(),
            mint,
            source: Pubkey::new_unique(),
            destination: Pubkey::new_unique(),
            path,
        };
        let swig_account = fixture.context.svm.get_account(&swig).unwrap();
        let swig_id = SwigWithRoles::from_bytes(&swig_account.data)
            .unwrap()
            .state
            .id;
        match path {
            SigningPath::SubAccountV1 => {
                let (vault, bump) = Pubkey::find_program_address(
                    &sub_account_seeds(&swig_id, &1u32.to_le_bytes()),
                    &program_id(),
                );
                let ix = CreateSubAccountInstruction::new_with_ed25519_authority(
                    swig,
                    fixture.authority.pubkey(),
                    fixture.context.default_payer.pubkey(),
                    vault,
                    1,
                    bump,
                )
                .unwrap();
                fixture.send_instruction(ix).unwrap();
                fixture.vault = vault;
            },
            SigningPath::SubAccountV2 => {
                let (state, state_bump) = Pubkey::find_program_address(
                    &sub_account_v2_state_seeds(&swig_id, &0u32.to_le_bytes()),
                    &program_id(),
                );
                let (vault, asset_bump) = Pubkey::find_program_address(
                    &sub_account_v2_asset_seeds(&swig_id, &0u32.to_le_bytes()),
                    &program_id(),
                );
                let ix = CreateSubAccountV2Instruction::new_with_ed25519_authority(
                    swig,
                    fixture.authority.pubkey(),
                    fixture.context.default_payer.pubkey(),
                    state,
                    vault,
                    1,
                    state_bump,
                    asset_bump,
                )
                .unwrap();
                fixture.send_instruction(ix).unwrap();
                fixture.vault = vault;
                fixture.sub_state = state;
            },
            _ => {},
        }
        let mut mint_data = vec![
            0;
            ExtensionType::try_calculate_account_len::<Mint>(&[
                ExtensionType::TransferFeeConfig
            ],)
            .unwrap()
        ];
        let mut mint_state =
            StateWithExtensionsMut::<Mint>::unpack_uninitialized(&mut mint_data).unwrap();
        let fees = mint_state
            .init_extension::<TransferFeeConfig>(false)
            .unwrap();
        fees.older_transfer_fee.transfer_fee_basis_points = fee_bps.into();
        fees.older_transfer_fee.maximum_fee = u64::MAX.into();
        fees.newer_transfer_fee = fees.older_transfer_fee;
        mint_state.base = Mint {
            supply: INITIAL_AMOUNT,
            decimals: 0,
            is_initialized: true,
            ..Default::default()
        };
        mint_state.pack_base();
        mint_state.init_account_type().unwrap();
        fixture.install_token_account(mint, mint_data);
        for (key, owner, amount) in [
            (fixture.source, fixture.vault, INITIAL_AMOUNT),
            (
                fixture.destination,
                if personal_destination {
                    fixture.authority.pubkey()
                } else {
                    fixture.vault
                },
                0,
            ),
        ] {
            let mut data = vec![
                0;
                ExtensionType::try_calculate_account_len::<TokenAccount>(&[
                    ExtensionType::MemoTransfer,
                    ExtensionType::TransferFeeAmount
                ],)
                .unwrap()
            ];
            let mut state =
                StateWithExtensionsMut::<TokenAccount>::unpack_uninitialized(&mut data).unwrap();
            // Put an extension before the fee payload to exercise variable TLV positioning.
            state.init_extension::<MemoTransfer>(false).unwrap();
            state.init_extension::<TransferFeeAmount>(false).unwrap();
            state.base = TokenAccount {
                mint,
                owner,
                amount,
                state: AccountState::Initialized,
                ..Default::default()
            };
            state.pack_base();
            state.init_account_type().unwrap();
            fixture.install_token_account(key, data);
        }
        fixture
    }

    fn install_token_account(&mut self, key: Pubkey, data: Vec<u8>) {
        self.context
            .svm
            .set_account(
                key,
                Account {
                    lamports: self
                        .context
                        .svm
                        .minimum_balance_for_rent_exemption(data.len()),
                    data,
                    owner: TOKEN_2022,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
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

    fn send(
        &mut self,
        inner: Instruction,
    ) -> Result<TransactionMetadata, Box<FailedTransactionMetadata>> {
        let ix = match self.path {
            SigningPath::Limited | SigningPath::All => SignV2Instruction::new_ed25519_with_signers(
                self.swig,
                self.wallet,
                self.authority.pubkey(),
                inner,
                1,
                &[self.authority.pubkey()],
            )
            .unwrap(),
            SigningPath::SubAccountV1 => SubAccountSignInstruction::new_with_ed25519_authority(
                self.swig,
                self.vault,
                self.authority.pubkey(),
                1,
                vec![inner],
            )
            .unwrap(),
            SigningPath::SubAccountV2 => SubAccountSignV2Instruction::new_with_ed25519_authority(
                self.swig,
                self.sub_state,
                self.vault,
                self.authority.pubkey(),
                1,
                0,
                vec![inner],
            )
            .unwrap(),
        };
        self.send_instruction(ix)
    }

    fn transfer(&self, amount: u64) -> Instruction {
        transfer_checked(
            &TOKEN_2022,
            &self.source,
            &self.mint,
            &self.destination,
            &self.vault,
            &[],
            amount,
            0,
        )
        .unwrap()
    }

    fn token_balance(&self, key: Pubkey) -> (u64, u64) {
        let account = self.context.svm.get_account(&key).unwrap();
        let state = StateWithExtensions::<TokenAccount>::unpack(&account.data).unwrap();
        (
            state.base.amount,
            u64::from(
                state
                    .get_extension::<TransferFeeAmount>()
                    .unwrap()
                    .withheld_amount,
            ),
        )
    }

    fn remaining(&self) -> u64 {
        let account = self.context.svm.get_account(&self.swig).unwrap();
        SwigWithRoles::from_bytes(&account.data)
            .unwrap()
            .get_role(1)
            .unwrap()
            .unwrap()
            .get_action::<TokenLimit>(self.mint.as_ref())
            .unwrap()
            .unwrap()
            .current_amount
    }

    fn protected_state(&self) -> Vec<Option<Account>> {
        [
            self.swig,
            self.vault,
            self.sub_state,
            self.mint,
            self.source,
            self.destination,
            self.authority.pubkey(),
        ]
        .into_iter()
        .map(|key| self.context.svm.get_account(&key))
        .collect()
    }
}

#[test]
fn fee_receipts_and_harvests_preserve_spend_accounting() {
    for personal_destination in [false, true] {
        let mut fixture = Fixture::new(SigningPath::Limited, personal_destination, 100);
        let receipt = fixture.send(fixture.transfer(LIMIT)).unwrap();
        assert_eq!(
            fixture.token_balance(fixture.source),
            (INITIAL_AMOUNT - LIMIT, 0)
        );
        assert_eq!(fixture.token_balance(fixture.destination), (99, 1));
        assert_eq!(fixture.remaining(), 0);
        let harvest =
            harvest_withheld_tokens_to_mint(&TOKEN_2022, &fixture.mint, &[&fixture.destination])
                .unwrap();
        fixture.send(harvest).unwrap();
        assert_eq!(fixture.token_balance(fixture.destination), (99, 0));
        assert_eq!(fixture.remaining(), 0);
        let mint = fixture.context.svm.get_account(&fixture.mint).unwrap();
        assert_eq!(
            u64::from(
                StateWithExtensions::<Mint>::unpack(&mint.data)
                    .unwrap()
                    .get_extension::<TransferFeeConfig>()
                    .unwrap()
                    .withheld_amount
            ),
            1
        );
        println!(
            "limited transfer: personal={personal_destination}, CU={}",
            receipt.compute_units_consumed
        );
    }
}

#[test]
fn personal_fee_receipts_work_through_every_isolation_caller() {
    for path in [
        SigningPath::All,
        SigningPath::SubAccountV1,
        SigningPath::SubAccountV2,
    ] {
        let mut fixture = Fixture::new(path, true, 100);
        let receipt = fixture.send(fixture.transfer(LIMIT)).unwrap();
        assert_eq!(fixture.token_balance(fixture.destination), (99, 1));
        println!(
            "{path:?} personal receipt CU={}",
            receipt.compute_units_consumed
        );
    }
}

#[test]
fn zero_fee_transfer_keeps_the_same_limit_units() {
    let mut fixture = Fixture::new(SigningPath::Limited, false, 0);
    fixture.send(fixture.transfer(LIMIT)).unwrap();
    assert_eq!(fixture.token_balance(fixture.destination), (100, 0));
    assert_eq!(fixture.remaining(), 0);
}

#[test]
fn fee_transfer_over_limit_leaves_protected_state_unchanged() {
    let mut fixture = Fixture::new(SigningPath::Limited, true, 100);
    let before = fixture.protected_state();
    let failure = fixture.send(fixture.transfer(LIMIT + 1)).unwrap_err();
    assert!(failure
        .meta
        .logs
        .iter()
        .any(|line| line == &format!("Program {TOKEN_2022} success")));
    assert_eq!(
        failure.err,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(
                SwigAuthenticateError::PermissionDeniedInsufficientBalance as u32
            )
        )
    );
    assert_eq!(fixture.protected_state(), before);
}

#[test]
fn other_extension_payloads_remain_protected() {
    for personal_destination in [false, true] {
        let mut fixture = Fixture::new(SigningPath::Limited, personal_destination, 100);
        let owner = if personal_destination {
            fixture.authority.pubkey()
        } else {
            fixture.vault
        };
        let ix =
            enable_required_transfer_memos(&TOKEN_2022, &fixture.destination, &owner, &[]).unwrap();
        let before = fixture.protected_state();
        let failure = fixture.send(ix).unwrap_err();
        assert!(failure
            .meta
            .logs
            .iter()
            .any(|line| line == &format!("Program {TOKEN_2022} success")));
        let error = if personal_destination {
            SwigError::PermissionDeniedAuthorityExternalAssetChange
        } else {
            SwigError::AccountDataModifiedUnexpectedly
        };
        assert_eq!(
            failure.err,
            TransactionError::InstructionError(0, InstructionError::Custom(error as u32))
        );
        assert_eq!(fixture.protected_state(), before);
    }
}
