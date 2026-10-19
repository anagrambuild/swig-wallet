#![cfg(not(feature = "program_scope_test"))]
//! Spending policies after ordinary transfers and closure through SignV2.

mod common;

use common::*;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use litesvm_token::{spl_token, CreateAssociatedTokenAccount};
use solana_program::program_pack::Pack;
use solana_sdk::{
    account::Account,
    instruction::{Instruction, InstructionError},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{Transaction, TransactionError, VersionedTransaction},
};
use spl_token_2022_interface::{instruction as token_instruction, state::Mint, ID as TOKEN_2022};
use swig::actions::sign_v2::SignV2Args;
use swig_interface::{compact_instructions, AuthorityConfig, ClientAction, SignV2Instruction};
use swig_state::{
    action::{
        close_swig_authority::CloseSwigAuthority, program::Program,
        token_destination_limit::TokenDestinationLimit, token_limit::TokenLimit,
        token_recurring_destination_limit::TokenRecurringDestinationLimit,
        token_recurring_limit::TokenRecurringLimit,
    },
    authority::AuthorityType,
    swig::{swig_wallet_address_seeds, SwigWithRoles},
    IntoBytes, SwigAuthenticateError,
};

const AMOUNT: u64 = 100;
const WINDOW: u64 = 10;

#[derive(Clone, Copy, Debug)]
enum LimitKind {
    Fixed,
    Recurring,
    Destination,
    RecurringDestination,
}

#[derive(Clone, Copy, Debug)]
enum TransferKind {
    Unchecked,
    Checked,
}

struct Fixture {
    context: Context,
    authority: Keypair,
    swig: Pubkey,
    wallet: Pubkey,
    mint: Pubkey,
    source: Pubkey,
    destination: Pubkey,
    token_program: Pubkey,
}

impl Fixture {
    fn new(token_program: Pubkey, limits: &[(LimitKind, u64)]) -> Self {
        let mut context = setup_test_context().unwrap();
        context.svm.warp_to_slot(0);
        let root = Keypair::new();
        let authority = Keypair::new();
        let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
        let wallet =
            Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id())
                .0;
        let mint_keypair = Keypair::new();
        let mint = mint_keypair.pubkey();
        let create_mint = solana_system_interface::instruction::create_account(
            &context.default_payer.pubkey(),
            &mint,
            context.svm.minimum_balance_for_rent_exemption(Mint::LEN),
            Mint::LEN as u64,
            &token_program,
        );
        let initialize_mint = token_instruction::initialize_mint2(
            &token_program,
            &mint,
            &context.default_payer.pubkey(),
            None,
            9,
        )
        .unwrap();
        context
            .svm
            .send_transaction(Transaction::new_signed_with_payer(
                &[create_mint, initialize_mint],
                Some(&context.default_payer.pubkey()),
                &[&context.default_payer, &mint_keypair],
                context.svm.latest_blockhash(),
            ))
            .unwrap();
        let destination =
            CreateAssociatedTokenAccount::new(&mut context.svm, &context.default_payer, &mint)
                .owner(&Pubkey::new_unique())
                .token_program_id(&token_program)
                .send()
                .unwrap();
        let mut actions = vec![
            ClientAction::Program(Program {
                program_id: token_program.to_bytes(),
            }),
            ClientAction::CloseSwigAuthority(CloseSwigAuthority),
        ];
        for &(kind, amount) in limits {
            actions.push(match kind {
                LimitKind::Fixed => ClientAction::TokenLimit(TokenLimit {
                    token_mint: mint.to_bytes(),
                    current_amount: amount,
                }),
                LimitKind::Recurring => ClientAction::TokenRecurringLimit(TokenRecurringLimit {
                    token_mint: mint.to_bytes(),
                    window: WINDOW,
                    limit: amount,
                    current: amount,
                    last_reset: 0,
                }),
                LimitKind::Destination => {
                    ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                        token_mint: mint.to_bytes(),
                        destination: destination.to_bytes(),
                        amount,
                    })
                },
                LimitKind::RecurringDestination => {
                    ClientAction::TokenRecurringDestinationLimit(TokenRecurringDestinationLimit {
                        token_mint: mint.to_bytes(),
                        destination: destination.to_bytes(),
                        recurring_amount: amount,
                        window: WINDOW,
                        last_reset: 0,
                        current_amount: amount,
                    })
                },
            });
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
        let source = Self::fund_source(&mut context, &wallet, &mint, &token_program);
        Self {
            context,
            authority,
            swig,
            wallet,
            mint,
            source,
            destination,
            token_program,
        }
    }

    fn fund_source(
        context: &mut Context,
        wallet: &Pubkey,
        mint: &Pubkey,
        token_program: &Pubkey,
    ) -> Pubkey {
        // A closed ATA may be recreated, but its spending policy persists in Swig.
        context.svm.expire_blockhash();
        let source =
            CreateAssociatedTokenAccount::new(&mut context.svm, &context.default_payer, mint)
                .owner(wallet)
                .token_program_id(token_program)
                .send()
                .unwrap();
        let mint_to = token_instruction::mint_to(
            token_program,
            mint,
            &source,
            &context.default_payer.pubkey(),
            &[],
            AMOUNT,
        )
        .unwrap();
        context
            .svm
            .send_transaction(Transaction::new_signed_with_payer(
                &[mint_to],
                Some(&context.default_payer.pubkey()),
                &[&context.default_payer],
                context.svm.latest_blockhash(),
            ))
            .unwrap();
        let source_account = context.svm.get_account(&source).unwrap();
        assert_eq!(source_account.owner, *token_program);
        // Token-2022 ATAs carry ImmutableOwner beyond the shared account layout.
        if *token_program == TOKEN_2022 {
            assert!(source_account.data.len() > 165);
        }
        source
    }

    fn transfer_and_close(
        &mut self,
        destination: Pubkey,
        kind: TransferKind,
    ) -> Result<TransactionMetadata, Box<FailedTransactionMetadata>> {
        // Exercise both supported encodings; unchecked transfers remain valid
        // for the ordinary mints used here.
        #[allow(deprecated)]
        let transfer = match kind {
            TransferKind::Unchecked => token_instruction::transfer(
                &self.token_program,
                &self.source,
                &destination,
                &self.wallet,
                &[],
                AMOUNT,
            ),
            TransferKind::Checked => token_instruction::transfer_checked(
                &self.token_program,
                &self.source,
                &self.mint,
                &destination,
                &self.wallet,
                &[],
                AMOUNT,
                9,
            ),
        }
        .unwrap();
        let close = token_instruction::close_account(
            &self.token_program,
            &self.source,
            &self.context.default_payer.pubkey(),
            &self.wallet,
            &[],
        )
        .unwrap();
        // The public builder accepts one CPI. Keep its fixed account contract and
        // use the production compact encoder for the ordinary transfer + close.
        let base = SignV2Instruction::new_ed25519(
            self.swig,
            self.wallet,
            self.authority.pubkey(),
            transfer.clone(),
            1,
        )
        .unwrap();
        let (accounts, compact) = compact_instructions(
            self.wallet,
            base.accounts[..3].to_vec(),
            vec![transfer, close],
        )
        .unwrap();
        let payload = compact.into_bytes().unwrap();
        let args = SignV2Args::new(1, u16::try_from(payload.len()).unwrap());
        let instruction = Instruction {
            accounts,
            data: [args.into_bytes().unwrap(), &payload, &[2]].concat(),
            ..base
        };
        let message = v0::Message::try_compile(
            &self.context.default_payer.pubkey(),
            &[instruction],
            &[],
            self.context.svm.latest_blockhash(),
        )
        .unwrap();
        let transaction = VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[&self.context.default_payer, &self.authority],
        )
        .unwrap();
        self.context
            .svm
            .send_transaction(transaction)
            .map_err(Box::new)
    }

    fn limit_state(&self, kind: LimitKind) -> (u64, Option<u64>) {
        let account = self.context.svm.get_account(&self.swig).unwrap();
        let swig = SwigWithRoles::from_bytes(&account.data).unwrap();
        let role = swig.get_role(1).unwrap().unwrap();
        let mut combined_key = [0; 64];
        combined_key[..32].copy_from_slice(self.mint.as_ref());
        combined_key[32..].copy_from_slice(self.destination.as_ref());
        match kind {
            LimitKind::Fixed => (
                role.get_action::<TokenLimit>(self.mint.as_ref())
                    .unwrap()
                    .unwrap()
                    .current_amount,
                None,
            ),
            LimitKind::Recurring => {
                let limit = role
                    .get_action::<TokenRecurringLimit>(self.mint.as_ref())
                    .unwrap()
                    .unwrap();
                (limit.current, Some(limit.last_reset))
            },
            LimitKind::Destination => (
                role.get_action::<TokenDestinationLimit>(&combined_key)
                    .unwrap()
                    .unwrap()
                    .amount,
                None,
            ),
            LimitKind::RecurringDestination => {
                let limit = role
                    .get_action::<TokenRecurringDestinationLimit>(&combined_key)
                    .unwrap()
                    .unwrap();
                (limit.current_amount, Some(limit.last_reset))
            },
        }
    }

    fn assert_rejected_without_changes(
        &mut self,
        destination: Pubkey,
        kind: TransferKind,
        expected: InstructionError,
    ) {
        let keys = [self.swig, self.source, self.destination, destination];
        let before: Vec<Account> = keys
            .iter()
            .map(|key| self.context.svm.get_account(key).unwrap())
            .collect();
        let error = self.transfer_and_close(destination, kind).unwrap_err();
        assert_eq!(
            error.err,
            TransactionError::InstructionError(0, expected),
            "{:?}",
            error.meta.logs
        );
        for (key, original) in keys.iter().zip(before) {
            assert_eq!(self.context.svm.get_account(key).unwrap(), original);
        }
    }
}

fn exceeded_error(kind: LimitKind) -> InstructionError {
    match kind {
        LimitKind::Fixed => InstructionError::Custom(
            SwigAuthenticateError::PermissionDeniedInsufficientBalance as u32,
        ),
        LimitKind::Recurring => InstructionError::InsufficientFunds,
        LimitKind::Destination => InstructionError::Custom(
            SwigAuthenticateError::PermissionDeniedTokenDestinationLimitExceeded as u32,
        ),
        LimitKind::RecurringDestination => InstructionError::Custom(
            SwigAuthenticateError::PermissionDeniedRecurringTokenDestinationLimitExceeded as u32,
        ),
    }
}

#[test]
fn closed_token_accounts_enforce_each_limit_and_consume_exact_debits() {
    for token_program in [spl_token::ID, TOKEN_2022] {
        for transfer in [TransferKind::Unchecked, TransferKind::Checked] {
            let mut missing = Fixture::new(token_program, &[]);
            missing.assert_rejected_without_changes(
                missing.destination,
                transfer,
                InstructionError::Custom(
                    SwigAuthenticateError::PermissionDeniedMissingPermission as u32,
                ),
            );
            for kind in [
                LimitKind::Fixed,
                LimitKind::Recurring,
                LimitKind::Destination,
                LimitKind::RecurringDestination,
            ] {
                for allowance in [AMOUNT - 1, AMOUNT, AMOUNT + 1] {
                    let mut fixture = Fixture::new(token_program, &[(kind, allowance)]);
                    if allowance < AMOUNT {
                        fixture.assert_rejected_without_changes(
                            fixture.destination,
                            transfer,
                            exceeded_error(kind),
                        );
                    } else {
                        let before_reset = fixture.limit_state(kind).1;
                        fixture
                            .transfer_and_close(fixture.destination, transfer)
                            .unwrap();
                        assert_eq!(
                            fixture.limit_state(kind),
                            (allowance - AMOUNT, before_reset)
                        );
                        assert!(fixture.context.svm.get_account(&fixture.source).is_none());
                        let received = fixture
                            .context
                            .svm
                            .get_account(&fixture.destination)
                            .unwrap();
                        assert_eq!(
                            u64::from_le_bytes(received.data[64..72].try_into().unwrap()),
                            AMOUNT
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn closed_token_destination_limits_require_the_configured_destination() {
    for token_program in [spl_token::ID, TOKEN_2022] {
        for transfer in [TransferKind::Unchecked, TransferKind::Checked] {
            for kind in [LimitKind::Destination, LimitKind::RecurringDestination] {
                let mut fixture =
                    Fixture::new(token_program, &[(LimitKind::Fixed, AMOUNT), (kind, AMOUNT)]);
                let other = CreateAssociatedTokenAccount::new(
                    &mut fixture.context.svm,
                    &fixture.context.default_payer,
                    &fixture.mint,
                )
                .owner(&Pubkey::new_unique())
                .token_program_id(&token_program)
                .send()
                .unwrap();
                fixture.assert_rejected_without_changes(
                    other,
                    transfer,
                    InstructionError::Custom(
                        SwigAuthenticateError::PermissionDeniedMissingPermission as u32,
                    ),
                );
            }
        }
    }
}

#[test]
fn closed_tokens_consume_both_general_and_destination_budgets() {
    for token_program in [spl_token::ID, TOKEN_2022] {
        for (general, destination) in [
            (LimitKind::Fixed, LimitKind::Destination),
            (LimitKind::Recurring, LimitKind::RecurringDestination),
        ] {
            for (general_amount, destination_amount) in [(99, 100), (100, 99), (100, 100)] {
                let mut fixture = Fixture::new(
                    token_program,
                    &[(general, general_amount), (destination, destination_amount)],
                );
                if general_amount < AMOUNT || destination_amount < AMOUNT {
                    fixture.assert_rejected_without_changes(
                        fixture.destination,
                        TransferKind::Checked,
                        exceeded_error(if general_amount < AMOUNT {
                            general
                        } else {
                            destination
                        }),
                    );
                } else {
                    fixture
                        .transfer_and_close(fixture.destination, TransferKind::Checked)
                        .unwrap();
                    assert_eq!(fixture.limit_state(general).0, 0);
                    assert_eq!(fixture.limit_state(destination).0, 0);
                }
            }
        }
    }
}

#[test]
fn recurring_closed_token_limits_persist_until_the_window_resets() {
    for token_program in [spl_token::ID, TOKEN_2022] {
        for kind in [LimitKind::Recurring, LimitKind::RecurringDestination] {
            let mut fixture = Fixture::new(token_program, &[(kind, AMOUNT)]);
            fixture
                .transfer_and_close(fixture.destination, TransferKind::Checked)
                .unwrap();
            assert_eq!(fixture.limit_state(kind), (0, Some(0)));
            fixture.source = Fixture::fund_source(
                &mut fixture.context,
                &fixture.wallet,
                &fixture.mint,
                &fixture.token_program,
            );
            // The window is inclusive: exactly WINDOW slots does not reset it.
            fixture.context.svm.warp_to_slot(WINDOW);
            fixture.assert_rejected_without_changes(
                fixture.destination,
                TransferKind::Checked,
                exceeded_error(kind),
            );
            fixture.context.svm.warp_to_slot(WINDOW + 1);
            fixture.context.svm.expire_blockhash();
            fixture
                .transfer_and_close(fixture.destination, TransferKind::Checked)
                .unwrap();
            let expected_reset = match kind {
                LimitKind::Recurring => WINDOW,
                LimitKind::RecurringDestination => WINDOW + 1,
                _ => unreachable!(),
            };
            assert_eq!(fixture.limit_state(kind), (0, Some(expected_reset)));
            let received = fixture
                .context
                .svm
                .get_account(&fixture.destination)
                .unwrap();
            assert_eq!(
                u64::from_le_bytes(received.data[64..72].try_into().unwrap()),
                AMOUNT * 2
            );
        }
    }
}
