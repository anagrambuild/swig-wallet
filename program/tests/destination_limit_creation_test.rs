//! Destination-limit creation rules: a role may hold at most one
//! destination-limit action of each type for the same `(destination, mint)`
//! key. A regular + recurring pair for the same key stays allowed, since the
//! recurring allowance acts as the per-window budget and the one-shot amount
//! as the total budget.

#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_sdk::{
    instruction::{Instruction, InstructionError},
    message::{v0, VersionedMessage},
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{
    AddAuthorityInstruction, AuthorityConfig, ClientAction, UpdateAuthorityData,
    UpdateAuthorityInstruction,
};
use swig_state::{
    action::{
        program_all::ProgramAll, sol_destination_limit::SolDestinationLimit,
        sol_recurring_destination_limit::SolRecurringDestinationLimit,
        token_destination_limit::TokenDestinationLimit,
        token_recurring_destination_limit::TokenRecurringDestinationLimit,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds},
    SwigStateError,
};

const ROOT_ACTING: u32 = 0;

struct Harness {
    context: SwigTestContext,
    swig: Pubkey,
    wallet: Pubkey,
    root: Keypair,
}

impl Harness {
    fn new() -> Self {
        let mut context = setup_test_context().unwrap();
        let root = Keypair::new();
        context
            .svm
            .airdrop(&root.pubkey(), LAMPORTS_PER_SOL)
            .unwrap();
        let id = rand::random::<[u8; 32]>();
        let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
        let wallet =
            Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id())
                .0;
        create_swig_ed25519(&mut context, &root, id).unwrap();
        context.svm.airdrop(&wallet, 10 * LAMPORTS_PER_SOL).unwrap();
        context.svm.warp_to_slot(100);
        Self {
            context,
            swig,
            wallet,
            root,
        }
    }

    fn add_authority_ix(
        &self,
        card: &Keypair,
        actions: Vec<ClientAction>,
    ) -> anyhow::Result<Instruction> {
        AddAuthorityInstruction::new_with_ed25519_authority(
            self.swig,
            self.context.default_payer.pubkey(),
            self.root.pubkey(),
            ROOT_ACTING,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: card.pubkey().as_ref(),
            },
            actions,
        )
    }

    fn update_ix(
        &self,
        authority_id: u32,
        update_data: UpdateAuthorityData,
    ) -> anyhow::Result<Instruction> {
        UpdateAuthorityInstruction::new_with_ed25519_authority(
            self.swig,
            self.context.default_payer.pubkey(),
            self.root.pubkey(),
            ROOT_ACTING,
            authority_id,
            update_data,
        )
    }

    fn send(
        &mut self,
        instructions: &[Instruction],
        signers: &[Keypair],
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        self.context.svm.expire_blockhash();
        let mut ixs = vec![ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)];
        ixs.extend_from_slice(instructions);
        let message = v0::Message::try_compile(
            &self.context.default_payer.pubkey(),
            &ixs,
            &[],
            self.context.svm.latest_blockhash(),
        )
        .unwrap();
        let mut all_signers = vec![&self.context.default_payer];
        for signer in signers {
            all_signers.push(signer);
        }
        let tx =
            VersionedTransaction::try_new(VersionedMessage::V0(message), &all_signers).unwrap();
        self.context.svm.send_transaction(tx)
    }
}

fn ok(result: Result<TransactionMetadata, FailedTransactionMetadata>) -> TransactionMetadata {
    result.unwrap_or_else(|failed| {
        panic!(
            "transaction failed: {:?}\n{}",
            failed.err,
            failed.meta.pretty_logs()
        )
    })
}

fn custom_error(result: Result<TransactionMetadata, FailedTransactionMetadata>) -> u32 {
    match result {
        Ok(_) => panic!("transaction unexpectedly succeeded"),
        Err(failed) => match failed.err {
            TransactionError::InstructionError(_, InstructionError::Custom(code)) => code,
            other => panic!("unexpected error {other:?}\n{}", failed.meta.pretty_logs()),
        },
    }
}

/// Swig's root creation path through the full instruction flow.
#[test]
fn add_authority_rejects_duplicate_sol_destination_limits() {
    let merchant = Keypair::new().pubkey();
    let mut h = Harness::new();
    let card = Keypair::new();
    h.context
        .svm
        .airdrop(&card.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    let ix = h
        .add_authority_ix(
            &card,
            vec![
                ClientAction::SolDestinationLimit(SolDestinationLimit {
                    destination: merchant.to_bytes(),
                    amount: LAMPORTS_PER_SOL,
                }),
                ClientAction::SolDestinationLimit(SolDestinationLimit {
                    destination: merchant.to_bytes(),
                    amount: 2 * LAMPORTS_PER_SOL,
                }),
            ],
        )
        .unwrap();
    assert_eq!(
        custom_error(h.send(&[ix], &[h.root.insecure_clone()])),
        SwigStateError::DuplicateDestinationLimit as u32
    );
}

#[test]
fn add_authority_allows_a_regular_and_recurring_pair() {
    let merchant = Keypair::new().pubkey();
    let mut h = Harness::new();
    let card = Keypair::new();
    h.context
        .svm
        .airdrop(&card.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    let ix = h
        .add_authority_ix(
            &card,
            vec![
                ClientAction::SolDestinationLimit(SolDestinationLimit {
                    destination: merchant.to_bytes(),
                    amount: 4 * LAMPORTS_PER_SOL,
                }),
                ClientAction::SolRecurringDestinationLimit(SolRecurringDestinationLimit {
                    destination: merchant.to_bytes(),
                    recurring_amount: LAMPORTS_PER_SOL,
                    window: 100,
                    last_reset: 0,
                    current_amount: LAMPORTS_PER_SOL,
                }),
            ],
        )
        .unwrap();
    ok(h.send(&[ix], &[h.root.insecure_clone()]));
}

#[test]
fn add_authority_rejects_duplicate_token_destination_limits() {
    let mut h = Harness::new();
    let card = Keypair::new();
    h.context
        .svm
        .airdrop(&card.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    let merchant = Keypair::new().pubkey();
    let ix = h
        .add_authority_ix(
            &card,
            vec![
                ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                    token_mint: [1u8; 32],
                    destination: merchant.to_bytes(),
                    amount: 100,
                }),
                ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                    token_mint: [1u8; 32],
                    destination: merchant.to_bytes(),
                    amount: 200,
                }),
            ],
        )
        .unwrap();
    assert_eq!(
        custom_error(h.send(&[ix], &[h.root.insecure_clone()])),
        SwigStateError::DuplicateDestinationLimit as u32
    );
}

#[test]
fn adding_actions_may_not_introduce_a_duplicate() {
    let merchant = Keypair::new().pubkey();
    let mut h = Harness::new();
    let card = Keypair::new();
    h.context
        .svm
        .airdrop(&card.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    let add = h
        .add_authority_ix(
            &card,
            vec![ClientAction::SolDestinationLimit(SolDestinationLimit {
                destination: merchant.to_bytes(),
                amount: LAMPORTS_PER_SOL,
            })],
        )
        .unwrap();
    ok(h.send(&[add], &[h.root.insecure_clone()]));

    // A second same-type limit for the same destination is rejected.
    let ix = h
        .update_ix(
            1,
            UpdateAuthorityData::AddActions(vec![ClientAction::SolDestinationLimit(
                SolDestinationLimit {
                    destination: merchant.to_bytes(),
                    amount: 2 * LAMPORTS_PER_SOL,
                },
            )]),
        )
        .unwrap();
    assert_eq!(
        custom_error(h.send(&[ix], &[h.root.insecure_clone()])),
        SwigStateError::DuplicateDestinationLimit as u32
    );

    // The intended pair - a recurring companion for the same destination - is
    // accepted.
    let ix = h
        .update_ix(
            1,
            UpdateAuthorityData::AddActions(vec![ClientAction::SolRecurringDestinationLimit(
                SolRecurringDestinationLimit {
                    destination: merchant.to_bytes(),
                    recurring_amount: LAMPORTS_PER_SOL,
                    window: 100,
                    last_reset: 0,
                    current_amount: LAMPORTS_PER_SOL,
                },
            )]),
        )
        .unwrap();
    ok(h.send(&[ix], &[h.root.insecure_clone()]));
}

#[test]
fn replace_all_may_not_introduce_a_duplicate() {
    let merchant = Keypair::new().pubkey();
    let mut h = Harness::new();
    let card = Keypair::new();
    h.context
        .svm
        .airdrop(&card.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    let add = h
        .add_authority_ix(
            &card,
            vec![ClientAction::SolDestinationLimit(SolDestinationLimit {
                destination: merchant.to_bytes(),
                amount: LAMPORTS_PER_SOL,
            })],
        )
        .unwrap();
    ok(h.send(&[add], &[h.root.insecure_clone()]));

    let ix = h
        .update_ix(
            1,
            UpdateAuthorityData::ReplaceAll(vec![
                ClientAction::ProgramAll(ProgramAll),
                ClientAction::SolDestinationLimit(SolDestinationLimit {
                    destination: merchant.to_bytes(),
                    amount: LAMPORTS_PER_SOL,
                }),
                ClientAction::SolDestinationLimit(SolDestinationLimit {
                    destination: merchant.to_bytes(),
                    amount: 2 * LAMPORTS_PER_SOL,
                }),
            ]),
        )
        .unwrap();
    assert_eq!(
        custom_error(h.send(&[ix], &[h.root.insecure_clone()])),
        SwigStateError::DuplicateDestinationLimit as u32
    );
}
