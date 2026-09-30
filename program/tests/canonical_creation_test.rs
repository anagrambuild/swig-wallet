#![cfg(not(feature = "program_scope_test"))]
//! Creation must retain the bump argument while rejecting alternate config PDAs.
mod common;
#[path = "../src/error.rs"]
mod swig_error;

use common::*;
use solana_sdk::{
    instruction::{Instruction, InstructionError},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_error::SwigError;
use swig_interface::{AuthorityConfig, ClientAction, CreateInstruction};
use swig_state::{
    action::all::All,
    authority::AuthorityType,
    swig::{
        swig_account_seeds, swig_account_seeds_with_bump, swig_wallet_address_seeds, SwigWithRoles,
    },
};

fn send(
    context: &mut SwigTestContext,
    authority: &Keypair,
    ix: Instruction,
) -> Result<(), TransactionError> {
    context.svm.expire_blockhash();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, authority],
    )
    .unwrap();
    context.svm.send_transaction(tx).map(|_| ()).map_err(|e| {
        eprintln!("{}", e.meta.pretty_logs());
        e.err
    })
}

fn alternate_config(id: &[u8; 32]) -> (Pubkey, u8) {
    let (_, canonical_bump) = Pubkey::find_program_address(&swig_account_seeds(id), &program_id());
    (0..canonical_bump)
        .rev()
        .find_map(|bump| {
            Pubkey::create_program_address(
                &swig_account_seeds_with_bump(id, &[bump]),
                &program_id(),
            )
            .ok()
            .map(|key| (key, bump))
        })
        .expect("fixture must have another valid config bump")
}

fn create_instruction(config: Pubkey, bump: u8, root: &Keypair, id: [u8; 32]) -> Instruction {
    let (wallet, wallet_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(config.as_ref()), &program_id());
    CreateInstruction::new(
        config,
        bump,
        root.pubkey(),
        wallet,
        wallet_bump,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: root.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {})],
        id,
    )
    .unwrap()
}

/// Assert the exact preflight error and rollback of every supplied account except
/// the transaction fee payer. This includes token data, authority state and SOL.
fn assert_rejected_unchanged(
    context: &mut SwigTestContext,
    authority: &Keypair,
    ix: Instruction,
    error: SwigError,
) {
    let before: Vec<_> = ix
        .accounts
        .iter()
        .filter(|meta| meta.pubkey != context.default_payer.pubkey())
        .map(|meta| (meta.pubkey, context.svm.get_account(&meta.pubkey)))
        .collect();
    assert_eq!(
        send(context, authority, ix),
        Err(TransactionError::InstructionError(
            0,
            InstructionError::Custom(error as u32)
        ))
    );
    for (key, account) in before {
        assert_eq!(
            context.svm.get_account(&key),
            account,
            "account {key} changed"
        );
    }
}

fn creation_context() -> (SwigTestContext, Keypair) {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    context.svm.airdrop(&root.pubkey(), 10_000_000_000).unwrap();
    (context, root)
}

#[test]
fn creation_accepts_and_stores_canonical_bump() {
    let (mut context, root) = creation_context();
    let id = [41; 32];
    let (canonical, bump) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    send(
        &mut context,
        &root,
        create_instruction(canonical, bump, &root, id),
    )
    .unwrap();
    let account = context.svm.get_account(&canonical).unwrap();
    let swig = SwigWithRoles::from_bytes(&account.data).unwrap();
    assert_eq!(account.owner, program_id());
    assert_eq!(swig.state.id, id);
    assert_eq!(swig.state.bump, bump);
    assert_eq!(swig.state.roles, 1);
}

#[test]
fn creation_rejects_valid_noncanonical_config_without_mutation() {
    let (mut context, root) = creation_context();
    let id = [41; 32];
    let (alternate, alternate_bump) = alternate_config(&id);
    // Both address and supplied bump describe a real off-curve PDA for this ID.
    // The pre-fix implementation accepted this instruction.
    let ix = create_instruction(alternate, alternate_bump, &root, id);
    assert_rejected_unchanged(&mut context, &root, ix, SwigError::InvalidSeedSwigAccount);
}

#[test]
fn creation_rejects_wrong_supplied_bump_at_canonical_address_without_mutation() {
    let (mut context, root) = creation_context();
    let id = [41; 32];
    let (canonical, _) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let (_, alternate_bump) = alternate_config(&id);
    // A canonical account key alone is insufficient: validate the caller's byte too.
    let ix = create_instruction(canonical, alternate_bump, &root, id);
    assert_rejected_unchanged(&mut context, &root, ix, SwigError::InvalidSeedSwigAccount);
}
