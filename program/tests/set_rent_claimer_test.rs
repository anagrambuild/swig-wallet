#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_sdk::{
    message::{v0, VersionedMessage},
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ClientAction, SetRentClaimerV1Instruction};
use swig_state::{
    action::sol_limit::SolLimit,
    authority::AuthorityType,
    swig::Swig,
    tail::rent_claimer,
};

#[test_log::test]
fn test_set_rent_claimer_happy_path() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();
    let claimer = Keypair::new();

    set_rent_claimer_with_ed25519(&mut context, &swig_pubkey, &authority, 0, claimer.pubkey())
        .unwrap();

    let swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    let parts = Swig::split_parts(&swig_account.data).unwrap();
    let parsed = rent_claimer::read_strict(parts.tail).unwrap();
    assert_eq!(parsed, Some(&claimer.pubkey().to_bytes()));
}

#[test_log::test]
fn test_set_rent_claimer_rejects_zero_pubkey() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let set_ix = SetRentClaimerV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        context.default_payer.pubkey(),
        authority.pubkey(),
        0,
        [0u8; 32],
    )
    .unwrap();
    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[ComputeBudgetInstruction::set_compute_unit_limit(400_000), set_ix],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &authority]).unwrap();
    let result = context.svm.send_transaction(tx);
    assert!(result.is_err(), "zero rent claimer pubkey must fail");
}

#[test_log::test]
fn test_set_rent_claimer_rejects_swig_self() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let set_ix = SetRentClaimerV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        context.default_payer.pubkey(),
        authority.pubkey(),
        0,
        swig_pubkey.to_bytes(),
    )
    .unwrap();
    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                set_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &authority]).unwrap();
    let result = context.svm.send_transaction(tx);
    assert!(result.is_err(), "swig as its own rent claimer must fail");
}

#[test_log::test]
fn test_set_rent_claimer_is_one_shot() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    set_rent_claimer_with_ed25519(
        &mut context,
        &swig_pubkey,
        &authority,
        0,
        Keypair::new().pubkey(),
    )
    .unwrap();

    let second = set_rent_claimer_with_ed25519(
        &mut context,
        &swig_pubkey,
        &authority,
        0,
        Keypair::new().pubkey(),
    );
    assert!(second.is_err(), "rent claimer should be immutable");
}

#[test_log::test]
fn test_set_rent_claimer_requires_permission() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let limited = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    context
        .svm
        .airdrop(&limited.pubkey(), 10_000_000_000)
        .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: limited.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1_000_000 })],
    )
    .unwrap();

    let result = set_rent_claimer_with_ed25519(
        &mut context,
        &swig_pubkey,
        &limited,
        1,
        Keypair::new().pubkey(),
    );
    assert!(
        result.is_err(),
        "authority without All/CloseSwigAuthority must fail"
    );
}
