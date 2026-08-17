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
    action::{sol_limit::SolLimit, sub_account::SubAccount},
    authority::AuthorityType,
    swig::{swig_wallet_address_seeds, Swig},
    tail::{active_sub_account_count, rent_claimer},
};

fn add_sub_account_authority(
    context: &mut SwigTestContext,
    swig: &solana_sdk::pubkey::Pubkey,
    root: &Keypair,
    authority: &Keypair,
) {
    context
        .svm
        .airdrop(&authority.pubkey(), 10_000_000_000)
        .unwrap();
    add_authority_with_ed25519_root(
        context,
        swig,
        root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccount(SubAccount::new_for_creation())],
    )
    .unwrap();
}

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
fn test_set_rent_claimer_after_active_count_preserves_both_tail_entries() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let child_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();
    add_sub_account_authority(&mut context, &swig, &root, &child_authority);

    create_sub_account(&mut context, &swig, &child_authority, 1, id).unwrap();
    let claimer = Keypair::new();
    set_rent_claimer_with_ed25519(&mut context, &swig, &root, 0, claimer.pubkey()).unwrap();

    let account = context.svm.get_account(&swig).unwrap();
    let parts = Swig::split_parts(&account.data).unwrap();
    assert_eq!(
        rent_claimer::read_strict(parts.tail).unwrap(),
        Some(&claimer.pubkey().to_bytes())
    );
    assert_eq!(active_sub_account_count::read(parts.tail).unwrap(), Some(1));
}

#[test_log::test]
fn test_create_sub_account_after_rent_claimer_preserves_both_tail_entries() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let child_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();
    let claimer = Keypair::new();
    set_rent_claimer_with_ed25519(&mut context, &swig, &root, 0, claimer.pubkey()).unwrap();
    add_sub_account_authority(&mut context, &swig, &root, &child_authority);

    create_sub_account(&mut context, &swig, &child_authority, 1, id).unwrap();

    let account = context.svm.get_account(&swig).unwrap();
    let parts = Swig::split_parts(&account.data).unwrap();
    assert_eq!(
        rent_claimer::read_strict(parts.tail).unwrap(),
        Some(&claimer.pubkey().to_bytes())
    );
    assert_eq!(active_sub_account_count::read(parts.tail).unwrap(), Some(1));
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
fn test_set_rent_claimer_rejects_swig_wallet_address() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();
    let (swig_wallet_address, _) = solana_sdk::pubkey::Pubkey::find_program_address(
        &swig_wallet_address_seeds(swig_pubkey.as_ref()),
        &program_id(),
    );

    let set_ix = SetRentClaimerV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        context.default_payer.pubkey(),
        authority.pubkey(),
        0,
        swig_wallet_address.to_bytes(),
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
    assert!(
        result.is_err(),
        "swig wallet address as rent claimer must fail"
    );
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
