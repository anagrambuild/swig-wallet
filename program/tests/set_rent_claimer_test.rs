#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_sdk::{
    instruction::InstructionError,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{AuthorityConfig, ClientAction, SetRentClaimerV1Instruction};
use swig_state::{
    action::{sol_limit::SolLimit, sub_account::SubAccount},
    authority::AuthorityType,
    swig::{
        swig_account_seeds, swig_wallet_address_seeds, swig_wallet_address_seeds_with_bump, Swig,
    },
    tail::{active_sub_account_count, rent_claimer},
    Transmutable,
};

/// `SwigError::SignV2CannotBeUsedWithSwigV1`. The program's error module is
/// private to integration tests, so mirror its stable error code here.
const ERR_V2_WITH_SWIG_V1: u32 = 47;
/// `SwigError::InvalidRentClaimerValue`.
const ERR_INVALID_RENT_CLAIMER_VALUE: u32 = 60;

#[derive(Clone, Copy)]
enum WrongBumpOutcome {
    OnCurve,
    OffCurve,
}

fn send_set_rent_claimer(
    context: &mut SwigTestContext,
    swig: Pubkey,
    authority: &Keypair,
    rent_claimer: Pubkey,
) -> Result<(), TransactionError> {
    let set_ix = SetRentClaimerV1Instruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        authority.pubkey(),
        0,
        rent_claimer.to_bytes(),
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
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, authority]).unwrap();
    context
        .svm
        .send_transaction(tx)
        .map(|_| ())
        .map_err(|e| e.err)
}

fn setup_v1_with_wrong_bump_outcome(
    context: &mut SwigTestContext,
    outcome: WrongBumpOutcome,
) -> (Pubkey, Pubkey, Keypair) {
    let authority = Keypair::new();

    for candidate in 0..=u32::MAX {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&candidate.to_le_bytes());
        let (swig, _) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
        let (wallet_address, _) =
            Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
        let wrong_bump = [0u8];
        let wrong_address = Pubkey::create_program_address(
            &swig_wallet_address_seeds_with_bump(swig.as_ref(), &wrong_bump),
            &program_id(),
        );
        let matches = match outcome {
            WrongBumpOutcome::OnCurve => wrong_address.is_err(),
            WrongBumpOutcome::OffCurve => {
                matches!(wrong_address, Ok(address) if address != wallet_address)
            },
        };
        if matches {
            let (created_swig, _) = create_swig_ed25519(context, &authority, id).unwrap();
            assert_eq!(created_swig, swig);
            // `convert_swig_to_v1` writes reserved_lamports = 256. Its low byte
            // is zero, so the vulnerable implementation used bump 0 above.
            convert_swig_to_v1(context, &swig);
            return (swig, wallet_address, authority);
        }
    }

    panic!("could not find a Swig id with the requested bump outcome")
}

fn assert_v1_rejected_without_mutation(outcome: WrongBumpOutcome) {
    let mut context = setup_test_context().unwrap();
    let (swig, wallet_address, authority) = setup_v1_with_wrong_bump_outcome(&mut context, outcome);
    let before = context.svm.get_account(&swig).unwrap();

    let result = send_set_rent_claimer(&mut context, swig, &authority, wallet_address);
    assert_eq!(
        result,
        Err(TransactionError::InstructionError(
            1,
            InstructionError::Custom(ERR_V2_WITH_SWIG_V1),
        ))
    );

    let after = context.svm.get_account(&swig).unwrap();
    assert_eq!(
        after.data, before.data,
        "rejection must not resize or write the tail"
    );
    assert_eq!(
        after.lamports, before.lamports,
        "rejection must not transfer rent into the swig"
    );
}

fn alternate_valid_wallet_bump(swig: &Pubkey, canonical_bump: u8) -> u8 {
    for bump in (0..=u8::MAX).rev() {
        if bump == 0 || bump == canonical_bump {
            continue;
        }
        let bump_seed = [bump];
        if Pubkey::create_program_address(
            &swig_wallet_address_seeds_with_bump(swig.as_ref(), &bump_seed),
            &program_id(),
        )
        .is_ok()
        {
            return bump;
        }
    }
    panic!("a second valid wallet-address bump should exist")
}

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
    let id = [0x22; 32];
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
fn test_set_rent_claimer_rejects_v1_before_on_curve_bump_derivation() {
    assert_v1_rejected_without_mutation(WrongBumpOutcome::OnCurve);
}

#[test_log::test]
fn test_set_rent_claimer_rejects_v1_before_off_curve_bump_comparison() {
    assert_v1_rejected_without_mutation(WrongBumpOutcome::OffCurve);
}

#[test_log::test]
fn test_set_rent_claimer_rejects_wallet_address_when_v1_passes_version_heuristic() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();
    let (wallet_address, canonical_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let alternate_bump = alternate_valid_wallet_bump(&swig, canonical_bump);

    convert_swig_to_v1(&mut context, &swig);
    let mut malformed = context.svm.get_account(&swig).unwrap();
    // A V1 header stores `reserved_lamports` over bytes 40..48. Make its low
    // byte look like a valid but non-canonical bump and the next three bytes
    // look like V2 padding. This passes the shared version heuristic and would
    // bypass the old stored-bump comparison.
    malformed.data[40] = alternate_bump;
    malformed.data[41..Swig::LEN].fill(0);
    context.svm.set_account(swig, malformed).unwrap();
    let before = context.svm.get_account(&swig).unwrap();

    let result = send_set_rent_claimer(&mut context, swig, &authority, wallet_address);
    assert_eq!(
        result,
        Err(TransactionError::InstructionError(
            1,
            InstructionError::Custom(ERR_INVALID_RENT_CLAIMER_VALUE),
        ))
    );

    let after = context.svm.get_account(&swig).unwrap();
    assert_eq!(
        after.data, before.data,
        "rejection must not write an immutable tail"
    );
    assert_eq!(after.lamports, before.lamports);
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
