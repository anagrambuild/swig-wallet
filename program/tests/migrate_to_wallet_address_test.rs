#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_sdk::{
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig::actions::migrate_to_wallet_address_v1::MigrateToWalletAddressV1Args;
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state::{
    action::{sub_account_v2::SubAccountV2All, Permission},
    authority::AuthorityType,
    swig::{swig_wallet_address_seeds, swig_wallet_address_seeds_with_bump, Swig},
    IntoBytes, SwigStateError, Transmutable,
};

/// `SwigError::InvalidSeedSwigAccount`. The program's error module is private,
/// so the stable custom error code is mirrored here.
const ERR_INVALID_SEED_SWIG_ACCOUNT: u32 = 9;
/// `SwigError::SwigAlreadyMigrated`.
const ERR_SWIG_ALREADY_MIGRATED: u32 = 76;
const OWNER_MISMATCH_SWIG_ACCOUNT_ERROR: u32 = 1;
const INVALID_SYSTEM_PROGRAM_ERROR: u32 = 24;

fn migrate_instruction(
    swig: Pubkey,
    authority: Pubkey,
    payer: Pubkey,
    swig_wallet_address: Pubkey,
    wallet_address_bump: u8,
    authority_is_signer: bool,
    system_program: Pubkey,
) -> Instruction {
    let mut data = MigrateToWalletAddressV1Args::new(wallet_address_bump, 0)
        .into_bytes()
        .expect("migrate args should serialize")
        .to_vec();
    data.push(1);

    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(swig, false),
            AccountMeta::new_readonly(authority, authority_is_signer),
            AccountMeta::new(payer, true),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(system_program, false),
        ],
        data,
    }
}

fn setup_unmigrated_swig() -> (SwigTestContext, Keypair, Pubkey, Pubkey, u8) {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig, _bench) = create_swig_ed25519(&mut context, &authority, id).unwrap();
    convert_swig_to_v1(&mut context, &swig);

    let (swig_wallet_address, wallet_address_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    (
        context,
        authority,
        swig,
        swig_wallet_address,
        wallet_address_bump,
    )
}

fn alternate_wallet_address(swig: &Pubkey, canonical_bump: u8) -> (Pubkey, u8) {
    for bump in (0..=u8::MAX).rev() {
        if bump == canonical_bump {
            continue;
        }
        let bump_seed = [bump];
        if let Ok(address) = Pubkey::create_program_address(
            &swig_wallet_address_seeds_with_bump(swig.as_ref(), &bump_seed),
            &program_id(),
        ) {
            return (address, bump);
        }
    }
    panic!("a second valid wallet-address bump should exist");
}

#[test_log::test]
fn test_migration_rejects_nonsigner_authority() {
    let (mut context, authority, swig, swig_wallet_address, wallet_address_bump) =
        setup_unmigrated_swig();

    let migrate_ix = migrate_instruction(
        swig,
        authority.pubkey(),
        context.default_payer.pubkey(),
        swig_wallet_address,
        wallet_address_bump,
        false,
        solana_system_interface::program::ID,
    );

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                migrate_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer]).unwrap();

    let result = context.svm.send_transaction(tx);

    assert!(
        result.is_err(),
        "migration must fail when the role authority does not sign"
    );
}

#[test_log::test]
fn test_migration_accepts_authenticated_authority() {
    let (mut context, authority, swig, swig_wallet_address, wallet_address_bump) =
        setup_unmigrated_swig();

    let migrate_ix = migrate_instruction(
        swig,
        authority.pubkey(),
        context.default_payer.pubkey(),
        swig_wallet_address,
        wallet_address_bump,
        true,
        solana_system_interface::program::ID,
    );

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                migrate_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &authority]).unwrap();

    let result = context.svm.send_transaction(tx);

    assert!(
        result.is_ok(),
        "authenticated migration should succeed: {:?}",
        result.err()
    );

    let swig_account = context.svm.get_account(&swig).unwrap();
    let migrated_swig = unsafe { Swig::load_unchecked(&swig_account.data[..Swig::LEN]).unwrap() };
    assert_eq!(migrated_swig.wallet_bump, wallet_address_bump);
}

#[test_log::test]
fn test_migration_rejects_stored_future_v2_scope() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig, _bench) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    // Build a legacy stored scope while the header presents a V2 counter, then
    // downgrade the same bytes to V1. Migration would reset the real counter to
    // zero while preserving this role, turning the scope into a future grant.
    let counter_offset = core::mem::offset_of!(Swig, sub_account_counter);
    let mut account = context.svm.get_account(&swig).unwrap();
    account.data[counter_offset..counter_offset + 4].copy_from_slice(&1u32.to_le_bytes());
    context.svm.set_account(swig, account).unwrap();
    let scoped_authority = Keypair::new();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: scoped_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccountV2All(SubAccountV2All::new(0))],
    )
    .unwrap();
    convert_swig_to_v1(&mut context, &swig);

    let (swig_wallet_address, wallet_address_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let before_swig = context.svm.get_account(&swig).unwrap();
    let before_wallet = context.svm.get_account(&swig_wallet_address).unwrap();
    let migrate_ix = migrate_instruction(
        swig,
        authority.pubkey(),
        context.default_payer.pubkey(),
        swig_wallet_address,
        wallet_address_bump,
        true,
        solana_system_interface::program::ID,
    );
    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[migrate_ix],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &authority]).unwrap();

    let error = context.svm.send_transaction(tx).unwrap_err();
    assert_eq!(
        error.err,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(
                SwigStateError::SubAccountV2PermissionTargetDoesNotExist as u32,
            ),
        )
    );
    assert_eq!(context.svm.get_account(&swig).unwrap(), before_swig);
    assert_eq!(
        context.svm.get_account(&swig_wallet_address).unwrap(),
        before_wallet
    );
}

#[test_log::test]
fn test_migration_rejects_stored_duplicate_nonrepeatable_action_atomically() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let (swig, _) =
        create_swig_ed25519(&mut context, &authority, rand::random::<[u8; 32]>()).unwrap();
    duplicate_last_role_action(&mut context, &swig, 0, Permission::All).unwrap();
    convert_swig_to_v1(&mut context, &swig);

    let rent_payer = Keypair::new();
    context
        .svm
        .airdrop(&rent_payer.pubkey(), 1_000_000_000)
        .unwrap();
    let (swig_wallet_address, wallet_address_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let before_swig = context.svm.get_account(&swig).unwrap();
    let before_wallet = context.svm.get_account(&swig_wallet_address).unwrap();
    let before_rent_payer = context.svm.get_account(&rent_payer.pubkey()).unwrap();
    let migrate_ix = migrate_instruction(
        swig,
        authority.pubkey(),
        rent_payer.pubkey(),
        swig_wallet_address,
        wallet_address_bump,
        true,
        solana_system_interface::program::ID,
    );
    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[migrate_ix],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx =
        VersionedTransaction::try_new(message, &[&context.default_payer, &authority, &rent_payer])
            .unwrap();

    let error = context.svm.send_transaction(tx).unwrap_err();
    assert_eq!(
        error.err,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(SwigStateError::DuplicateNonRepeatableAction as u32),
        )
    );
    assert_eq!(context.svm.get_account(&swig).unwrap(), before_swig);
    assert_eq!(
        context.svm.get_account(&swig_wallet_address).unwrap(),
        before_wallet
    );
    assert_eq!(
        context.svm.get_account(&rent_payer.pubkey()).unwrap(),
        before_rent_payer
    );
}

#[test_log::test]
fn test_migration_rejects_alternate_valid_wallet_bump() {
    let (mut context, authority, swig, _swig_wallet_address, canonical_bump) =
        setup_unmigrated_swig();
    let (alternate_address, alternate_bump) = alternate_wallet_address(&swig, canonical_bump);
    let before = context.svm.get_account(&swig).unwrap().data;

    let migrate_ix = migrate_instruction(
        swig,
        authority.pubkey(),
        context.default_payer.pubkey(),
        alternate_address,
        alternate_bump,
        true,
        solana_system_interface::program::ID,
    );
    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[migrate_ix],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &authority]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        matches!(
            result,
            Err(ref error)
                if matches!(
                    error.err,
                    TransactionError::InstructionError(
                        _,
                        InstructionError::Custom(ERR_INVALID_SEED_SWIG_ACCOUNT)
                    )
                )
        ),
        "migration must reject a noncanonical but valid wallet-address bump with \
         InvalidSeedSwigAccount; got {result:?}"
    );
    assert_eq!(
        context.svm.get_account(&swig).unwrap().data,
        before,
        "a rejected alternate bump must not modify the Swig"
    );
}

#[test_log::test]
fn test_migration_rejects_replay_without_resetting_sub_account_counter() {
    let (mut context, authority, swig, swig_wallet_address, wallet_address_bump) =
        setup_unmigrated_swig();

    let migrate_ix = migrate_instruction(
        swig,
        authority.pubkey(),
        context.default_payer.pubkey(),
        swig_wallet_address,
        wallet_address_bump,
        true,
        solana_system_interface::program::ID,
    );
    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[migrate_ix],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &authority]).unwrap();
    context
        .svm
        .send_transaction(tx)
        .expect("initial migration should succeed");

    let mut migrated_account = context.svm.get_account(&swig).unwrap();
    let counter_offset = core::mem::offset_of!(Swig, sub_account_counter);
    migrated_account.data[counter_offset..counter_offset + 4].copy_from_slice(&7u32.to_le_bytes());
    context.svm.set_account(swig, migrated_account).unwrap();
    let before_replay = context.svm.get_account(&swig).unwrap().data;

    context.svm.expire_blockhash();
    let replay_ix = migrate_instruction(
        swig,
        authority.pubkey(),
        context.default_payer.pubkey(),
        swig_wallet_address,
        wallet_address_bump,
        true,
        solana_system_interface::program::ID,
    );
    let replay_message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[replay_ix],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let replay_tx =
        VersionedTransaction::try_new(replay_message, &[&context.default_payer, &authority])
            .unwrap();

    let replay_result = context.svm.send_transaction(replay_tx);
    assert!(
        matches!(
            replay_result,
            Err(ref error)
                if matches!(
                    error.err,
                    TransactionError::InstructionError(
                        _,
                        InstructionError::Custom(ERR_SWIG_ALREADY_MIGRATED)
                    )
                )
        ),
        "an already-migrated Swig must reject migration replay with SwigAlreadyMigrated; got \
         {replay_result:?}"
    );
    assert_eq!(
        context.svm.get_account(&swig).unwrap().data,
        before_replay,
        "replay rejection must preserve the full Swig account"
    );
    let after = context.svm.get_account(&swig).unwrap();
    let swig_state = unsafe { Swig::load_unchecked(&after.data[..Swig::LEN]).unwrap() };
    assert_eq!(swig_state.sub_account_counter, 7);
}

#[test_log::test]
fn test_migration_rejects_non_program_owned_swig() {
    let (mut context, authority, swig, swig_wallet_address, wallet_address_bump) =
        setup_unmigrated_swig();

    let mut swig_account = context.svm.get_account(&swig).unwrap();
    swig_account.owner = solana_system_interface::program::ID;
    context.svm.set_account(swig, swig_account).unwrap();

    let migrate_ix = migrate_instruction(
        swig,
        authority.pubkey(),
        context.default_payer.pubkey(),
        swig_wallet_address,
        wallet_address_bump,
        true,
        solana_system_interface::program::ID,
    );

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                migrate_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &authority]).unwrap();

    let error = context.svm.send_transaction(tx).unwrap_err();
    assert_eq!(
        error.err,
        TransactionError::InstructionError(
            1,
            InstructionError::Custom(OWNER_MISMATCH_SWIG_ACCOUNT_ERROR),
        )
    );
}

#[test_log::test]
fn test_migration_rejects_wrong_system_program() {
    let (mut context, authority, swig, swig_wallet_address, wallet_address_bump) =
        setup_unmigrated_swig();

    let migrate_ix = migrate_instruction(
        swig,
        authority.pubkey(),
        context.default_payer.pubkey(),
        swig_wallet_address,
        wallet_address_bump,
        true,
        context.default_payer.pubkey(),
    );

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                migrate_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &authority]).unwrap();

    let error = context.svm.send_transaction(tx).unwrap_err();
    assert_eq!(
        error.err,
        TransactionError::InstructionError(
            1,
            InstructionError::Custom(INVALID_SYSTEM_PROGRAM_ERROR),
        )
    );
}
