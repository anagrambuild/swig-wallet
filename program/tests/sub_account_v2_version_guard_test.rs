#![cfg(not(feature = "program_scope_test"))]
//! The V2 sub-account instructions must refuse a pre-wallet-address (V1) Swig.
//!
//! The guard used to be `swig.wallet_bump == 0`, which reads only byte 40. On a
//! V1 account that byte is the low byte of `reserved_lamports`, and a
//! rent-carrying balance leaves it non-zero — so the check accepted nearly every
//! real V1 account. A mainnet census at the time of writing found 72 of 78 V1
//! accounts slipping through. These tests pin the behaviour to `is_swig_v2`,
//! which also requires the three padding bytes above the bump to be zero.
mod common;

use common::*;
use solana_sdk::{
    instruction::{Instruction, InstructionError},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{
    AuthorityConfig, ClientAction, CreateSubAccountV2Instruction, SubAccountSignV2Instruction,
    ToggleSubAccountV2Instruction, WithdrawFromSubAccountV2Instruction,
};
use swig_state::{
    action::sub_account_v2::SubAccountV2Create,
    authority::AuthorityType,
    swig::{
        sub_account_v2_asset_seeds, sub_account_v2_state_seeds, swig_wallet_address_seeds, Swig,
        SwigWithRoles,
    },
    Transmutable,
};

/// `SwigError::SignV2CannotBeUsedWithSwigV1`. The program's `error` module is
/// private to the crate, so the code is mirrored here.
const ERR_V2_WITH_SWIG_V1: u32 = 47;

/// `SwigError::InvalidSwigAccountDiscriminator`, which `require_swig_v2` also
/// uses for an account too short to hold a header.
const ERR_INVALID_DISCRIMINATOR: u32 = 0;

/// Byte offset of `Swig::wallet_bump`; V1 stored `reserved_lamports: u64` here.
const WALLET_BUMP_OFFSET: usize = 40;

/// A real mainnet V1 reserve. Low byte is `0x80`, so the old `wallet_bump == 0`
/// guard let it through; bytes above it are non-zero, so `is_swig_v2` rejects it.
const V1_RESERVE_NONZERO_LOW_BYTE: u64 = 1_614_720;

/// The rarer V1 reserve whose low byte is zero — the only shape the old guard
/// caught. Must stay rejected.
const V1_RESERVE_ZERO_LOW_BYTE: u64 = 3_786_240;

fn role_id_of(context: &SwigTestContext, swig: &Pubkey, authority: &Pubkey) -> u32 {
    let data = context.svm.get_account(swig).unwrap().data;
    SwigWithRoles::from_bytes(&data)
        .unwrap()
        .lookup_role_id(authority.as_ref())
        .unwrap()
        .unwrap()
}

fn v2_state_pda(id: &[u8; 32], subacc_id: u32) -> (Pubkey, u8) {
    let id_le = subacc_id.to_le_bytes();
    Pubkey::find_program_address(&sub_account_v2_state_seeds(id, &id_le), &program_id())
}

fn v2_asset_pda(id: &[u8; 32], subacc_id: u32) -> (Pubkey, u8) {
    let id_le = subacc_id.to_le_bytes();
    Pubkey::find_program_address(&sub_account_v2_asset_seeds(id, &id_le), &program_id())
}

fn send(
    context: &mut SwigTestContext,
    payer: &Keypair,
    ix: Instruction,
) -> Result<(), TransactionError> {
    let message =
        v0::Message::try_compile(&payer.pubkey(), &[ix], &[], context.svm.latest_blockhash())
            .unwrap();
    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[payer.insecure_clone()])
            .unwrap();
    context
        .svm
        .send_transaction(tx)
        .map(|_| ())
        .map_err(|e| e.err)
}

/// Asserts the transaction failed with `SignV2CannotBeUsedWithSwigV1` rather
/// than merely failing — the V1 guard is easy to "pass" for the wrong reason.
fn assert_rejected_as_v1(result: Result<(), TransactionError>, what: &str) {
    match result {
        Ok(()) => panic!("{what} must be rejected on a V1 swig, but it succeeded"),
        Err(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
            assert_eq!(
                code, ERR_V2_WITH_SWIG_V1,
                "{what} failed with custom error {code}, expected \
                 SignV2CannotBeUsedWithSwigV1 ({ERR_V2_WITH_SWIG_V1})"
            );
        },
        Err(other) => panic!("{what} failed with {other:?}, expected a custom program error"),
    }
}

/// Builds a V2 swig with a creator role but *no* sub-account, then downgrades
/// the header to V1. Leaving the counter unused means a create would draw id 0
/// and its PDAs are still free — so without the guard the create genuinely
/// succeeds, rather than reverting on a PDA mismatch.
fn setup_v1_before_any_sub_account(
    context: &mut SwigTestContext,
    reserved_lamports: u64,
) -> (Pubkey, [u8; 32], Keypair, u32) {
    let root = Keypair::new();
    let creator = Keypair::new();
    context.svm.airdrop(&root.pubkey(), 10_000_000_000).unwrap();
    context
        .svm
        .airdrop(&creator.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(context, &root, id).unwrap();
    add_authority_with_ed25519_root(
        context,
        &swig_key,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: creator.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccountV2Create(SubAccountV2Create)],
    )
    .unwrap();
    let creator_role = role_id_of(context, &swig_key, &creator.pubkey());

    let mut account = context.svm.get_account(&swig_key).unwrap();
    account.data[WALLET_BUMP_OFFSET..WALLET_BUMP_OFFSET + 8]
        .copy_from_slice(&reserved_lamports.to_le_bytes());
    context.svm.set_account(swig_key, account).unwrap();

    (swig_key, id, creator, creator_role)
}

/// Builds a healthy V2 swig with a creator role and sub-account 0, funded.
fn setup_v2_with_sub_account(
    context: &mut SwigTestContext,
) -> (Pubkey, [u8; 32], Keypair, u32, Pubkey, Pubkey) {
    let root = Keypair::new();
    let creator = Keypair::new();
    context.svm.airdrop(&root.pubkey(), 10_000_000_000).unwrap();
    context
        .svm
        .airdrop(&creator.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(context, &root, id).unwrap();
    add_authority_with_ed25519_root(
        context,
        &swig_key,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: creator.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccountV2Create(SubAccountV2Create)],
    )
    .unwrap();
    let creator_role = role_id_of(context, &swig_key, &creator.pubkey());

    // Create sub-account 0 while the swig is still V2, so the state and asset
    // accounts the runtime instructions need actually exist.
    let (state_pda, state_bump) = v2_state_pda(&id, 0);
    let (asset_pda, asset_bump) = v2_asset_pda(&id, 0);
    let ix = CreateSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        asset_pda,
        creator_role,
        state_bump,
        asset_bump,
    )
    .unwrap();
    send(context, &creator, ix).unwrap();
    context.svm.airdrop(&asset_pda, 1_000_000_000).unwrap();

    (swig_key, id, creator, creator_role, state_pda, asset_pda)
}

/// As [`setup_v2_with_sub_account`], then rewrites the header's trailing `u64`
/// so the account presents as V1.
fn setup_then_downgrade(
    context: &mut SwigTestContext,
    reserved_lamports: u64,
) -> (Pubkey, [u8; 32], Keypair, u32, Pubkey, Pubkey) {
    let parts = setup_v2_with_sub_account(context);
    let swig_key = parts.0;

    // Overwrite `wallet_bump ++ _padding ++ sub_account_counter` with the
    // `reserved_lamports: u64` a V1 account carried at the same offset.
    let mut account = context.svm.get_account(&swig_key).unwrap();
    account.data[WALLET_BUMP_OFFSET..WALLET_BUMP_OFFSET + 8]
        .copy_from_slice(&reserved_lamports.to_le_bytes());
    context.svm.set_account(swig_key, account).unwrap();

    parts
}

#[test_log::test]
fn test_v1_header_shape_is_what_the_old_guard_missed() {
    // Guards the premise of these tests: this reserve leaves byte 40 non-zero,
    // so `wallet_bump == 0` would not have fired.
    let bytes = V1_RESERVE_NONZERO_LOW_BYTE.to_le_bytes();
    assert_ne!(bytes[0], 0, "low byte must be non-zero to model the bypass");
    assert!(
        bytes[1..4].iter().any(|b| *b != 0),
        "padding bytes must be non-zero for is_swig_v2 to reject"
    );

    // And the offset this test file pokes really is `wallet_bump`.
    assert_eq!(WALLET_BUMP_OFFSET, core::mem::offset_of!(Swig, wallet_bump));
    assert_eq!(Swig::LEN, 48);
}

#[test_log::test]
fn test_create_sub_account_v2_rejects_v1_swig() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, id, creator, creator_role, ..) =
        setup_then_downgrade(&mut context, V1_RESERVE_NONZERO_LOW_BYTE);

    // A V1 header exposes no counter, so the id a create would draw is garbage;
    // any id is fine here because the guard must fire before the draw.
    let (state_pda, state_bump) = v2_state_pda(&id, 1);
    let (asset_pda, asset_bump) = v2_asset_pda(&id, 1);
    let ix = CreateSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        asset_pda,
        creator_role,
        state_bump,
        asset_bump,
    )
    .unwrap();

    assert_rejected_as_v1(send(&mut context, &creator, ix), "CreateSubAccountV2");
}

#[test_log::test]
fn test_create_sub_account_v2_does_not_corrupt_a_v1_header() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, id, creator, creator_role) =
        setup_v1_before_any_sub_account(&mut context, V1_RESERVE_NONZERO_LOW_BYTE);

    let before = context.svm.get_account(&swig_key).unwrap().data
        [WALLET_BUMP_OFFSET..WALLET_BUMP_OFFSET + 8]
        .to_vec();

    // Bytes 44..48 of this reserve are zero, so a create reads the counter as 0
    // and draws id 0. Building for id 0 means the PDAs line up and nothing else
    // can reject the instruction — only the version guard stands in the way.
    let (state_pda, state_bump) = v2_state_pda(&id, 0);
    let (asset_pda, asset_bump) = v2_asset_pda(&id, 0);
    let ix = CreateSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        asset_pda,
        creator_role,
        state_bump,
        asset_bump,
    )
    .unwrap();
    assert_rejected_as_v1(send(&mut context, &creator, ix), "CreateSubAccountV2");

    // Consuming an id writes `counter + 1` into bytes 44..48, which on a V1
    // account silently adds 2^32 to reserved_lamports.
    let after = context.svm.get_account(&swig_key).unwrap().data
        [WALLET_BUMP_OFFSET..WALLET_BUMP_OFFSET + 8]
        .to_vec();
    assert_eq!(before, after, "V1 header must be left untouched");
    assert!(
        context.svm.get_account(&state_pda).is_none()
            || context.svm.get_account(&state_pda).unwrap().owner != program_id(),
        "no V2 state account may be created under a V1 swig"
    );
}

#[test_log::test]
fn test_sub_account_sign_v2_rejects_v1_swig() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, _id, creator, creator_role, state_pda, asset_pda) =
        setup_then_downgrade(&mut context, V1_RESERVE_NONZERO_LOW_BYTE);

    let recipient = Keypair::new();
    let inner = solana_system_interface::instruction::transfer(&asset_pda, &recipient.pubkey(), 1);
    let ix = SubAccountSignV2Instruction::new_with_ed25519_authority(
        swig_key,
        state_pda,
        asset_pda,
        creator.pubkey(),
        creator_role,
        0,
        vec![inner],
    )
    .unwrap();

    assert_rejected_as_v1(send(&mut context, &creator, ix), "SubAccountSignV2");
}

#[test_log::test]
fn test_withdraw_from_sub_account_v2_rejects_v1_swig() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, _id, creator, creator_role, state_pda, asset_pda) =
        setup_then_downgrade(&mut context, V1_RESERVE_NONZERO_LOW_BYTE);

    let (wallet, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());
    let ix = WithdrawFromSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        asset_pda,
        wallet,
        creator_role,
        0,
        1_000,
    )
    .unwrap();

    assert_rejected_as_v1(send(&mut context, &creator, ix), "WithdrawFromSubAccountV2");
}

#[test_log::test]
fn test_toggle_sub_account_v2_rejects_v1_swig() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, _id, creator, creator_role, state_pda, _asset) =
        setup_then_downgrade(&mut context, V1_RESERVE_NONZERO_LOW_BYTE);

    let ix = ToggleSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        creator_role,
        0,
        false,
    )
    .unwrap();

    assert_rejected_as_v1(send(&mut context, &creator, ix), "ToggleSubAccountV2");
}

#[test_log::test]
fn test_v1_swig_with_zero_low_byte_still_rejected() {
    // The one shape the old guard did catch must keep being rejected.
    let mut context = setup_test_context().unwrap();
    let (swig_key, _id, creator, creator_role, state_pda, _asset) =
        setup_then_downgrade(&mut context, V1_RESERVE_ZERO_LOW_BYTE);

    let ix = ToggleSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        creator_role,
        0,
        false,
    )
    .unwrap();

    assert_rejected_as_v1(send(&mut context, &creator, ix), "ToggleSubAccountV2");
}

/// `is_swig_v2` is a conjunction: non-zero bump **and** zeroed padding. This
/// pins the second half. A header with the real wallet bump but dirty padding
/// is not a shape the program writes, and the old `wallet_bump == 0` check
/// would have waved it straight through.
#[test_log::test]
fn test_v2_header_with_dirty_padding_is_rejected() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, _id, creator, creator_role, state_pda, _asset) =
        setup_then_downgrade(&mut context, V1_RESERVE_NONZERO_LOW_BYTE);

    // Restore the genuine wallet bump, then dirty only the padding.
    let mut account = context.svm.get_account(&swig_key).unwrap();
    let (_, wallet_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());
    account.data[WALLET_BUMP_OFFSET] = wallet_bump;
    account.data[WALLET_BUMP_OFFSET + 1] = 0;
    account.data[WALLET_BUMP_OFFSET + 2] = 1;
    account.data[WALLET_BUMP_OFFSET + 3] = 0;
    context.svm.set_account(swig_key, account).unwrap();

    let ix = ToggleSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        creator_role,
        0,
        false,
    )
    .unwrap();

    assert_rejected_as_v1(send(&mut context, &creator, ix), "ToggleSubAccountV2");
}

/// An account too short to hold a Swig header must be rejected before
/// `is_swig_v2` reads offset 40..44 -- that read is `unsafe` and assumes the
/// length was checked. The program does own short accounts.
#[test_log::test]
fn test_swig_shorter_than_the_header_is_rejected() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, _id, creator, creator_role, state_pda, _asset) =
        setup_then_downgrade(&mut context, V1_RESERVE_NONZERO_LOW_BYTE);

    // Keep a valid discriminator so the length guard is what stops us.
    let mut account = context.svm.get_account(&swig_key).unwrap();
    account.data.truncate(Swig::LEN - 1);
    context.svm.set_account(swig_key, account).unwrap();

    let ix = ToggleSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        creator_role,
        0,
        false,
    )
    .unwrap();

    match send(&mut context, &creator, ix) {
        Ok(()) => panic!("a truncated swig must not be accepted"),
        Err(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
            assert_eq!(
                code, ERR_INVALID_DISCRIMINATOR,
                "expected the length guard to reject, got custom error {code}"
            );
        },
        Err(other) => panic!("expected a custom program error, got {other:?}"),
    }
}

/// Regression for the window `is_swig_v2` reads.
///
/// `sub_account_counter` sits in the four bytes above `_padding` and becomes
/// non-zero the moment a V2 sub-account exists. An earlier version of the check
/// read the last eight header bytes as one `u64`, which covered the counter --
/// so creating a single sub-account flipped a healthy V2 wallet to being read as
/// V1 and bricked every subsequent V2 instruction. Widening the window again
/// must fail here.
#[test_log::test]
fn test_sub_account_counter_does_not_flip_swig_to_v1() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, id, creator, creator_role, state_pda, asset_pda) =
        setup_v2_with_sub_account(&mut context);

    // Drive the counter well past zero.
    for subacc_id in 1..4u32 {
        let (state, state_bump) = v2_state_pda(&id, subacc_id);
        let (asset, asset_bump) = v2_asset_pda(&id, subacc_id);
        let ix = CreateSubAccountV2Instruction::new_with_ed25519_authority(
            swig_key,
            creator.pubkey(),
            creator.pubkey(),
            state,
            asset,
            creator_role,
            state_bump,
            asset_bump,
        )
        .unwrap();
        send(&mut context, &creator, ix).unwrap();
    }

    let counter = {
        let data = context.svm.get_account(&swig_key).unwrap().data;
        let swig = unsafe { Swig::load_unchecked(&data[..Swig::LEN]).unwrap() };
        swig.sub_account_counter
    };
    assert_eq!(
        counter, 4,
        "counter must be non-zero for this to mean anything"
    );

    // Every runtime instruction must still see a V2 wallet. The asset PDA is
    // already funded by the setup.
    let recipient = Keypair::new();
    let inner =
        solana_system_interface::instruction::transfer(&asset_pda, &recipient.pubkey(), 1_000_000);
    let sign = SubAccountSignV2Instruction::new_with_ed25519_authority(
        swig_key,
        state_pda,
        asset_pda,
        creator.pubkey(),
        creator_role,
        0,
        vec![inner],
    )
    .unwrap();
    send(&mut context, &creator, sign).expect("sign must work with a non-zero counter");

    let (wallet, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());
    let withdraw = WithdrawFromSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        asset_pda,
        wallet,
        creator_role,
        0,
        1_000,
    )
    .unwrap();
    send(&mut context, &creator, withdraw).expect("withdraw must work with a non-zero counter");

    let toggle = ToggleSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        creator_role,
        0,
        false,
    )
    .unwrap();
    send(&mut context, &creator, toggle).expect("toggle must work with a non-zero counter");
}
