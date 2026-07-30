#![cfg(not(feature = "program_scope_test"))]
//! Secp256k1 and Secp256r1 coverage for the V2 sub-account runtime operations.
//!
//! `sub_account_v2_test.rs` and `sub_account_v2_matrix_test.rs` exercise the
//! semantics under Ed25519. This file covers the same runtime operations —
//! sign, SOL withdraw, and toggle — under both Secp authority types, where the
//! authenticated payload additionally commits to the instruction's account
//! list and the authority's replay odometer.
//!
//! Sub-accounts are created by an Ed25519 role; the Secp authority is then
//! granted the scoped action under test. That keeps each test focused on the
//! Secp authentication path for one runtime operation.
mod common;

use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use common::*;
use solana_sdk::{
    clock::Clock,
    instruction::Instruction,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{
    AuthorityConfig, ClientAction, CreateSubAccountV2Instruction, SubAccountSignV2Instruction,
    ToggleSubAccountV2Instruction, WithdrawFromSubAccountV2Instruction,
};
use swig_state::{
    action::sub_account_v2::{
        SubAccountV2Create, SubAccountV2Sign, SubAccountV2Toggle, SubAccountV2Withdraw,
    },
    authority::{secp256k1::Secp256k1Authority, secp256r1::Secp256r1Authority, AuthorityType},
    sub_account_v2::SubAccountV2,
    swig::{
        sub_account_v2_asset_seeds, sub_account_v2_state_seeds, swig_wallet_address_seeds,
        SwigWithRoles,
    },
    Transmutable,
};

const CREATOR_ROLE_ID: u32 = 1;
const SECP_ROLE_ID: u32 = 2;
const SUBACC_ID: u32 = 0;

/// Generates a secp256r1 key pair, returning the signing key and its
/// compressed public key.
fn secp256r1_keypair() -> (openssl::ec::EcKey<openssl::pkey::Private>, [u8; 33]) {
    use openssl::{
        bn::BigNumContext,
        ec::{EcGroup, EcKey, PointConversionForm},
        nid::Nid,
    };

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let signing_key = EcKey::generate(&group).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let pubkey_bytes = signing_key
        .public_key()
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();
    (signing_key, pubkey_bytes.try_into().unwrap())
}

/// The 64-byte uncompressed public key a Secp256k1 authority is registered
/// under (the leading format byte is dropped).
fn secp256k1_authority_bytes(wallet: &PrivateKeySigner) -> Vec<u8> {
    let encoded = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();
    encoded[1..].to_vec()
}

/// Reads the replay odometer for a Secp authority role. Secp signatures commit
/// to `odometer + 1`, so every test derives its counter from this rather than
/// assuming a fixed value.
fn odometer(context: &SwigTestContext, swig_key: &Pubkey, role_id: u32, r1: bool) -> u32 {
    let data = context.svm.get_account(swig_key).unwrap().data;
    let swig = SwigWithRoles::from_bytes(&data).unwrap();
    let role = swig.get_role(role_id).unwrap().unwrap();
    if r1 {
        role.authority
            .as_any()
            .downcast_ref::<Secp256r1Authority>()
            .unwrap()
            .signature_odometer
    } else {
        role.authority
            .as_any()
            .downcast_ref::<Secp256k1Authority>()
            .unwrap()
            .signature_odometer
    }
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
    ixs: Vec<Instruction>,
) -> anyhow::Result<()> {
    let message =
        v0::Message::try_compile(&payer.pubkey(), &ixs, &[], context.svm.latest_blockhash())
            .unwrap();
    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[payer.insecure_clone()])
            .unwrap();
    context
        .svm
        .send_transaction(tx)
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("tx failed: {:?}", e))
}

struct SecpFixture {
    swig: Pubkey,
    id: [u8; 32],
    payer: Keypair,
    state_pda: Pubkey,
    asset_pda: Pubkey,
    swig_wallet_address: Pubkey,
}

/// Builds a swig with an Ed25519 root, an Ed25519 creator role that creates
/// sub-account 0, and a Secp authority (role 2) holding `secp_actions`.
fn setup(
    context: &mut SwigTestContext,
    authority_type: AuthorityType,
    authority_bytes: &[u8],
    secp_actions: Vec<ClientAction>,
) -> SecpFixture {
    let root = Keypair::new();
    let creator = Keypair::new();
    context.svm.airdrop(&root.pubkey(), 10_000_000_000).unwrap();
    context
        .svm
        .airdrop(&creator.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(context, &root, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    add_authority_with_ed25519_root(
        context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: creator.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccountV2Create(SubAccountV2Create)],
    )
    .unwrap();

    let (state_pda, state_bump) = v2_state_pda(&id, SUBACC_ID);
    let (asset_pda, asset_bump) = v2_asset_pda(&id, SUBACC_ID);
    let create_ix = CreateSubAccountV2Instruction::new_with_ed25519_authority(
        swig,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        asset_pda,
        CREATOR_ROLE_ID,
        state_bump,
        asset_bump,
    )
    .unwrap();
    send(context, &creator, vec![create_ix]).unwrap();

    add_authority_with_ed25519_root(
        context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type,
            authority: authority_bytes,
        },
        secp_actions,
    )
    .unwrap();

    SecpFixture {
        swig,
        id,
        payer: creator,
        state_pda,
        asset_pda,
        swig_wallet_address,
    }
}

fn state_enabled(context: &SwigTestContext, state_pda: &Pubkey) -> bool {
    let data = context.svm.get_account(state_pda).unwrap().data;
    let state = unsafe { SubAccountV2::load_unchecked(&data).unwrap() };
    state.is_enabled().unwrap()
}

// ---------------------------------------------------------------- sign

#[test_log::test]
fn test_secp256k1_sub_account_sign_v2() {
    let mut context = setup_test_context().unwrap();
    let wallet = LocalSigner::random();
    let authority_bytes = secp256k1_authority_bytes(&wallet);
    let fixture = setup(
        &mut context,
        AuthorityType::Secp256k1,
        &authority_bytes,
        vec![ClientAction::SubAccountV2Sign(SubAccountV2Sign::new(
            SUBACC_ID,
        ))],
    );

    context
        .svm
        .airdrop(&fixture.asset_pda, 1_000_000_000)
        .unwrap();
    let recipient = Keypair::new();
    let transfer_amount = 100_000_000;
    let inner = solana_system_interface::instruction::transfer(
        &fixture.asset_pda,
        &recipient.pubkey(),
        transfer_amount,
    );

    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        wallet.sign_hash_sync(&B256::from(hash)).unwrap().as_bytes()
    };
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let counter = odometer(&context, &fixture.swig, SECP_ROLE_ID, false) + 1;

    let ix = SubAccountSignV2Instruction::new_with_secp256k1_authority(
        fixture.swig,
        fixture.state_pda,
        fixture.asset_pda,
        signing_fn,
        current_slot,
        counter,
        SECP_ROLE_ID,
        SUBACC_ID,
        vec![inner],
    )
    .unwrap();

    send(&mut context, &fixture.payer, vec![ix]).expect("secp256k1 sign v2 should succeed");
    assert_eq!(
        context
            .svm
            .get_account(&recipient.pubkey())
            .unwrap()
            .lamports,
        transfer_amount
    );
    assert_eq!(
        odometer(&context, &fixture.swig, SECP_ROLE_ID, false),
        counter
    );
}

#[test_log::test]
fn test_secp256r1_sub_account_sign_v2() {
    let mut context = setup_test_context().unwrap();
    let (signing_key, public_key) = secp256r1_keypair();
    let fixture = setup(
        &mut context,
        AuthorityType::Secp256r1,
        &public_key,
        vec![ClientAction::SubAccountV2Sign(SubAccountV2Sign::new(
            SUBACC_ID,
        ))],
    );

    context
        .svm
        .airdrop(&fixture.asset_pda, 1_000_000_000)
        .unwrap();
    let recipient = Keypair::new();
    let transfer_amount = 100_000_000;
    let inner = solana_system_interface::instruction::transfer(
        &fixture.asset_pda,
        &recipient.pubkey(),
        transfer_amount,
    );

    let mut signing_fn = |message_hash: &[u8]| -> [u8; 64] {
        solana_secp256r1_program::sign_message(
            message_hash,
            &signing_key.private_key_to_der().unwrap(),
        )
        .unwrap()
    };
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let counter = odometer(&context, &fixture.swig, SECP_ROLE_ID, true) + 1;

    let ixs = SubAccountSignV2Instruction::new_with_secp256r1_authority(
        fixture.swig,
        fixture.state_pda,
        fixture.asset_pda,
        &mut signing_fn,
        current_slot,
        counter,
        SECP_ROLE_ID,
        SUBACC_ID,
        vec![inner],
        &public_key,
    )
    .unwrap();

    send(&mut context, &fixture.payer, ixs).expect("secp256r1 sign v2 should succeed");
    assert_eq!(
        context
            .svm
            .get_account(&recipient.pubkey())
            .unwrap()
            .lamports,
        transfer_amount
    );
    assert_eq!(
        odometer(&context, &fixture.swig, SECP_ROLE_ID, true),
        counter
    );
}

// ------------------------------------------------------------ sol withdraw

#[test_log::test]
fn test_secp256k1_withdraw_sol_from_sub_account_v2() {
    let mut context = setup_test_context().unwrap();
    let wallet = LocalSigner::random();
    let authority_bytes = secp256k1_authority_bytes(&wallet);
    let fixture = setup(
        &mut context,
        AuthorityType::Secp256k1,
        &authority_bytes,
        vec![ClientAction::SubAccountV2Withdraw(
            SubAccountV2Withdraw::new(SUBACC_ID),
        )],
    );

    context
        .svm
        .airdrop(&fixture.asset_pda, 1_000_000_000)
        .unwrap();
    let before = context
        .svm
        .get_account(&fixture.swig_wallet_address)
        .unwrap()
        .lamports;
    let amount = 250_000_000;

    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        wallet.sign_hash_sync(&B256::from(hash)).unwrap().as_bytes()
    };
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let counter = odometer(&context, &fixture.swig, SECP_ROLE_ID, false) + 1;

    let ix = WithdrawFromSubAccountV2Instruction::new_with_secp256k1_authority(
        fixture.swig,
        fixture.payer.pubkey(),
        signing_fn,
        current_slot,
        counter,
        fixture.state_pda,
        fixture.asset_pda,
        fixture.swig_wallet_address,
        SECP_ROLE_ID,
        SUBACC_ID,
        amount,
    )
    .unwrap();

    send(&mut context, &fixture.payer, vec![ix]).expect("secp256k1 sol withdraw should succeed");
    assert_eq!(
        context
            .svm
            .get_account(&fixture.swig_wallet_address)
            .unwrap()
            .lamports,
        before + amount
    );
}

#[test_log::test]
fn test_secp256r1_withdraw_sol_from_sub_account_v2() {
    let mut context = setup_test_context().unwrap();
    let (signing_key, public_key) = secp256r1_keypair();
    let fixture = setup(
        &mut context,
        AuthorityType::Secp256r1,
        &public_key,
        vec![ClientAction::SubAccountV2Withdraw(
            SubAccountV2Withdraw::new(SUBACC_ID),
        )],
    );

    context
        .svm
        .airdrop(&fixture.asset_pda, 1_000_000_000)
        .unwrap();
    let before = context
        .svm
        .get_account(&fixture.swig_wallet_address)
        .unwrap()
        .lamports;
    let amount = 250_000_000;

    let mut signing_fn = |message_hash: &[u8]| -> [u8; 64] {
        solana_secp256r1_program::sign_message(
            message_hash,
            &signing_key.private_key_to_der().unwrap(),
        )
        .unwrap()
    };
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let counter = odometer(&context, &fixture.swig, SECP_ROLE_ID, true) + 1;

    let ixs = WithdrawFromSubAccountV2Instruction::new_with_secp256r1_authority(
        fixture.swig,
        fixture.payer.pubkey(),
        &mut signing_fn,
        current_slot,
        counter,
        fixture.state_pda,
        fixture.asset_pda,
        fixture.swig_wallet_address,
        SECP_ROLE_ID,
        SUBACC_ID,
        amount,
        &public_key,
    )
    .unwrap();

    send(&mut context, &fixture.payer, ixs).expect("secp256r1 sol withdraw should succeed");
    assert_eq!(
        context
            .svm
            .get_account(&fixture.swig_wallet_address)
            .unwrap()
            .lamports,
        before + amount
    );
}

// --------------------------------------------------------------- toggle

#[test_log::test]
fn test_secp256k1_toggle_sub_account_v2() {
    let mut context = setup_test_context().unwrap();
    let wallet = LocalSigner::random();
    let authority_bytes = secp256k1_authority_bytes(&wallet);
    let fixture = setup(
        &mut context,
        AuthorityType::Secp256k1,
        &authority_bytes,
        vec![ClientAction::SubAccountV2Toggle(SubAccountV2Toggle::new(
            SUBACC_ID,
        ))],
    );
    assert!(state_enabled(&context, &fixture.state_pda));

    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        wallet.sign_hash_sync(&B256::from(hash)).unwrap().as_bytes()
    };
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let counter = odometer(&context, &fixture.swig, SECP_ROLE_ID, false) + 1;

    let ix = ToggleSubAccountV2Instruction::new_with_secp256k1_authority(
        fixture.swig,
        fixture.payer.pubkey(),
        signing_fn,
        current_slot,
        counter,
        fixture.state_pda,
        SECP_ROLE_ID,
        SUBACC_ID,
        false,
    )
    .unwrap();

    send(&mut context, &fixture.payer, vec![ix]).expect("secp256k1 toggle should succeed");
    assert!(
        !state_enabled(&context, &fixture.state_pda),
        "kill-switch should be off"
    );
}

#[test_log::test]
fn test_secp256r1_toggle_sub_account_v2() {
    let mut context = setup_test_context().unwrap();
    let (signing_key, public_key) = secp256r1_keypair();
    let fixture = setup(
        &mut context,
        AuthorityType::Secp256r1,
        &public_key,
        vec![ClientAction::SubAccountV2Toggle(SubAccountV2Toggle::new(
            SUBACC_ID,
        ))],
    );
    assert!(state_enabled(&context, &fixture.state_pda));

    let mut signing_fn = |message_hash: &[u8]| -> [u8; 64] {
        solana_secp256r1_program::sign_message(
            message_hash,
            &signing_key.private_key_to_der().unwrap(),
        )
        .unwrap()
    };
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let counter = odometer(&context, &fixture.swig, SECP_ROLE_ID, true) + 1;

    let ixs = ToggleSubAccountV2Instruction::new_with_secp256r1_authority(
        fixture.swig,
        fixture.payer.pubkey(),
        &mut signing_fn,
        current_slot,
        counter,
        fixture.state_pda,
        SECP_ROLE_ID,
        SUBACC_ID,
        false,
        &public_key,
    )
    .unwrap();

    send(&mut context, &fixture.payer, ixs).expect("secp256r1 toggle should succeed");
    assert!(
        !state_enabled(&context, &fixture.state_pda),
        "kill-switch should be off"
    );
}
