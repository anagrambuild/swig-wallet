#![cfg(not(feature = "program_scope_test"))]

mod common;

use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use common::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    sysvar::clock::Clock,
    transaction::VersionedTransaction,
};
use swig::actions::replace_authority_v1::REPLACE_AUTHORITY_PROOF_V1_DISCRIMINATOR;
use swig_interface::{
    AuthorityConfig, ClientAction, CreateSessionInstruction, ReplaceAuthorityInstruction,
};
use swig_state::{
    action::{
        all_but_manage_authority::AllButManageAuthority, manage_authority::ManageAuthority,
        replace_authority::ReplaceAuthority,
    },
    authority::{
        ed25519::{CreateEd25519SessionAuthority, ED25519Authority, Ed25519SessionAuthority},
        programexec::ProgramExecAuthority,
        secp256k1::{CreateSecp256k1SessionAuthority, Secp256k1Authority},
        secp256r1::{CreateSecp256r1SessionAuthority, Secp256r1Authority},
        AuthorityType,
    },
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
    IntoBytes,
};

solana_sdk::declare_id!("BXAu5ZWHnGun2XZjUZ9nqwiZ5dNVmofPGYdMC4rx4qLV");
const TEST_POLICY_PROGRAM_ID: Pubkey = ID;
const TEST_POLICY_PROGRAM_PATH: &str = "../target/deploy/test_program_authority.so";

fn deploy_policy_test_program(context: &mut SwigTestContext) -> anyhow::Result<Pubkey> {
    let program_data = std::fs::read(TEST_POLICY_PROGRAM_PATH).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read test policy program: {}. Make sure to run `cargo build-sbf` first.",
            e
        )
    })?;
    context
        .svm
        .add_program(TEST_POLICY_PROGRAM_ID, &program_data)?;
    Ok(TEST_POLICY_PROGRAM_ID)
}

fn replacement_proof_instruction(
    policy_program_id: Pubkey,
    swig: Pubkey,
    swig_wallet_address: Pubkey,
    acting_role_id: u32,
    target_role_id: u32,
    authority_type: AuthorityType,
    current_authority: &[u8],
    new_authority: &[u8],
) -> Instruction {
    let data = ReplaceAuthorityInstruction::program_exec_proof_data(
        swig,
        swig_wallet_address,
        acting_role_id,
        target_role_id,
        authority_type,
        current_authority,
        new_authority,
    )
    .unwrap();

    Instruction {
        program_id: policy_program_id,
        accounts: vec![
            AccountMeta::new_readonly(swig, false),
            AccountMeta::new_readonly(swig_wallet_address, false),
        ],
        data,
    }
}

fn create_test_secp256r1_keypair() -> (openssl::ec::EcKey<openssl::pkey::Private>, [u8; 33]) {
    use openssl::{
        bn::BigNumContext,
        ec::{EcGroup, EcKey, PointConversionForm},
        nid::Nid,
    };

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let signing_key = EcKey::generate(&group).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let public_key = signing_key
        .public_key()
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap()
        .try_into()
        .unwrap();
    (signing_key, public_key)
}

fn create_test_secp256r1_public_key() -> [u8; 33] {
    create_test_secp256r1_keypair().1
}

fn compressed_evm_public_key(wallet: &PrivateKeySigner) -> Vec<u8> {
    wallet
        .credential()
        .verifying_key()
        .to_encoded_point(true)
        .to_bytes()
        .to_vec()
}

fn send_replacement_transaction(
    context: &mut SwigTestContext,
    instructions: &[Instruction],
) -> Result<(), Box<litesvm::types::FailedTransactionMetadata>> {
    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        instructions,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&context.default_payer])
        .unwrap();
    context
        .svm
        .send_transaction(tx)
        .map(|_| ())
        .map_err(Box::new)
}

fn send_ed25519_replace(
    context: &mut SwigTestContext,
    swig: Pubkey,
    acting_authority: &Keypair,
    acting_role_id: u32,
    target_role_id: u32,
    new_authority: &[u8],
) -> Result<(), Box<litesvm::types::FailedTransactionMetadata>> {
    context.svm.expire_blockhash();
    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig,
        acting_authority.pubkey(),
        acting_role_id,
        target_role_id,
        new_authority,
    )
    .unwrap();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, acting_authority],
    )
    .unwrap();
    context
        .svm
        .send_transaction(transaction)
        .map(|_| ())
        .map_err(Box::new)
}

fn add_program_exec_replacer(
    context: &mut SwigTestContext,
    swig: &Pubkey,
    root_authority: &Keypair,
    policy_program_id: Pubkey,
    actions: Vec<ClientAction>,
) {
    let authority = ProgramExecAuthority::create_authority_data(
        &policy_program_id.to_bytes(),
        &REPLACE_AUTHORITY_PROOF_V1_DISCRIMINATOR,
    );
    add_authority_with_ed25519_root(
        context,
        swig,
        root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::ProgramExec,
            authority: &authority,
        },
        actions,
    )
    .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn program_exec_replacement_instructions(
    policy_program_id: Pubkey,
    swig: Pubkey,
    swig_wallet_address: Pubkey,
    acting_role_id: u32,
    target_role_id: u32,
    target_authority_type: AuthorityType,
    current_authority: &[u8],
    new_authority: &[u8],
) -> Vec<Instruction> {
    let proof = replacement_proof_instruction(
        policy_program_id,
        swig,
        swig_wallet_address,
        acting_role_id,
        target_role_id,
        target_authority_type,
        current_authority,
        new_authority,
    );
    ReplaceAuthorityInstruction::new_with_program_exec(
        swig,
        swig_wallet_address,
        proof,
        acting_role_id,
        target_role_id,
        new_authority,
    )
    .unwrap()
}

#[test_log::test]
fn test_ed25519_authority_can_replace_authority_without_changing_actions() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let old_target = Keypair::new();
    let new_target = Keypair::new();
    let acting_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: old_target.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: acting_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ReplaceAuthority(ReplaceAuthority::new(1))],
    )
    .unwrap();

    let before_account = context.svm.get_account(&swig).unwrap();
    let before_state = SwigWithRoles::from_bytes(&before_account.data).unwrap();
    let before_actions = before_state.get_role(1).unwrap().unwrap().actions.to_vec();

    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig,
        acting_authority.pubkey(),
        2,
        1,
        new_target.pubkey().as_ref(),
    )
    .unwrap();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, &acting_authority],
    )
    .unwrap();
    context.svm.send_transaction(transaction).unwrap();

    let account = context.svm.get_account(&swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let target_role = state.get_role(1).unwrap().unwrap();
    let target = target_role
        .authority
        .as_any()
        .downcast_ref::<ED25519Authority>()
        .unwrap();
    assert_eq!(target.public_key, new_target.pubkey().to_bytes());
    assert_eq!(target_role.actions, before_actions.as_slice());
}

#[test_log::test]
fn test_all_permission_can_replace_authority() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let old_target = Keypair::new();
    let new_target = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: old_target.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    send_ed25519_replace(
        &mut context,
        swig,
        &root,
        0,
        1,
        new_target.pubkey().as_ref(),
    )
    .unwrap();

    let account = context.svm.get_account(&swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    assert_eq!(
        state
            .get_role(1)
            .unwrap()
            .unwrap()
            .authority
            .identity()
            .unwrap(),
        new_target.pubkey().as_ref()
    );
}

#[test_log::test]
fn test_manage_authority_permission_can_replace_authority() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let old_target = Keypair::new();
    let new_target = Keypair::new();
    let manager = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: old_target.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: manager.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    send_ed25519_replace(
        &mut context,
        swig,
        &manager,
        2,
        1,
        new_target.pubkey().as_ref(),
    )
    .unwrap();

    let account = context.svm.get_account(&swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    assert_eq!(
        state
            .get_role(1)
            .unwrap()
            .unwrap()
            .authority
            .identity()
            .unwrap(),
        new_target.pubkey().as_ref()
    );
}

#[test_log::test]
fn test_all_but_manage_authority_cannot_replace_authority() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let old_target = Keypair::new();
    let new_target = Keypair::new();
    let acting_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: old_target.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: acting_authority.pubkey().as_ref(),
        },
        vec![ClientAction::AllButManageAuthority(AllButManageAuthority)],
    )
    .unwrap();

    assert!(send_ed25519_replace(
        &mut context,
        swig,
        &acting_authority,
        2,
        1,
        new_target.pubkey().as_ref(),
    )
    .is_err());

    let account = context.svm.get_account(&swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    assert_eq!(
        state
            .get_role(1)
            .unwrap()
            .unwrap()
            .authority
            .identity()
            .unwrap(),
        old_target.pubkey().as_ref()
    );
}

#[test_log::test]
fn test_replace_authority_rejects_same_signer_for_every_supported_target_type() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();
    let target_actions = || vec![ClientAction::ManageAuthority(ManageAuthority {})];

    let ed25519_target = Keypair::new();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: ed25519_target.pubkey().as_ref(),
        },
        target_actions(),
    )
    .unwrap();

    let ed25519_session_target = Keypair::new();
    let ed25519_session = CreateEd25519SessionAuthority::new(
        ed25519_session_target.pubkey().to_bytes(),
        [1; 32],
        100,
    );
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519Session,
            authority: ed25519_session.into_bytes().unwrap(),
        },
        target_actions(),
    )
    .unwrap();

    let secp256k1_target = compressed_evm_public_key(&LocalSigner::random());
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256k1,
            authority: &secp256k1_target,
        },
        target_actions(),
    )
    .unwrap();

    let secp256k1_session_target = compressed_evm_public_key(&LocalSigner::random());
    let mut padded_secp256k1_session_target = [0u8; 64];
    padded_secp256k1_session_target[..33].copy_from_slice(&secp256k1_session_target);
    let secp256k1_session =
        CreateSecp256k1SessionAuthority::new(padded_secp256k1_session_target, [2; 32], 100);
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256k1Session,
            authority: secp256k1_session.into_bytes().unwrap(),
        },
        target_actions(),
    )
    .unwrap();

    let secp256r1_target = create_test_secp256r1_public_key();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256r1,
            authority: &secp256r1_target,
        },
        target_actions(),
    )
    .unwrap();

    let secp256r1_session_target = create_test_secp256r1_public_key();
    let secp256r1_session =
        CreateSecp256r1SessionAuthority::new(secp256r1_session_target, [3; 32], 100);
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256r1Session,
            authority: secp256r1_session.into_bytes().unwrap(),
        },
        target_actions(),
    )
    .unwrap();

    let same_signers = [
        (1, ed25519_target.pubkey().to_bytes().to_vec()),
        (2, ed25519_session_target.pubkey().to_bytes().to_vec()),
        (3, secp256k1_target),
        (4, secp256k1_session_target),
        (5, secp256r1_target.to_vec()),
        (6, secp256r1_session_target.to_vec()),
    ];

    for (target_role_id, same_signer) in &same_signers {
        assert!(
            send_ed25519_replace(&mut context, swig, &root, 0, *target_role_id, same_signer)
                .is_err(),
            "target role {target_role_id} accepted its existing signer"
        );
    }

    let account = context.svm.get_account(&swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    for (target_role_id, same_signer) in &same_signers {
        assert_eq!(
            state
                .get_role(*target_role_id)
                .unwrap()
                .unwrap()
                .authority
                .identity()
                .unwrap(),
            same_signer,
            "target role {target_role_id} changed after a rejected replacement"
        );
    }
}

#[test_log::test]
fn test_replace_authority_permission_is_scoped_to_target_role() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let old_target = Keypair::new();
    let new_target = Keypair::new();
    let acting_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: old_target.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: acting_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ReplaceAuthority(ReplaceAuthority::new(0))],
    )
    .unwrap();

    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig,
        acting_authority.pubkey(),
        2,
        1,
        new_target.pubkey().as_ref(),
    )
    .unwrap();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, &acting_authority],
    )
    .unwrap();
    assert!(context.svm.send_transaction(transaction).is_err());

    let account = context.svm.get_account(&swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let target = state
        .get_role(1)
        .unwrap()
        .unwrap()
        .authority
        .as_any()
        .downcast_ref::<ED25519Authority>()
        .unwrap();
    assert_eq!(target.public_key, old_target.pubkey().to_bytes());
}

#[test_log::test]
fn test_secp256k1_authority_can_replace_authority() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let old_target = Keypair::new();
    let new_target = Keypair::new();
    let acting_wallet = LocalSigner::random();
    let acting_signer = compressed_evm_public_key(&acting_wallet);
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: old_target.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256k1,
            authority: &acting_signer,
        },
        vec![ClientAction::ReplaceAuthority(ReplaceAuthority::new(1))],
    )
    .unwrap();

    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let hash = B256::from_slice(&payload[..32]);
        acting_wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };
    let replace_ix = ReplaceAuthorityInstruction::new_with_secp256k1_authority(
        swig,
        signing_fn,
        current_slot,
        1,
        2,
        1,
        new_target.pubkey().as_ref(),
    )
    .unwrap();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transaction =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])
            .unwrap();
    context.svm.send_transaction(transaction).unwrap();

    let account = context.svm.get_account(&swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let target = state
        .get_role(1)
        .unwrap()
        .unwrap()
        .authority
        .as_any()
        .downcast_ref::<ED25519Authority>()
        .unwrap();
    assert_eq!(target.public_key, new_target.pubkey().to_bytes());
}

#[test_log::test]
fn test_secp256r1_authority_can_replace_authority() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let old_target = Keypair::new();
    let new_target = Keypair::new();
    let (acting_key, acting_signer) = create_test_secp256r1_keypair();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: old_target.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256r1,
            authority: &acting_signer,
        },
        vec![ClientAction::ReplaceAuthority(ReplaceAuthority::new(1))],
    )
    .unwrap();

    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let signing_fn = |message_hash: &[u8]| -> [u8; 64] {
        solana_secp256r1_program::sign_message(
            message_hash,
            &acting_key.private_key_to_der().unwrap(),
        )
        .unwrap()
    };
    let instructions = ReplaceAuthorityInstruction::new_with_secp256r1_authority(
        swig,
        signing_fn,
        current_slot,
        1,
        2,
        1,
        new_target.pubkey().as_ref(),
        &acting_signer,
    )
    .unwrap();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &instructions,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transaction =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])
            .unwrap();
    context.svm.send_transaction(transaction).unwrap();

    let account = context.svm.get_account(&swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let target = state
        .get_role(1)
        .unwrap()
        .unwrap()
        .authority
        .as_any()
        .downcast_ref::<ED25519Authority>()
        .unwrap();
    assert_eq!(target.public_key, new_target.pubkey().to_bytes());
}

#[test_log::test]
fn test_active_session_can_replace_its_own_signer_and_is_invalidated() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let old_owner = Keypair::new();
    let new_owner = Keypair::new();
    let session_key = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    let session_authority =
        CreateEd25519SessionAuthority::new(old_owner.pubkey().to_bytes(), [0; 32], 100);
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519Session,
            authority: session_authority.into_bytes().unwrap(),
        },
        vec![ClientAction::ReplaceAuthority(ReplaceAuthority::new(1))],
    )
    .unwrap();

    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + 1);
    context.svm.expire_blockhash();
    let create_session_ix = CreateSessionInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        old_owner.pubkey(),
        1,
        session_key.pubkey(),
        50,
    )
    .unwrap();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[create_session_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, &old_owner],
    )
    .unwrap();
    context.svm.send_transaction(transaction).unwrap();

    context.svm.expire_blockhash();
    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig,
        session_key.pubkey(),
        1,
        1,
        new_owner.pubkey().as_ref(),
    )
    .unwrap();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, &session_key],
    )
    .unwrap();
    context.svm.send_transaction(transaction).unwrap();

    let account = context.svm.get_account(&swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let role = state.get_role(1).unwrap().unwrap();
    let authority = role
        .authority
        .as_any()
        .downcast_ref::<Ed25519SessionAuthority>()
        .unwrap();
    assert_eq!(authority.public_key, new_owner.pubkey().to_bytes());
    assert_eq!(authority.session_key, [0; 32]);
    assert_eq!(authority.current_session_expiration, 0);
    assert!(role
        .get_action::<ReplaceAuthority>(&1u32.to_le_bytes())
        .unwrap()
        .is_some());
}

#[test_log::test]
fn test_replace_authority_rejects_wrong_key_length_without_mutation() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let old_target = Keypair::new();
    let acting_authority = Keypair::new();
    let new_passkey = create_test_secp256r1_public_key();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: old_target.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: acting_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ReplaceAuthority(ReplaceAuthority::new(1))],
    )
    .unwrap();

    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig,
        acting_authority.pubkey(),
        2,
        1,
        &new_passkey,
    )
    .unwrap();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, &acting_authority],
    )
    .unwrap();
    assert!(context.svm.send_transaction(transaction).is_err());

    let account = context.svm.get_account(&swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let target = state
        .get_role(1)
        .unwrap()
        .unwrap()
        .authority
        .as_any()
        .downcast_ref::<ED25519Authority>()
        .unwrap();
    assert_eq!(target.public_key, old_target.pubkey().to_bytes());
}

#[test_log::test]
fn test_program_exec_replacement_rotates_passkey_authority() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let policy_program_id = deploy_policy_test_program(&mut context).unwrap();
    let old_passkey = create_test_secp256r1_public_key();
    let new_passkey = create_test_secp256r1_public_key();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256r1,
            authority: &old_passkey,
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();
    add_program_exec_replacer(
        &mut context,
        &swig,
        &root_authority,
        policy_program_id,
        vec![ClientAction::ReplaceAuthority(ReplaceAuthority::new(1))],
    );

    let instructions = program_exec_replacement_instructions(
        policy_program_id,
        swig,
        swig_wallet_address,
        2,
        1,
        AuthorityType::Secp256r1,
        &old_passkey,
        &new_passkey,
    );
    send_replacement_transaction(&mut context, &instructions).unwrap();

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let replaced_role = swig_state.get_role(1).unwrap().unwrap();
    let replaced_authority = replaced_role
        .authority
        .as_any()
        .downcast_ref::<Secp256r1Authority>()
        .unwrap();
    assert_eq!(replaced_authority.public_key, new_passkey);
    assert_eq!(replaced_authority.signature_odometer, 0);
    assert!(replaced_role
        .get_action::<ManageAuthority>(&[])
        .unwrap()
        .is_some());
}

#[test_log::test]
fn test_program_exec_replacement_rotates_ed25519_authority() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let new_root_authority = Keypair::new();
    let policy_program_id = deploy_policy_test_program(&mut context).unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    add_program_exec_replacer(
        &mut context,
        &swig,
        &root_authority,
        policy_program_id,
        vec![ClientAction::ReplaceAuthority(ReplaceAuthority::new(0))],
    );

    let instructions = program_exec_replacement_instructions(
        policy_program_id,
        swig,
        swig_wallet_address,
        1,
        0,
        AuthorityType::Ed25519,
        root_authority.pubkey().as_ref(),
        new_root_authority.pubkey().as_ref(),
    );
    send_replacement_transaction(&mut context, &instructions).unwrap();

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let replaced_authority = swig_state
        .get_role(0)
        .unwrap()
        .unwrap()
        .authority
        .as_any()
        .downcast_ref::<ED25519Authority>()
        .unwrap();
    assert_eq!(
        replaced_authority.public_key,
        new_root_authority.pubkey().to_bytes()
    );
}

#[test_log::test]
fn test_program_exec_replacement_rotates_secp256k1_authority() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let old_authority = compressed_evm_public_key(&LocalSigner::random());
    let new_authority = compressed_evm_public_key(&LocalSigner::random());
    let policy_program_id = deploy_policy_test_program(&mut context).unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256k1,
            authority: &old_authority,
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();
    add_program_exec_replacer(
        &mut context,
        &swig,
        &root_authority,
        policy_program_id,
        vec![ClientAction::ReplaceAuthority(ReplaceAuthority::new(1))],
    );

    let instructions = program_exec_replacement_instructions(
        policy_program_id,
        swig,
        swig_wallet_address,
        2,
        1,
        AuthorityType::Secp256k1,
        &old_authority,
        &new_authority,
    );
    send_replacement_transaction(&mut context, &instructions).unwrap();

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let replaced_authority = swig_state
        .get_role(1)
        .unwrap()
        .unwrap()
        .authority
        .as_any()
        .downcast_ref::<Secp256k1Authority>()
        .unwrap();
    assert_eq!(
        replaced_authority.public_key.as_ref(),
        new_authority.as_slice()
    );
    assert_eq!(replaced_authority.signature_odometer, 0);
}

#[test_log::test]
fn test_program_exec_replacement_requires_authority_management_permission() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let old_passkey = create_test_secp256r1_public_key();
    let new_passkey = create_test_secp256r1_public_key();
    let policy_program_id = deploy_policy_test_program(&mut context).unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256r1,
            authority: &old_passkey,
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();
    add_program_exec_replacer(
        &mut context,
        &swig,
        &root_authority,
        policy_program_id,
        vec![ClientAction::AllButManageAuthority(AllButManageAuthority)],
    );

    let instructions = program_exec_replacement_instructions(
        policy_program_id,
        swig,
        swig_wallet_address,
        2,
        1,
        AuthorityType::Secp256r1,
        &old_passkey,
        &new_passkey,
    );
    assert!(send_replacement_transaction(&mut context, &instructions).is_err());

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(
        swig_state
            .get_role(1)
            .unwrap()
            .unwrap()
            .authority
            .identity()
            .unwrap(),
        old_passkey
    );
}

#[test_log::test]
fn test_program_exec_replacement_rejects_mismatched_proof_fields() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let old_passkey = create_test_secp256r1_public_key();
    let new_passkey = create_test_secp256r1_public_key();
    let unrelated_passkey = create_test_secp256r1_public_key();
    let policy_program_id = deploy_policy_test_program(&mut context).unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256r1,
            authority: &old_passkey,
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();
    add_program_exec_replacer(
        &mut context,
        &swig,
        &root_authority,
        policy_program_id,
        vec![ClientAction::ReplaceAuthority(ReplaceAuthority::new(1))],
    );

    let mismatched_proofs = [
        ReplaceAuthorityInstruction::program_exec_proof_data(
            swig,
            swig_wallet_address,
            3,
            1,
            AuthorityType::Secp256r1,
            &old_passkey,
            &new_passkey,
        )
        .unwrap(),
        ReplaceAuthorityInstruction::program_exec_proof_data(
            swig,
            swig_wallet_address,
            2,
            9,
            AuthorityType::Secp256r1,
            &old_passkey,
            &new_passkey,
        )
        .unwrap(),
        ReplaceAuthorityInstruction::program_exec_proof_data(
            swig,
            swig_wallet_address,
            2,
            1,
            AuthorityType::Secp256k1,
            &old_passkey,
            &new_passkey,
        )
        .unwrap(),
        ReplaceAuthorityInstruction::program_exec_proof_data(
            swig,
            swig_wallet_address,
            2,
            1,
            AuthorityType::Secp256r1,
            &unrelated_passkey,
            &new_passkey,
        )
        .unwrap(),
        ReplaceAuthorityInstruction::program_exec_proof_data(
            swig,
            swig_wallet_address,
            2,
            1,
            AuthorityType::Secp256r1,
            &old_passkey,
            &unrelated_passkey,
        )
        .unwrap(),
        ReplaceAuthorityInstruction::program_exec_proof_data(
            Pubkey::new_unique(),
            swig_wallet_address,
            2,
            1,
            AuthorityType::Secp256r1,
            &old_passkey,
            &new_passkey,
        )
        .unwrap(),
        ReplaceAuthorityInstruction::program_exec_proof_data(
            swig,
            Pubkey::new_unique(),
            2,
            1,
            AuthorityType::Secp256r1,
            &old_passkey,
            &new_passkey,
        )
        .unwrap(),
    ];

    for proof_data in mismatched_proofs {
        context.svm.expire_blockhash();
        let proof = Instruction {
            program_id: policy_program_id,
            accounts: vec![
                AccountMeta::new_readonly(swig, false),
                AccountMeta::new_readonly(swig_wallet_address, false),
            ],
            data: proof_data,
        };
        let instructions = ReplaceAuthorityInstruction::new_with_program_exec(
            swig,
            swig_wallet_address,
            proof,
            2,
            1,
            &new_passkey,
        )
        .unwrap();
        assert!(send_replacement_transaction(&mut context, &instructions).is_err());
    }

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(
        swig_state
            .get_role(1)
            .unwrap()
            .unwrap()
            .authority
            .identity()
            .unwrap(),
        old_passkey
    );
}

#[test_log::test]
fn test_program_exec_replacement_rejects_malformed_proof() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let old_passkey = create_test_secp256r1_public_key();
    let new_passkey = create_test_secp256r1_public_key();
    let policy_program_id = deploy_policy_test_program(&mut context).unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256r1,
            authority: &old_passkey,
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();
    add_program_exec_replacer(
        &mut context,
        &swig,
        &root_authority,
        policy_program_id,
        vec![ClientAction::ReplaceAuthority(ReplaceAuthority::new(1))],
    );

    for proof_data in [
        REPLACE_AUTHORITY_PROOF_V1_DISCRIMINATOR.to_vec(),
        [
            REPLACE_AUTHORITY_PROOF_V1_DISCRIMINATOR.as_slice(),
            &[0u8; 33],
        ]
        .concat(),
    ] {
        context.svm.expire_blockhash();
        let proof = Instruction {
            program_id: policy_program_id,
            accounts: vec![
                AccountMeta::new_readonly(swig, false),
                AccountMeta::new_readonly(swig_wallet_address, false),
            ],
            data: proof_data,
        };
        let instructions = ReplaceAuthorityInstruction::new_with_program_exec(
            swig,
            swig_wallet_address,
            proof,
            2,
            1,
            &new_passkey,
        )
        .unwrap();
        assert!(send_replacement_transaction(&mut context, &instructions).is_err());
    }

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(
        swig_state
            .get_role(1)
            .unwrap()
            .unwrap()
            .authority
            .identity()
            .unwrap(),
        old_passkey
    );
}
