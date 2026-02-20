#![cfg(not(feature = "program_scope_test"))]

mod common;
use common::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{AuthorityConfig, ClientAction, IsValidSignatureInstruction, SiwsChallengeV1};
use swig_state::{
    action::sol_limit::SolLimit, authority::AuthorityType, swig::swig_wallet_address_seeds,
    swig::SwigWithRoles, IntoBytes,
};

fn role_id_for_authority(
    context: &Context,
    swig_pubkey: &Pubkey,
    authority: &Pubkey,
) -> anyhow::Result<u32> {
    let swig_account = context
        .svm
        .get_account(swig_pubkey)
        .ok_or(anyhow::anyhow!("Swig account not found"))?;
    let swig = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig
        .lookup_role_id(authority.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .ok_or(anyhow::anyhow!("Role not found for authority"))?;
    Ok(role_id)
}

fn build_challenge(
    swig: Pubkey,
    swig_wallet_address: Pubkey,
    role_id: u32,
    scopes: &[&str],
) -> SiwsChallengeV1 {
    let mut resources = vec![
        format!("urn:swig:v1:swig:{swig}"),
        format!("urn:swig:v1:swig_wallet_address:{swig_wallet_address}"),
        format!("urn:swig:v1:swig_program:{}", program_id()),
        format!("urn:swig:v1:role_id:{role_id}"),
    ];
    resources.extend(
        scopes
            .iter()
            .map(|scope| format!("urn:swig:v1:scope:{scope}")),
    );

    SiwsChallengeV1 {
        domain: "example.com".to_string(),
        address: swig_wallet_address.to_string(),
        statement: Some("Sign in to Swig".to_string()),
        uri: "https://example.com/login".to_string(),
        version: "1".to_string(),
        chain_id: Some("solana:devnet".to_string()),
        nonce: "abc123ef".to_string(),
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expiration_time: None,
        not_before: None,
        request_id: None,
        resources,
    }
}

#[test_log::test]
fn test_is_valid_signature_ed25519_happy_path() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let role_id = role_id_for_authority(&context, &swig, &swig_authority.pubkey()).unwrap();
    let challenge = build_challenge(swig, swig_wallet_address, role_id, &["ProgramScope"]);

    let validate_ix = IsValidSignatureInstruction::new_with_ed25519_authority(
        swig,
        swig_wallet_address,
        swig_authority.pubkey(),
        role_id,
        &challenge,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[validate_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[
            context.default_payer.insecure_clone(),
            swig_authority.insecure_clone(),
        ],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(result.is_ok(), "is_valid_signature should succeed");
}

#[test_log::test]
fn test_is_valid_signature_rejects_missing_scope_permission() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let limited_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&limited_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: limited_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1_000_000 })],
    )
    .unwrap();

    let limited_role_id = role_id_for_authority(&context, &swig, &limited_authority.pubkey())
        .unwrap();
    let challenge = build_challenge(
        swig,
        swig_wallet_address,
        limited_role_id,
        &["ManageAuthority"],
    );

    let validate_ix = IsValidSignatureInstruction::new_with_ed25519_authority(
        swig,
        swig_wallet_address,
        limited_authority.pubkey(),
        limited_role_id,
        &challenge,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[validate_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[
            context.default_payer.insecure_clone(),
            limited_authority.insecure_clone(),
        ],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "is_valid_signature should reject missing scope permission"
    );
    assert_eq!(
        result.unwrap_err().err,
        TransactionError::InstructionError(0, InstructionError::Custom(3006))
    );
}

#[test_log::test]
fn test_is_valid_signature_rejects_role_resource_mismatch() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let role_id = role_id_for_authority(&context, &swig, &swig_authority.pubkey()).unwrap();
    let wrong_role_id = role_id + 1;
    let challenge = build_challenge(swig, swig_wallet_address, wrong_role_id, &["ProgramScope"]);

    let validate_ix = IsValidSignatureInstruction::new_with_ed25519_authority(
        swig,
        swig_wallet_address,
        swig_authority.pubkey(),
        role_id,
        &challenge,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[validate_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[
            context.default_payer.insecure_clone(),
            swig_authority.insecure_clone(),
        ],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "is_valid_signature should reject mismatched role_id resource"
    );
    assert_eq!(
        result.unwrap_err().err,
        TransactionError::InstructionError(0, InstructionError::Custom(3005))
    );
}

#[test_log::test]
fn test_is_valid_signature_rejects_malformed_abnf_challenge() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let role_id = role_id_for_authority(&context, &swig, &swig_authority.pubkey()).unwrap();

    let malformed_challenge = b"example.com wants you to sign in with your Solana account:\n3KMf9P7w2nQx5R8tUvYcBdEghJkMNpQrS\n\nNonce: abcdef12\nVersion: 1";

    let args = swig_interface::swig::actions::is_valid_signature::IsValidSignatureArgs::new(
        role_id,
        malformed_challenge.len() as u16,
    );
    let arg_bytes = args.into_bytes().unwrap();

    let validate_ix = Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(swig, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(swig_authority.pubkey(), true),
        ],
        data: [arg_bytes, malformed_challenge, &[2]].concat(),
    };

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[validate_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[
            context.default_payer.insecure_clone(),
            swig_authority.insecure_clone(),
        ],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "is_valid_signature should reject malformed ABNF challenge"
    );
    assert_eq!(
        result.unwrap_err().err,
        TransactionError::InstructionError(0, InstructionError::InvalidInstructionData)
    );
}
