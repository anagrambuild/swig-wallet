#![cfg(not(feature = "program_scope_test"))]

mod common;
use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use common::*;
use solana_sdk::{
    clock::Clock,
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{AuthorityConfig, ClientAction, IsValidSignatureInstruction, SiwsChallengeV1};
use swig_state::{
    action::sol_limit::SolLimit,
    authority::{secp256k1::Secp256k1Authority, secp256r1::Secp256r1Authority, AuthorityType},
    swig::swig_wallet_address_seeds,
    swig::SwigWithRoles,
    IntoBytes,
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

fn role_id_for_authority_bytes(
    context: &Context,
    swig_pubkey: &Pubkey,
    authority: &[u8],
) -> anyhow::Result<u32> {
    let swig_account = context
        .svm
        .get_account(swig_pubkey)
        .ok_or(anyhow::anyhow!("Swig account not found"))?;
    let swig = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig
        .lookup_role_id(authority)
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .ok_or(anyhow::anyhow!("Role not found for authority"))?;
    Ok(role_id)
}

fn secp256k1_authority_bytes(wallet: &PrivateKeySigner) -> [u8; 64] {
    let key_bytes = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();
    let mut authority = [0u8; 64];
    authority.copy_from_slice(&key_bytes[1..]);
    authority
}

fn secp256k1_signature_odometer(
    context: &Context,
    swig_pubkey: &Pubkey,
    authority_bytes: &[u8],
) -> anyhow::Result<u32> {
    let swig_account = context
        .svm
        .get_account(swig_pubkey)
        .ok_or(anyhow::anyhow!("Swig account not found"))?;
    let swig = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig
        .lookup_role_id(authority_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .ok_or(anyhow::anyhow!("Role not found for authority"))?;
    let role = swig
        .get_role(role_id)
        .map_err(|e| anyhow::anyhow!("Failed to get role {:?}", e))?
        .ok_or(anyhow::anyhow!("Role not found"))?;
    let authority = role
        .authority
        .as_any()
        .downcast_ref::<Secp256k1Authority>()
        .ok_or(anyhow::anyhow!("Role authority is not secp256k1"))?;
    Ok(authority.signature_odometer)
}

fn secp256r1_signature_odometer(
    context: &Context,
    swig_pubkey: &Pubkey,
    public_key: &[u8],
) -> anyhow::Result<u32> {
    let swig_account = context
        .svm
        .get_account(swig_pubkey)
        .ok_or(anyhow::anyhow!("Swig account not found"))?;
    let swig = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig
        .lookup_role_id(public_key)
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .ok_or(anyhow::anyhow!("Role not found for authority"))?;
    let role = swig
        .get_role(role_id)
        .map_err(|e| anyhow::anyhow!("Failed to get role {:?}", e))?
        .ok_or(anyhow::anyhow!("Role not found"))?;
    let authority = role
        .authority
        .as_any()
        .downcast_ref::<Secp256r1Authority>()
        .ok_or(anyhow::anyhow!("Role authority is not secp256r1"))?;
    Ok(authority.signature_odometer)
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
    let pubkey_bytes = signing_key
        .public_key()
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();
    let pubkey_array: [u8; 33] = pubkey_bytes.try_into().unwrap();
    (signing_key, pubkey_array)
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

fn must<T, E: core::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error:?}"),
    }
}

#[test_log::test]
fn test_is_valid_signature_ed25519_happy_path() {
    let mut context = must(setup_test_context(), "setup test context");
    let swig_authority = Keypair::new();
    must(
        context.svm.airdrop(&swig_authority.pubkey(), 1_000_000_000),
        "airdrop swig authority",
    );

    let id = rand::random::<[u8; 32]>();
    let (swig, _) = must(
        create_swig_ed25519(&mut context, &swig_authority, id),
        "create swig ed25519",
    );
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let role_id = must(
        role_id_for_authority(&context, &swig, &swig_authority.pubkey()),
        "lookup role id for swig authority",
    );
    let challenge = build_challenge(swig, swig_wallet_address, role_id, &["ProgramScope"]);

    let validate_ix = must(
        IsValidSignatureInstruction::new_with_ed25519_authority(
            swig,
            swig_wallet_address,
            swig_authority.pubkey(),
            role_id,
            &challenge,
        ),
        "build is_valid_signature instruction",
    );

    let message = must(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[validate_ix],
            &[],
            context.svm.latest_blockhash(),
        ),
        "compile transaction message",
    );
    let tx = must(
        VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[
                context.default_payer.insecure_clone(),
                swig_authority.insecure_clone(),
            ],
        ),
        "build transaction",
    );

    let result = context.svm.send_transaction(tx);
    assert!(result.is_ok(), "is_valid_signature should succeed");
}

#[test_log::test]
fn test_is_valid_signature_secp256k1_happy_path() {
    let mut context = must(setup_test_context(), "setup test context");
    let wallet = LocalSigner::random();

    let id = rand::random::<[u8; 32]>();
    let (swig, _) = must(
        create_swig_secp256k1(&mut context, &wallet, id),
        "create swig secp256k1",
    );
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let authority_bytes = secp256k1_authority_bytes(&wallet);
    let role_id = must(
        role_id_for_authority_bytes(&context, &swig, &authority_bytes),
        "lookup role id for secp256k1 authority",
    );
    let challenge = build_challenge(swig, swig_wallet_address, role_id, &["ProgramScope"]);
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let next_counter = must(
        secp256k1_signature_odometer(&context, &swig, &authority_bytes),
        "read secp256k1 odometer",
    ) + 1;

    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        wallet.sign_hash_sync(&B256::from(hash)).unwrap().as_bytes()
    };

    let validate_ix = must(
        IsValidSignatureInstruction::new_with_secp256k1_authority(
            swig,
            swig_wallet_address,
            signing_fn,
            current_slot,
            next_counter,
            role_id,
            &challenge,
        ),
        "build is_valid_signature secp256k1 instruction",
    );

    let message = must(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[validate_ix],
            &[],
            context.svm.latest_blockhash(),
        ),
        "compile transaction message",
    );
    let tx = must(
        VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[context.default_payer.insecure_clone()],
        ),
        "build transaction",
    );

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "secp256k1 is_valid_signature should succeed: {:?}",
        result.err()
    );
}

#[test_log::test]
fn test_is_valid_signature_secp256r1_happy_path() {
    let mut context = must(setup_test_context(), "setup test context");
    let (signing_key, public_key) = create_test_secp256r1_keypair();

    let id = rand::random::<[u8; 32]>();
    let (swig, _) = must(
        create_swig_secp256r1(&mut context, &public_key, id),
        "create swig secp256r1",
    );
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let role_id = must(
        role_id_for_authority_bytes(&context, &swig, &public_key),
        "lookup role id for secp256r1 authority",
    );
    let challenge = build_challenge(swig, swig_wallet_address, role_id, &["ProgramScope"]);
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let next_counter = must(
        secp256r1_signature_odometer(&context, &swig, &public_key),
        "read secp256r1 odometer",
    ) + 1;

    let signing_fn = |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap()
    };

    let validate_ixs = must(
        IsValidSignatureInstruction::new_with_secp256r1_authority(
            swig,
            swig_wallet_address,
            signing_fn,
            current_slot,
            next_counter,
            role_id,
            &challenge,
            &public_key,
        ),
        "build is_valid_signature secp256r1 instruction",
    );

    let message = must(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &validate_ixs,
            &[],
            context.svm.latest_blockhash(),
        ),
        "compile transaction message",
    );
    let tx = must(
        VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[context.default_payer.insecure_clone()],
        ),
        "build transaction",
    );

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "secp256r1 is_valid_signature should succeed: {:?}",
        result.err()
    );
}

#[test_log::test]
fn test_is_valid_signature_rejects_swig_resource_mismatch() {
    let mut context = must(setup_test_context(), "setup test context");
    let swig_authority = Keypair::new();
    must(
        context.svm.airdrop(&swig_authority.pubkey(), 1_000_000_000),
        "airdrop swig authority",
    );

    let id = rand::random::<[u8; 32]>();
    let (swig, _) = must(
        create_swig_ed25519(&mut context, &swig_authority, id),
        "create swig ed25519",
    );
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let role_id = must(
        role_id_for_authority(&context, &swig, &swig_authority.pubkey()),
        "lookup role id for swig authority",
    );

    let mut challenge = build_challenge(swig, swig_wallet_address, role_id, &["ProgramScope"]);
    challenge.resources[0] = format!("urn:swig:v1:swig:{}", Pubkey::new_unique());

    let validate_ix = must(
        IsValidSignatureInstruction::new_with_ed25519_authority(
            swig,
            swig_wallet_address,
            swig_authority.pubkey(),
            role_id,
            &challenge,
        ),
        "build is_valid_signature instruction",
    );

    let message = must(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[validate_ix],
            &[],
            context.svm.latest_blockhash(),
        ),
        "compile transaction message",
    );
    let tx = must(
        VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[
                context.default_payer.insecure_clone(),
                swig_authority.insecure_clone(),
            ],
        ),
        "build transaction",
    );

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "is_valid_signature should reject swig resource mismatch"
    );
    match result {
        Ok(_) => panic!("expected swig resource mismatch failure"),
        Err(error) => {
            assert_eq!(
                error.err,
                TransactionError::InstructionError(0, InstructionError::Custom(3005))
            );
        },
    }
}

#[test_log::test]
fn test_is_valid_signature_rejects_program_resource_mismatch() {
    let mut context = must(setup_test_context(), "setup test context");
    let swig_authority = Keypair::new();
    must(
        context.svm.airdrop(&swig_authority.pubkey(), 1_000_000_000),
        "airdrop swig authority",
    );

    let id = rand::random::<[u8; 32]>();
    let (swig, _) = must(
        create_swig_ed25519(&mut context, &swig_authority, id),
        "create swig ed25519",
    );
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let role_id = must(
        role_id_for_authority(&context, &swig, &swig_authority.pubkey()),
        "lookup role id for swig authority",
    );

    let mut challenge = build_challenge(swig, swig_wallet_address, role_id, &["ProgramScope"]);
    challenge.resources[2] = format!("urn:swig:v1:swig_program:{}", Pubkey::new_unique());

    let validate_ix = must(
        IsValidSignatureInstruction::new_with_ed25519_authority(
            swig,
            swig_wallet_address,
            swig_authority.pubkey(),
            role_id,
            &challenge,
        ),
        "build is_valid_signature instruction",
    );

    let message = must(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[validate_ix],
            &[],
            context.svm.latest_blockhash(),
        ),
        "compile transaction message",
    );
    let tx = must(
        VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[
                context.default_payer.insecure_clone(),
                swig_authority.insecure_clone(),
            ],
        ),
        "build transaction",
    );

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "is_valid_signature should reject program id mismatch"
    );
    match result {
        Ok(_) => panic!("expected program id mismatch failure"),
        Err(error) => {
            assert_eq!(
                error.err,
                TransactionError::InstructionError(0, InstructionError::Custom(3005))
            );
        },
    }
}

#[test_log::test]
fn test_is_valid_signature_rejects_challenge_wallet_address_mismatch() {
    let mut context = must(setup_test_context(), "setup test context");
    let swig_authority = Keypair::new();
    must(
        context.svm.airdrop(&swig_authority.pubkey(), 1_000_000_000),
        "airdrop swig authority",
    );

    let id = rand::random::<[u8; 32]>();
    let (swig, _) = must(
        create_swig_ed25519(&mut context, &swig_authority, id),
        "create swig ed25519",
    );
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let role_id = must(
        role_id_for_authority(&context, &swig, &swig_authority.pubkey()),
        "lookup role id for swig authority",
    );

    let mut challenge = build_challenge(swig, swig_wallet_address, role_id, &["ProgramScope"]);
    challenge.address = Pubkey::new_unique().to_string();

    let validate_ix = must(
        IsValidSignatureInstruction::new_with_ed25519_authority(
            swig,
            swig_wallet_address,
            swig_authority.pubkey(),
            role_id,
            &challenge,
        ),
        "build is_valid_signature instruction",
    );

    let message = must(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[validate_ix],
            &[],
            context.svm.latest_blockhash(),
        ),
        "compile transaction message",
    );
    let tx = must(
        VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[
                context.default_payer.insecure_clone(),
                swig_authority.insecure_clone(),
            ],
        ),
        "build transaction",
    );

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "is_valid_signature should reject challenge address mismatch"
    );
    match result {
        Ok(_) => panic!("expected challenge address mismatch failure"),
        Err(error) => {
            assert_eq!(
                error.err,
                TransactionError::InstructionError(0, InstructionError::Custom(3005))
            );
        },
    }
}

#[test_log::test]
fn test_is_valid_signature_rejects_duplicate_urn_resources() {
    let mut context = must(setup_test_context(), "setup test context");
    let swig_authority = Keypair::new();
    must(
        context.svm.airdrop(&swig_authority.pubkey(), 1_000_000_000),
        "airdrop swig authority",
    );

    let id = rand::random::<[u8; 32]>();
    let (swig, _) = must(
        create_swig_ed25519(&mut context, &swig_authority, id),
        "create swig ed25519",
    );
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let role_id = must(
        role_id_for_authority(&context, &swig, &swig_authority.pubkey()),
        "lookup role id for swig authority",
    );

    let mut challenge = build_challenge(swig, swig_wallet_address, role_id, &["ProgramScope"]);
    challenge.resources.push(format!("urn:swig:v1:swig:{swig}"));

    let validate_ix = must(
        IsValidSignatureInstruction::new_with_ed25519_authority(
            swig,
            swig_wallet_address,
            swig_authority.pubkey(),
            role_id,
            &challenge,
        ),
        "build is_valid_signature instruction",
    );

    let message = must(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[validate_ix],
            &[],
            context.svm.latest_blockhash(),
        ),
        "compile transaction message",
    );
    let tx = must(
        VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[
                context.default_payer.insecure_clone(),
                swig_authority.insecure_clone(),
            ],
        ),
        "build transaction",
    );

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "duplicate URN resources should be rejected"
    );
    match result {
        Ok(_) => panic!("expected duplicate URN rejection"),
        Err(error) => {
            assert_eq!(
                error.err,
                TransactionError::InstructionError(0, InstructionError::InvalidInstructionData)
            );
        },
    }
}

#[test_log::test]
fn test_is_valid_signature_allows_empty_scopes() {
    let mut context = must(setup_test_context(), "setup test context");
    let swig_authority = Keypair::new();
    must(
        context.svm.airdrop(&swig_authority.pubkey(), 1_000_000_000),
        "airdrop swig authority",
    );

    let id = rand::random::<[u8; 32]>();
    let (swig, _) = must(
        create_swig_ed25519(&mut context, &swig_authority, id),
        "create swig ed25519",
    );
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let role_id = must(
        role_id_for_authority(&context, &swig, &swig_authority.pubkey()),
        "lookup role id for swig authority",
    );
    let challenge = build_challenge(swig, swig_wallet_address, role_id, &[]);

    let validate_ix = must(
        IsValidSignatureInstruction::new_with_ed25519_authority(
            swig,
            swig_wallet_address,
            swig_authority.pubkey(),
            role_id,
            &challenge,
        ),
        "build is_valid_signature instruction",
    );

    let message = must(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[validate_ix],
            &[],
            context.svm.latest_blockhash(),
        ),
        "compile transaction message",
    );
    let tx = must(
        VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[
                context.default_payer.insecure_clone(),
                swig_authority.insecure_clone(),
            ],
        ),
        "build transaction",
    );

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "is_valid_signature should allow challenge without scopes"
    );
}

#[test_log::test]
fn test_is_valid_signature_rejects_missing_scope_permission() {
    let mut context = must(setup_test_context(), "setup test context");
    let swig_authority = Keypair::new();
    let limited_authority = Keypair::new();
    must(
        context.svm.airdrop(&swig_authority.pubkey(), 1_000_000_000),
        "airdrop swig authority",
    );
    must(
        context
            .svm
            .airdrop(&limited_authority.pubkey(), 1_000_000_000),
        "airdrop limited authority",
    );

    let id = rand::random::<[u8; 32]>();
    let (swig, _) = must(
        create_swig_ed25519(&mut context, &swig_authority, id),
        "create swig ed25519",
    );
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    must(
        add_authority_with_ed25519_root(
            &mut context,
            &swig,
            &swig_authority,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: limited_authority.pubkey().as_ref(),
            },
            vec![ClientAction::SolLimit(SolLimit { amount: 1_000_000 })],
        ),
        "add limited authority",
    );

    let limited_role_id = must(
        role_id_for_authority(&context, &swig, &limited_authority.pubkey()),
        "lookup limited role id",
    );
    let challenge = build_challenge(
        swig,
        swig_wallet_address,
        limited_role_id,
        &["ManageAuthority"],
    );

    let validate_ix = must(
        IsValidSignatureInstruction::new_with_ed25519_authority(
            swig,
            swig_wallet_address,
            limited_authority.pubkey(),
            limited_role_id,
            &challenge,
        ),
        "build is_valid_signature instruction",
    );

    let message = must(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[validate_ix],
            &[],
            context.svm.latest_blockhash(),
        ),
        "compile transaction message",
    );
    let tx = must(
        VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[
                context.default_payer.insecure_clone(),
                limited_authority.insecure_clone(),
            ],
        ),
        "build transaction",
    );

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "is_valid_signature should reject missing scope permission"
    );
    match result {
        Ok(_) => panic!("expected missing scope permission failure"),
        Err(error) => {
            assert_eq!(
                error.err,
                TransactionError::InstructionError(0, InstructionError::Custom(3006))
            );
        },
    }
}

#[test_log::test]
fn test_is_valid_signature_rejects_role_resource_mismatch() {
    let mut context = must(setup_test_context(), "setup test context");
    let swig_authority = Keypair::new();
    must(
        context.svm.airdrop(&swig_authority.pubkey(), 1_000_000_000),
        "airdrop swig authority",
    );

    let id = rand::random::<[u8; 32]>();
    let (swig, _) = must(
        create_swig_ed25519(&mut context, &swig_authority, id),
        "create swig ed25519",
    );
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let role_id = must(
        role_id_for_authority(&context, &swig, &swig_authority.pubkey()),
        "lookup role id for swig authority",
    );
    let wrong_role_id = role_id + 1;
    let challenge = build_challenge(swig, swig_wallet_address, wrong_role_id, &["ProgramScope"]);

    let validate_ix = must(
        IsValidSignatureInstruction::new_with_ed25519_authority(
            swig,
            swig_wallet_address,
            swig_authority.pubkey(),
            role_id,
            &challenge,
        ),
        "build is_valid_signature instruction",
    );

    let message = must(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[validate_ix],
            &[],
            context.svm.latest_blockhash(),
        ),
        "compile transaction message",
    );
    let tx = must(
        VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[
                context.default_payer.insecure_clone(),
                swig_authority.insecure_clone(),
            ],
        ),
        "build transaction",
    );

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "is_valid_signature should reject mismatched role_id resource"
    );
    match result {
        Ok(_) => panic!("expected role resource mismatch failure"),
        Err(error) => {
            assert_eq!(
                error.err,
                TransactionError::InstructionError(0, InstructionError::Custom(3005))
            );
        },
    }
}

#[test_log::test]
fn test_is_valid_signature_rejects_malformed_abnf_challenge() {
    let mut context = must(setup_test_context(), "setup test context");
    let swig_authority = Keypair::new();
    must(
        context.svm.airdrop(&swig_authority.pubkey(), 1_000_000_000),
        "airdrop swig authority",
    );

    let id = rand::random::<[u8; 32]>();
    let (swig, _) = must(
        create_swig_ed25519(&mut context, &swig_authority, id),
        "create swig ed25519",
    );
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let role_id = must(
        role_id_for_authority(&context, &swig, &swig_authority.pubkey()),
        "lookup role id for swig authority",
    );

    let malformed_challenge = b"example.com wants you to sign in with your Solana account:\n3KMf9P7w2nQx5R8tUvYcBdEghJkMNpQrS\n\nNonce: abcdef12\nVersion: 1";

    let args = swig_interface::swig::actions::is_valid_signature::IsValidSignatureArgs::new(
        role_id,
        malformed_challenge.len() as u16,
    );
    let arg_bytes = must(args.into_bytes(), "serialize args");

    let validate_ix = Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(swig, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(swig_authority.pubkey(), true),
        ],
        data: [arg_bytes, malformed_challenge, &[2]].concat(),
    };

    let message = must(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[validate_ix],
            &[],
            context.svm.latest_blockhash(),
        ),
        "compile transaction message",
    );
    let tx = must(
        VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[
                context.default_payer.insecure_clone(),
                swig_authority.insecure_clone(),
            ],
        ),
        "build transaction",
    );

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "is_valid_signature should reject malformed ABNF challenge"
    );
    match result {
        Ok(_) => panic!("expected malformed challenge failure"),
        Err(error) => {
            assert_eq!(
                error.err,
                TransactionError::InstructionError(0, InstructionError::InvalidInstructionData)
            );
        },
    }
}
