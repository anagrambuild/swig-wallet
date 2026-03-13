#![cfg(not(feature = "program_scope_test"))]

mod common;
use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use common::*;
use solana_sdk::{
    clock::Clock,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::IsValidSignatureInstruction;
use swig_state::{
    authority::{secp256k1::Secp256k1Authority, secp256r1::Secp256r1Authority},
    swig::{swig_wallet_address_seeds, SwigWithRoles},
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

fn must<T, E: core::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error:?}"),
    }
}

fn arbitrary_payload() -> Vec<u8> {
    vec![0, 255, 17, 42, b's', b'w', b'i', b'g']
}

#[test_log::test]
fn test_is_valid_signature_ed25519_accepts_arbitrary_payload() {
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
    let payload = arbitrary_payload();

    let validate_ix = must(
        IsValidSignatureInstruction::new_with_ed25519_authority(
            swig,
            swig_wallet_address,
            swig_authority.pubkey(),
            role_id,
            &payload,
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
        "ed25519 is_valid_signature should succeed for arbitrary payload: {:?}",
        result.err()
    );
}

#[test_log::test]
fn test_is_valid_signature_secp256k1_accepts_arbitrary_payload_without_mutating_odometer() {
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
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let current_counter = must(
        secp256k1_signature_odometer(&context, &swig, &authority_bytes),
        "read secp256k1 odometer",
    );
    let payload = arbitrary_payload();

    let signing_fn = |message_hash: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&message_hash[..32]);
        wallet.sign_hash_sync(&B256::from(hash)).unwrap().as_bytes()
    };

    let validate_ix = must(
        IsValidSignatureInstruction::new_with_secp256k1_authority(
            swig,
            swig_wallet_address,
            signing_fn,
            current_slot,
            current_counter + 1,
            role_id,
            &payload,
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
        "secp256k1 is_valid_signature should succeed for arbitrary payload: {:?}",
        result.err()
    );

    let final_counter = must(
        secp256k1_signature_odometer(&context, &swig, &authority_bytes),
        "read secp256k1 odometer after validation",
    );
    assert_eq!(
        final_counter, current_counter,
        "is_valid_signature must not mutate the secp256k1 odometer"
    );
}

#[test_log::test]
fn test_is_valid_signature_secp256r1_accepts_arbitrary_payload_without_mutating_odometer() {
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
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let current_counter = must(
        secp256r1_signature_odometer(&context, &swig, &public_key),
        "read secp256r1 odometer",
    );
    let payload = arbitrary_payload();

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
            current_counter + 1,
            role_id,
            &payload,
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
        "secp256r1 is_valid_signature should succeed for arbitrary payload: {:?}",
        result.err()
    );

    let final_counter = must(
        secp256r1_signature_odometer(&context, &swig, &public_key),
        "read secp256r1 odometer after validation",
    );
    assert_eq!(
        final_counter, current_counter,
        "is_valid_signature must not mutate the secp256r1 odometer"
    );
}

#[test_log::test]
fn test_is_valid_signature_rejects_unknown_role_id() {
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
    let payload = arbitrary_payload();

    let validate_ix = must(
        IsValidSignatureInstruction::new_with_ed25519_authority(
            swig,
            swig_wallet_address,
            swig_authority.pubkey(),
            u32::MAX,
            &payload,
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
    assert!(result.is_err(), "unknown role_id should be rejected");
}

#[test_log::test]
fn test_is_valid_signature_rejects_tampered_secp256k1_payload() {
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
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let current_counter = must(
        secp256k1_signature_odometer(&context, &swig, &authority_bytes),
        "read secp256k1 odometer",
    );
    let payload = arbitrary_payload();

    let signing_fn = |message_hash: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&message_hash[..32]);
        wallet.sign_hash_sync(&B256::from(hash)).unwrap().as_bytes()
    };

    let mut validate_ix = must(
        IsValidSignatureInstruction::new_with_secp256k1_authority(
            swig,
            swig_wallet_address,
            signing_fn,
            current_slot,
            current_counter + 1,
            role_id,
            &payload,
        ),
        "build is_valid_signature secp256k1 instruction",
    );
    let args_len = core::mem::size_of::<
        swig_interface::swig::actions::is_valid_signature::IsValidSignatureArgs,
    >();
    validate_ix.data[args_len] ^= 0x01;

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
    assert!(result.is_err(), "tampered payload should be rejected");
}
