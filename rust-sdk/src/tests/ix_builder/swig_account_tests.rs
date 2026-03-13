use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use solana_program::pubkey::Pubkey;
use solana_sdk::{
    message::{v0, VersionedMessage},
    signature::{Keypair, Signer},
    transaction::VersionedTransaction,
};
use swig_interface::program_id;
use swig_state::{
    authority::AuthorityType,
    swig::{swig_account_seeds, SwigWithRoles},
};

use super::*;
use crate::client_role::{Ed25519ClientRole, Secp256k1ClientRole};

#[test_log::test]
fn test_create_swig_account_with_ed25519_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [1u8; 32];
    let authority = Keypair::new();
    let payer = context.default_payer;
    let role_id = 0;

    let builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        payer.pubkey(),
        role_id,
    );

    let ix = builder.create_swig_account_instruction().unwrap();

    let msg = v0::Message::try_compile(&payer.pubkey(), &[ix], &[], context.svm.latest_blockhash())
        .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to create Swig account: {:?}",
        result.err()
    );

    // Verify the account was created correctly
    let (swig_key, _) = Pubkey::find_program_address(&swig_account_seeds(&swig_id), &program_id());
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let root_role = swig_data.get_role(0).unwrap().unwrap();

    assert_eq!(swig_data.state.id, swig_id);
    assert_eq!(swig_data.state.roles, 1);
}

#[test_log::test]
fn test_create_swig_account_with_secp256k1_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [1u8; 32];

    let wallet = LocalSigner::random();

    let secp_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    let payer = &context.default_payer;
    let role_id = 0;

    let builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Secp256k1ClientRole::new(
            secp_pubkey,
            Box::new(|_| [0u8; 65]),
        )),
        payer.pubkey(),
        role_id,
    );

    let ix = builder.create_swig_account_instruction().unwrap();
    let msg = v0::Message::try_compile(&payer.pubkey(), &[ix], &[], context.svm.latest_blockhash())
        .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to create Swig account: {:?}",
        result.err()
    );

    // Verify the account was created correctly
    let (swig_key, _) = Pubkey::find_program_address(&swig_account_seeds(&swig_id), &program_id());
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let root_role = swig_data.get_role(0).unwrap().unwrap();

    assert_eq!(swig_data.state.id, swig_id);
    assert_eq!(swig_data.state.roles, 1);
    assert_eq!(
        root_role.authority.authority_type(),
        AuthorityType::Secp256k1
    );
}
