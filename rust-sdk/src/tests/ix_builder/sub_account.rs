use super::*;
use crate::tests::common::*;
use alloy_primitives::B256;
use alloy_signer::SignerSync;
use litesvm_token::spl_token;
use solana_program::pubkey::Pubkey;
use solana_sdk::{clock::Clock, signature::Keypair, transaction::VersionedTransaction};

#[test_log::test]
fn test_create_sub_account() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [3u8; 32];
    let authority = Keypair::new();
    let role_id = 0;

    // First create the Swig account
    let (swig_key, _) = create_swig_ed25519(&mut context, &authority, swig_id).unwrap();

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        AuthorityManager::Ed25519(authority.pubkey()),
        context.default_payer.pubkey(),
        role_id,
    );

    // Add a new authority to the Swig account with SubAccount permission
    let new_authority = Keypair::new();
    let ix = builder
        .add_authority_instruction(
            AuthorityType::Ed25519,
            &new_authority.pubkey().to_bytes(),
            vec![Permission::SubAccount],
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&context.default_payer])
        .unwrap();

    context.svm.process_transaction(&tx).unwrap();

    // Create a sub account

    let ix = builder.create_subaccount(role_id).unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&context.default_payer])
        .unwrap();
}
