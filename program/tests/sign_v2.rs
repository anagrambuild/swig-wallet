#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.

mod common;
use common::*;
use solana_sdk::{
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ClientAction, SignV2Instruction};
use swig_state::{
    action::all::All,
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds},
};

#[test_log::test]
fn test_sign_v2_transfer_sol() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    
    // Setup accounts
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) = Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    
    // Create the swig account
    let (_, _transaction_metadata) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    
    // Add some funds to the swig account
    context.svm.airdrop(&swig, 10_000_000_000).unwrap();
    
    // Create a simple transfer instruction
    let transfer_amount = 100_000_000; // 0.1 SOL
    let transfer_ix = system_instruction::transfer(&swig, &recipient.pubkey(), transfer_amount);
    
    // Create SignV2 instruction with the swig_wallet_address
    let sign_v2_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        swig_authority.pubkey(),
        swig_authority.pubkey(),
        transfer_ix,
        0, // role_id 0 for root authority
    )
    .unwrap();
    
    // Build and execute transaction
    let transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    
    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message), 
        &[&swig_authority]
    )
    .unwrap();
    
    let initial_recipient_balance = context.svm.get_account(&recipient.pubkey()).unwrap().lamports;
    let initial_swig_balance = context.svm.get_account(&swig).unwrap().lamports;
    
    // Execute the transaction
    let result = context.svm.send_transaction(transfer_tx);
    
    if result.is_err() {
        println!("Transaction failed: {:?}", result.err());
        assert!(false, "SignV2 transaction should succeed");
    } else {
        let txn = result.unwrap();
        println!("SignV2 Transfer successful - CU consumed: {:?}", txn.compute_units_consumed);
        println!("Logs: {}", txn.pretty_logs());
    }
    
    // Verify the transfer was successful
    let final_recipient_balance = context.svm.get_account(&recipient.pubkey()).unwrap().lamports;
    let final_swig_balance = context.svm.get_account(&swig).unwrap().lamports;
    
    assert_eq!(
        final_recipient_balance, 
        initial_recipient_balance + transfer_amount,
        "Recipient should have received the transfer amount"
    );
    
    assert_eq!(
        final_swig_balance,
        initial_swig_balance - transfer_amount,
        "Swig account should have the transfer amount deducted"
    );
    
    println!("✅ SignV2 test passed: Successfully transferred {} lamports", transfer_amount);
}