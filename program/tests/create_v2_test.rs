#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.

mod common;

use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use common::*;
use litesvm_token::spl_token::{self, instruction::TokenInstruction};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    sysvar::{clock::Clock, rent::Rent},
    transaction::VersionedTransaction,
};
use solana_system_interface::instruction as system_instruction;
use swig_interface::SignV2Instruction;
use swig_state::{
    authority::{secp256k1::Secp256k1Authority, AuthorityType},
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
};

#[test_log::test]
fn test_create_v2() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let swig_created = create_swig_ed25519(&mut context, &authority, id);
    assert!(swig_created.is_ok(), "{:?}", swig_created.err());
    let (swig_key, bench) = swig_created.unwrap();
    println!("Create CU {:?}", bench.compute_units_consumed);
    println!("logs: {:?}", bench.logs);
    if let Some(account) = context.svm.get_account(&swig_key) {
        println!("swig_data: {:?}", account.data);
        let swig = SwigWithRoles::from_bytes(&account.data).unwrap();

        assert_eq!(swig.state.roles, 1);
        assert_eq!(swig.state.id, id);
        assert_eq!(swig.state.role_counter, 1);
    }
}

#[test_log::test]
fn test_create_basic_token_transfer_v2() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
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
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_wallet_address_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &recipient.pubkey(),
        &recipient,
    )
    .unwrap();

    // Mint tokens to the swig_wallet_address token account
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_wallet_address_ata,
        1000,
    )
    .unwrap();

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    let ixd = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_wallet_address_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig_wallet_address, false), /* Use swig_wallet_address as the
                                                           * authority */
        ],
        data: TokenInstruction::Transfer { amount: 100 }.pack(),
    };

    // Use SignV2Instruction instead of SignInstruction
    let sign_v2_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        swig_authority.pubkey(),
        ixd,
        0, // role_id 0 for root authority
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&swig_authority])
            .unwrap();
    let res = context.svm.send_transaction(transfer_tx);
    if res.is_err() {
        println!("{:?}", res.err());
        assert!(false, "SignV2 token transfer should succeed");
    } else {
        let res = res.unwrap();
        println!("logs {:?}", res.logs);
        println!("Sign Transfer V2 CU {:?}", res.compute_units_consumed);
    }

    // Verify the token transfer was successful
    let account = context.svm.get_account(&swig_wallet_address_ata).unwrap();
    let token_account = spl_token::state::Account::unpack(&account.data).unwrap();
    assert_eq!(token_account.amount, 900);

    let recipient_account = context.svm.get_account(&recipient_ata).unwrap();
    let recipient_token_account =
        spl_token::state::Account::unpack(&recipient_account.data).unwrap();
    assert_eq!(recipient_token_account.amount, 100);
}

#[test_log::test]
fn test_create_and_sign_secp256k1_v2() {
    let mut context = setup_test_context().unwrap();

    // Generate a random Ethereum wallet
    let wallet = LocalSigner::random();

    let id = rand::random::<[u8; 32]>();
    let swig_created = create_swig_secp256k1(&mut context, &wallet, id);
    assert!(swig_created.is_ok(), "{:?}", swig_created.err());
    let (swig_key, bench) = swig_created.unwrap();
    println!("Create CU {:?}", bench.compute_units_consumed);
    println!("logs: {:?}", bench.logs);
    if let Some(account) = context.svm.get_account(&swig_key) {
        let swig = SwigWithRoles::from_bytes(&account.data).unwrap();
        let role = swig.get_role(0).unwrap().unwrap();
        let secp_auth = role
            .authority
            .as_any()
            .downcast_ref::<Secp256k1Authority>()
            .unwrap();
        assert_eq!(
            role.position.authority_type,
            AuthorityType::Secp256k1 as u16
        );
        assert_eq!(
            secp_auth.public_key,
            wallet.credential().verifying_key().to_sec1_bytes().as_ref()
        );
        assert_eq!(swig.state.roles, 1);
        assert_eq!(swig.state.id, id);
        assert_eq!(swig.state.role_counter, 1);
    }

    // Get the swig_wallet_address PDA for SignV2
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    // Sign a SOL transfer with the secp256k1 authority using SignV2
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    // Get current slot and counter
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let transfer_amount = 5_000_000_000; // 5 SOL

    // Create SOL transfer instruction from swig_wallet_address to recipient
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    // Create the signing function that will use our Ethereum wallet
    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        // Sign the hash with the wallet
        let signature = wallet.sign_hash_sync(&hash).unwrap();

        println!("signature: {:?}", signature.as_bytes());
        signature.as_bytes()
    };

    // Create the SignV2 instruction with secp256k1
    let sign_v2_ix = SignV2Instruction::new_secp256k1(
        swig_key,
        swig_wallet_address,
        signing_fn,
        current_slot,
        1, // counter = 1 (first transaction)
        transfer_ix,
        0, // Role ID 0
    )
    .unwrap();

    // Create and send the transaction
    let transfer_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message),
        &[&context.default_payer],
    )
    .unwrap();

    let res = context.svm.send_transaction(transfer_tx);
    assert!(
        res.is_ok(),
        "SignV2 secp256k1 transaction failed: {:?}",
        res.err()
    );

    let transaction_result = res.unwrap();
    println!(
        "Sign Transfer V2 CU {:?}",
        transaction_result.compute_units_consumed
    );
    println!("logs: {:?}", transaction_result.logs);

    // Verify the transfer was successful
    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(recipient_account.lamports, 10_000_000_000 + transfer_amount);

    let swig_wallet_address_account = context.svm.get_account(&swig_wallet_address).unwrap();

    // Just verify that the balance is approximately what we expect
    // (the exact amount will depend on rent calculations and system overhead)
    // We'll just check that it's in a reasonable range: has most of the funds but
    // not more than we started with
    let initial_funds = 10_000_000_000u64;
    let remaining_balance = swig_wallet_address_account.lamports;

    println!(
        "swig_wallet_address remaining balance: {}",
        remaining_balance
    );
    println!("transfer amount: {}", transfer_amount);

    // Balance should be less than initial funds (since we transferred some out)
    assert!(
        remaining_balance < initial_funds,
        "Remaining balance {} should be less than initial funds {}",
        remaining_balance,
        initial_funds
    );

    // Balance should be greater than initial funds minus transfer minus reasonable
    // overhead (1M lamports)
    assert!(
        remaining_balance >= initial_funds - transfer_amount - 1_000_000,
        "Remaining balance {} should be at least {} (initial {} - transfer {} - overhead)",
        remaining_balance,
        initial_funds - transfer_amount - 1_000_000,
        initial_funds,
        transfer_amount
    );
}
