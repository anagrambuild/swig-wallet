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
    system_instruction,
    transaction::VersionedTransaction,
};
use swig_state_x::{
    authority::{secp256k1::Secp256k1Authority, AuthorityType},
    swig::{swig_account_seeds, SwigWithRoles},
};

#[test_log::test]
fn test_create() {
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
fn test_create_basic_token_transfer() {
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
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig,
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
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    let ixd = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer { amount: 100 }.pack(),
    };

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        swig_authority.pubkey(),
        swig_authority.pubkey(),
        ixd,
        0,
    )
    .unwrap();
    let transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_ix],
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
    } else {
        let res = res.unwrap();
        println!("logs {:?}", res.logs);
        println!("Sign Transfer CU {:?}", res.compute_units_consumed);
    }
    let account = context.svm.get_account(&swig_ata).unwrap();
    let token_account = spl_token::state::Account::unpack(&account.data).unwrap();
    assert_eq!(token_account.amount, 900);
}

#[test_log::test]
fn test_create_and_sign_secp256k1() {
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

    // Sign a SOL transfer with the secp256k1 authority
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context.svm.airdrop(&swig_key, 10_000_000_000).unwrap();

    // Use latest_blockhash to get the current slot simulation
    let current_slot = 0; // LiteSVM doesn't expose get_slot, using 0 for tests
    let transfer_amount = 5_000_000_000; // 5 SOL

    // Create SOL transfer instruction
    let transfer_ix = system_instruction::transfer(&swig_key, &recipient.pubkey(), transfer_amount);

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

    // Create the sign instruction with secp256k1
    let sign_ix = swig_interface::SignInstruction::new_secp256k1(
        swig_key,
        context.default_payer.pubkey(),
        signing_fn,
        current_slot,
        transfer_ix,
        0, // Role ID 0
    )
    .unwrap();

    // Create and send the transaction
    let transfer_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
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
    assert!(res.is_ok(), "Transaction failed: {:?}", res.err());

    let transaction_result = res.unwrap();
    println!(
        "Sign Transfer CU {:?}",
        transaction_result.compute_units_consumed
    );
    println!("logs: {:?}", transaction_result.logs);

    // Verify the transfer was successful
    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(recipient_account.lamports, 10_000_000_000 + transfer_amount);

    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(
        swig_account.lamports,
        swig_state.state.reserved_lamports + 10_000_000_000 - transfer_amount
    );
}
