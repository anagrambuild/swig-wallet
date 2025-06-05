#![cfg(not(feature = "program_scope_test"))]

mod common;
use common::*;
use litesvm_token::spl_token;
use solana_sdk::{
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
    program_pack::Pack,
    clock::Clock,
};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state_x::{
    swig::{swig_account_seeds, AuthorizationLock, SwigWithRoles, Swig},
    Transmutable, IntoBytes,
};

/// Test that validates creating a swig, adding an authorization lock, and then 
/// trying to spend over the authorization lock limit should fail, but spending 
/// within the limit should succeed.
#[test_log::test]
fn test_authorization_lock_enforcement() {
    let mut context = setup_test_context().unwrap();

    // Setup accounts
    let swig_authority = Keypair::new(); // This will have All permissions
    let token_authority = Keypair::new(); // This will have only token limit permissions
    let recipient = Keypair::new();

    // Airdrop to participants
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&token_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // Setup token mint
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    // Create swig account
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let swig_create_result = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_result.is_ok());

    // Setup token accounts
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
        &context.default_payer,
    )
    .unwrap();

    // Mint tokens to swig account
    let initial_token_amount = 1000;
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        initial_token_amount,
    )
    .unwrap();

    // Add token authority with limited token permissions FIRST
    use swig_state_x::action::token_limit::TokenLimit;
    let token_action = ClientAction::TokenLimit(TokenLimit {
        token_mint: mint_pubkey.to_bytes(),
        current_amount: 1000, // Allow up to 1000 tokens
    });

    let add_authority_ix = swig_interface::AddAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Acting role ID (swig_authority has All permissions)
        swig_interface::AuthorityConfig {
            authority_type: swig_state_x::authority::AuthorityType::Ed25519,
            authority: &token_authority.pubkey().to_bytes(),
        },
        vec![token_action],
    ).unwrap();

    let add_authority_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_authority_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_authority_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let add_authority_result = context.svm.send_transaction(add_authority_tx);
    assert!(add_authority_result.is_ok(), "Adding token authority should succeed");

    // Add authorization lock for 500 tokens with a future expiry AFTER adding the authority
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let lock_amount = 500u64;
    let expiry_slot = current_slot + 1000; // Far in the future

    let add_lock_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        mint_pubkey.to_bytes(),
        lock_amount,
        expiry_slot,
    ).unwrap();

    let add_lock_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[add_lock_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_lock_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_lock_message),
        &[&swig_authority],
    )
    .unwrap();

    let add_lock_result = context.svm.send_transaction(add_lock_tx);
    assert!(add_lock_result.is_ok(), "Adding authorization lock should succeed");

    // Verify the authorization lock was added
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_with_roles.state.authorization_locks, 1);
    
    let auth_locks = swig_with_roles.get_authorization_locks().unwrap();
    assert_eq!(auth_locks.len(), 1);
    
    println!("=== AUTHORIZATION LOCK ENFORCEMENT TEST ===");
    println!("Authorization locks count: {}", auth_locks.len());
    for (i, lock) in auth_locks.iter().enumerate() {
        println!("Lock {}: mint={:?}, amount={}, expiry_slot={}", 
                 i, lock.token_mint, lock.amount, lock.expiry_slot);
    }
    println!("Token authority limit: 1000 tokens");
    println!("Test scenarios:");
    println!("  - Over limit (600 tokens): Should FAIL (exceeds 500 auth lock)");
    println!("  - Within limit (400 tokens): Should PASS (within 500 auth lock)");
    println!("  - Exact limit (500 tokens): Should PASS (equals 500 auth lock)");
    println!("===============================================");
    
    assert_eq!(auth_locks[0].token_mint, mint_pubkey.to_bytes());
    assert_eq!(auth_locks[0].amount, lock_amount);
    assert_eq!(auth_locks[0].expiry_slot, expiry_slot);

    // Test 1: Try to transfer more than the authorization lock limit (600 tokens)
    // This should fail because it exceeds the authorization lock
    let over_limit_amount = 600;
    
    let over_limit_transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig,
        &[],
        over_limit_amount,
    )
    .unwrap();

    let over_limit_sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        context.default_payer.pubkey(),
        token_authority.pubkey(),
        over_limit_transfer_ix,
        1, // authority role id (token_authority is role 1)
    )
    .unwrap();

    let over_limit_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[over_limit_sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let over_limit_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(over_limit_message),
        &[&context.default_payer, &token_authority],
    )
    .unwrap();

    let over_limit_result = context.svm.send_transaction(over_limit_tx);
    assert!(over_limit_result.is_err(), "Transfer over authorization lock limit should fail");

    // Test 2: Transfer within the authorization lock limit (400 tokens)
    // This should succeed
    let within_limit_amount = 400;
    
    let within_limit_transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig,
        &[],
        within_limit_amount,
    )
    .unwrap();

    let within_limit_sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        context.default_payer.pubkey(),
        token_authority.pubkey(),
        within_limit_transfer_ix,
        1, // authority role id (token_authority is role 1)
    )
    .unwrap();

    let within_limit_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[within_limit_sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let within_limit_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(within_limit_message),
        &[&context.default_payer, &token_authority],
    )
    .unwrap();

    let within_limit_result = context.svm.send_transaction(within_limit_tx);
    assert!(within_limit_result.is_ok(), "Transfer within authorization lock limit should succeed");

    // Verify the token transfer actually happened
    let recipient_token_account = context.svm.get_account(&recipient_ata).unwrap();
    let recipient_balance = spl_token::state::Account::unpack(&recipient_token_account.data).unwrap().amount;
    assert_eq!(recipient_balance, within_limit_amount);

    // Verify swig balance decreased
    let swig_token_account = context.svm.get_account(&swig_ata).unwrap();
    let swig_balance = spl_token::state::Account::unpack(&swig_token_account.data).unwrap().amount;
    assert_eq!(swig_balance, initial_token_amount - within_limit_amount);

    // Test 3: Try to transfer exactly the authorization lock limit (500 tokens remaining)
    // This should succeed
    let exact_limit_amount = 500;
    
    let exact_limit_transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig,
        &[],
        exact_limit_amount,
    )
    .unwrap();

    let exact_limit_sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        context.default_payer.pubkey(),
        token_authority.pubkey(),
        exact_limit_transfer_ix,
        1, // authority role id (token_authority is role 1)
    )
    .unwrap();

    let exact_limit_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[exact_limit_sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let exact_limit_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(exact_limit_message),
        &[&context.default_payer, &token_authority],
    )
    .unwrap();

    let exact_limit_result = context.svm.send_transaction(exact_limit_tx);
    assert!(exact_limit_result.is_ok(), "Transfer of exact authorization lock limit should succeed");

    // Verify final balances
    let final_recipient_account = context.svm.get_account(&recipient_ata).unwrap();
    let final_recipient_balance = spl_token::state::Account::unpack(&final_recipient_account.data).unwrap().amount;
    assert_eq!(final_recipient_balance, within_limit_amount + exact_limit_amount);

    let final_swig_account = context.svm.get_account(&swig_ata).unwrap();
    let final_swig_balance = spl_token::state::Account::unpack(&final_swig_account.data).unwrap().amount;
    assert_eq!(final_swig_balance, initial_token_amount - within_limit_amount - exact_limit_amount);
}

/// Test authorization lock expiry behavior
#[test_log::test]
fn test_authorization_lock_expiry() {
    let mut context = setup_test_context().unwrap();

    // Setup accounts
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    // Airdrop to participants
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // Setup token mint
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    // Create swig account
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let swig_create_result = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_result.is_ok());

    // Setup token accounts
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
        &context.default_payer,
    )
    .unwrap();

    // Mint tokens to swig account
    let initial_token_amount = 1000;
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        initial_token_amount,
    )
    .unwrap();

    // Test 1: Try to add an authorization lock that has already expired
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let expired_slot = if current_slot > 0 { current_slot - 1 } else { 0 }; // Already expired

    println!("=== AUTHORIZATION LOCK EXPIRY TEST ===");
    println!("Current slot: {}", current_slot);
    println!("Trying to add lock with expired slot: {}", expired_slot);
    println!("Expected result: FAIL (expired authorization lock should be rejected)");
    println!("==========================================");

    let add_expired_lock_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        mint_pubkey.to_bytes(),
        500,
        expired_slot,
    ).unwrap();

    let add_expired_lock_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[add_expired_lock_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_expired_lock_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_expired_lock_message),
        &[&swig_authority],
    )
    .unwrap();

    let add_expired_lock_result = context.svm.send_transaction(add_expired_lock_tx);
    assert!(add_expired_lock_result.is_err(), "Adding expired authorization lock should fail");
}

/// Test that multiple authorization locks work correctly
#[test_log::test]
fn test_multiple_authorization_locks() {
    let mut context = setup_test_context().unwrap();

    // Setup accounts
    let swig_authority = Keypair::new(); // This will have All permissions
    let token_authority = Keypair::new(); // This will have only token limit permissions
    let recipient = Keypair::new();

    // Airdrop to participants
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&token_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // Setup two different token mints
    let mint1_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let mint2_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    // Create swig account
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let swig_create_result = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_result.is_ok());

    // Setup token accounts for both mints
    let swig_ata1 = setup_ata(
        &mut context.svm,
        &mint1_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();

    let swig_ata2 = setup_ata(
        &mut context.svm,
        &mint2_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();

    let recipient_ata1 = setup_ata(
        &mut context.svm,
        &mint1_pubkey,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    let recipient_ata2 = setup_ata(
        &mut context.svm,
        &mint2_pubkey,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Mint tokens to both swig accounts
    let initial_token_amount = 1000;
    mint_to(
        &mut context.svm,
        &mint1_pubkey,
        &context.default_payer,
        &swig_ata1,
        initial_token_amount,
    )
    .unwrap();

    mint_to(
        &mut context.svm,
        &mint2_pubkey,
        &context.default_payer,
        &swig_ata2,
        initial_token_amount,
    )
    .unwrap();

    // Add authorization locks for both tokens
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let expiry_slot = current_slot + 1000;

    // Lock 1: 300 tokens for mint1
    let add_lock1_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        mint1_pubkey.to_bytes(),
        300,
        expiry_slot,
    ).unwrap();

    // Lock 2: 400 tokens for mint2  
    let add_lock2_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        mint2_pubkey.to_bytes(),
        400,
        expiry_slot,
    ).unwrap();

    // Add both locks
    for lock_ix in [add_lock1_ix, add_lock2_ix] {
        let message = v0::Message::try_compile(
            &swig_authority.pubkey(),
            &[lock_ix],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap();

        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[&swig_authority],
        )
        .unwrap();

        let result = context.svm.send_transaction(tx);
        assert!(result.is_ok(), "Adding authorization lock should succeed");
    }

    // Verify both locks were added
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_with_roles.state.authorization_locks, 2);

    let all_auth_locks = swig_with_roles.get_authorization_locks().unwrap();
    println!("=== MULTIPLE AUTHORIZATION LOCKS TEST ===");
    println!("Authorization locks count: {}", all_auth_locks.len());
    for (i, lock) in all_auth_locks.iter().enumerate() {
        println!("Lock {}: mint={:?}, amount={}, expiry_slot={}", 
                 i, lock.token_mint, lock.amount, lock.expiry_slot);
    }
    println!("Token authority limit: 250 tokens for mint1");
    println!("Test scenarios:");
    println!("  - Transfer 200 tokens of mint1: Should PASS (within 300 auth lock)");
    println!("  - Transfer 350 tokens of mint2: Should PASS (within 400 auth lock)");
    println!("  - Transfer 400 tokens of mint1: Should FAIL (exceeds 300 auth lock)");
    println!("=============================================");

    // Add token authority with limited token permissions for mint1
    use swig_state_x::action::token_limit::TokenLimit;
    let token_action = ClientAction::TokenLimit(TokenLimit {
        token_mint: mint1_pubkey.to_bytes(),
        current_amount: 250, // Allow up to 250 tokens for mint1 (less than the 300 auth lock)
    });

    let add_authority_ix = swig_interface::AddAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Acting role ID (swig_authority has All permissions)
        swig_interface::AuthorityConfig {
            authority_type: swig_state_x::authority::AuthorityType::Ed25519,
            authority: &token_authority.pubkey().to_bytes(),
        },
        vec![token_action],
    ).unwrap();

    let add_authority_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_authority_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_authority_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let add_authority_result = context.svm.send_transaction(add_authority_tx);
    assert!(add_authority_result.is_ok(), "Adding token authority should succeed");

    // Test transfers within each lock's limits
    // Transfer 200 tokens of mint1 (within 300 limit)
    let transfer1_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata1,
        &recipient_ata1,
        &swig,
        &[],
        200,
    )
    .unwrap();

    let sign1_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        swig_authority.pubkey(),
        swig_authority.pubkey(),
        transfer1_ix,
        0,
    )
    .unwrap();

    let message1 = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign1_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx1 = VersionedTransaction::try_new(
        VersionedMessage::V0(message1),
        &[&swig_authority],
    )
    .unwrap();

    let result1 = context.svm.send_transaction(tx1);
    assert!(result1.is_ok(), "Transfer of mint1 within lock limit should succeed");

    // Transfer 350 tokens of mint2 (within 400 limit)
    let transfer2_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata2,
        &recipient_ata2,
        &swig,
        &[],
        350,
    )
    .unwrap();

    let sign2_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        swig_authority.pubkey(),
        swig_authority.pubkey(),
        transfer2_ix,
        0,
    )
    .unwrap();

    let message2 = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx2 = VersionedTransaction::try_new(
        VersionedMessage::V0(message2),
        &[&swig_authority],
    )
    .unwrap();

    let result2 = context.svm.send_transaction(tx2);
    assert!(result2.is_ok(), "Transfer of mint2 within lock limit should succeed");

    // Test transfer that exceeds mint1 lock (400 tokens, exceeds 300 limit)
    let over_limit_transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata1,
        &recipient_ata1,
        &swig,
        &[],
        400,
    )
    .unwrap();

    let over_limit_sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        context.default_payer.pubkey(),
        token_authority.pubkey(),
        over_limit_transfer_ix,
        1, // authority role id (token_authority is role 1)
    )
    .unwrap();

    let over_limit_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[over_limit_sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let over_limit_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(over_limit_message),
        &[&context.default_payer, &token_authority],
    )
    .unwrap();

    let over_limit_result = context.svm.send_transaction(over_limit_tx);
    assert!(over_limit_result.is_err(), "Transfer exceeding mint1 lock limit should fail");
}