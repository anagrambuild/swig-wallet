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
        context.default_payer.pubkey(),
        0, // acting_role_id: swig_authority has All permissions (role 0)
        mint_pubkey.to_bytes(),
        lock_amount,
        expiry_slot,
    ).unwrap();

    let add_lock_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_lock_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_lock_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_lock_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let add_lock_result = context.svm.send_transaction(add_lock_tx);
    assert!(add_lock_result.is_ok(), "Adding authorization lock should succeed");

    // Verify the authorization lock was added
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_with_roles.state.authorization_locks, 1);
    
    let (auth_locks, count) = swig_with_roles.get_authorization_locks_for_test::<10>().unwrap();
    assert_eq!(count, 1);
    
    println!("=== AUTHORIZATION LOCK ENFORCEMENT TEST ===");
    println!("Authorization locks count: {}", count);
    for i in 0..count {
        if let Some(lock) = auth_locks[i] {
            println!("Lock {}: mint={:?}, amount={}, expiry_slot={}", 
                     i, lock.token_mint, lock.amount, lock.expiry_slot);
        }
    }
    println!("Token authority limit: 1000 tokens");
    println!("Test scenarios:");
    println!("  - Over limit (600 tokens): Should FAIL (exceeds 500 auth lock)");
    println!("  - Within limit (400 tokens): Should PASS (within 500 auth lock)");
    println!("  - Exact limit (500 tokens): Should PASS (equals 500 auth lock)");
    println!("===============================================");
    
    let first_lock = auth_locks[0].unwrap();
    assert_eq!(first_lock.token_mint, mint_pubkey.to_bytes());
    assert_eq!(first_lock.amount, lock_amount);
    assert_eq!(first_lock.expiry_slot, expiry_slot);

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
        context.default_payer.pubkey(),
        0, // acting_role_id: swig_authority has All permissions
        mint_pubkey.to_bytes(),
        500,
        expired_slot,
    ).unwrap();

    let add_expired_lock_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_expired_lock_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_expired_lock_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_expired_lock_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let add_expired_lock_result = context.svm.send_transaction(add_expired_lock_tx);
    assert!(add_expired_lock_result.is_err(), "Adding expired authorization lock should fail");
}

/// Test that expired authorization locks are automatically removed during sign operations
#[test_log::test]
fn test_expired_authorization_lock_cleanup() {
    let mut context = setup_test_context().unwrap();

    // Setup accounts
    let swig_authority = Keypair::new();
    let token_authority = Keypair::new();
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

    // Add token authority
    use swig_state_x::action::token_limit::TokenLimit;
    let token_action = ClientAction::TokenLimit(TokenLimit {
        token_mint: mint_pubkey.to_bytes(),
        current_amount: 1000, 
    });

    let add_authority_ix = swig_interface::AddAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, 
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

    // Add authorization lock that will expire soon
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let short_expiry_slot = current_slot + 5; // Will expire soon

    let add_lock_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0, // acting_role_id: swig_authority has All permissions
        mint_pubkey.to_bytes(),
        500,
        short_expiry_slot,
    ).unwrap();

    let add_lock_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_lock_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_lock_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_lock_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let add_lock_result = context.svm.send_transaction(add_lock_tx);
    assert!(add_lock_result.is_ok(), "Adding authorization lock should succeed");

    // Verify the authorization lock was added
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_with_roles.state.authorization_locks, 1);

    println!("=== EXPIRED AUTHORIZATION LOCK CLEANUP TEST ===");
    println!("Current slot: {}", current_slot);
    println!("Lock expiry slot: {}", short_expiry_slot);
    println!("Authorization locks before expiry: {}", swig_with_roles.state.authorization_locks);
    
    // Display the lock details
    let (auth_locks, count) = swig_with_roles.get_authorization_locks_for_test::<10>().unwrap();
    for i in 0..count {
        if let Some(lock) = auth_locks[i] {
            println!("Lock {}: mint={:?}, amount={}, expiry_slot={}", 
                     i, lock.token_mint, lock.amount, lock.expiry_slot);
            println!("  → Lock will expire at slot {}, current slot is {}", 
                     lock.expiry_slot, current_slot);
        }
    }

    // Advance time past the expiry slot
    context.svm.warp_to_slot(short_expiry_slot + 10);
    let new_current_slot = context.svm.get_sysvar::<Clock>().slot;
    println!();
    println!("TIME WARP:");
    println!("New current slot after warp: {}", new_current_slot);
    println!("Lock expiry slot: {}", short_expiry_slot);
    println!("Lock is now {} slots expired", new_current_slot - short_expiry_slot);
    println!("Expected: Lock should be removed during next sign operation");
    println!();

    // Perform a token transfer that will trigger the cleanup
    let transfer_amount = 100;
    println!("PERFORMING SIGN OPERATION:");
    println!("Transfer amount: {} tokens", transfer_amount);
    println!("This will trigger expired lock cleanup...");
    
    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig,
        &[],
        transfer_amount,
    )
    .unwrap();

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        context.default_payer.pubkey(),
        token_authority.pubkey(),
        transfer_ix,
        1, // authority role id
    )
    .unwrap();

    let sign_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let sign_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(sign_message),
        &[&context.default_payer, &token_authority],
    )
    .unwrap();

    let sign_result = context.svm.send_transaction(sign_tx);
    assert!(sign_result.is_ok(), "Sign operation should succeed");
    println!("✅ Sign operation completed successfully");
    println!();

    // Verify that the expired authorization lock was removed
    let swig_account_after = context.svm.get_account(&swig).unwrap();
    let swig_with_roles_after = SwigWithRoles::from_bytes(&swig_account_after.data).unwrap();
    
    println!("CLEANUP RESULTS:");
    println!("Authorization locks after cleanup: {}", swig_with_roles_after.state.authorization_locks);
    println!("Authorization locks before cleanup: {}", swig_with_roles.state.authorization_locks);
    println!("Locks removed: {}", swig_with_roles.state.authorization_locks - swig_with_roles_after.state.authorization_locks);
    
    // Display remaining locks (should be none)
    let (remaining_locks, remaining_count) = swig_with_roles_after.get_authorization_locks_for_test::<10>().unwrap();
    println!("Remaining locks: {}", remaining_count);
    for i in 0..remaining_count {
        if let Some(lock) = remaining_locks[i] {
            println!("  Remaining Lock {}: mint={:?}, amount={}, expiry_slot={}", 
                     i, lock.token_mint, lock.amount, lock.expiry_slot);
        }
    }
    
    println!("Expected: 0 (expired lock should be removed)");
    println!("============================================");
    
    assert_eq!(swig_with_roles_after.state.authorization_locks, 0, 
               "Expired authorization lock should have been removed");

    // Verify the token transfer still succeeded
    let recipient_token_account = context.svm.get_account(&recipient_ata).unwrap();
    let recipient_balance = spl_token::state::Account::unpack(&recipient_token_account.data).unwrap().amount;
    assert_eq!(recipient_balance, transfer_amount);
    println!("✅ Token transfer verification: {} tokens successfully transferred", transfer_amount);
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

    println!("=== MULTIPLE AUTHORIZATION LOCKS TEST ===");
    println!("Setting up authorization locks:");
    println!("Current slot: {}", current_slot);
    println!("Expiry slot: {} (+1000 slots)", expiry_slot);
    println!("Mint1: {:?}", mint1_pubkey.to_bytes());
    println!("Mint2: {:?}", mint2_pubkey.to_bytes());
    println!();

    // Lock 1: 300 tokens for mint1
    println!("Adding Lock 1 for mint1: 300 tokens");
    let add_lock1_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0, // acting_role_id: swig_authority has All permissions
        mint1_pubkey.to_bytes(),
        300,
        expiry_slot,
    ).unwrap();

    // Lock 2: 400 tokens for mint2  
    println!("Adding Lock 2 for mint2: 400 tokens");
    let add_lock2_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0, // acting_role_id: swig_authority has All permissions
        mint2_pubkey.to_bytes(),
        400,
        expiry_slot,
    ).unwrap();

    // Add both locks
    for lock_ix in [add_lock1_ix, add_lock2_ix] {
        let message = v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[lock_ix],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap();

        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[&context.default_payer, &swig_authority],
        )
        .unwrap();

        let result = context.svm.send_transaction(tx);
        assert!(result.is_ok(), "Adding authorization lock should succeed");
    }
    println!("✅ Both authorization locks added successfully");
    println!();

    // Verify both locks were added
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_with_roles.state.authorization_locks, 2);

    let (all_auth_locks, count) = swig_with_roles.get_authorization_locks_for_test::<10>().unwrap();
    println!("VERIFICATION - Authorization locks in account:");
    println!("Total authorization locks count: {}", count);
    for i in 0..count {
        if let Some(lock) = all_auth_locks[i] {
            println!("Lock {}: mint={:?}, amount={}, expiry_slot={}", 
                     i, lock.token_mint, lock.amount, lock.expiry_slot);
            // Check which mint this corresponds to
            if lock.token_mint == mint1_pubkey.to_bytes() {
                println!("  → This is the MINT1 lock (300 tokens)");
            } else if lock.token_mint == mint2_pubkey.to_bytes() {
                println!("  → This is the MINT2 lock (400 tokens)");
            }
        }
    }
    println!();
    println!("AUTHORITY SETUP:");
    println!("Token authority limit: 250 tokens for mint1 ONLY");
    println!("Swig authority: unlimited permissions (All)");
    println!();
    println!("TEST SCENARIOS:");
    println!("  1. Transfer 200 tokens of mint1 using swig_authority: Should PASS (within 300 auth lock)");
    println!("  2. Transfer 350 tokens of mint2 using swig_authority: Should PASS (within 400 auth lock)");
    println!("  3. Transfer 400 tokens of mint1 using token_authority: Should FAIL (exceeds 300 auth lock)");
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
    println!();
    println!("EXECUTING TEST SCENARIO 1:");
    println!("Transfer 200 tokens of mint1 using swig_authority (All permissions)");
    println!("Expected: PASS (200 < 300 auth lock limit)");
    
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
    println!("✅ Scenario 1 PASSED: 200 tokens of mint1 transferred successfully");

    // Transfer 350 tokens of mint2 (within 400 limit)
    println!();
    println!("EXECUTING TEST SCENARIO 2:");
    println!("Transfer 350 tokens of mint2 using swig_authority (All permissions)");
    println!("Expected: PASS (350 < 400 auth lock limit)");
    
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
    println!("✅ Scenario 2 PASSED: 350 tokens of mint2 transferred successfully");

    // Test transfer that exceeds mint1 lock (400 tokens, exceeds 300 limit)
    println!();
    println!("EXECUTING TEST SCENARIO 3:");
    println!("Transfer 400 tokens of mint1 using token_authority (250 token limit)");
    println!("Expected: FAIL (400 > 300 auth lock limit, AND 400 > 250 token limit)");
    println!("Note: This tests that authorization locks are enforced even with limited authorities");
    
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
    println!("✅ Scenario 3 PASSED: Transfer correctly rejected (exceeds auth lock limit)");
    println!();
    println!("FINAL VERIFICATION:");
    
    // Check final state
    let final_swig_account = context.svm.get_account(&swig).unwrap();
    let final_swig_with_roles = SwigWithRoles::from_bytes(&final_swig_account.data).unwrap();
    let (final_locks, final_count) = final_swig_with_roles.get_authorization_locks_for_test::<10>().unwrap();
    
    println!("Authorization locks still present: {}", final_count);
    println!("All locks should still be active (none expired)");
    for i in 0..final_count {
        if let Some(lock) = final_locks[i] {
            let current_test_slot = context.svm.get_sysvar::<Clock>().slot;
            let expires_in = if lock.expiry_slot > current_test_slot { 
                lock.expiry_slot - current_test_slot 
            } else { 
                0 
            };
            println!("Lock {}: amount={}, expires in {} slots", i, lock.amount, expires_in);
        }
    }
    println!("✅ Multiple authorization locks test completed successfully!");
    println!("=============================================");
}

/// Test that multiple authorization locks for the same token mint are combined
#[test_log::test]
fn test_combined_authorization_locks_same_mint() {
    let mut context = setup_test_context().unwrap();

    // Setup accounts
    let swig_authority = Keypair::new();
    let token_authority = Keypair::new();
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

    // Add token authority with limited permissions
    use swig_state_x::action::token_limit::TokenLimit;
    let token_action = ClientAction::TokenLimit(TokenLimit {
        token_mint: mint_pubkey.to_bytes(),
        current_amount: 150, // Allow up to 150 tokens (less than combined auth locks)
    });

    let add_authority_ix = swig_interface::AddAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, 
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

    // Add multiple authorization locks for the SAME mint
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let expiry_slot = current_slot + 1000;

    println!("=== COMBINED AUTHORIZATION LOCKS TEST ===");
    println!("Setting up multiple authorization locks for the SAME mint:");
    println!("Current slot: {}", current_slot);
    println!("Expiry slot: {} (+1000 slots)", expiry_slot);
    println!("Mint: {:?}", mint_pubkey.to_bytes());
    println!();

    // Lock 1: 100 tokens for the same mint
    println!("Adding Lock 1 for mint: 100 tokens");
    let add_lock1_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0, // acting_role_id: swig_authority has All permissions
        mint_pubkey.to_bytes(),
        100,
        expiry_slot,
    ).unwrap();

    // Lock 2: 120 tokens for the same mint
    println!("Adding Lock 2 for SAME mint: 120 tokens");
    let add_lock2_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0, // acting_role_id: swig_authority has All permissions
        mint_pubkey.to_bytes(),
        120,
        expiry_slot,
    ).unwrap();

    // Add both locks
    for (i, lock_ix) in [add_lock1_ix, add_lock2_ix].iter().enumerate() {
        let message = v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[lock_ix.clone()],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap();

        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[&context.default_payer, &swig_authority],
        )
        .unwrap();

        let result = context.svm.send_transaction(tx);
        assert!(result.is_ok(), "Adding authorization lock {} should succeed", i + 1);
    }
    println!("✅ Both authorization locks added successfully");
    println!();

    // Verify both locks were added
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_with_roles.state.authorization_locks, 2);

    let (all_auth_locks, count) = swig_with_roles.get_authorization_locks_for_test::<10>().unwrap();
    println!("VERIFICATION - Authorization locks in account:");
    println!("Total authorization locks count: {}", count);
    let mut total_amount = 0u64;
    for i in 0..count {
        if let Some(lock) = all_auth_locks[i] {
            println!("Lock {}: mint={:?}, amount={}, expiry_slot={}", 
                     i, lock.token_mint, lock.amount, lock.expiry_slot);
            total_amount += lock.amount;
        }
    }
    println!();
    println!("COMBINED AUTHORIZATION:");
    println!("Individual locks: 100 + 120 = {} tokens", total_amount);
    println!("Token authority limit: 150 tokens");
    println!("Expected behavior: Combined auth locks should allow up to {} tokens", total_amount);
    println!();

    // Test scenarios
    println!("TEST SCENARIOS:");
    println!("  1. Transfer 200 tokens: Should PASS (200 < 220 combined auth locks)");
    println!("  2. Transfer 250 tokens: Should FAIL (250 > 220 combined auth locks)");
    println!("=============================================");
    println!();

    // Test 1: Transfer 200 tokens (within combined limit of 220)
    println!("EXECUTING TEST SCENARIO 1:");
    println!("Transfer 200 tokens using token_authority (150 token limit)");
    println!("Expected: PASS (200 < 220 combined auth lock limit)");
    
    let transfer_amount = 200;
    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig,
        &[],
        transfer_amount,
    )
    .unwrap();

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        context.default_payer.pubkey(),
        token_authority.pubkey(),
        transfer_ix,
        1, // authority role id (token_authority is role 1)
    )
    .unwrap();

    let sign_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let sign_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(sign_message),
        &[&context.default_payer, &token_authority],
    )
    .unwrap();

    let sign_result = context.svm.send_transaction(sign_tx);
    assert!(sign_result.is_ok(), "Transfer within combined authorization lock limit should succeed");
    println!("✅ Scenario 1 PASSED: 200 tokens transferred successfully (combined auth locks worked)");

    // Verify the token transfer actually happened
    let recipient_token_account = context.svm.get_account(&recipient_ata).unwrap();
    let recipient_balance = spl_token::state::Account::unpack(&recipient_token_account.data).unwrap().amount;
    assert_eq!(recipient_balance, transfer_amount);

    // Test 2: Transfer 250 tokens (exceeds combined limit of 220)
    println!();
    println!("EXECUTING TEST SCENARIO 2:");
    println!("Transfer 250 tokens using token_authority (150 token limit)");
    println!("Expected: FAIL (250 > 220 combined auth lock limit)");
    
    let over_limit_amount = 250;
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
        1, // authority role id
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
    assert!(over_limit_result.is_err(), "Transfer exceeding combined authorization lock limit should fail");
    println!("✅ Scenario 2 PASSED: Transfer correctly rejected (exceeds combined auth lock limit)");
    
    println!();
    println!("FINAL VERIFICATION:");
    println!("✅ Combined authorization locks working correctly!");
    println!("✅ Multiple locks for same mint are properly summed (100 + 120 = 220)");
    println!("✅ Transfers within combined limit (200) succeed");
    println!("✅ Transfers exceeding combined limit (250) are rejected");
    println!("=============================================");
}