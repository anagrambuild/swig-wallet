#![cfg(not(feature = "program_scope_test"))]

mod common;
use common::*;
use solana_sdk::{
    clock::Clock,
    message::{v0, VersionedMessage},
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ClientAction, SignV2Instruction};
use swig_state::{
    action::{
        manage_authority::ManageAuthority, manage_authorization_locks::ManageAuthorizationLocks,
        program::Program, program_all::ProgramAll, sol_limit::SolLimit,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds, AuthorizationLock, SwigWithRoles},
    Transmutable,
};

/// Test that validates authorization lock amount limits are enforced correctly
/// in SignV2. This test creates a role with ManageAuthority and ProgramAll
/// permissions, adds an authorization lock, and verifies the lock is enforced.
#[test_log::test]
fn test_authorization_lock_with_sign_v2_exceeds_limit() {
    let mut context = setup_test_context().unwrap();

    // Setup accounts
    let swig_authority = Keypair::new();
    let limited_authority = Keypair::new();
    let recipient = Keypair::new();

    // Airdrop funds to participants
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 20_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&limited_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), 1_000_000_000)
        .unwrap();

    // Create swig account (root has All permissions)
    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    println!("=== AUTHORIZATION LOCK LIMIT ENFORCEMENT TEST ===");
    create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    println!("✅ Swig account created");

    // Fund the swig_wallet_address PDA
    let wallet_funding_amount = 10 * LAMPORTS_PER_SOL;
    let transfer_to_wallet_ix = system_instruction::transfer(
        &swig_authority.pubkey(),
        &swig_wallet_address,
        wallet_funding_amount,
    );

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &swig_authority.pubkey(),
                &[transfer_to_wallet_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&swig_authority],
    )
    .unwrap();

    context.svm.send_transaction(transfer_tx).unwrap();
    println!(
        "✅ Swig wallet funded with {} lamports (10 SOL)",
        wallet_funding_amount
    );

    // Add a second authority with ManageAuthority, ManageAuthorizationLocks, ProgramAll, and specific Program permissions
    // This gives it the ability to spend via system program and manage its own authorization locks
    println!("Adding second authority with ManageAuthority, ManageAuthorizationLocks, ProgramAll, and System Program permissions");
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: limited_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ManageAuthority(ManageAuthority {}),
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::Program(Program {
                program_id: solana_sdk::system_program::ID.to_bytes(),
            }),
        ],
    )
    .unwrap();
    println!("✅ Second authority added (role ID: 1)");

    // Add authorization lock to the limited authority's role (role 1)
    // The authorization lock will be associated with the acting_role_id,
    // so we need the limited_authority (role 1) to add it to itself
    let sol_mint = [0u8; 32];
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let lock_amount = 1 * LAMPORTS_PER_SOL; // Only allow 1 SOL
    let expiry_slot = current_slot + 10000;

    println!(
        "Adding authorization lock to role 1 (by role 1 itself) with limit: {} lamports (1 SOL)",
        lock_amount
    );

    let add_lock_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        limited_authority.pubkey(), // The limited authority adds the lock to itself
        context.default_payer.pubkey(),
        1, // Acting as role 1 to add the lock to role 1
        sol_mint,
        lock_amount,
        expiry_slot,
        swig_wallet_address, // Balance account for validation
    )
    .unwrap();

    let add_lock_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &context.default_payer.pubkey(),
                &[add_lock_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&context.default_payer, &limited_authority], // Sign with limited_authority since it's acting
    )
    .unwrap();

    context.svm.send_transaction(add_lock_tx).unwrap();
    println!("✅ Authorization lock added to role 1");
    println!();

    // Test 1: Transfer within the lock limit - should SUCCEED
    let within_limit_amount = 500_000_000; // 0.5 SOL (within 1 SOL limit)
    println!(
        "TEST 1: Attempting to transfer {} lamports (0.5 SOL) - WITHIN lock limit",
        within_limit_amount
    );
    println!("Expected: Transaction should SUCCEED");

    let transfer_ix_within = system_instruction::transfer(
        &swig_wallet_address,
        &recipient.pubkey(),
        within_limit_amount,
    );

    let sign_v2_ix_within = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        limited_authority.pubkey(),
        transfer_ix_within,
        1, // Use role 1 (limited authority)
    )
    .unwrap();

    let sign_v2_tx_within = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &limited_authority.pubkey(),
                &[sign_v2_ix_within],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&limited_authority],
    )
    .unwrap();

    let result_within = context.svm.send_transaction(sign_v2_tx_within);

    assert!(
        result_within.is_ok(),
        "Transaction within lock limit should succeed: {:?}",
        result_within.err()
    );
    println!("✅ TEST 1 PASSED: Transaction within limit succeeded");
    println!();

    // Test 2: Attempt to transfer MORE than the authorization lock allows - should FAIL
    let transfer_amount = 2 * LAMPORTS_PER_SOL; // Trying to transfer 2 SOL (exceeds 1 SOL limit)
    println!(
        "TEST 2: Attempting to transfer {} lamports (2 SOL) - EXCEEDS lock limit",
        transfer_amount
    );
    println!("Expected: Transaction should FAIL");

    context.svm.expire_blockhash();

    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    let sign_v2_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        limited_authority.pubkey(),
        transfer_ix,
        1, // Use role 1 (limited authority)
    )
    .unwrap();

    let sign_v2_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &limited_authority.pubkey(),
                &[sign_v2_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&limited_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(sign_v2_tx);

    assert!(
        result.is_err(),
        "Transaction should fail when exceeding authorization lock limit"
    );
    println!(
        "✅ TEST 2 PASSED: Transaction correctly FAILED when exceeding authorization lock limit"
    );
    println!();
    println!("✅ AUTHORIZATION LOCK LIMIT ENFORCEMENT TEST PASSED!");
    println!("======================================================");
}

/// Test that validates expired authorization locks are rejected by SignV2
#[test_log::test]
fn test_authorization_lock_with_sign_v2_expired_lock() {
    let mut context = setup_test_context().unwrap();

    // Setup accounts
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), 1_000_000_000)
        .unwrap();

    // Create swig account
    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    println!("=== EXPIRED AUTHORIZATION LOCK TEST ===");
    create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    println!("✅ Swig account created");

    // Fund the swig_wallet_address PDA
    let wallet_funding_amount = 5 * LAMPORTS_PER_SOL;
    let transfer_to_wallet_ix = system_instruction::transfer(
        &swig_authority.pubkey(),
        &swig_wallet_address,
        wallet_funding_amount,
    );

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &swig_authority.pubkey(),
                &[transfer_to_wallet_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&swig_authority],
    )
    .unwrap();

    context.svm.send_transaction(transfer_tx).unwrap();
    println!("✅ Swig wallet funded");

    // Add authorization lock with short expiry
    let sol_mint = [0u8; 32];
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let lock_amount = 2 * LAMPORTS_PER_SOL;
    let expiry_slot = current_slot + 10; // Will expire soon

    println!("Adding authorization lock:");
    println!("  Current slot: {}", current_slot);
    println!("  Expiry slot: {}", expiry_slot);

    let add_lock_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0,
        sol_mint,
        lock_amount,
        expiry_slot,
        swig_wallet_address, // Balance account for validation
    )
    .unwrap();

    let add_lock_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &context.default_payer.pubkey(),
                &[add_lock_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    context.svm.send_transaction(add_lock_tx).unwrap();
    println!("✅ Authorization lock added");
    println!();

    // Warp time forward past the expiry
    println!("Warping time forward past expiry slot...");
    context.svm.warp_to_slot(expiry_slot + 100);
    context.svm.expire_blockhash();
    let new_slot = context.svm.get_sysvar::<Clock>().slot;
    println!("  New current slot: {}", new_slot);
    println!("  Authorization lock is now EXPIRED");
    println!();

    // Attempt to use the expired authorization lock
    // Since the lock is expired, it should NOT apply, and the transaction should
    // fall back to checking other permissions (in this case, "All" permission)
    let transfer_amount = 1 * LAMPORTS_PER_SOL;
    println!(
        "Attempting to transfer {} lamports (1 SOL) with EXPIRED lock",
        transfer_amount
    );
    println!("Expected: Transaction should SUCCEED (expired lock doesn't block, falls back to 'All' permission)");

    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    let sign_v2_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        swig_authority.pubkey(),
        transfer_ix,
        0,
    )
    .unwrap();

    let sign_v2_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &swig_authority.pubkey(),
                &[sign_v2_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&swig_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(sign_v2_tx);

    // Expired authorization locks should not block transactions
    // The transaction should fall back to other permissions (e.g., "All")
    assert!(
        result.is_ok(),
        "Transaction should succeed when authorization lock is expired (falls back to 'All' permission): {:?}",
        result.err()
    );
    println!(
        "✅ Transaction correctly SUCCEEDED with expired lock (fell back to 'All' permission)"
    );
    println!("   Expired locks don't block - they simply become ineffective");
    println!();
    println!("✅ EXPIRED AUTHORIZATION LOCK TEST COMPLETED!");
    println!("======================================================");
}

/// Helper to print swig wallet balance, sol limit, and auth locks after a withdraw.
fn print_swig_details(
    context: &SwigTestContext,
    swig: &Pubkey,
    swig_wallet_address: &Pubkey,
    sol_mint: &[u8; 32],
    label: &str,
) {
    let swig_acc = context.svm.get_account(swig).unwrap();
    let swig_wallet_balance = context.svm.get_balance(swig_wallet_address).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_acc.data).unwrap();
    let limited_authority_role = swig_with_roles.get_role(1).unwrap().unwrap();
    println!("Swig details after {}:", label);
    println!("--------------------------------");
    println!(
        "Swig wallet balance: {} lamports ({} SOL)",
        swig_wallet_balance,
        swig_wallet_balance as f64 / LAMPORTS_PER_SOL as f64
    );
    if let Some(sol_limit) = limited_authority_role.get_action::<SolLimit>(&[]).unwrap() {
        println!(
            "sol limit: {} lamports ({} SOL)",
            sol_limit.amount,
            sol_limit.amount as f64 / LAMPORTS_PER_SOL as f64
        );
    }
    let (auth_locks, count) = swig_with_roles.get_authorization_locks_by_role::<10>(1).unwrap();
    for i in 0..count {
        if let Some(lock) = &auth_locks[i] {
            if lock.token_mint == *sol_mint {
                println!(
                    "auth lock: {} lamports ({} SOL)",
                    lock.amount,
                    lock.amount as f64 / LAMPORTS_PER_SOL as f64
                );
            }
        }
    }
    println!("--------------------------------");
}

/// Drain wallet test
#[test_log::test]
fn test_drain_wallet() {
    let mut context = setup_test_context().unwrap();

    let swig_authority = Keypair::new();
    let limited_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 20_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&limited_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), 1_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    println!("=== DRAIN WALLET TEST ===");
    create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    println!("Swig account created");

    let swig_initial_balance = 5 * LAMPORTS_PER_SOL;
    let lock_amount = 2 * LAMPORTS_PER_SOL;
    let sol_limit_amount = 3 * LAMPORTS_PER_SOL;

    // Withdraw amounts in SOL; each entry triggers a transfer of that many SOL
    let withdraws: Vec<u64> = vec![3, 1, 1];

    context
        .svm
        .airdrop(&swig_wallet_address, swig_initial_balance)
        .unwrap();
    println!(
        " Swig wallet funded with {} SOL",
        swig_initial_balance as f64 / LAMPORTS_PER_SOL as f64
    );

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: limited_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
            ClientAction::SolLimit(SolLimit {
                amount: sol_limit_amount,
            }),
            ClientAction::Program(Program {
                program_id: solana_sdk::system_program::ID.to_bytes(),
            }),
        ],
    )
    .unwrap();
    println!(
        "Authority added with {} SOL limit and ManageAuthorizationLocks (role ID: 1)",
        sol_limit_amount as f64 / LAMPORTS_PER_SOL as f64
    );

    let sol_mint = [0u8; 32];
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let expiry_slot = current_slot + 10000;

    let add_lock_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        limited_authority.pubkey(),
        context.default_payer.pubkey(),
        1,
        sol_mint,
        lock_amount,
        expiry_slot,
        swig_wallet_address,
    )
    .unwrap();

    let add_lock_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &context.default_payer.pubkey(),
                &[add_lock_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&context.default_payer, &limited_authority],
    )
    .unwrap();

    context.svm.send_transaction(add_lock_tx).unwrap();
    println!(
        "Authorization lock added for {} SOL",
        lock_amount as f64 / LAMPORTS_PER_SOL as f64
    );
    println!();

    for (i, sol_amount) in withdraws.iter().enumerate() {
        let lamports = sol_amount * LAMPORTS_PER_SOL;
        let test_num = i + 1;

        println!(
            "TEST {}: Attempting to withdraw {} lamports ({} SOL)",
            test_num,
            lamports,
            *sol_amount
        );

        context.svm.expire_blockhash();

        let transfer_ix =
            system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), lamports);

        let sign_v2_ix = SignV2Instruction::new_ed25519(
            swig,
            swig_wallet_address,
            limited_authority.pubkey(),
            transfer_ix,
            1,
        )
        .unwrap();

        let sign_v2_tx = VersionedTransaction::try_new(
            VersionedMessage::V0(
                v0::Message::try_compile(
                    &limited_authority.pubkey(),
                    &[sign_v2_ix],
                    &[],
                    context.svm.latest_blockhash(),
                )
                .unwrap(),
            ),
            &[&limited_authority],
        )
        .unwrap();

        let result = context.svm.send_transaction(sign_v2_tx);
        println!("result: {:?}", result.is_ok());
        if let Err(e) = &result {
            println!("error: {:?}", e);
        }
        println!();

        print_swig_details(
            &context,
            &swig,
            &swig_wallet_address,
            &sol_mint,
            &format!("withdraw {} ({} SOL)", test_num, sol_amount),
        );
        println!();
    }
}
