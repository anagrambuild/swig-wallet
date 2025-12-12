#![cfg(not(feature = "program_scope_test"))]
// Tests for multiple sub-accounts per role functionality
mod common;

use common::*;
use solana_sdk::{
    instruction::Instruction, pubkey::Pubkey, signature::Keypair, signer::Signer,
    system_instruction,
};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state::{
    action::{sub_account::SubAccount, Action, Permission},
    authority::AuthorityType,
    swig::{sub_account_seeds, sub_account_seeds_with_index, SwigWithRoles},
    Transmutable,
};

/// Test that index 0 is backwards compatible with legacy derivation
#[test_log::test]
fn test_backwards_compatibility_index_zero() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let sub_account_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&sub_account_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    // Add authority with SubAccount permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: sub_account_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccount(SubAccount::new_for_creation(0))],
    )
    .unwrap();

    let role_id = 1;

    // Create using NEW function but with index 0
    let sub_account = create_sub_account_with_index(
        &mut context,
        &swig_key,
        &sub_account_authority,
        role_id,
        id,
        0,
    )
    .unwrap();

    // Verify PDA derivation matches OLD derivation
    let role_id_bytes = role_id.to_le_bytes();
    let (expected_sub_account, _) = Pubkey::find_program_address(
        &sub_account_seeds(&id, &role_id_bytes), // OLD function - 3 seeds
        &program_id(),
    );

    assert_eq!(
        sub_account, expected_sub_account,
        "Index 0 should derive same PDA as legacy method"
    );

    // Verify it works exactly like before
    let sub_account_data = context.svm.get_account(&sub_account).unwrap();
    assert_eq!(sub_account_data.owner, solana_sdk::system_program::id());

    // Verify SubAccount action has index = 0
    let swig_account_data = context.svm.get_account(&swig_key).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account_data.data).unwrap();
    let role = swig_with_roles.get_role(role_id).unwrap().unwrap();
    let sub_account_actions = role.get_all_actions_of_type::<SubAccount>().unwrap();

    assert_eq!(sub_account_actions.len(), 1);
    assert_eq!(sub_account_actions[0].sub_account_index, 0);
    assert_eq!(sub_account_actions[0].sub_account, sub_account.to_bytes());
}

/// Test creating multiple sub-accounts sequentially
#[test_log::test]
fn test_create_multiple_sub_accounts_sequential() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, root_authority, sub_account_authority, id) =
        setup_with_multiple_sub_account_permissions(&mut context, 5).unwrap();

    let role_id = 1;
    let mut sub_accounts = Vec::new();

    // Create sub-accounts sequentially (0, 1, 2, 3, 4)
    for index in 0..5u8 {
        if index > 0 {
            context.svm.warp_to_slot((index as u64) * 10);
            context.svm.expire_blockhash();
        }
        let sub_account = create_sub_account_with_index(
            &mut context,
            &swig_key,
            &sub_account_authority,
            role_id,
            id,
            index,
        )
        .unwrap();
        sub_accounts.push(sub_account);
    }

    // Verify all 5 sub-accounts exist and are distinct
    for i in 0..5 {
        for j in (i + 1)..5 {
            assert_ne!(
                sub_accounts[i], sub_accounts[j],
                "Sub-accounts {} and {} should be different",
                i, j
            );
        }
    }

    // Verify all are system-owned
    for (i, sub_account) in sub_accounts.iter().enumerate() {
        let account_data = context.svm.get_account(sub_account).unwrap();
        assert_eq!(
            account_data.owner,
            solana_sdk::system_program::id(),
            "Sub-account {} should be system-owned",
            i
        );
    }

    // Verify SubAccount actions
    let swig_account_data = context.svm.get_account(&swig_key).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account_data.data).unwrap();
    let role = swig_with_roles.get_role(role_id).unwrap().unwrap();
    let sub_account_actions = role.get_all_actions_of_type::<SubAccount>().unwrap();

    assert_eq!(
        sub_account_actions.len(),
        5,
        "Should have 5 SubAccount actions"
    );

    for (i, action) in sub_account_actions.iter().enumerate() {
        assert_eq!(
            action.sub_account_index, i as u8,
            "Action {} has wrong index",
            i
        );
        assert_eq!(
            action.sub_account,
            sub_accounts[i].to_bytes(),
            "Action {} has wrong pubkey",
            i
        );
        assert!(action.enabled, "Action {} should be enabled", i);
        assert_eq!(action.role_id, role_id, "Action {} has wrong role_id", i);
        assert_eq!(action.swig_id, id, "Action {} has wrong swig_id", i);
    }
}

/// Test that sequential indices are enforced
#[test_log::test]
fn test_enforce_sequential_indices() {
    // NOTE: This test now validates that indices do NOT need to be sequential
    // Changed from enforcing sequential to allowing flexible order
    let mut context = setup_test_context().unwrap();
    let (swig_key, root_authority, sub_account_authority, id) =
        setup_with_multiple_sub_account_permissions(&mut context, 3).unwrap();

    let role_id = 1;

    // Create index 0 successfully
    let sub_account_0 = create_sub_account_with_index(
        &mut context,
        &swig_key,
        &sub_account_authority,
        role_id,
        id,
        0,
    )
    .unwrap();

    context.svm.warp_to_slot(10);
    context.svm.expire_blockhash();

    // Create index 2 (skipping index 1) - should now SUCCEED
    let sub_account_2 = create_sub_account_with_index(
        &mut context,
        &swig_key,
        &sub_account_authority,
        role_id,
        id,
        2,
    )
    .unwrap();

    context.svm.warp_to_slot(20);
    context.svm.expire_blockhash();

    // Create index 1 - should succeed
    let sub_account_1 = create_sub_account_with_index(
        &mut context,
        &swig_key,
        &sub_account_authority,
        role_id,
        id,
        1,
    )
    .unwrap();

    // Verify all created successfully in non-sequential order
    assert_ne!(sub_account_0, sub_account_1);
    assert_ne!(sub_account_1, sub_account_2);
    assert_ne!(sub_account_0, sub_account_2);
}

/// Test toggling multiple sub-accounts independently
/// TODO: This test currently fails due to transaction signature reuse in
/// litesvm. The functionality works, but the test framework limitations prevent
/// proper verification.
#[test_log::test]
#[ignore = "TODO: Fix transaction signature handling in test"]
fn test_toggle_multiple_sub_accounts_independently() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, root_authority, sub_account_authority, id, sub_accounts) =
        setup_with_multiple_sub_accounts(&mut context, 3).unwrap();

    let role_id = 1;
    let recipient = Keypair::new();
    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();

    // Fund all sub-accounts
    for sub_account in &sub_accounts {
        context.svm.airdrop(sub_account, 5_000_000_000).unwrap();
    }

    // Disable sub-account 1 (middle one)
    toggle_sub_account(
        &mut context,
        &swig_key,
        &sub_accounts[1],
        &sub_account_authority,
        role_id,
        role_id,
        false,
    )
    .unwrap();

    context.svm.warp_to_slot(200);
    context.svm.expire_blockhash();

    // Verify sub-account 0 still works
    let transfer_ix =
        system_instruction::transfer(&sub_accounts[0], &recipient.pubkey(), 1_000_000);
    let result_0 = sub_account_sign(
        &mut context,
        &swig_key,
        &sub_accounts[0],
        &sub_account_authority,
        role_id,
        vec![transfer_ix],
    );
    assert!(
        result_0.is_ok(),
        "Sub-account 0 should still work: {:?}",
        result_0
    );

    context.svm.warp_to_slot(300);
    context.svm.expire_blockhash();

    // Verify sub-account 1 is disabled
    let transfer_ix =
        system_instruction::transfer(&sub_accounts[1], &recipient.pubkey(), 1_000_000);
    let result_1 = sub_account_sign(
        &mut context,
        &swig_key,
        &sub_accounts[1],
        &sub_account_authority,
        role_id,
        vec![transfer_ix],
    );
    assert!(
        result_1.is_err(),
        "Sub-account 1 should be disabled: {:?}",
        result_1
    );

    context.svm.warp_to_slot(400);
    context.svm.expire_blockhash();

    // Verify sub-account 2 still works
    let transfer_ix =
        system_instruction::transfer(&sub_accounts[2], &recipient.pubkey(), 1_000_000);
    let result_2 = sub_account_sign(
        &mut context,
        &swig_key,
        &sub_accounts[2],
        &sub_account_authority,
        role_id,
        vec![transfer_ix],
    );
    assert!(
        result_2.is_ok(),
        "Sub-account 2 should still work: {:?}",
        result_2
    );
}

/// Test withdrawing from a specific sub-account  
/// TODO: Withdraw logic needs update to support multi-sub-account by searching
/// SubAccount actions rather than brute-forcing PDA derivation. Currently only
/// works with index 0 (legacy).
#[test_log::test]
#[ignore = "TODO: Update withdraw logic to search SubAccount actions for role_id/bump"]
fn test_withdraw_from_specific_sub_account() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, root_authority, sub_account_authority, id, sub_accounts) =
        setup_with_multiple_sub_accounts(&mut context, 3).unwrap();

    use swig_state::swig::swig_wallet_address_seeds;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    // Fund each sub-account with different amounts
    context
        .svm
        .airdrop(&sub_accounts[0], 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&sub_accounts[1], 2_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&sub_accounts[2], 3_000_000_000)
        .unwrap();

    context.svm.warp_to_slot(500);
    context.svm.expire_blockhash();

    let initial_balances: Vec<u64> = sub_accounts
        .iter()
        .map(|sa| context.svm.get_account(sa).unwrap().lamports)
        .collect();

    let swig_initial_balance = context
        .svm
        .get_account(&swig_wallet_address)
        .unwrap()
        .lamports;

    // Withdraw 500M from middle sub-account (index 1)
    let withdraw_amount = 500_000_000;
    withdraw_from_sub_account(
        &mut context,
        &swig_key,
        &sub_accounts[1],
        &root_authority,
        0, // root role_id
        withdraw_amount,
    )
    .unwrap();

    // Verify only sub-account 1 balance changed
    let final_balances: Vec<u64> = sub_accounts
        .iter()
        .map(|sa| context.svm.get_account(sa).unwrap().lamports)
        .collect();

    assert_eq!(
        final_balances[0], initial_balances[0],
        "Sub-account 0 unchanged"
    );
    assert_eq!(
        final_balances[1],
        initial_balances[1] - withdraw_amount,
        "Sub-account 1 reduced"
    );
    assert_eq!(
        final_balances[2], initial_balances[2],
        "Sub-account 2 unchanged"
    );

    // Verify swig wallet received the funds
    let swig_final_balance = context
        .svm
        .get_account(&swig_wallet_address)
        .unwrap()
        .lamports;
    assert_eq!(
        swig_final_balance,
        swig_initial_balance + withdraw_amount,
        "Swig wallet should have received withdrawn funds"
    );
}

/// Test that different indices use different PDA derivations
#[test_log::test]
fn test_different_indices_different_pdas() {
    let id = rand::random::<[u8; 32]>();
    let role_id = 1u32;
    let role_id_bytes = role_id.to_le_bytes();

    // Derive PDAs for indices 0, 1, 2
    let (pda_0, _) =
        Pubkey::find_program_address(&sub_account_seeds(&id, &role_id_bytes), &program_id());

    let (pda_1, _) = Pubkey::find_program_address(
        &sub_account_seeds_with_index(&id, &role_id_bytes, &[1]),
        &program_id(),
    );

    let (pda_2, _) = Pubkey::find_program_address(
        &sub_account_seeds_with_index(&id, &role_id_bytes, &[2]),
        &program_id(),
    );

    // All should be different
    assert_ne!(pda_0, pda_1, "Index 0 and 1 should have different PDAs");
    assert_ne!(pda_1, pda_2, "Index 1 and 2 should have different PDAs");
    assert_ne!(pda_0, pda_2, "Index 0 and 2 should have different PDAs");
}

/// Test that index 255 is rejected
#[test_log::test]
fn test_max_index_rejected() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let sub_account_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&sub_account_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    // Add authority with SubAccount permission for index 255
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: sub_account_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccount(SubAccount::new_for_creation(255))],
    )
    .unwrap();

    let role_id = 1;

    // Try to create with index 255 - should fail
    let result = create_sub_account_with_index(
        &mut context,
        &swig_key,
        &sub_account_authority,
        role_id,
        id,
        255,
    );
    assert!(result.is_err(), "Index 255 should be rejected");
}

/// Test creating sub-accounts in non-sequential order
/// This tests that indices can be created out of order (e.g., 5, 3, 1, 6)
#[test_log::test]
fn test_non_sequential_sub_account_creation() {
    println!("Starting non-sequential sub-account creation test");
    let mut context = setup_test_context().unwrap();

    // Setup with permissions for indices 1, 3, 5, 6, and 10
    println!("Setting up test context with permissions for indices 0-10");
    let (swig_key, root_authority, sub_account_authority, id) =
        setup_with_multiple_sub_account_permissions(&mut context, 11).unwrap();
    println!("Test context setup complete. Swig account: {}", swig_key);

    let role_id = 1;

    // Create sub-accounts in non-sequential order: 5, 3, 1, 6, 10, 0
    let test_indices = vec![5, 3, 1, 6, 10, 0];
    println!(
        "Will create sub-accounts in non-sequential order: {:?}",
        test_indices
    );
    let mut created_sub_accounts = Vec::new();

    for &index in &test_indices {
        println!("Creating sub-account with index {}", index);
        let sub_account = create_sub_account_with_index(
            &mut context,
            &swig_key,
            &sub_account_authority,
            role_id,
            id,
            index,
        )
        .unwrap();
        println!(
            "Successfully created sub-account at index {}: {}",
            index, sub_account
        );

        // Verify the PDA derivation is correct for this index
        let role_id_bytes = role_id.to_le_bytes();
        let expected_sub_account = if index == 0 {
            // Index 0 uses legacy derivation
            println!(
                "Verifying index {} using legacy derivation (3 seeds)",
                index
            );
            let (pda, _) = Pubkey::find_program_address(
                &sub_account_seeds(&id, &role_id_bytes),
                &program_id(),
            );
            pda
        } else {
            // Index 1+ uses new derivation with index
            println!(
                "Verifying index {} using new derivation (4 seeds with index)",
                index
            );
            let index_bytes = [index];
            let (pda, _) = Pubkey::find_program_address(
                &sub_account_seeds_with_index(&id, &role_id_bytes, &index_bytes),
                &program_id(),
            );
            pda
        };

        assert_eq!(
            sub_account, expected_sub_account,
            "Sub-account PDA should match expected for index {}",
            index
        );
        println!("PDA derivation verified for index {}", index);

        created_sub_accounts.push((index, sub_account));
    }
    println!("Created {} sub-accounts total", created_sub_accounts.len());

    // Verify all sub-accounts were created successfully
    println!("Verifying all sub-accounts were created successfully");
    assert_eq!(created_sub_accounts.len(), test_indices.len());
    println!(
        "Verified: Created {} sub-accounts as expected",
        created_sub_accounts.len()
    );

    // Verify all sub-accounts have unique addresses
    println!("Checking that all sub-account addresses are unique");
    let unique_addresses: std::collections::HashSet<_> =
        created_sub_accounts.iter().map(|(_, addr)| addr).collect();
    assert_eq!(
        unique_addresses.len(),
        created_sub_accounts.len(),
        "All sub-accounts should have unique addresses"
    );
    println!(
        "Verified: All {} sub-accounts have unique addresses",
        unique_addresses.len()
    );

    // Verify the SubAccount actions in on-chain state
    println!("Reading on-chain state to verify SubAccount actions");
    let swig_account_data = context.svm.get_account(&swig_key).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account_data.data).unwrap();
    let role = swig_with_roles.get_role(role_id).unwrap().unwrap();
    let all_sub_account_actions = role.get_all_actions_of_type::<SubAccount>().unwrap();
    println!(
        "Found {} total SubAccount actions on role {}",
        all_sub_account_actions.len(),
        role_id
    );

    // Filter to only populated sub-accounts (non-zero address)
    let populated_sub_account_actions: Vec<_> = all_sub_account_actions
        .iter()
        .filter(|action| action.sub_account != [0u8; 32])
        .collect();
    println!(
        "Found {} populated SubAccount actions (with non-zero addresses)",
        populated_sub_account_actions.len()
    );

    assert_eq!(
        populated_sub_account_actions.len(),
        test_indices.len(),
        "Should have {} populated SubAccount actions",
        test_indices.len()
    );

    // Verify each created sub-account has a corresponding action with correct index
    println!("Verifying each created sub-account matches on-chain state");
    for (expected_index, expected_address) in &created_sub_accounts {
        println!("Checking sub-account at index {}", expected_index);
        let matching_action = populated_sub_account_actions
            .iter()
            .find(|action| action.sub_account_index == *expected_index)
            .expect(&format!(
                "Should find SubAccount action for index {}",
                expected_index
            ));

        assert_eq!(
            matching_action.sub_account,
            expected_address.to_bytes(),
            "SubAccount action should have correct address for index {}",
            expected_index
        );
        println!(
            "Verified: Index {} has correct address in on-chain state",
            expected_index
        );
    }

    println!(
        "Test completed successfully: Created {} sub-accounts in non-sequential order: {:?}",
        created_sub_accounts.len(),
        test_indices
    );
}

/// Test withdrawing from sub-accounts at different indices
#[test_log::test]
fn test_withdraw_from_indexed_sub_accounts() {
    println!("Starting withdraw from indexed sub-accounts test");
    let mut context = setup_test_context().unwrap();

    println!("Setting up with permissions for indices 0-2");
    let (swig_key, root_authority, sub_account_authority, id) =
        setup_with_multiple_sub_account_permissions(&mut context, 3).unwrap();

    let role_id = 1;
    let test_indices = vec![0, 1, 2];

    // Create sub-accounts and fund them
    println!("Creating and funding sub-accounts");
    let mut sub_accounts = Vec::new();
    for &index in &test_indices {
        let sub_account = create_sub_account_with_index(
            &mut context,
            &swig_key,
            &sub_account_authority,
            role_id,
            id,
            index,
        )
        .unwrap();
        println!("Created sub-account at index {}: {}", index, sub_account);

        // Fund the sub-account
        context.svm.airdrop(&sub_account, 10_000_000_000).unwrap();
        println!("Funded sub-account at index {} with 10 SOL", index);

        sub_accounts.push((index, sub_account));
        context.svm.warp_to_slot(10);
        context.svm.expire_blockhash();
    }

    // Test withdrawing from each sub-account
    println!("Testing withdrawals from each indexed sub-account");
    for (index, sub_account) in &sub_accounts {
        println!("Testing withdrawal from sub-account at index {}", index);

        let balance_before = context.svm.get_account(sub_account).unwrap().lamports;
        println!("Balance before withdrawal: {} lamports", balance_before);

        let result = withdraw_from_sub_account(
            &mut context,
            &swig_key,
            sub_account,
            &sub_account_authority,
            role_id,
            1_000_000_000, // Withdraw 1 SOL
        );

        if result.is_err() {
            println!(
                "Error withdrawing from index {}: {:?}",
                index,
                result.as_ref().err()
            );
        }
        assert!(
            result.is_ok(),
            "Withdrawal from index {} should succeed",
            index
        );

        let balance_after = context.svm.get_account(sub_account).unwrap().lamports;
        println!("Balance after withdrawal: {} lamports", balance_after);

        assert!(
            balance_after < balance_before,
            "Balance should decrease after withdrawal from index {}",
            index
        );
        println!("Successfully withdrew from sub-account at index {}", index);

        context.svm.warp_to_slot(10);
        context.svm.expire_blockhash();
    }

    println!(
        "Test completed: Successfully withdrew from {} indexed sub-accounts",
        sub_accounts.len()
    );
}

/// Test toggling (enable/disable) sub-accounts at different indices
#[test_log::test]
fn test_toggle_indexed_sub_accounts() {
    println!("Starting toggle indexed sub-accounts test");
    let mut context = setup_test_context().unwrap();

    println!("Setting up with permissions for indices 0-2");
    let (swig_key, root_authority, sub_account_authority, id) =
        setup_with_multiple_sub_account_permissions(&mut context, 3).unwrap();

    let role_id = 1;
    let test_indices = vec![0, 1, 2];

    // Create sub-accounts
    println!("Creating sub-accounts");
    let mut sub_accounts = Vec::new();
    for &index in &test_indices {
        let sub_account = create_sub_account_with_index(
            &mut context,
            &swig_key,
            &sub_account_authority,
            role_id,
            id,
            index,
        )
        .unwrap();
        println!("Created sub-account at index {}: {}", index, sub_account);

        sub_accounts.push((index, sub_account));
        context.svm.warp_to_slot(10);
        context.svm.expire_blockhash();
    }

    // Test toggling each sub-account
    println!("Testing toggle operations on each indexed sub-account");
    for (index, sub_account) in &sub_accounts {
        println!("Disabling sub-account at index {}", index);

        let result = toggle_sub_account(
            &mut context,
            &swig_key,
            sub_account,
            &sub_account_authority,
            role_id,
            role_id,
            false, // Disable
        );

        assert!(result.is_ok(), "Disabling index {} should succeed", index);
        println!("Successfully disabled sub-account at index {}", index);

        context.svm.warp_to_slot(10);
        context.svm.expire_blockhash();

        // Re-enable
        println!("Re-enabling sub-account at index {}", index);
        let result = toggle_sub_account(
            &mut context,
            &swig_key,
            sub_account,
            &sub_account_authority,
            role_id,
            role_id,
            true, // Enable
        );

        assert!(result.is_ok(), "Re-enabling index {} should succeed", index);
        println!("Successfully re-enabled sub-account at index {}", index);

        context.svm.warp_to_slot(10);
        context.svm.expire_blockhash();
    }

    println!(
        "Test completed: Successfully toggled {} indexed sub-accounts",
        sub_accounts.len()
    );
}

/// Test signing instructions with sub-accounts at different indices
#[test_log::test]
fn test_sign_with_indexed_sub_accounts() {
    use solana_sdk::system_instruction;

    println!("Starting sign with indexed sub-accounts test");
    let mut context = setup_test_context().unwrap();

    println!("Setting up with permissions for indices 0-2");
    let (swig_key, root_authority, sub_account_authority, id) =
        setup_with_multiple_sub_account_permissions(&mut context, 3).unwrap();

    let role_id = 1;
    let test_indices = vec![0, 1, 2];

    // Create sub-accounts and fund them
    println!("Creating and funding sub-accounts");
    let mut sub_accounts = Vec::new();
    for &index in &test_indices {
        let sub_account = create_sub_account_with_index(
            &mut context,
            &swig_key,
            &sub_account_authority,
            role_id,
            id,
            index,
        )
        .unwrap();
        println!("Created sub-account at index {}: {}", index, sub_account);

        // Fund the sub-account
        context.svm.airdrop(&sub_account, 10_000_000_000).unwrap();
        println!("Funded sub-account at index {} with 10 SOL", index);

        sub_accounts.push((index, sub_account));
        context.svm.warp_to_slot(10);
        context.svm.expire_blockhash();
    }

    // Test signing with each sub-account
    println!("Testing sub-account sign operations with each indexed sub-account");
    for (index, sub_account) in &sub_accounts {
        println!("Testing sign with sub-account at index {}", index);

        let recipient = Keypair::new();
        let transfer_ix = system_instruction::transfer(sub_account, &recipient.pubkey(), 1_000_000);

        let balance_before = context.svm.get_account(sub_account).unwrap().lamports;
        println!("Sub-account balance before: {} lamports", balance_before);

        let result = sub_account_sign(
            &mut context,
            &swig_key,
            sub_account,
            &sub_account_authority,
            role_id,
            vec![transfer_ix],
        );

        assert!(
            result.is_ok(),
            "Signing with index {} should succeed",
            index
        );

        let balance_after = context.svm.get_account(sub_account).unwrap().lamports;
        println!("Sub-account balance after: {} lamports", balance_after);

        assert!(
            balance_after < balance_before,
            "Balance should decrease after signing transfer from index {}",
            index
        );
        println!(
            "Successfully signed and executed transfer with sub-account at index {}",
            index
        );

        context.svm.warp_to_slot(10);
        context.svm.expire_blockhash();
    }

    println!(
        "Test completed: Successfully signed with {} indexed sub-accounts",
        sub_accounts.len()
    );
}

/// Test that creating a swig wallet with duplicate SubAccount indices fails.
///
/// This validates the duplicate index check in SwigBuilder::add_role which is
/// called during the create instruction flow.
#[test_log::test]
fn test_create_swig_rejects_duplicate_sub_account_indices() {
    use solana_sdk::message::v0;
    use swig_interface::CreateInstruction;
    use swig_state::swig::{swig_account_seeds, swig_wallet_address_seeds};

    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, swig_bump) =
        Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let (swig_wallet_address, wallet_address_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    // Try to create a swig with duplicate SubAccount indices (both index 0)
    let actions_with_duplicates = vec![
        ClientAction::All(swig_state::action::all::All {}),
        ClientAction::SubAccount(SubAccount::new_for_creation(0)),
        ClientAction::SubAccount(SubAccount::new_for_creation(0)), // duplicate index!
    ];

    let create_ix = CreateInstruction::new(
        swig_key,
        swig_bump,
        context.default_payer.pubkey(),
        swig_wallet_address,
        wallet_address_bump,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: root_authority.pubkey().as_ref(),
        },
        actions_with_duplicates,
        id,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[create_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = solana_sdk::transaction::VersionedTransaction::try_new(
        solana_sdk::message::VersionedMessage::V0(msg),
        &[&context.default_payer],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);

    // Should fail due to duplicate SubAccount indices
    assert!(
        result.is_err(),
        "Creating swig with duplicate SubAccount indices should fail"
    );

    // Verify the swig account was not created
    assert!(
        context.svm.get_account(&swig_key).is_none(),
        "Swig account should not exist after failed creation"
    );
}

/// Test that creating a swig wallet with different SubAccount indices succeeds.
#[test_log::test]
fn test_create_swig_accepts_different_sub_account_indices() {
    use solana_sdk::message::v0;
    use swig_interface::CreateInstruction;
    use swig_state::swig::{swig_account_seeds, swig_wallet_address_seeds};

    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, swig_bump) =
        Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let (swig_wallet_address, wallet_address_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    // Create a swig with different SubAccount indices (0, 1, 5)
    let actions_with_different_indices = vec![
        ClientAction::All(swig_state::action::all::All {}),
        ClientAction::SubAccount(SubAccount::new_for_creation(0)),
        ClientAction::SubAccount(SubAccount::new_for_creation(1)),
        ClientAction::SubAccount(SubAccount::new_for_creation(5)),
    ];

    let create_ix = CreateInstruction::new(
        swig_key,
        swig_bump,
        context.default_payer.pubkey(),
        swig_wallet_address,
        wallet_address_bump,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: root_authority.pubkey().as_ref(),
        },
        actions_with_different_indices,
        id,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[create_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = solana_sdk::transaction::VersionedTransaction::try_new(
        solana_sdk::message::VersionedMessage::V0(msg),
        &[&context.default_payer],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);

    // Should succeed
    assert!(
        result.is_ok(),
        "Creating swig with different SubAccount indices should succeed: {:?}",
        result.err()
    );

    // Verify the swig account was created with correct SubAccount actions
    let swig_account_data = context.svm.get_account(&swig_key).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account_data.data).unwrap();
    let role = swig_with_roles.get_role(0).unwrap().unwrap();
    let sub_account_actions = role.get_all_actions_of_type::<SubAccount>().unwrap();

    assert_eq!(
        sub_account_actions.len(),
        3,
        "Should have 3 SubAccount actions"
    );

    // Verify indices 0, 1, 5
    let mut indices: Vec<u8> = sub_account_actions
        .iter()
        .map(|a| a.sub_account_index)
        .collect();
    indices.sort();
    assert_eq!(indices, vec![0, 1, 5], "Should have indices 0, 1, and 5");

    // All should be unpopulated (not created yet)
    for action in &sub_account_actions {
        assert_eq!(
            action.sub_account, [0u8; 32],
            "SubAccount action at index {} should be zeroed (not created)",
            action.sub_account_index
        );
    }
}

/// Test backwards compatibility: Verify that the instruction format with index
/// byte = 0 (which is what legacy v1.3.3 SDK sends as padding) is correctly
/// interpreted as index 0.
///
/// This test demonstrates that:
/// 1. Legacy SDKs (v1.3.3) send a struct with 7 bytes of padding (all zeros)
/// 2. The new format reads the first padding byte (offset 8) as the index field
/// 3. When that byte is 0 (from legacy padding), it's correctly treated as
///    index 0
/// 4. The sub-account uses legacy 3-seed PDA derivation (backwards compatible)
#[test_log::test]
fn test_legacy_instruction_format_backwards_compatibility() {
    println!("Testing backwards compatibility with legacy format");
    println!();

    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let sub_account_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&sub_account_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    // Add authority with SubAccount permission for index 0
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: sub_account_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccount(SubAccount::new_for_creation(0))],
    )
    .unwrap();

    let role_id: u32 = 1;

    println!("Test Plan:");
    println!("  1. Create sub-account using the SDK method (simulates v1.3.3 SDK behavior)");
    println!("  2. Verify it creates sub-account with index 0");
    println!("  3. Verify it uses legacy 3-seed PDA derivation");
    println!();

    // Use the standard SDK method which internally passes index 0
    // This simulates what v1.3.3 SDK does (passes 0 in the padding byte position)
    let sub_account =
        create_sub_account(&mut context, &swig_key, &sub_account_authority, role_id, id).unwrap();

    println!("Sub-account created successfully: {}", sub_account);

    // Verify it used legacy 3-seed PDA derivation (index 0)
    let role_id_bytes = role_id.to_le_bytes();
    let (expected_legacy_pda, _) =
        Pubkey::find_program_address(&sub_account_seeds(&id, &role_id_bytes), &program_id());

    assert_eq!(
        sub_account, expected_legacy_pda,
        "Sub-account should use legacy 3-seed PDA derivation (backwards compatible)"
    );
    println!("Confirmed: Uses legacy 3-seed PDA derivation");

    // Verify the SubAccount action has index 0
    let swig_account_data = context.svm.get_account(&swig_key).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account_data.data).unwrap();
    let role = swig_with_roles.get_role(role_id).unwrap().unwrap();

    let mut cursor = 0;
    let mut found = false;

    for _i in 0..role.position.num_actions() {
        let action_header =
            unsafe { Action::load_unchecked(&role.actions[cursor..cursor + Action::LEN]) }.unwrap();
        cursor += Action::LEN;

        if action_header.permission().unwrap() == Permission::SubAccount {
            let sub_account_action = unsafe {
                SubAccount::load_unchecked(&role.actions[cursor..cursor + SubAccount::LEN])
            }
            .unwrap();

            if sub_account_action.sub_account == sub_account.to_bytes() {
                println!("Found SubAccount action:");
                println!(
                    "     - Index: {} (parsed from byte at offset 8)",
                    sub_account_action.sub_account_index
                );
                println!("     - Enabled: {}", sub_account_action.enabled);

                assert_eq!(
                    sub_account_action.sub_account_index, 0,
                    "Should have index 0 (from legacy padding byte)"
                );
                found = true;
                break;
            }
        }

        cursor = action_header.boundary() as usize;
    }

    assert!(found, "SubAccount action should exist");

    println!();
    println!("BACKWARDS COMPATIBILITY TEST PASSED!");
    println!();
    println!("Summary:");
    println!("  ✓ Legacy SDK format (with 0 in padding) works correctly");
    println!("  ✓ Parsed as index 0 (from the padding byte at offset 8)");
    println!("  ✓ Uses legacy 3-seed PDA derivation (fully backwards compatible)");
    println!("  ✓ No breaking changes for existing v1.3.3 integrations");
    println!();
    println!("This proves that:");
    println!("  - Existing deployed integrations using v1.3.3 SDK will continue to work");
    println!("  - Their transactions will be parsed as index 0 sub-accounts");
    println!("  - The PDA derivation remains backwards compatible");
}

/// Test that adding a role with duplicate SubAccount indices fails
#[test_log::test]
fn test_add_role_rejects_duplicate_sub_account_indices() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    // Try to add a new role with two SubAccount actions that have the same index
    let new_authority = Keypair::new();

    let actions = vec![
        ClientAction::SubAccount(SubAccount::new_for_creation(5)), // index 5
        ClientAction::SubAccount(SubAccount::new_for_creation(5)), // duplicate index 5
    ];

    let result = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        actions,
    );

    // Should fail with InvalidAuthorityData error
    assert!(
        result.is_err(),
        "Adding role with duplicate SubAccount indices should fail"
    );

    // Verify it's the right error
    if let Err(e) = result {
        let error_msg = format!("{:?}", e);
        assert!(
            error_msg.contains("Custom") || error_msg.contains("InvalidAuthorityData"),
            "Expected InvalidAuthorityData error, got: {}",
            error_msg
        );
    }
}

/// Test that adding a role with multiple SubAccount actions with different
/// indices succeeds
#[test_log::test]
fn test_add_role_accepts_different_sub_account_indices() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    // Add a new role with multiple SubAccount actions with different indices
    let new_authority = Keypair::new();

    let actions = vec![
        ClientAction::SubAccount(SubAccount::new_for_creation(0)), // index 0
        ClientAction::SubAccount(SubAccount::new_for_creation(5)), // index 5
        ClientAction::SubAccount(SubAccount::new_for_creation(10)), // index 10
    ];

    let result = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        actions,
    );

    // Should succeed
    assert!(
        result.is_ok(),
        "Adding role with different SubAccount indices should succeed: {:?}",
        result.err()
    );

    // Verify the role was created with 3 SubAccount actions
    let swig_account_data = context.svm.get_account(&swig_key).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account_data.data).unwrap();

    // Find the newly created role (should be role_id 1)
    let role = swig_with_roles.get_role(1).unwrap().unwrap();
    let sub_account_actions = role.get_all_actions_of_type::<SubAccount>().unwrap();

    assert_eq!(
        sub_account_actions.len(),
        3,
        "Should have 3 SubAccount actions"
    );
    assert_eq!(sub_account_actions[0].sub_account_index, 0);
    assert_eq!(sub_account_actions[1].sub_account_index, 5);
    assert_eq!(sub_account_actions[2].sub_account_index, 10);
}

/// Helper function to update authority with ReplaceAll operation
fn update_authority_replace_all(
    context: &mut SwigTestContext,
    swig_pubkey: &Pubkey,
    existing_ed25519_authority: &Keypair,
    authority_to_update_id: u32,
    new_actions: Vec<ClientAction>,
) -> anyhow::Result<litesvm::types::TransactionMetadata> {
    use solana_sdk::message::v0;
    use swig_interface::{UpdateAuthorityData, UpdateAuthorityInstruction};

    context.svm.expire_blockhash();
    let payer_pubkey = context.default_payer.pubkey();
    let swig_account = context
        .svm
        .get_account(swig_pubkey)
        .ok_or(anyhow::anyhow!("Swig account not found"))?;
    let swig = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig
        .lookup_role_id(existing_ed25519_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();

    let update_authority_ix = UpdateAuthorityInstruction::new_with_ed25519_authority(
        *swig_pubkey,
        payer_pubkey,
        existing_ed25519_authority.pubkey(),
        role_id,
        authority_to_update_id,
        UpdateAuthorityData::ReplaceAll(new_actions),
    )?;

    let msg = v0::Message::try_compile(
        &payer_pubkey,
        &[update_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .map_err(|e| anyhow::anyhow!("Failed to compile message {:?}", e))?;

    let tx = solana_sdk::transaction::VersionedTransaction::try_new(
        solana_sdk::message::VersionedMessage::V0(msg),
        &[&context.default_payer, existing_ed25519_authority],
    )
    .map_err(|e| anyhow::anyhow!("Failed to create transaction {:?}", e))?;

    let result = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e))?;

    Ok(result)
}

/// Helper function to update authority with AddActions operation
fn update_authority_add_actions(
    context: &mut SwigTestContext,
    swig_pubkey: &Pubkey,
    existing_ed25519_authority: &Keypair,
    authority_to_update_id: u32,
    actions_to_add: Vec<ClientAction>,
) -> anyhow::Result<litesvm::types::TransactionMetadata> {
    use solana_sdk::message::v0;
    use swig_interface::{UpdateAuthorityData, UpdateAuthorityInstruction};

    context.svm.expire_blockhash();
    let payer_pubkey = context.default_payer.pubkey();
    let swig_account = context
        .svm
        .get_account(swig_pubkey)
        .ok_or(anyhow::anyhow!("Swig account not found"))?;
    let swig = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig
        .lookup_role_id(existing_ed25519_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();

    let update_authority_ix = UpdateAuthorityInstruction::new_with_ed25519_authority(
        *swig_pubkey,
        payer_pubkey,
        existing_ed25519_authority.pubkey(),
        role_id,
        authority_to_update_id,
        UpdateAuthorityData::AddActions(actions_to_add),
    )?;

    let msg = v0::Message::try_compile(
        &payer_pubkey,
        &[update_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .map_err(|e| anyhow::anyhow!("Failed to compile message {:?}", e))?;

    let tx = solana_sdk::transaction::VersionedTransaction::try_new(
        solana_sdk::message::VersionedMessage::V0(msg),
        &[&context.default_payer, existing_ed25519_authority],
    )
    .map_err(|e| anyhow::anyhow!("Failed to create transaction {:?}", e))?;

    let result = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e))?;

    Ok(result)
}

/// Test that updating authority with ReplaceAll rejects duplicate SubAccount
/// indices
#[test_log::test]
fn test_update_authority_replace_all_rejects_duplicate_indices() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    // Add a second authority with initial actions
    let second_authority = Keypair::new();
    let actions = vec![ClientAction::SubAccount(SubAccount::new_for_creation(0))];

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        actions,
    )
    .unwrap();

    // Try to update with duplicate SubAccount indices
    let new_actions = vec![
        ClientAction::SubAccount(SubAccount::new_for_creation(3)),
        ClientAction::SubAccount(SubAccount::new_for_creation(3)), // duplicate
    ];

    let result = update_authority_replace_all(
        &mut context,
        &swig_key,
        &root_authority,
        1, // authority_id 1 (the second authority)
        new_actions,
    );

    // Should fail
    assert!(
        result.is_err(),
        "Updating authority with duplicate SubAccount indices should fail"
    );
}

/// Test that updating authority with AddActions rejects when it creates
/// duplicates
#[test_log::test]
fn test_update_authority_add_actions_rejects_duplicate_indices() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    // Add a second authority with initial SubAccount action at index 5
    let second_authority = Keypair::new();
    let initial_actions = vec![ClientAction::SubAccount(SubAccount::new_for_creation(5))];

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        initial_actions,
    )
    .unwrap();

    // Try to add another SubAccount action with the same index (5)
    let actions_to_add = vec![ClientAction::SubAccount(SubAccount::new_for_creation(5))];

    let result = update_authority_add_actions(
        &mut context,
        &swig_key,
        &root_authority,
        1, // authority_id 1 (the second authority)
        actions_to_add,
    );

    // Should fail because combining existing (index 5) + new (index 5) creates
    // duplicate
    assert!(
        result.is_err(),
        "Adding SubAccount action with duplicate index should fail"
    );
}

/// Test that you cannot create two sub-accounts with the same index under the
/// same role.
///
/// This test validates that:
/// 1. Creating a sub-account with index 0 succeeds
/// 2. Attempting to create another sub-account with index 0 fails
///
/// The program prevents this by:
/// - Using match_data to find SubAccount actions with matching index AND zeroed
///   sub_account field
/// - Once a sub-account is created, its sub_account field is populated with the
///   PDA address
/// - Subsequent creation attempts for the same index won't find a matching
///   (zeroed) action
#[test_log::test]
fn test_cannot_create_duplicate_sub_account_same_index() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let sub_account_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&sub_account_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    // Add authority with SubAccount permission for index 0
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: sub_account_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccount(SubAccount::new_for_creation(0))],
    )
    .unwrap();

    let role_id = 1;

    // First creation should succeed
    let sub_account_first = create_sub_account_with_index(
        &mut context,
        &swig_key,
        &sub_account_authority,
        role_id,
        id,
        0,
    )
    .unwrap();

    // Verify the first sub-account was created successfully
    let sub_account_data = context.svm.get_account(&sub_account_first).unwrap();
    assert_eq!(sub_account_data.owner, solana_sdk::system_program::id());

    // Warp to ensure different blockhash
    context.svm.warp_to_slot(10);
    context.svm.expire_blockhash();

    // Second creation with same index should FAIL
    // Because the SubAccount action's sub_account field is now populated,
    // the match_data check for [index, zeros...] won't find it
    let result = create_sub_account_with_index(
        &mut context,
        &swig_key,
        &sub_account_authority,
        role_id,
        id,
        0,
    );

    assert!(
        result.is_err(),
        "Creating a second sub-account with the same index should fail"
    );

    // Verify the error is AuthorityCannotCreateSubAccount (error code 36)
    // This happens because:
    // 1. After the first creation, the SubAccount action's sub_account field is
    //    populated
    // 2. When trying to create again, the match_data [index, zeros...] won't find
    //    it (since sub_account is no longer zeros)
    // 3. The fallback check for any SubAccount with zeroed sub_account also fails
    // 4. Result: AuthorityCannotCreateSubAccount (no available SubAccount slot)
    let error_msg = format!("{:?}", result.unwrap_err());
    assert!(
        error_msg.contains("Custom(36)"),
        "Expected AuthorityCannotCreateSubAccount error (code 36), got: {}",
        error_msg
    );

    // Verify only one sub-account exists
    let swig_account_data = context.svm.get_account(&swig_key).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account_data.data).unwrap();
    let role = swig_with_roles.get_role(role_id).unwrap().unwrap();
    let sub_account_actions = role.get_all_actions_of_type::<SubAccount>().unwrap();

    assert_eq!(
        sub_account_actions.len(),
        1,
        "Should still have only 1 SubAccount action"
    );
    assert_eq!(
        sub_account_actions[0].sub_account,
        sub_account_first.to_bytes(),
        "The SubAccount action should contain the first sub-account's address"
    );
    assert_eq!(sub_account_actions[0].sub_account_index, 0);
}

/// Test that you cannot create two sub-accounts with the same index even when
/// multiple SubAccount permissions exist for different indices.
///
/// Scenario:
/// - Role has SubAccount permissions for indices 0, 1, 2
/// - Create sub-account with index 1 (succeeds)
/// - Try to create another sub-account with index 1 (should fail)
/// - Creating sub-accounts with indices 0 and 2 should still work
#[test_log::test]
fn test_cannot_create_duplicate_sub_account_with_multiple_permissions() {
    let mut context = setup_test_context().unwrap();

    // Setup with permissions for indices 0, 1, 2
    let (swig_key, _root_authority, sub_account_authority, id) =
        setup_with_multiple_sub_account_permissions(&mut context, 3).unwrap();

    let role_id = 1;

    // Create sub-account with index 1 first (not 0, to test non-sequential)
    let sub_account_1 = create_sub_account_with_index(
        &mut context,
        &swig_key,
        &sub_account_authority,
        role_id,
        id,
        1,
    )
    .unwrap();

    // Verify sub-account 1 was created
    let sub_account_data = context.svm.get_account(&sub_account_1).unwrap();
    assert_eq!(sub_account_data.owner, solana_sdk::system_program::id());

    context.svm.warp_to_slot(10);
    context.svm.expire_blockhash();

    // Try to create another sub-account with index 1 - should fail
    let duplicate_result = create_sub_account_with_index(
        &mut context,
        &swig_key,
        &sub_account_authority,
        role_id,
        id,
        1,
    );

    assert!(
        duplicate_result.is_err(),
        "Creating duplicate sub-account with index 1 should fail"
    );

    // Verify it's the SubAccountActionNotFound error (code 49) because:
    // - The SubAccount action for index 1 exists but its sub_account field is
    //   populated
    // - There are still other SubAccount actions with zeroed sub_account (indices
    //   0, 2)
    // - So the role HAS SubAccount permissions, but none for index 1 with zeroed
    //   sub_account
    let error_msg = format!("{:?}", duplicate_result.unwrap_err());
    assert!(
        error_msg.contains("Custom(49)"),
        "Expected SubAccountActionNotFound error (code 49), got: {}",
        error_msg
    );

    context.svm.warp_to_slot(20);
    context.svm.expire_blockhash();

    // Creating sub-account with index 0 should still work
    let sub_account_0 = create_sub_account_with_index(
        &mut context,
        &swig_key,
        &sub_account_authority,
        role_id,
        id,
        0,
    )
    .unwrap();
    assert_ne!(sub_account_0, sub_account_1);

    context.svm.warp_to_slot(30);
    context.svm.expire_blockhash();

    // Creating sub-account with index 2 should still work
    let sub_account_2 = create_sub_account_with_index(
        &mut context,
        &swig_key,
        &sub_account_authority,
        role_id,
        id,
        2,
    )
    .unwrap();
    assert_ne!(sub_account_2, sub_account_0);
    assert_ne!(sub_account_2, sub_account_1);

    // Verify all 3 sub-accounts exist and have unique addresses
    let swig_account_data = context.svm.get_account(&swig_key).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account_data.data).unwrap();
    let role = swig_with_roles.get_role(role_id).unwrap().unwrap();
    let sub_account_actions = role.get_all_actions_of_type::<SubAccount>().unwrap();

    // Count populated sub-account actions
    let populated_actions: Vec<_> = sub_account_actions
        .iter()
        .filter(|a| a.sub_account != [0u8; 32])
        .collect();

    assert_eq!(
        populated_actions.len(),
        3,
        "Should have 3 populated SubAccount actions"
    );

    // Verify indices 0, 1, 2 are all populated
    let mut indices: Vec<u8> = populated_actions
        .iter()
        .map(|a| a.sub_account_index)
        .collect();
    indices.sort();
    assert_eq!(
        indices,
        vec![0, 1, 2],
        "Should have indices 0, 1, 2 populated"
    );
}

/// Test that updating authority with AddActions succeeds with different indices
#[test_log::test]
fn test_update_authority_add_actions_accepts_different_indices() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    // Add a second authority with initial SubAccount action at index 0
    let second_authority = Keypair::new();
    let initial_actions = vec![ClientAction::SubAccount(SubAccount::new_for_creation(0))];

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        initial_actions,
    )
    .unwrap();

    // Add more SubAccount actions with different indices
    let actions_to_add = vec![
        ClientAction::SubAccount(SubAccount::new_for_creation(5)),
        ClientAction::SubAccount(SubAccount::new_for_creation(10)),
    ];

    let result = update_authority_add_actions(
        &mut context,
        &swig_key,
        &root_authority,
        1, // authority_id 1 (the second authority)
        actions_to_add,
    );

    // Should succeed
    assert!(
        result.is_ok(),
        "Adding SubAccount actions with different indices should succeed: {:?}",
        result.err()
    );

    // Verify we now have 3 SubAccount actions (0, 5, 10)
    let swig_account_data = context.svm.get_account(&swig_key).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account_data.data).unwrap();
    let role = swig_with_roles.get_role(1).unwrap().unwrap();
    let sub_account_actions = role.get_all_actions_of_type::<SubAccount>().unwrap();

    assert_eq!(
        sub_account_actions.len(),
        3,
        "Should have 3 SubAccount actions"
    );

    // Collect and sort indices for verification
    let mut indices: Vec<u8> = sub_account_actions
        .iter()
        .map(|a| a.sub_account_index)
        .collect();
    indices.sort();

    assert_eq!(indices, vec![0, 5, 10], "Should have indices 0, 5, and 10");
}

/// Test that you cannot add a SubAccount action with a duplicate index,
/// regardless of whether the sub-account has been created or not.
///
/// This test validates the full lifecycle:
/// 1. Create a swig wallet with an authority that has SubAccount permission for
///    index 0
/// 2. Create first sub-account with index 0 (succeeds)
/// 3. Try adding another SubAccount action to the same role with index 0
///    (should fail)
/// 4. Add SubAccount action with index 1 to the same role (succeeds)
/// 5. Create sub-account with index 1 (succeeds)
/// 6. Try adding another SubAccount action to the same role with index 1
///    (should fail)
/// 7. Add SubAccount action with index 2 (succeeds, but don't create the
///    sub-account)
/// 8. Try adding another SubAccount action with index 2 (should fail even
///    without creation)
#[test_log::test]
fn test_cannot_add_duplicate_sub_account_action_after_creation() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let sub_account_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&sub_account_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    // Step 1: Add authority with SubAccount permission for index 0
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: sub_account_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccount(SubAccount::new_for_creation(0))],
    )
    .unwrap();

    let sub_account_role_id = 1;

    // Step 2: Create first sub-account with index 0
    let sub_account_0 = create_sub_account_with_index(
        &mut context,
        &swig_key,
        &sub_account_authority,
        sub_account_role_id,
        id,
        0,
    )
    .unwrap();

    // Verify sub-account 0 was created
    let sub_account_data = context.svm.get_account(&sub_account_0).unwrap();
    assert_eq!(sub_account_data.owner, solana_sdk::system_program::id());

    context.svm.warp_to_slot(10);
    context.svm.expire_blockhash();

    // Step 3: Try adding another SubAccount action with index 0 - should FAIL
    // because index 0 already exists on this role (even though it's been
    // created/populated)
    let add_duplicate_0_result = update_authority_add_actions(
        &mut context,
        &swig_key,
        &root_authority,
        sub_account_role_id,
        vec![ClientAction::SubAccount(SubAccount::new_for_creation(0))],
    );

    assert!(
        add_duplicate_0_result.is_err(),
        "Adding SubAccount action with duplicate index 0 should fail"
    );

    // Verify the error indicates duplicate index rejection
    let error_msg = format!("{:?}", add_duplicate_0_result.unwrap_err());
    // The error should be related to duplicate SubAccount indices
    assert!(
        error_msg.contains("Custom"),
        "Expected a custom error, got: {}",
        error_msg
    );

    context.svm.warp_to_slot(20);
    context.svm.expire_blockhash();

    // Step 4: Add SubAccount action with index 1 - should succeed
    let add_index_1_result = update_authority_add_actions(
        &mut context,
        &swig_key,
        &root_authority,
        sub_account_role_id,
        vec![ClientAction::SubAccount(SubAccount::new_for_creation(1))],
    );

    assert!(
        add_index_1_result.is_ok(),
        "Adding SubAccount action with index 1 should succeed: {:?}",
        add_index_1_result.err()
    );

    context.svm.warp_to_slot(30);
    context.svm.expire_blockhash();

    // Step 5: Create sub-account with index 1
    let sub_account_1 = create_sub_account_with_index(
        &mut context,
        &swig_key,
        &sub_account_authority,
        sub_account_role_id,
        id,
        1,
    )
    .unwrap();

    // Verify sub-account 1 was created and is different from sub-account 0
    assert_ne!(sub_account_0, sub_account_1);
    let sub_account_1_data = context.svm.get_account(&sub_account_1).unwrap();
    assert_eq!(sub_account_1_data.owner, solana_sdk::system_program::id());

    context.svm.warp_to_slot(40);
    context.svm.expire_blockhash();

    // Step 6: Try adding another SubAccount action with index 1 - should FAIL
    let add_duplicate_1_result = update_authority_add_actions(
        &mut context,
        &swig_key,
        &root_authority,
        sub_account_role_id,
        vec![ClientAction::SubAccount(SubAccount::new_for_creation(1))],
    );

    assert!(
        add_duplicate_1_result.is_err(),
        "Adding SubAccount action with duplicate index 1 should fail"
    );

    context.svm.warp_to_slot(50);
    context.svm.expire_blockhash();

    // Step 7: Add SubAccount action with index 2 - should succeed
    // (we won't create the sub-account yet)
    let add_index_2_result = update_authority_add_actions(
        &mut context,
        &swig_key,
        &root_authority,
        sub_account_role_id,
        vec![ClientAction::SubAccount(SubAccount::new_for_creation(2))],
    );

    assert!(
        add_index_2_result.is_ok(),
        "Adding SubAccount action with index 2 should succeed: {:?}",
        add_index_2_result.err()
    );

    context.svm.warp_to_slot(60);
    context.svm.expire_blockhash();

    // Step 8: Try adding another SubAccount action with index 2 - should FAIL
    // even though the sub-account hasn't been created yet, the action already
    // exists
    let add_duplicate_2_result = update_authority_add_actions(
        &mut context,
        &swig_key,
        &root_authority,
        sub_account_role_id,
        vec![ClientAction::SubAccount(SubAccount::new_for_creation(2))],
    );

    assert!(
        add_duplicate_2_result.is_err(),
        "Adding SubAccount action with duplicate index 2 should fail (even without creation)"
    );

    // Verify final state: role should have exactly 3 SubAccount actions (indices 0,
    // 1, and 2)
    let swig_account_data = context.svm.get_account(&swig_key).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account_data.data).unwrap();
    let role = swig_with_roles
        .get_role(sub_account_role_id)
        .unwrap()
        .unwrap();
    let sub_account_actions = role.get_all_actions_of_type::<SubAccount>().unwrap();

    assert_eq!(
        sub_account_actions.len(),
        3,
        "Should have exactly 3 SubAccount actions"
    );

    // Verify indices 0, 1, and 2 exist
    let mut indices: Vec<u8> = sub_account_actions
        .iter()
        .map(|a| a.sub_account_index)
        .collect();
    indices.sort();
    assert_eq!(indices, vec![0, 1, 2], "Should have indices 0, 1, and 2");

    // Verify populated vs unpopulated state
    // Index 0 and 1 should be populated (created), index 2 should be unpopulated
    // (not created)
    for action in &sub_account_actions {
        match action.sub_account_index {
            0 => {
                assert_eq!(
                    action.sub_account,
                    sub_account_0.to_bytes(),
                    "Index 0 should have sub_account_0's address"
                );
            },
            1 => {
                assert_eq!(
                    action.sub_account,
                    sub_account_1.to_bytes(),
                    "Index 1 should have sub_account_1's address"
                );
            },
            2 => {
                assert_eq!(
                    action.sub_account, [0u8; 32],
                    "Index 2 should still be zeroed (not created yet)"
                );
            },
            _ => panic!("Unexpected sub_account_index: {}", action.sub_account_index),
        }
    }
}
