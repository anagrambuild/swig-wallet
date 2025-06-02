#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{swig, AuthorityConfig, ClientAction};
use swig_state_x::{
    action::{
        all::All, manage_authority::ManageAuthority, program::Program, sol_limit::SolLimit,
        Action, Permission,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, SwigWithRoles},
    IntoBytes, Transmutable,
};

use swig::actions::remove_actions_from_role_v1::RemoveActionsFromRoleV1Args;

fn build_remove_actions_from_role_ix_data(
    acting_role_id: u32,
    target_role_id: u32,
    indices: Vec<u16>,
) -> Vec<u8> {
    let args = RemoveActionsFromRoleV1Args::new(
        acting_role_id,
        target_role_id,
        indices.len() as u16,
    );
    
    let mut ix_data = Vec::new();
    ix_data.extend_from_slice(args.into_bytes().unwrap());
    
    // Add action indices as u16 little-endian bytes
    for index in indices {
        ix_data.extend_from_slice(&index.to_le_bytes());
    }
    
    // Add authority payload for Ed25519 - single byte indicating the account index
    // of the authority that needs to sign
    ix_data.push(3); // Authority will be at index 3
    
    ix_data
}

#[test_log::test]
fn test_remove_actions_from_role_success() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    
    // Create a second authority with multiple actions
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    
    // Add second authority with multiple actions: SolLimit, Program, another SolLimit
    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::SolLimit(SolLimit { amount: 1_000_000 }),
            ClientAction::Program(Program { program_id: [4; 32] }),
            ClientAction::SolLimit(SolLimit { amount: 5_000_000 }),
        ],
    )
    .unwrap();
    
    // Verify the role initially has 3 actions
    let swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();
    assert_eq!(role.position.num_actions(), 3);
    let all_actions = role.get_all_actions().unwrap();
    assert_eq!(all_actions.len(), 3);
    
    // Remove the middle action (index 1, which is the Program action)
    let remove_indices = vec![1]; // Remove Program action
    let ix_data = build_remove_actions_from_role_ix_data(0, 1, remove_indices);
    
    let accounts = vec![
        solana_sdk::instruction::AccountMeta::new(swig_pubkey, false),
        solana_sdk::instruction::AccountMeta::new(swig_authority.pubkey(), true),
        solana_sdk::instruction::AccountMeta::new_readonly(pinocchio_system::ID.into(), false),
        solana_sdk::instruction::AccountMeta::new_readonly(swig_authority.pubkey(), true), // Authority signer
    ];
    
    let ix = solana_sdk::instruction::Instruction {
        program_id: program_id(),
        accounts,
        data: ix_data,
    };
    
    let msg = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(10000000),
            ix,
        ],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[swig_authority.insecure_clone()],
    )
    .unwrap();
    
    let result = context.svm.send_transaction(tx);
    assert!(result.is_ok(), "Failed to remove actions from role: {:?}", result);
    
    // Verify the role now has 2 actions (SolLimit and SolLimit)
    let swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();
    
    // Should have 2 actions now (two SolLimit actions)
    assert_eq!(role.position.num_actions(), 2);
    
    // Verify with get_all_actions
    let all_actions = role.get_all_actions().unwrap();
    assert_eq!(all_actions.len(), 2, "Should have exactly 2 actions after removal");
    
    // Verify the remaining actions are both SolLimit actions
    for action in all_actions.iter() {
        assert_eq!(action.permission().unwrap(), Permission::SolLimit);
    }
}

#[test_log::test]
fn test_remove_multiple_actions_from_role_success() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    
    // Create a second authority with multiple actions
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    
    // Add second authority with 4 actions: SolLimit, Program, SolLimit, Program
    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::SolLimit(SolLimit { amount: 1_000_000 }),
            ClientAction::Program(Program { program_id: [4; 32] }),
            ClientAction::SolLimit(SolLimit { amount: 5_000_000 }),
            ClientAction::Program(Program { program_id: [5; 32] }),
        ],
    )
    .unwrap();
    
    // Verify the role initially has 4 actions
    let swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();
    assert_eq!(role.position.num_actions(), 4);
    
    // Debug: Check what actions we have before removal
    let all_actions_before = role.get_all_actions().unwrap();
    println!("Before removal: {} actions", all_actions_before.len());
    for (i, action) in all_actions_before.iter().enumerate() {
        println!("Action {}: {:?}", i, action.permission());
    }
    
    // Remove multiple actions (indices 1 and 3, both Program actions)
    let remove_indices = vec![1, 3]; // Remove both Program actions
    let ix_data = build_remove_actions_from_role_ix_data(0, 1, remove_indices);
    
    let accounts = vec![
        solana_sdk::instruction::AccountMeta::new(swig_pubkey, false),
        solana_sdk::instruction::AccountMeta::new(swig_authority.pubkey(), true),
        solana_sdk::instruction::AccountMeta::new_readonly(pinocchio_system::ID.into(), false),
        solana_sdk::instruction::AccountMeta::new_readonly(swig_authority.pubkey(), true), // Authority signer
    ];
    
    let ix = solana_sdk::instruction::Instruction {
        program_id: program_id(),
        accounts,
        data: ix_data,
    };
    
    let msg = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(10000000),
            ix,
        ],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[swig_authority.insecure_clone()],
    )
    .unwrap();
    
    let result = context.svm.send_transaction(tx);
    assert!(result.is_ok(), "Failed to remove multiple actions from role: {:?}", result);
    
    // Verify the role now has 2 actions (both SolLimit actions)
    let swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();
    
    // Debug: Check what actions we have after removal
    println!("After removal: position.num_actions() = {}", role.position.num_actions());
    let all_actions = role.get_all_actions().unwrap();
    println!("After removal: get_all_actions().len() = {}", all_actions.len());
    for (i, action) in all_actions.iter().enumerate() {
        println!("Action {}: {:?}, boundary: {}", i, action.permission(), action.boundary());
    }
    
    // Manual debug parsing to see what's in the actions data
    println!("\nDebug: Manual action parsing after removal:");
    let actions_data = role.actions;
    println!("Total actions data length: {}", actions_data.len());
    let mut cursor = 0;
    let mut idx = 0;
    while cursor < actions_data.len() && idx < 5 { // Limit to 5 to avoid infinite loop
        if cursor + 8 > actions_data.len() {
            println!("Not enough data for action header at cursor {}", cursor);
            break;
        }
        let action_type = u16::from_le_bytes([actions_data[cursor], actions_data[cursor + 1]]);
        let action_len = u16::from_le_bytes([actions_data[cursor + 2], actions_data[cursor + 3]]);
        let action_boundary = u32::from_le_bytes([
            actions_data[cursor + 4],
            actions_data[cursor + 5],
            actions_data[cursor + 6],
            actions_data[cursor + 7],
        ]);
        println!("Action {}: type={}, len={}, boundary={}, cursor={}", idx, action_type, action_len, action_boundary, cursor);
        
        if action_boundary as usize <= cursor || action_boundary as usize > actions_data.len() {
            println!("Invalid boundary - would go to {} but actions_data.len() is {}", action_boundary, actions_data.len());
            break;
        }
        
        cursor = action_boundary as usize;
        idx += 1;
    }
    
    // Should have 2 actions now (both SolLimit actions)
    assert_eq!(role.position.num_actions(), 2);
    
    // Verify with get_all_actions
    assert_eq!(all_actions.len(), 2, "Should have exactly 2 actions after removal");
    
    // Verify the remaining actions are both SolLimit actions
    for action in all_actions.iter() {
        assert_eq!(action.permission().unwrap(), Permission::SolLimit);
    }
}

#[test_log::test]
fn test_remove_actions_from_role_no_permission() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    
    // Create a second authority without ManageAuthority permission
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    
    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1_000_000 })], // No ManageAuthority or All
    )
    .unwrap();
    
    // Try to remove actions using the second authority which doesn't have permission
    let remove_indices = vec![0]; // Try to remove first action
    let ix_data = build_remove_actions_from_role_ix_data(1, 0, remove_indices); // Use role 1 (second_authority) to modify role 0
    
    let accounts = vec![
        solana_sdk::instruction::AccountMeta::new(swig_pubkey, false),
        solana_sdk::instruction::AccountMeta::new(second_authority.pubkey(), true),
        solana_sdk::instruction::AccountMeta::new_readonly(pinocchio_system::ID.into(), false),
        solana_sdk::instruction::AccountMeta::new_readonly(second_authority.pubkey(), true), // Authority signer
    ];
    
    let ix = solana_sdk::instruction::Instruction {
        program_id: program_id(),
        accounts,
        data: ix_data,
    };
    
    let msg = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[second_authority.insecure_clone()],
    )
    .unwrap();
    
    let result = context.svm.send_transaction(tx);
    assert!(result.is_err(), "Should fail without proper permissions");
}

#[test_log::test]
fn test_remove_actions_from_role_invalid_target() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    
    // Try to remove actions from non-existent role
    let remove_indices = vec![0];
    let ix_data = build_remove_actions_from_role_ix_data(0, 999, remove_indices); // Invalid target role ID
    
    let accounts = vec![
        solana_sdk::instruction::AccountMeta::new(swig_pubkey, false),
        solana_sdk::instruction::AccountMeta::new(swig_authority.pubkey(), true),
        solana_sdk::instruction::AccountMeta::new_readonly(pinocchio_system::ID.into(), false),
        solana_sdk::instruction::AccountMeta::new_readonly(swig_authority.pubkey(), true), // Authority signer
    ];
    
    let ix = solana_sdk::instruction::Instruction {
        program_id: program_id(),
        accounts,
        data: ix_data,
    };
    
    let msg = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[swig_authority.insecure_clone()],
    )
    .unwrap();
    
    let result = context.svm.send_transaction(tx);
    assert!(result.is_err(), "Should fail with non-existent target role");
}

#[test_log::test]
fn test_remove_actions_from_role_index_out_of_bounds() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    
    // Create a second authority with just one action
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    
    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1_000_000 })],
    )
    .unwrap();
    
    // Try to remove an action with an out-of-bounds index
    let remove_indices = vec![5]; // Index 5 doesn't exist (only index 0 exists)
    let ix_data = build_remove_actions_from_role_ix_data(0, 1, remove_indices);
    
    let accounts = vec![
        solana_sdk::instruction::AccountMeta::new(swig_pubkey, false),
        solana_sdk::instruction::AccountMeta::new(swig_authority.pubkey(), true),
        solana_sdk::instruction::AccountMeta::new_readonly(pinocchio_system::ID.into(), false),
        solana_sdk::instruction::AccountMeta::new_readonly(swig_authority.pubkey(), true), // Authority signer
    ];
    
    let ix = solana_sdk::instruction::Instruction {
        program_id: program_id(),
        accounts,
        data: ix_data,
    };
    
    let msg = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[swig_authority.insecure_clone()],
    )
    .unwrap();
    
    let result = context.svm.send_transaction(tx);
    assert!(result.is_err(), "Should fail with out-of-bounds index");
}

#[test_log::test]
fn test_remove_actions_from_role_remove_all_actions() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    
    // Create a second authority with just one action
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    
    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1_000_000 })],
    )
    .unwrap();
    
    // Try to remove the only action (index 0) - this should fail
    let remove_indices = vec![0]; // Try to remove the only action
    let ix_data = build_remove_actions_from_role_ix_data(0, 1, remove_indices);
    
    let accounts = vec![
        solana_sdk::instruction::AccountMeta::new(swig_pubkey, false),
        solana_sdk::instruction::AccountMeta::new(swig_authority.pubkey(), true),
        solana_sdk::instruction::AccountMeta::new_readonly(pinocchio_system::ID.into(), false),
        solana_sdk::instruction::AccountMeta::new_readonly(swig_authority.pubkey(), true), // Authority signer
    ];
    
    let ix = solana_sdk::instruction::Instruction {
        program_id: program_id(),
        accounts,
        data: ix_data,
    };
    
    let msg = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[swig_authority.insecure_clone()],
    )
    .unwrap();
    
    let result = context.svm.send_transaction(tx);
    assert!(result.is_err(), "Should fail when trying to remove all actions from a role");
}

#[test_log::test]
fn test_remove_actions_from_role_duplicate_indices() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    
    // Create a second authority with multiple actions
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    
    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::SolLimit(SolLimit { amount: 1_000_000 }),
            ClientAction::Program(Program { program_id: [4; 32] }),
            ClientAction::SolLimit(SolLimit { amount: 5_000_000 }),
        ],
    )
    .unwrap();
    
    // Try to remove actions with duplicate indices
    let remove_indices = vec![1, 1]; // Duplicate index 1
    let ix_data = build_remove_actions_from_role_ix_data(0, 1, remove_indices);
    
    let accounts = vec![
        solana_sdk::instruction::AccountMeta::new(swig_pubkey, false),
        solana_sdk::instruction::AccountMeta::new(swig_authority.pubkey(), true),
        solana_sdk::instruction::AccountMeta::new_readonly(pinocchio_system::ID.into(), false),
        solana_sdk::instruction::AccountMeta::new_readonly(swig_authority.pubkey(), true), // Authority signer
    ];
    
    let ix = solana_sdk::instruction::Instruction {
        program_id: program_id(),
        accounts,
        data: ix_data,
    };
    
    let msg = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[swig_authority.insecure_clone()],
    )
    .unwrap();
    
    let result = context.svm.send_transaction(tx);
    assert!(result.is_err(), "Should fail with duplicate indices");
}

#[test_log::test]
fn test_remove_actions_from_role_empty_indices() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    
    // Try to remove actions with no indices provided
    let remove_indices: Vec<u16> = vec![]; // Empty indices
    let ix_data = build_remove_actions_from_role_ix_data(0, 0, remove_indices);
    
    let accounts = vec![
        solana_sdk::instruction::AccountMeta::new(swig_pubkey, false),
        solana_sdk::instruction::AccountMeta::new(swig_authority.pubkey(), true),
        solana_sdk::instruction::AccountMeta::new_readonly(pinocchio_system::ID.into(), false),
        solana_sdk::instruction::AccountMeta::new_readonly(swig_authority.pubkey(), true), // Authority signer
    ];
    
    let ix = solana_sdk::instruction::Instruction {
        program_id: program_id(),
        accounts,
        data: ix_data,
    };
    
    let msg = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[swig_authority.insecure_clone()],
    )
    .unwrap();
    
    let result = context.svm.send_transaction(tx);
    assert!(result.is_err(), "Should fail with empty indices");
}