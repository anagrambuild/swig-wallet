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

use swig::actions::add_actions_to_role_v1::AddActionsToRoleV1Args;

fn build_add_actions_to_role_ix_data(
    acting_role_id: u32,
    target_role_id: u32,
    actions: Vec<ClientAction>,
) -> Vec<u8> {
    // Build actions data
    let mut actions_data = Vec::new();
    let mut num_actions = 0u8;
    
    for action in actions {
        match action {
            ClientAction::All(all) => {
                let action_header = Action::client_new(Permission::All, All::LEN as u16);
                actions_data.extend_from_slice(action_header.into_bytes().unwrap());
                actions_data.extend_from_slice(all.into_bytes().unwrap());
                num_actions += 1;
            }
            ClientAction::ManageAuthority(manage) => {
                let action_header = Action::client_new(Permission::ManageAuthority, ManageAuthority::LEN as u16);
                actions_data.extend_from_slice(action_header.into_bytes().unwrap());
                actions_data.extend_from_slice(manage.into_bytes().unwrap());
                num_actions += 1;
            }
            ClientAction::SolLimit(sol_limit) => {
                let action_header = Action::client_new(Permission::SolLimit, SolLimit::LEN as u16);
                actions_data.extend_from_slice(action_header.into_bytes().unwrap());
                actions_data.extend_from_slice(sol_limit.into_bytes().unwrap());
                num_actions += 1;
            }
            ClientAction::Program(program) => {
                let action_header = Action::client_new(Permission::Program, Program::LEN as u16);
                actions_data.extend_from_slice(action_header.into_bytes().unwrap());
                actions_data.extend_from_slice(program.into_bytes().unwrap());
                num_actions += 1;
            }
            _ => panic!("Unsupported action type"),
        }
    }
    
    let args = AddActionsToRoleV1Args::new(
        acting_role_id,
        target_role_id,
        actions_data.len() as u16,
        num_actions,
    );
    
    let mut ix_data = Vec::new();
    ix_data.extend_from_slice(args.into_bytes().unwrap());
    ix_data.extend_from_slice(&actions_data);
    // Add authority payload for Ed25519 - single byte indicating the account index
    // of the authority that needs to sign
    ix_data.push(3); // Authority will be at index 3
    
    ix_data
}

#[test_log::test]
fn test_add_actions_to_role_success() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    
    // Create a second authority with limited permissions
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    
    // Add second authority with just SolLimit permission
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
    
    // Now add more actions to the second role using the first authority
    let new_actions = vec![
        ClientAction::Program(Program {
            program_id: [4; 32],
        }),
        ClientAction::SolLimit(SolLimit { amount: 5_000_000 }),
    ];
    
    let ix_data = build_add_actions_to_role_ix_data(0, 1, new_actions);
    
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
    assert!(result.is_ok(), "Failed to add actions to role: {:?}", result);
    
    // Verify the role now has the additional actions
    let swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    
    let role = swig_state.get_role(1).unwrap().unwrap();
    
    // Should have 3 actions now (original SolLimit + Program + new SolLimit)
    assert_eq!(role.position.num_actions(), 3);
    
    // Double check with get_all_actions
    let all_actions = role.get_all_actions().unwrap();
    assert_eq!(all_actions.len(), 3, "Should have exactly 3 actions, but got {}", all_actions.len());
}

#[test_log::test]
fn test_add_actions_to_role_no_permission() {
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
    
    // Try to add actions using the second authority which doesn't have permission
    let new_actions = vec![
        ClientAction::Program(Program {
            program_id: [4; 32],
        }),
    ];
    
    let ix_data = build_add_actions_to_role_ix_data(1, 0, new_actions); // Use role 1 (second_authority) to modify role 0
    
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
fn test_add_actions_to_role_invalid_target() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    
    // Try to add actions to non-existent role
    let new_actions = vec![
        ClientAction::Program(Program {
            program_id: [4; 32],
        }),
    ];
    
    let ix_data = build_add_actions_to_role_ix_data(0, 999, new_actions); // Invalid target role ID
    
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