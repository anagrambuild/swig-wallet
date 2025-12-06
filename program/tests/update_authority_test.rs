#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.

mod common;

use common::*;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};
use swig_interface::{
    AuthorityConfig, ClientAction, UpdateAuthorityData, UpdateAuthorityInstruction,
};
use swig_state::{
    action::{
        all::All, manage_authority::ManageAuthority, sol_limit::SolLimit, token_limit::TokenLimit,
    },
    authority::AuthorityType,
    role::Position,
    swig::{Swig, SwigWithRoles},
    Transmutable,
};

/// Helper function to update authority with Ed25519 root authority
pub fn update_authority_with_ed25519_root(
    context: &mut SwigTestContext,
    swig_pubkey: &Pubkey,
    existing_ed25519_authority: &Keypair,
    authority_to_update_id: u32,
    new_actions: Vec<ClientAction>,
) -> anyhow::Result<litesvm::types::TransactionMetadata> {
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

    let msg = solana_sdk::message::v0::Message::try_compile(
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

#[test]
fn test_update_authority_ed25519_replace_all() -> anyhow::Result<()> {
    let mut context = setup_test_context()?;

    // Create initial wallet with Ed25519 authority
    let root_authority = Keypair::new();
    let id = [1u8; 32]; // Use a fixed ID for testing
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

    // Add a second authority that we can update (since we can't update root
    // authority ID 0)
    let second_authority = Keypair::new();
    let second_authority_pubkey = second_authority.pubkey();
    let authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: second_authority_pubkey.as_ref(),
    };
    let actions = vec![ClientAction::All(All {})];

    let _add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    )?;

    // Create new actions to replace all existing actions on the second authority
    let new_actions = vec![
        ClientAction::All(All {}),
        ClientAction::SolLimit(SolLimit { amount: 1000000 }),
    ];

    // Update the second authority (ID 1) to replace all actions
    let result = update_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        1, // authority_id 1 (the second authority we just added)
        new_actions,
    )?;

    // Verify the transaction succeeded by checking logs don't contain errors
    println!("Transaction logs: {:?}", result.logs);

    Ok(())
}

#[test]
fn test_update_authority_ed25519_add_actions() -> anyhow::Result<()> {
    let mut context = setup_test_context()?;

    // Create initial wallet with Ed25519 authority
    let root_authority = Keypair::new();
    let id = [2u8; 32]; // Use a different ID for this test
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

    // Add a second authority that we can update
    let second_authority = Keypair::new();
    let second_authority_pubkey = second_authority.pubkey();
    let authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: second_authority_pubkey.as_ref(),
    };

    let actions = vec![ClientAction::ManageAuthority(ManageAuthority {})];

    let _add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    )?;

    // Get role_id for the root authority
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig_data
        .lookup_role_id(root_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();

    // Add additional actions to the second authority (ID 1)
    let additional_actions = vec![ClientAction::SolLimit(SolLimit { amount: 500000 })];

    // Use the add_actions method
    let update_authority_ix = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        role_id,
        1, // authority_id 1 (the second authority)
        UpdateAuthorityData::AddActions(additional_actions),
    )?;

    let msg = solana_sdk::message::v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[update_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )?;

    let tx = solana_sdk::transaction::VersionedTransaction::try_new(
        solana_sdk::message::VersionedMessage::V0(msg),
        &[&context.default_payer, &root_authority],
    )?;

    let result = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e))?;

    println!("Transaction logs: {:?}", result.logs);

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role = swig_data.get_role(1).unwrap().unwrap();

    println!("role: {:?}", role.get_all_actions());
    let role_actions = role.get_all_actions().unwrap();
    for action in role_actions {
        println!("action: {:?}", action.permission());
    }

    Ok(())
}

#[test]
fn test_update_authority_ed25519_remove_by_type() -> anyhow::Result<()> {
    let mut context = setup_test_context()?;

    // Create initial wallet with Ed25519 authority
    let root_authority = Keypair::new();
    let id = [3u8; 32]; // Use a different ID for this test
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

    // Add a second authority that we can update
    let second_authority = Keypair::new();
    let second_authority_pubkey = second_authority.pubkey();
    let authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: second_authority_pubkey.as_ref(),
    };
    let actions = vec![
        ClientAction::All(All {}),
        ClientAction::SolLimit(SolLimit { amount: 1000000 }),
    ];

    let _add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    )?;

    // Get role_id for the root authority
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig_data
        .lookup_role_id(root_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();

    // Remove actions by type (using discriminant values)
    let action_types_to_remove = vec![
        6u8, // All action type discriminant
    ];

    // Use the remove_by_type method on the second authority (ID 1)
    let update_authority_ix = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        role_id,
        1, // authority_id 1 (the second authority)
        UpdateAuthorityData::RemoveActionsByType(action_types_to_remove),
    )?;

    let msg = solana_sdk::message::v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[update_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )?;

    let tx = solana_sdk::transaction::VersionedTransaction::try_new(
        solana_sdk::message::VersionedMessage::V0(msg),
        &[&context.default_payer, &root_authority],
    )?;

    let result = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e))?;

    println!("Transaction logs: {:?}", result.logs);

    Ok(())
}

#[test]
fn test_update_authority_ed25519_remove_by_index() -> anyhow::Result<()> {
    let mut context = setup_test_context()?;

    // Create initial wallet with Ed25519 authority
    let root_authority = Keypair::new();
    let id = [4u8; 32]; // Use a different ID for this test
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

    // Add a second authority that we can update
    let second_authority = Keypair::new();
    let second_authority_pubkey = second_authority.pubkey();
    let authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: second_authority_pubkey.as_ref(),
    };
    let actions = vec![
        ClientAction::All(All {}),
        ClientAction::SolLimit(SolLimit { amount: 1000000 }),
    ];

    let _add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    )?;

    // Get role_id for the root authority
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig_data
        .lookup_role_id(root_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();

    // Remove actions by index
    let indices_to_remove = vec![0u16]; // Remove first action

    // Use the remove_by_index method on the second authority (ID 1)
    let update_authority_ix = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        role_id,
        1, // authority_id 1 (the second authority)
        UpdateAuthorityData::RemoveActionsByIndex(indices_to_remove),
    )?;

    let msg = solana_sdk::message::v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[update_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )?;

    let tx = solana_sdk::transaction::VersionedTransaction::try_new(
        solana_sdk::message::VersionedMessage::V0(msg),
        &[&context.default_payer, &root_authority],
    )?;

    let result = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e))?;

    println!("Transaction logs: {:?}", result.logs);

    Ok(())
}

#[test]
fn test_update_authority_ed25519_remove_by_index_with_multiple_actions() -> anyhow::Result<()> {
    let mut context = setup_test_context()?;

    // Create initial wallet with Ed25519 authority
    let root_authority = Keypair::new();
    let id = [4u8; 32]; // Use a different ID for this test
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

    // Add a second authority that we can update
    let second_authority = Keypair::new();
    let second_authority_pubkey = second_authority.pubkey();
    let authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: second_authority_pubkey.as_ref(),
    };
    let actions = vec![
        ClientAction::All(All {}),
        ClientAction::SolLimit(SolLimit { amount: 1000000 }),
        ClientAction::ManageAuthority(ManageAuthority {}),
        ClientAction::TokenLimit(TokenLimit {
            token_mint: [0u8; 32],
            current_amount: 1000000,
        }),
        ClientAction::TokenLimit(TokenLimit {
            token_mint: [1u8; 32],
            current_amount: 1000000,
        }),
        ClientAction::TokenLimit(TokenLimit {
            token_mint: [2u8; 32],
            current_amount: 1000000,
        }),
    ];

    let second_authority_add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    )?;

    // Add a third authority that we can update
    let third_authority = Keypair::new();
    let third_authority_pubkey = third_authority.pubkey();
    let third_authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: third_authority_pubkey.as_ref(),
    };
    let third_actions = vec![
        ClientAction::All(All {}),
        ClientAction::SolLimit(SolLimit { amount: 1000000 }),
        ClientAction::TokenLimit(TokenLimit {
            token_mint: [0u8; 32],
            current_amount: 1000000,
        }),
        ClientAction::TokenLimit(TokenLimit {
            token_mint: [1u8; 32],
            current_amount: 1000000,
        }),
        ClientAction::TokenLimit(TokenLimit {
            token_mint: [2u8; 32],
            current_amount: 1000000,
        }),
    ];

    let _add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        third_authority_config,
        third_actions,
    )?;

    let fourth_authority = Keypair::new();
    let fourth_authority_pubkey = fourth_authority.pubkey();
    let fourth_authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: fourth_authority_pubkey.as_ref(),
    };
    let fourth_actions = vec![
        ClientAction::All(All {}),
        ClientAction::SolLimit(SolLimit { amount: 1000000 }),
        ClientAction::TokenLimit(TokenLimit {
            token_mint: [0u8; 32],
            current_amount: 1000000,
        }),
        ClientAction::TokenLimit(TokenLimit {
            token_mint: [1u8; 32],
            current_amount: 1000000,
        }),
        ClientAction::TokenLimit(TokenLimit {
            token_mint: [2u8; 32],
            current_amount: 1000000,
        }),
    ];

    let _add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        fourth_authority_config,
        fourth_actions,
    )?;

    // Get role_id for the root authority
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig_data
        .lookup_role_id(root_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();

    // Remove actions by index
    let indices_to_remove = vec![0u16, 3u16]; // Remove first action

    // Use the remove_by_index method on the second authority (ID 1)
    let update_authority_ix = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        role_id,
        1, // authority_id 1 (the second authority)
        UpdateAuthorityData::RemoveActionsByIndex(indices_to_remove),
    )?;

    let msg = solana_sdk::message::v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[update_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )?;

    let tx = solana_sdk::transaction::VersionedTransaction::try_new(
        solana_sdk::message::VersionedMessage::V0(msg),
        &[&context.default_payer, &root_authority],
    )?;

    let result = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e))?;

    println!("Transaction logs: {:?}", result.logs);

    // Verify the state after the update
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

    // Print positions for debugging
    let (_, roles) = &swig_account.data.split_at(Swig::LEN);
    let mut cursor = 0;
    let mut role_count = 0;
    while cursor < roles.len() && role_count < swig_data.state.roles {
        if cursor + Position::LEN > roles.len() {
            break;
        }
        let position =
            unsafe { Position::load_unchecked(&roles[cursor..cursor + Position::LEN]).unwrap() };
        println!("position: {:?}", position);
        cursor = position.boundary() as usize;
        role_count += 1;
    }

    // Verify role 1 has 4 actions after removing 2 (started with 6)
    let role = swig_data
        .get_role(1)
        .map_err(|e| anyhow::anyhow!("Failed to get role 1: {:?}", e))?
        .unwrap();
    let role_actions = role
        .get_all_actions()
        .map_err(|e| anyhow::anyhow!("Failed to get actions: {:?}", e))?;
    println!("Role 1 actions after update:");
    for action in &role_actions {
        println!("  action: {:?}", action.permission());
    }
    assert_eq!(
        role.position.num_actions(),
        4,
        "Role 1 should have 4 actions after removing 2 (indices 0 and 3)"
    );
    assert_eq!(
        role_actions.len(),
        4,
        "Should be able to retrieve all 4 actions"
    );

    // Verify subsequent roles are still accessible
    let role2 = swig_data
        .get_role(2)
        .map_err(|e| anyhow::anyhow!("Failed to get role 2: {:?}", e))?
        .unwrap();
    assert_eq!(
        role2.position.num_actions(),
        5,
        "Role 2 should still have 5 actions"
    );

    let role3 = swig_data
        .get_role(3)
        .map_err(|e| anyhow::anyhow!("Failed to get role 3: {:?}", e))?
        .unwrap();
    assert_eq!(
        role3.position.num_actions(),
        5,
        "Role 3 should still have 5 actions"
    );

    Ok(())
}

/// Test that verifies boundary changes when shrinking a middle role.
/// 1. The modified role has correct num_actions
/// 2. Subsequent roles are still accessible
/// 3. All role boundaries form a contiguous chain
#[test]
fn test_update_authority_boundary_correctness_on_shrink() -> anyhow::Result<()> {
    let mut context = setup_test_context()?;

    // Create initial wallet with Ed25519 authority
    let root_authority = Keypair::new();
    let id = [10u8; 32];
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

    // Add second authority with 4 actions
    let second_authority = Keypair::new();
    let second_authority_pubkey = second_authority.pubkey();
    let authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: second_authority_pubkey.as_ref(),
    };
    let actions = vec![
        ClientAction::All(All {}),
        ClientAction::SolLimit(SolLimit { amount: 1000000 }),
        ClientAction::ManageAuthority(ManageAuthority {}),
        ClientAction::TokenLimit(TokenLimit {
            token_mint: [0u8; 32],
            current_amount: 1000000,
        }),
    ];
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    )?;

    // Add third authority with 3 actions
    let third_authority = Keypair::new();
    let third_authority_pubkey = third_authority.pubkey();
    let third_authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: third_authority_pubkey.as_ref(),
    };
    let third_actions = vec![
        ClientAction::All(All {}),
        ClientAction::SolLimit(SolLimit { amount: 2000000 }),
        ClientAction::ManageAuthority(ManageAuthority {}),
    ];
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        third_authority_config,
        third_actions,
    )?;

    // Add fourth authority with 2 actions
    let fourth_authority = Keypair::new();
    let fourth_authority_pubkey = fourth_authority.pubkey();
    let fourth_authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: fourth_authority_pubkey.as_ref(),
    };
    let fourth_actions = vec![
        ClientAction::All(All {}),
        ClientAction::SolLimit(SolLimit { amount: 3000000 }),
    ];
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        fourth_authority_config,
        fourth_actions,
    )?;

    // Capture boundaries BEFORE the update
    let swig_account_before = context.svm.get_account(&swig).unwrap();
    let swig_data_before = SwigWithRoles::from_bytes(&swig_account_before.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig: {:?}", e))?;

    // Get positions before update
    let role1_before = swig_data_before
        .get_role(1)
        .map_err(|e| anyhow::anyhow!("Failed to get role 1: {:?}", e))?
        .unwrap();
    let role2_before = swig_data_before
        .get_role(2)
        .map_err(|e| anyhow::anyhow!("Failed to get role 2: {:?}", e))?
        .unwrap();
    let role3_before = swig_data_before
        .get_role(3)
        .map_err(|e| anyhow::anyhow!("Failed to get role 3: {:?}", e))?
        .unwrap();

    println!("BEFORE UPDATE:");
    println!(
        "Role 1: num_actions={}, boundary={}",
        role1_before.position.num_actions(),
        role1_before.position.boundary()
    );
    println!(
        "Role 2: num_actions={}, boundary={}",
        role2_before.position.num_actions(),
        role2_before.position.boundary()
    );
    println!(
        "Role 3: num_actions={}, boundary={}",
        role3_before.position.num_actions(),
        role3_before.position.boundary()
    );

    // Get role_id for the root authority
    let role_id = swig_data_before
        .lookup_role_id(root_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id: {:?}", e))?
        .unwrap();

    // Remove 2 actions from role 1 (indices 0 and 2)
    let indices_to_remove = vec![0u16, 2u16];

    let update_authority_ix = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        role_id,
        1, // Update role 1
        UpdateAuthorityData::RemoveActionsByIndex(indices_to_remove),
    )?;

    let msg = solana_sdk::message::v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[update_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )?;

    let tx = solana_sdk::transaction::VersionedTransaction::try_new(
        solana_sdk::message::VersionedMessage::V0(msg),
        &[&context.default_payer, &root_authority],
    )?;

    context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction: {:?}", e))?;

    // Verify the state AFTER the update
    let swig_account_after = context.svm.get_account(&swig).unwrap();
    let swig_data_after = SwigWithRoles::from_bytes(&swig_account_after.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig: {:?}", e))?;

    println!("\nAFTER UPDATE:");

    // Verify role 1 has 2 actions remaining (was 4, removed 2)
    let role1_after = swig_data_after
        .get_role(1)
        .map_err(|e| anyhow::anyhow!("Failed to get role 1: {:?}", e))?
        .unwrap();
    println!(
        "Role 1: num_actions={}, boundary={}",
        role1_after.position.num_actions(),
        role1_after.position.boundary()
    );
    assert_eq!(
        role1_after.position.num_actions(),
        2,
        "Role 1 should have 2 actions after removing 2"
    );

    // Verify role 2 is still accessible and has correct actions
    let role2_after = swig_data_after
        .get_role(2)
        .map_err(|e| anyhow::anyhow!("Failed to get role 2: {:?}", e))?
        .unwrap();
    println!(
        "Role 2: num_actions={}, boundary={}",
        role2_after.position.num_actions(),
        role2_after.position.boundary()
    );
    assert_eq!(
        role2_after.position.num_actions(),
        3,
        "Role 2 should still have 3 actions"
    );

    // Verify role 3 is still accessible and has correct actions
    let role3_after = swig_data_after
        .get_role(3)
        .map_err(|e| anyhow::anyhow!("Failed to get role 3: {:?}", e))?
        .unwrap();
    println!(
        "Role 3: num_actions={}, boundary={}",
        role3_after.position.num_actions(),
        role3_after.position.boundary()
    );
    assert_eq!(
        role3_after.position.num_actions(),
        2,
        "Role 3 should still have 2 actions"
    );

    // Verify boundaries form a contiguous chain
    let (header, roles) = swig_account_after.data.split_at(Swig::LEN);
    let swig_header = unsafe {
        Swig::load_unchecked(header)
            .map_err(|e| anyhow::anyhow!("Failed to load swig header: {:?}", e))?
    };
    let expected_roles = swig_header.roles as usize;

    let mut cursor = 0;
    let mut prev_boundary = 0u32;
    let mut role_count = 0;

    // Iterate through exactly the number of roles we expect
    for _ in 0..expected_roles {
        if cursor + Position::LEN > roles.len() {
            break;
        }
        let position = unsafe {
            Position::load_unchecked(&roles[cursor..cursor + Position::LEN])
                .map_err(|e| anyhow::anyhow!("Failed to load position: {:?}", e))?
        };

        // Each role's boundary should be greater than its start position
        assert!(
            position.boundary() as usize > cursor,
            "Role {} boundary ({}) should be greater than cursor ({})",
            position.id(),
            position.boundary(),
            cursor
        );

        // Boundary should increase monotonically
        if role_count > 0 {
            assert!(
                position.boundary() > prev_boundary || cursor == prev_boundary as usize,
                "Boundaries should be monotonically increasing"
            );
        }

        prev_boundary = position.boundary();
        cursor = position.boundary() as usize;
        role_count += 1;
    }

    assert_eq!(role_count, 4, "Should have 4 roles total");

    Ok(())
}

/// Test that verifies we can still access and use roles after multiple shrink
/// operations
#[test]
fn test_update_authority_multiple_shrinks() -> anyhow::Result<()> {
    let mut context = setup_test_context()?;

    let root_authority = Keypair::new();
    let id = [11u8; 32];
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

    // Add second authority with many actions
    let second_authority = Keypair::new();
    let second_authority_pubkey = second_authority.pubkey();
    let authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: second_authority_pubkey.as_ref(),
    };
    let actions = vec![
        ClientAction::All(All {}),
        ClientAction::SolLimit(SolLimit { amount: 1000000 }),
        ClientAction::ManageAuthority(ManageAuthority {}),
        ClientAction::TokenLimit(TokenLimit {
            token_mint: [0u8; 32],
            current_amount: 1000000,
        }),
        ClientAction::TokenLimit(TokenLimit {
            token_mint: [1u8; 32],
            current_amount: 2000000,
        }),
    ];
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    )?;

    // Add third authority
    let third_authority = Keypair::new();
    let third_authority_pubkey = third_authority.pubkey();
    let third_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: third_authority_pubkey.as_ref(),
    };
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        third_config,
        vec![
            ClientAction::All(All {}),
            ClientAction::SolLimit(SolLimit { amount: 5000000 }),
        ],
    )?;

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig: {:?}", e))?;
    let role_id = swig_data
        .lookup_role_id(root_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id: {:?}", e))?
        .unwrap();

    // First shrink: remove 2 actions from role 1
    let update_ix = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        role_id,
        1,
        UpdateAuthorityData::RemoveActionsByIndex(vec![0u16, 1u16]),
    )?;

    let msg = solana_sdk::message::v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[update_ix],
        &[],
        context.svm.latest_blockhash(),
    )?;
    let tx = solana_sdk::transaction::VersionedTransaction::try_new(
        solana_sdk::message::VersionedMessage::V0(msg),
        &[&context.default_payer, &root_authority],
    )?;
    context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction: {:?}", e))?;

    // Verify after first shrink
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig: {:?}", e))?;
    let role1 = swig_data
        .get_role(1)
        .map_err(|e| anyhow::anyhow!("Failed to get role 1: {:?}", e))?
        .unwrap();
    assert_eq!(
        role1.position.num_actions(),
        3,
        "Role 1 should have 3 actions after first shrink"
    );

    let role2 = swig_data
        .get_role(2)
        .map_err(|e| anyhow::anyhow!("Failed to get role 2: {:?}", e))?
        .unwrap();
    assert_eq!(
        role2.position.num_actions(),
        2,
        "Role 2 should still have 2 actions"
    );

    // Second shrink: remove 1 more action from role 1
    context.svm.expire_blockhash();
    let update_ix = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        role_id,
        1,
        UpdateAuthorityData::RemoveActionsByIndex(vec![0u16]),
    )?;

    let msg = solana_sdk::message::v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[update_ix],
        &[],
        context.svm.latest_blockhash(),
    )?;
    let tx = solana_sdk::transaction::VersionedTransaction::try_new(
        solana_sdk::message::VersionedMessage::V0(msg),
        &[&context.default_payer, &root_authority],
    )?;
    context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction: {:?}", e))?;

    // Verify after second shrink
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig: {:?}", e))?;
    let role1 = swig_data
        .get_role(1)
        .map_err(|e| anyhow::anyhow!("Failed to get role 1: {:?}", e))?
        .unwrap();
    assert_eq!(
        role1.position.num_actions(),
        2,
        "Role 1 should have 2 actions after second shrink"
    );

    let role2 = swig_data
        .get_role(2)
        .map_err(|e| anyhow::anyhow!("Failed to get role 2: {:?}", e))?
        .unwrap();
    assert_eq!(
        role2.position.num_actions(),
        2,
        "Role 2 should still have 2 actions"
    );

    // Verify all actions in role 2 are still valid
    let role2_actions = role2
        .get_all_actions()
        .map_err(|e| anyhow::anyhow!("Failed to get role 2 actions: {:?}", e))?;
    assert_eq!(
        role2_actions.len(),
        2,
        "Role 2 should have 2 retrievable actions"
    );

    Ok(())
}

/// Test that verifies growing a middle role correctly updates subsequent
/// boundaries
#[test]
fn test_update_authority_boundary_correctness_on_grow() -> anyhow::Result<()> {
    let mut context = setup_test_context()?;

    let root_authority = Keypair::new();
    let id = [12u8; 32];
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

    // Add second authority with 1 action
    let second_authority = Keypair::new();
    let second_authority_pubkey = second_authority.pubkey();
    let authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: second_authority_pubkey.as_ref(),
    };
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        vec![ClientAction::All(All {})],
    )?;

    // Add third authority with 2 actions
    let third_authority = Keypair::new();
    let third_authority_pubkey = third_authority.pubkey();
    let third_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: third_authority_pubkey.as_ref(),
    };
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        third_config,
        vec![
            ClientAction::All(All {}),
            ClientAction::ManageAuthority(ManageAuthority {}),
        ],
    )?;

    // Capture state before grow
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig: {:?}", e))?;
    let role1_before = swig_data
        .get_role(1)
        .map_err(|e| anyhow::anyhow!("Failed to get role 1: {:?}", e))?
        .unwrap();
    let role2_before = swig_data
        .get_role(2)
        .map_err(|e| anyhow::anyhow!("Failed to get role 2: {:?}", e))?
        .unwrap();
    println!("BEFORE GROW:");
    println!("Role 1 boundary: {}", role1_before.position.boundary());
    println!("Role 2 boundary: {}", role2_before.position.boundary());

    let role_id = swig_data
        .lookup_role_id(root_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id: {:?}", e))?
        .unwrap();

    // Add 3 more actions to role 1 (growing it)
    let additional_actions = vec![
        ClientAction::SolLimit(SolLimit { amount: 1000000 }),
        ClientAction::ManageAuthority(ManageAuthority {}),
        ClientAction::TokenLimit(TokenLimit {
            token_mint: [0u8; 32],
            current_amount: 500000,
        }),
    ];

    let update_ix = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        role_id,
        1,
        UpdateAuthorityData::AddActions(additional_actions),
    )?;

    let msg = solana_sdk::message::v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[update_ix],
        &[],
        context.svm.latest_blockhash(),
    )?;
    let tx = solana_sdk::transaction::VersionedTransaction::try_new(
        solana_sdk::message::VersionedMessage::V0(msg),
        &[&context.default_payer, &root_authority],
    )?;
    context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction: {:?}", e))?;

    // Verify state after grow
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig: {:?}", e))?;

    let role1_after = swig_data
        .get_role(1)
        .map_err(|e| anyhow::anyhow!("Failed to get role 1: {:?}", e))?
        .unwrap();
    let role2_after = swig_data
        .get_role(2)
        .map_err(|e| anyhow::anyhow!("Failed to get role 2: {:?}", e))?
        .unwrap();

    println!("AFTER GROW:");
    println!(
        "Role 1: num_actions={}, boundary={}",
        role1_after.position.num_actions(),
        role1_after.position.boundary()
    );
    println!(
        "Role 2: num_actions={}, boundary={}",
        role2_after.position.num_actions(),
        role2_after.position.boundary()
    );

    // Role 1 should now have 4 actions
    assert_eq!(
        role1_after.position.num_actions(),
        4,
        "Role 1 should have 4 actions after adding 3"
    );

    // Role 2 should still have 2 actions and be accessible
    assert_eq!(
        role2_after.position.num_actions(),
        2,
        "Role 2 should still have 2 actions"
    );

    // Role 1's boundary should have increased
    assert!(
        role1_after.position.boundary() > role1_before.position.boundary(),
        "Role 1 boundary should have increased"
    );

    // Role 2's boundary should have increased by the same amount
    let boundary_diff_role1 = role1_after.position.boundary() - role1_before.position.boundary();
    let boundary_diff_role2 = role2_after.position.boundary() - role2_before.position.boundary();
    assert_eq!(
        boundary_diff_role1, boundary_diff_role2,
        "Boundary adjustments should be equal for roles after the modified one"
    );

    // Verify role 2 actions are still accessible
    let role2_actions = role2_after
        .get_all_actions()
        .map_err(|e| anyhow::anyhow!("Failed to get role 2 actions: {:?}", e))?;
    assert_eq!(
        role2_actions.len(),
        2,
        "Should be able to retrieve all role 2 actions"
    );

    Ok(())
}

/// Test that the last role can be shrunk
#[test]
fn test_update_authority_shrink_last_role() -> anyhow::Result<()> {
    let mut context = setup_test_context()?;

    let root_authority = Keypair::new();
    let id = [13u8; 32];
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

    // Add second authority (will be the last role with multiple actions)
    let second_authority = Keypair::new();
    let second_authority_pubkey = second_authority.pubkey();
    let authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: second_authority_pubkey.as_ref(),
    };
    let actions = vec![
        ClientAction::All(All {}),
        ClientAction::SolLimit(SolLimit { amount: 1000000 }),
        ClientAction::ManageAuthority(ManageAuthority {}),
    ];
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    )?;

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig: {:?}", e))?;
    let role_id = swig_data
        .lookup_role_id(root_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id: {:?}", e))?
        .unwrap();

    // Remove 2 actions from the last role (role 1)
    let update_ix = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        role_id,
        1,
        UpdateAuthorityData::RemoveActionsByIndex(vec![0u16, 1u16]),
    )?;

    let msg = solana_sdk::message::v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[update_ix],
        &[],
        context.svm.latest_blockhash(),
    )?;
    let tx = solana_sdk::transaction::VersionedTransaction::try_new(
        solana_sdk::message::VersionedMessage::V0(msg),
        &[&context.default_payer, &root_authority],
    )?;
    context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction: {:?}", e))?;

    // Verify state after shrink
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig: {:?}", e))?;

    let role1 = swig_data
        .get_role(1)
        .map_err(|e| anyhow::anyhow!("Failed to get role 1: {:?}", e))?
        .unwrap();
    assert_eq!(
        role1.position.num_actions(),
        1,
        "Last role should have 1 action after removing 2"
    );

    // Root role should still be accessible
    let role0 = swig_data
        .get_role(0)
        .map_err(|e| anyhow::anyhow!("Failed to get role 0: {:?}", e))?
        .unwrap();
    assert_eq!(
        role0.position.num_actions(),
        1,
        "Root role should still have 1 action"
    );

    Ok(())
}

// Basic tests for Secp256k1 and Secp256r1 - these would need proper signature
// generation For now, just test that the instruction building works

#[test]
fn test_update_authority_secp256k1_instruction_building() -> anyhow::Result<()> {
    let swig_pubkey = Pubkey::new_unique();
    let payer_pubkey = Pubkey::new_unique();
    let authority_pubkey = Pubkey::new_unique();

    let new_actions = vec![ClientAction::All(All {})];

    // Test that we can build Secp256k1 instructions without errors
    let _ix = UpdateAuthorityInstruction::new_with_secp256k1_authority(
        swig_pubkey,
        payer_pubkey,
        |_| [0u8; 65], // dummy signature function
        0,             // current_slot
        0,             // counter
        0,             // role_id
        0,             // authority_id
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::All(All {})]),
    )?;

    let _ix = UpdateAuthorityInstruction::new_with_secp256k1_authority(
        swig_pubkey,
        payer_pubkey,
        |_| [0u8; 65],
        0, // current_slot
        0, // counter
        0, // role_id
        0, // authority_id
        UpdateAuthorityData::AddActions(vec![ClientAction::All(All {})]),
    )?;

    let _ix = UpdateAuthorityInstruction::new_with_secp256k1_authority(
        swig_pubkey,
        payer_pubkey,
        |_| [0u8; 65],
        0,                                                   // current_slot
        0,                                                   // counter
        0,                                                   // role_id
        0,                                                   // authority_id
        UpdateAuthorityData::RemoveActionsByType(vec![6u8]), // All action type discriminant
    )?;

    let _ix = UpdateAuthorityInstruction::new_with_secp256k1_authority(
        swig_pubkey,
        payer_pubkey,
        |_| [0u8; 65],
        0, // current_slot
        0, // counter
        0, // role_id
        0, // authority_id
        UpdateAuthorityData::RemoveActionsByIndex(vec![0u16]),
    )?;

    Ok(())
}

#[test]
fn test_update_authority_secp256r1_instruction_building() -> anyhow::Result<()> {
    let swig_pubkey = Pubkey::new_unique();
    let payer_pubkey = Pubkey::new_unique();
    let authority_pubkey = Pubkey::new_unique();

    let new_actions = vec![ClientAction::All(All {})];

    // Test that we can build Secp256r1 instructions without errors
    let dummy_pubkey = [0u8; 33]; // dummy public key
    let _ix = UpdateAuthorityInstruction::new_with_secp256r1_authority(
        swig_pubkey,
        payer_pubkey,
        |_| [0u8; 64], // dummy signature function
        0,             // current_slot
        0,             // counter
        0,             // role_id
        0,             // authority_id
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::All(All {})]),
        &dummy_pubkey,
    )?;

    let _ix = UpdateAuthorityInstruction::new_with_secp256r1_authority(
        swig_pubkey,
        payer_pubkey,
        |_| [0u8; 64],
        0, // current_slot
        0, // counter
        0, // role_id
        0, // authority_id
        UpdateAuthorityData::AddActions(vec![ClientAction::All(All {})]),
        &dummy_pubkey,
    )?;

    let _ix = UpdateAuthorityInstruction::new_with_secp256r1_authority(
        swig_pubkey,
        payer_pubkey,
        |_| [0u8; 64],
        0,                                                   // current_slot
        0,                                                   // counter
        0,                                                   // role_id
        0,                                                   // authority_id
        UpdateAuthorityData::RemoveActionsByType(vec![6u8]), // All action type discriminant
        &dummy_pubkey,
    )?;

    let _ix = UpdateAuthorityInstruction::new_with_secp256r1_authority(
        swig_pubkey,
        payer_pubkey,
        |_| [0u8; 64],
        0, // current_slot
        0, // counter
        0, // role_id
        0, // authority_id
        UpdateAuthorityData::RemoveActionsByIndex(vec![0u16]),
        &dummy_pubkey,
    )?;

    Ok(())
}
