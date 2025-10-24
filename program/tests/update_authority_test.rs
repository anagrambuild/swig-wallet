#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.

mod common;

use anyhow::Ok;
use common::*;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};
use swig_interface::{
    AuthorityConfig, ClientAction, ManageAuthorizationLocksData,
    ManageAuthorizationLocksV1Instruction, UpdateAuthorityData, UpdateAuthorityInstruction,
};
use swig_state::{
    action::{
        all::All, authorization_lock::AuthorizationLock,
        manage_auth_lock::ManageAuthorizationLocks, manage_authority::ManageAuthority,
        program_all::ProgramAll, sol_limit::SolLimit, Permission,
    },
    authority::AuthorityType,
    swig::SwigWithRoles,
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
        2, // authority_id 2 (the second authority we just added)
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
        2, // authority_id 2 (the second authority)
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
    let role = swig_data.get_role(2).unwrap().unwrap();

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
        2, // authority_id 2 (the second authority)
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
        2, // authority_id 2 (the second authority)
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

#[test]
fn test_update_authority_with_auth_lock_operations() -> anyhow::Result<()> {
    let mut context = setup_test_context()?;

    // Create initial wallet with Ed25519 authority
    let root_authority = Keypair::new();

    let id = [5u8; 32]; // Use a different ID for this test
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

    // Add a second authority that we can update
    let second_authority = Keypair::new();
    let second_authority_pubkey = second_authority.pubkey();
    let authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: second_authority_pubkey.as_ref(),
    };
    let actions = vec![
        ClientAction::ProgramAll(ProgramAll {}),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
    ];

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig_data
        .lookup_role_id(root_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();

    let _add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    )?;

    // add auth lock to secondary authority which will create auth lock cache on global authority
    let add_auth_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        role_id,
        2, // authority_id 2 (the second authority)
        ManageAuthorizationLocksData::AddLock(vec![ClientAction::AuthorizationLock(
            AuthorizationLock {
                mint: [0u8; 32],
                amount: 1000000,
                expires_at: 1000000,
            },
        )]),
    )?;
    let msg = solana_sdk::message::v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_auth_lock_ix],
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

    // verify global authority has auth lock cache
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role = swig_data.get_role(2).unwrap().unwrap();
    let role_actions = role.get_all_actions().unwrap();

    let auth_lock_action = role.get_all_actions_of_type::<AuthorizationLock>().unwrap();
    assert!(auth_lock_action.len() == 1, "Expected 1 auth lock action");
    let auth_lock_action = auth_lock_action.get(0).unwrap();
    assert!(
        auth_lock_action.mint == [0u8; 32],
        "Expected mint to be [0u8; 32]"
    );
    assert!(
        auth_lock_action.amount == 1000000,
        "Expected amount to be 1000000"
    );
    assert!(
        auth_lock_action.expires_at == 1000000,
        "Expected expires_at to be 1000000"
    );

    // Remove by index auth lock from global authority
    let update_data = UpdateAuthorityData::RemoveActionsByIndex(vec![0u16]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        0, // authority_id 0 (the global authority)
        update_data,
    );
    assert!(
        result.is_err(),
        "Expected error when removing auth lock from global authority"
    );

    // Remove by type auth lock from global authority
    let update_data =
        UpdateAuthorityData::RemoveActionsByType(vec![Permission::AuthorizationLock as u8]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        0, // authority_id 0 (the global authority)
        update_data,
    );
    assert!(
        result.is_err(),
        "Expected error when removing auth lock from global authority"
    );

    // Replace all auth lock on global authority (with new auth lock)
    let update_data =
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [0u8; 32],
            amount: 1000000,
            expires_at: 1000000,
        })]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        0, // authority_id 0 (the global authority)
        update_data,
    );
    assert!(
        result.is_err(),
        "Expected error when replacing auth lock on global authority"
    );

    // Replace all auth lock on global authority (without new auth lock)
    let update_data =
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::ProgramAll(ProgramAll {})]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        0, // authority_id 0 (the global authority)
        update_data,
    );
    assert!(
        result.is_err(),
        "Expected error when replacing auth lock on global authority without new auth lock"
    );

    // Add auth lock to global authority
    let update_data =
        UpdateAuthorityData::AddActions(vec![ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [0u8; 32],
            amount: 1000000,
            expires_at: 1000000,
        })]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        0, // authority_id 0 (the global authority)
        update_data,
    );
    assert!(
        result.is_err(),
        "Expected error when replacing auth lock on global authority without new auth lock"
    );

    Ok(())
}

fn send_udpate_authority_transaction(
    context: &mut SwigTestContext,
    swig_pubkey: &Pubkey,
    root_authority: &Keypair,
    role_id: u32,
    authority_to_update_id: u32,
    update_authority_data: UpdateAuthorityData,
) -> anyhow::Result<litesvm::types::TransactionMetadata> {
    let update_authority_ix = UpdateAuthorityInstruction::new_with_ed25519_authority(
        *swig_pubkey,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        role_id,
        authority_to_update_id, // authority_id 0 (the global authority)
        update_authority_data,
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
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e))
}

fn send_auth_lock_operation_transaction(
    context: &mut SwigTestContext,
    swig_pubkey: &Pubkey,
    root_authority: &Keypair,
    role_id: u32,
    authority_to_update_id: u32,
) -> anyhow::Result<()> {
    let add_auth_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
        *swig_pubkey,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        role_id,
        2, // authority_id 2 (the second authority)
        ManageAuthorizationLocksData::AddLock(vec![ClientAction::AuthorizationLock(
            AuthorizationLock {
                mint: [1u8; 32],
                amount: 1000000,
                expires_at: 1000000,
            },
        )]),
    )?;
    let msg = solana_sdk::message::v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_auth_lock_ix],
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
    Ok(())
}

/// Test case:
/// - Have an authority with auth lock
/// - None of the cases should work that involves removing auth lock from the authority or the manage auth lock action
///
#[test]
fn test_update_authority_replaceall_auth_lock_mints_from_actions() -> anyhow::Result<()> {
    let mut context = setup_test_context()?;

    // Create initial wallet with Ed25519 authority
    let root_authority = Keypair::new();

    let id = [5u8; 32]; // Use a different ID for this test
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

    // Add a second authority that we can update
    let second_authority = Keypair::new();
    let second_authority_pubkey = second_authority.pubkey();
    let authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: second_authority_pubkey.as_ref(),
    };
    let actions = vec![
        ClientAction::ProgramAll(ProgramAll {}),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
    ];

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig_data
        .lookup_role_id(root_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();

    let _add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    )?;

    let result = send_auth_lock_operation_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
    )
    .unwrap();

    // Replace all auth lock on second authority
    let update_data =
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [1u8; 32],
            amount: 1000000,
            expires_at: 1000000,
        })]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
        update_data,
    );
    assert!(result.is_err());

    // Replace all with ManageAuthorizationLocks action
    let update_data =
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
        update_data,
    );
    assert!(result.is_err());

    // Replace all with SolLimit action
    let update_data =
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::SolLimit(SolLimit { amount: 1000000 })]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
        update_data,
    );
    assert!(result.is_err());

    Ok(())
}

/// Test case:
/// - Have an authority with auth lock
/// - None of the cases should work that involves removing auth lock from the authority or the manage auth lock action
///
#[test]
fn test_update_authority_replaceall_auth_lock_manage_from_actions() -> anyhow::Result<()> {
    let mut context = setup_test_context()?;

    // Create initial wallet with Ed25519 authority
    let root_authority = Keypair::new();

    let id = [5u8; 32]; // Use a different ID for this test
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

    // Add a second authority that we can update
    let second_authority = Keypair::new();
    let second_authority_pubkey = second_authority.pubkey();
    let authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: second_authority_pubkey.as_ref(),
    };
    let actions = vec![
        ClientAction::ProgramAll(ProgramAll {}),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
    ];

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig_data
        .lookup_role_id(root_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();

    let _add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    )?;

    // let result = send_auth_lock_operation_transaction(
    //     &mut context,
    //     &swig,
    //     &root_authority,
    //     role_id,
    //     2, // authority_id 2 (the second authority)
    // )
    // .unwrap();

    // Replace all auth lock on second authority
    let update_data =
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [1u8; 32],
            amount: 1000000,
            expires_at: 1000000,
        })]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
        update_data,
    );
    println!("Transaction logs: {:?}", result);
    assert!(result.is_err());

    // Replace all with AuthorizationLock action
    let update_data =
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
        update_data,
    );
    assert!(result.is_ok());

    // Replace all with SolLimit action
    let update_data =
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::SolLimit(SolLimit { amount: 1000000 })]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
        update_data,
    );
    assert!(result.is_ok());

    Ok(())
}

/// Test case:
/// - Have an authority with auth lock
/// - None of the cases should work that involves removing auth lock from the authority or the manage auth lock action
///
#[test]
fn test_update_authority_remove_by_type_auth_lock_mints_from_actions() -> anyhow::Result<()> {
    let mut context = setup_test_context()?;

    // Create initial wallet with Ed25519 authority
    let root_authority = Keypair::new();

    let id = [5u8; 32]; // Use a different ID for this test
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

    // Add a second authority that we can update
    let second_authority = Keypair::new();
    let second_authority_pubkey = second_authority.pubkey();
    let authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: second_authority_pubkey.as_ref(),
    };
    let actions = vec![
        ClientAction::ProgramAll(ProgramAll {}),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
    ];

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig_data
        .lookup_role_id(root_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();

    let _add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    )?;

    let result = send_auth_lock_operation_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
    )
    .unwrap();

    // Remove AuthorizationLock action from second authority
    let update_data =
        UpdateAuthorityData::RemoveActionsByType(vec![Permission::AuthorizationLock as u8]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
        update_data,
    );
    assert!(result.is_err());

    // Remove ManageAuthorizationLocks action from second authority
    let update_data =
        UpdateAuthorityData::RemoveActionsByType(vec![Permission::ManageAuthorizationLocks as u8]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
        update_data,
    );
    assert!(result.is_err());

    // Remove SolLimit action from second authority
    let update_data = UpdateAuthorityData::RemoveActionsByType(vec![Permission::SolLimit as u8]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
        update_data,
    );
    assert!(result.is_ok());

    Ok(())
}

/// Test case:
/// - Have an authority with auth lock
/// - None of the cases should work that involves removing auth lock from the authority or the manage auth lock action
///
#[test]
fn test_update_authority_remove_by_type_auth_lock_manage_from_actions() -> anyhow::Result<()> {
    let mut context = setup_test_context()?;

    // Create initial wallet with Ed25519 authority
    let root_authority = Keypair::new();

    let id = [5u8; 32]; // Use a different ID for this test
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

    // Add a second authority that we can update
    let second_authority = Keypair::new();
    let second_authority_pubkey = second_authority.pubkey();
    let authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: second_authority_pubkey.as_ref(),
    };
    let actions = vec![
        ClientAction::ProgramAll(ProgramAll {}),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
    ];

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig_data
        .lookup_role_id(root_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();

    let _add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    )?;

    // let result = send_auth_lock_operation_transaction(
    //     &mut context,
    //     &swig,
    //     &root_authority,
    //     role_id,
    //     2, // authority_id 2 (the second authority)
    // )
    // .unwrap();

    // Remove AuthorizationLock action from second authority
    let update_data =
        UpdateAuthorityData::RemoveActionsByType(vec![Permission::AuthorizationLock as u8]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
        update_data,
    );
    assert!(result.is_err());

    // Remove ManageAuthorizationLocks action from second authority
    let update_data =
        UpdateAuthorityData::RemoveActionsByType(vec![Permission::ManageAuthorizationLocks as u8]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
        update_data,
    );
    assert!(result.is_ok());

    // Remove SolLimit action from second authority
    let update_data = UpdateAuthorityData::RemoveActionsByType(vec![Permission::SolLimit as u8]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
        update_data,
    );
    assert!(result.is_ok());

    Ok(())
}

/// Test case:
/// - Have an authority with auth lock
/// - None of the cases should work that involves removing auth lock from the authority or the manage auth lock action
///
#[test]
fn test_update_authority_remove_by_index_auth_lock_mints_from_actions() -> anyhow::Result<()> {
    let mut context = setup_test_context()?;

    // Create initial wallet with Ed25519 authority
    let root_authority = Keypair::new();

    let id = [5u8; 32]; // Use a different ID for this test
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

    // Add a second authority that we can update
    let second_authority = Keypair::new();
    let second_authority_pubkey = second_authority.pubkey();
    let authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: second_authority_pubkey.as_ref(),
    };
    let actions = vec![
        ClientAction::ProgramAll(ProgramAll {}),
        ClientAction::SolLimit(SolLimit { amount: 1000000 }),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
    ];

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig_data
        .lookup_role_id(root_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();

    let _add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    )?;

    let result = send_auth_lock_operation_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
    )
    .unwrap();

    // Remove AuthorizationLock action from second authority
    let update_data = UpdateAuthorityData::RemoveActionsByIndex(vec![3]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
        update_data,
    );
    assert!(result.is_err());

    // Remove ManageAuthorizationLocks action from second authority
    let update_data = UpdateAuthorityData::RemoveActionsByIndex(vec![2]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
        update_data,
    );
    assert!(result.is_err());

    // Remove SolLimit action from second authority
    let update_data = UpdateAuthorityData::RemoveActionsByIndex(vec![1]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
        update_data,
    );

    assert!(result.is_ok());

    Ok(())
}

/// Test case:
/// - Have an authority with auth lock
/// - None of the cases should work that involves removing auth lock from the authority or the manage auth lock action
///
#[test]
fn test_update_authority_remove_by_index_auth_lock_manage_from_actions() -> anyhow::Result<()> {
    let mut context = setup_test_context()?;

    // Create initial wallet with Ed25519 authority
    let root_authority = Keypair::new();

    let id = [5u8; 32]; // Use a different ID for this test
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

    // Add a second authority that we can update
    let second_authority = Keypair::new();
    let second_authority_pubkey = second_authority.pubkey();
    let authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: second_authority_pubkey.as_ref(),
    };
    let actions = vec![
        ClientAction::ProgramAll(ProgramAll {}),
        ClientAction::SolLimit(SolLimit { amount: 1000000 }),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
    ];

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig_data
        .lookup_role_id(root_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();

    let _add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    )?;

    // let result = send_auth_lock_operation_transaction(
    //     &mut context,
    //     &swig,
    //     &root_authority,
    //     role_id,
    //     2, // authority_id 2 (the second authority)
    // )
    // .unwrap();

    // Remove ManageAuthorizationLocks action from second authority
    let update_data = UpdateAuthorityData::RemoveActionsByIndex(vec![2]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
        update_data,
    );
    assert!(result.is_ok());

    // Remove SolLimit action from second authority
    let update_data = UpdateAuthorityData::RemoveActionsByIndex(vec![1]);
    let result = send_udpate_authority_transaction(
        &mut context,
        &swig,
        &root_authority,
        role_id,
        2, // authority_id 2 (the second authority)
        update_data,
    );
    assert!(result.is_ok());

    Ok(())
}
