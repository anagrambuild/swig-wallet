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
use swig_interface::{ManageAuthorizationLocksData, ManageAuthorizationLocksV1Instruction};
use swig_state::{
    action::{
        all::All, authorization_lock::AuthorizationLock,
        manage_auth_lock::ManageAuthorizationLocks, manage_authority::ManageAuthority,
        sol_limit::SolLimit,
    },
    authority::AuthorityType,
    swig::SwigWithRoles,
};

/// Helper function to update authority with Ed25519 root authority
pub fn manage_authorization_locks_with_ed25519(
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

    let manage_authorization_locks_ix =
        ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
            *swig_pubkey,
            payer_pubkey,
            existing_ed25519_authority.pubkey(),
            role_id,
            authority_to_update_id,
            ManageAuthorizationLocksData::AddLock(new_actions),
        )?;

    let msg = solana_sdk::message::v0::Message::try_compile(
        &payer_pubkey,
        &[manage_authorization_locks_ix],
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
fn test_manage_authorization_locks_ed25519_add_lock() -> anyhow::Result<()> {
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
    let actions = vec![
        ClientAction::All(All {}),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
    ];

    let _add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    )?;

    // Create new actions to replace all existing actions on the second authority
    let new_actions = vec![
        ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [0u8; 32],
            amount: 1000000,
            expires_at: 1000000,
        }),
        ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [1u8; 32],
            amount: 2000000,
            expires_at: 2000000,
        }),
    ];

    // Update the second authority (ID 1) to replace all actions
    let result = manage_authorization_locks_with_ed25519(
        &mut context,
        &swig,
        &root_authority,
        2, // authority_id 2 (the second authority we just added)
        new_actions,
    )?;

    // Verify the transaction succeeded by checking logs don't contain errors
    println!("Transaction logs: {:?}", result.logs);

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role = swig_data.get_role(2).unwrap().unwrap();
    let role_actions = role.get_all_actions().unwrap();
    for action in role_actions {
        println!("action: {:?}", action.permission());
    }
    Ok(())
}

#[test]
fn test_manage_authorization_locks_ed25519_remove_lock() -> anyhow::Result<()> {
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
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
        ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [0u8; 32],
            amount: 1000000,
            expires_at: 1000000,
        }),
        ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [1u8; 32],
            amount: 2000000,
            expires_at: 2000000,
        }),
    ];

    let add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    );
    println!("Added authority with actions: {:?}", add_result);
    assert!(add_result.is_ok());

    // Add a third authority that we can update
    let third_authority = Keypair::new();
    let third_authority_pubkey = third_authority.pubkey();
    let authority_config = AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: third_authority_pubkey.as_ref(),
    };
    let actions = vec![
        ClientAction::All(All {}),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
        ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [0u8; 32],
            amount: 1000000,
            expires_at: 1000000,
        }),
        ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [1u8; 32],
            amount: 2000000,
            expires_at: 2000000,
        }),
    ];

    let _add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    );
    println!("Added third authority with actions: {:?}", add_result);
    assert!(add_result.is_ok());

    // Get role_id for the root authority
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig_data
        .lookup_role_id(root_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();
    println!("Got role_id {:?}", role_id);

    // Remove the lock
    let remove_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        role_id,
        2, // authority_id 2 (the second authority)
        ManageAuthorizationLocksData::RemoveLock(vec![[0u8; 32]]),
    )?;

    let msg = solana_sdk::message::v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_lock_ix],
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
    let role_actions = role.get_all_actions().unwrap();
    for action in role_actions {
        println!("action: {:?}", action.permission());
    }
    Ok(())
}

#[test]
fn test_manage_authorization_locks_ed25519_update_lock() -> anyhow::Result<()> {
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
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
        ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [0u8; 32],
            amount: 10,
            expires_at: 1000000,
        }),
        ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [1u8; 32],
            amount: 10,
            expires_at: 2000000,
        }),
    ];

    let add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    );
    println!("Added authority with actions: {:?}", add_result);
    assert!(add_result.is_ok());

    // Get role_id for the root authority
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig_data
        .lookup_role_id(root_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();
    println!("Got role_id {:?}", role_id);

    // Update the lock
    let remove_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        role_id,
        2, // authority_id 2 (the second authority)
        ManageAuthorizationLocksData::UpdateLock(vec![ClientAction::AuthorizationLock(
            AuthorizationLock {
                mint: [0u8; 32],
                amount: 20,
                expires_at: 20,
            },
        )]),
    )?;

    let msg = solana_sdk::message::v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_lock_ix],
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
    let role_actions = role.get_all_actions().unwrap();
    for action in role_actions {
        println!("action: {:?}", action.permission());
    }
    let authlock_actions = role.get_all_actions_of_type::<AuthorizationLock>().unwrap();
    for action in authlock_actions {
        println!("authlock_action: {:?}", action.mint);
        println!("authlock_action: {:?}", action.amount);
        println!("authlock_action: {:?}", action.expires_at);
    }
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
