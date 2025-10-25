#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.

mod common;

use common::*;
use solana_sdk::{
    instruction::InstructionError,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::TransactionError,
    transaction::VersionedTransaction,
};
use swig_interface::{
    AuthorityConfig, ClientAction, ManageAuthorizationLocksData,
    ManageAuthorizationLocksV1Instruction, SignV2Instruction, UpdateAuthorityData,
    UpdateAuthorityInstruction,
};
use swig_state::{
    action::{
        all::All, authorization_lock::AuthorizationLock,
        manage_auth_lock::ManageAuthorizationLocks, manage_authority::ManageAuthority,
        program_all::ProgramAll, sol_limit::SolLimit,
    },
    authority::AuthorityType,
    swig::{swig_wallet_address_seeds, SwigWithRoles},
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
    let initial_actions = vec![
        ClientAction::ProgramAll(ProgramAll {}),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
        ClientAction::SolLimit(SolLimit {
            amount: 2 * 1000000,
        }),
    ];

    let add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        initial_actions,
    );

    // Verify the authority was added successfully
    assert!(add_result.is_ok());

    // Verify initial state - check that the second authority has the expected actions
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

    // Verify we have 3 roles (global + root + second authority)
    assert_eq!(swig_data.state.roles, 3);

    // Get the second authority role (ID 2) and verify its initial actions
    let second_role = swig_data.get_role(2).unwrap().unwrap();
    let second_role_actions = second_role.get_all_actions().unwrap();
    assert_eq!(second_role_actions.len(), 3); // Should have 3 initial actions

    // Create new authorization lock actions to add
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

    // Add authorization locks to the second authority
    let result = manage_authorization_locks_with_ed25519(
        &mut context,
        &swig,
        &root_authority,
        2, // authority_id 2 (the second authority we just added)
        new_actions,
    );

    // Verify the transaction succeeded
    assert!(result.is_ok());

    // Verify the authorization locks were added correctly to the second authority
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

    let second_role = swig_data.get_role(2).unwrap().unwrap();
    let auth_lock_actions = second_role
        .get_all_actions_of_type::<AuthorizationLock>()
        .unwrap();

    // Should have 2 authorization lock actions
    assert_eq!(auth_lock_actions.len(), 2);

    // Verify the first authorization lock
    assert_eq!(auth_lock_actions[0].mint, [0u8; 32]);
    assert_eq!(auth_lock_actions[0].amount, 1000000);
    assert_eq!(auth_lock_actions[0].expires_at, 1000000);

    // Verify the second authorization lock
    assert_eq!(auth_lock_actions[1].mint, [1u8; 32]);
    assert_eq!(auth_lock_actions[1].amount, 2000000);
    assert_eq!(auth_lock_actions[1].expires_at, 2000000);

    // Verify global role cache was updated with the authorization locks
    let global_role = swig_data.get_role(0).unwrap().unwrap();
    let global_auth_lock_actions = global_role
        .get_all_actions_of_type::<AuthorizationLock>()
        .unwrap();

    // Global role should have the same authorization locks as the second authority
    assert_eq!(global_auth_lock_actions.len(), 2);

    // Verify the global cache has the first authorization lock
    assert_eq!(global_auth_lock_actions[0].mint, [0u8; 32]);
    assert_eq!(global_auth_lock_actions[0].amount, 1000000);
    assert_eq!(global_auth_lock_actions[0].expires_at, 1000000);

    // Verify the global cache has the second authorization lock
    assert_eq!(global_auth_lock_actions[1].mint, [1u8; 32]);
    assert_eq!(global_auth_lock_actions[1].amount, 2000000);
    assert_eq!(global_auth_lock_actions[1].expires_at, 2000000);

    // Derive wallet PDA and airdrop SOL to it
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;
    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000)
        .unwrap();

    // Also fund the secondary authority for fees
    context
        .svm
        .airdrop(&second_authority.pubkey(), 2_000_000)
        .unwrap();

    // Test 1: Create a SOL transaction that spends less than locked SOL (should succeed)
    let transfer_amount = 1000000; // Exactly the locked amount

    let transfer_ix = system_instruction::transfer(
        &swig_wallet_address,
        &context.default_payer.pubkey(),
        transfer_amount,
    );

    let sign_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        transfer_ix,
        2,
    )?;

    let message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )?;

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&second_authority])?;
    let result = context.svm.send_transaction(tx);

    // This should succeed because we're spending exactly the locked amount
    assert!(result.is_ok());

    // Test 2: Create a SOL transaction that spends more than locked SOL (should fail)
    let transfer_amount = 1000000 + 1; // More than the locked amount

    let transfer_ix = system_instruction::transfer(
        &swig_wallet_address,
        &context.default_payer.pubkey(),
        transfer_amount,
    );

    let sign_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        transfer_ix,
        2,
    )?;

    let message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )?;

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&second_authority])?;
    let result = context.svm.send_transaction(tx);

    // This should fail with the specific authorization lock error
    assert!(result.is_err());
    if let Err(e) = result {
        // Should get the authorization lock exceeded error
        assert!(matches!(
            e.err,
            TransactionError::InstructionError(_, InstructionError::Custom(3033))
        ));
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
    let initial_actions = vec![
        ClientAction::All(All {}),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
    ];

    let add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        initial_actions,
    );

    // Verify the authority was added successfully
    assert!(add_result.is_ok());

    // Verify initial state
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

    // Verify we have 3 roles (global + root + second authority)
    assert_eq!(swig_data.state.roles, 3);

    let auth_lock_actions = vec![
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

    let root_role_id = 1;

    // Add authorization locks to the second authority
    let add_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        root_role_id,
        2, // authority_id 2 (the second authority)
        ManageAuthorizationLocksData::AddLock(auth_lock_actions),
    )?;
    let msg = solana_sdk::message::v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_lock_ix],
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
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e));

    // Verify the add lock transaction succeeded
    assert!(result.is_ok());

    // Verify the authorization locks were added correctly
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

    let role = swig_data.get_role(2).unwrap().unwrap();
    let auth_lock_actions_before = role.get_all_actions_of_type::<AuthorizationLock>().unwrap();

    // Should have 2 authorization lock actions
    assert_eq!(auth_lock_actions_before.len(), 2);

    // Verify the first authorization lock
    assert_eq!(auth_lock_actions_before[0].mint, [0u8; 32]);
    assert_eq!(auth_lock_actions_before[0].amount, 1000000);
    assert_eq!(auth_lock_actions_before[0].expires_at, 1000000);

    // Verify the second authorization lock
    assert_eq!(auth_lock_actions_before[1].mint, [1u8; 32]);
    assert_eq!(auth_lock_actions_before[1].amount, 2000000);
    assert_eq!(auth_lock_actions_before[1].expires_at, 2000000);

    // Verify global role cache was updated with the authorization locks
    let global_role = swig_data.get_role(0).unwrap().unwrap();
    let global_auth_lock_actions_before = global_role
        .get_all_actions_of_type::<AuthorizationLock>()
        .unwrap();

    // Global role should have the same authorization locks as the second authority
    assert_eq!(global_auth_lock_actions_before.len(), 2);

    // Verify the global cache has the first authorization lock
    assert_eq!(global_auth_lock_actions_before[0].mint, [0u8; 32]);
    assert_eq!(global_auth_lock_actions_before[0].amount, 1000000);
    assert_eq!(global_auth_lock_actions_before[0].expires_at, 1000000);

    // Verify the global cache has the second authorization lock
    assert_eq!(global_auth_lock_actions_before[1].mint, [1u8; 32]);
    assert_eq!(global_auth_lock_actions_before[1].amount, 2000000);
    assert_eq!(global_auth_lock_actions_before[1].expires_at, 2000000);

    // Remove the first authorization lock
    let remove_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        root_role_id,
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
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e));

    // Verify the remove lock transaction succeeded
    assert!(result.is_ok());

    // Verify the authorization lock was removed correctly
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

    let role = swig_data.get_role(2).unwrap().unwrap();
    let auth_lock_actions_after = role.get_all_actions_of_type::<AuthorizationLock>().unwrap();

    // Should now have only 1 authorization lock action (the second one)
    assert_eq!(auth_lock_actions_after.len(), 1);

    // Verify the remaining authorization lock is the second one
    assert_eq!(auth_lock_actions_after[0].mint, [1u8; 32]);
    assert_eq!(auth_lock_actions_after[0].amount, 2000000);
    assert_eq!(auth_lock_actions_after[0].expires_at, 2000000);

    // Verify global role cache was updated after removal
    let global_role = swig_data.get_role(0).unwrap().unwrap();
    let global_auth_lock_actions_after = global_role
        .get_all_actions_of_type::<AuthorizationLock>()
        .unwrap();

    // Global role should now have only 1 authorization lock (the second one)
    assert_eq!(global_auth_lock_actions_after.len(), 1);

    // Verify the global cache has the remaining authorization lock
    assert_eq!(global_auth_lock_actions_after[0].mint, [1u8; 32]);
    assert_eq!(global_auth_lock_actions_after[0].amount, 2000000);
    assert_eq!(global_auth_lock_actions_after[0].expires_at, 2000000);

    Ok(())
}

#[test]
fn test_manage_authorization_locks_remove_locks() -> anyhow::Result<()> {
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
    let initial_actions = vec![
        ClientAction::All(All {}),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
    ];

    let add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        initial_actions,
    );

    // Verify the authority was added successfully
    assert!(add_result.is_ok());

    // Verify initial state
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

    // Verify we have 3 roles (global + root + second authority)
    assert_eq!(swig_data.state.roles, 3);

    let auth_lock_actions = vec![
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

    let root_role_id = 1;

    // Add authorization locks to the second authority
    let add_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        root_role_id,
        2, // authority_id 2 (the second authority)
        ManageAuthorizationLocksData::AddLock(auth_lock_actions),
    )?;
    let msg = solana_sdk::message::v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_lock_ix],
        &[],
        context.svm.latest_blockhash(),
    )?;
    let tx = solana_sdk::transaction::VersionedTransaction::try_new(
        solana_sdk::message::VersionedMessage::V0(msg),
        &[&context.default_payer, &root_authority],
    )?;
    let result = context.svm.send_transaction(tx);

    // Verify the add lock transaction succeeded
    assert!(result.is_ok());

    // Verify global role cache was updated after adding locks to second authority
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

    let global_role = swig_data.get_role(0).unwrap().unwrap();
    let global_auth_lock_actions = global_role
        .get_all_actions_of_type::<AuthorizationLock>()
        .unwrap();

    // Global role should have the authorization locks from the second authority
    assert_eq!(global_auth_lock_actions.len(), 2);

    // Verify the global cache has the first authorization lock
    assert_eq!(global_auth_lock_actions[0].mint, [0u8; 32]);
    assert_eq!(global_auth_lock_actions[0].amount, 1000000);
    assert_eq!(global_auth_lock_actions[0].expires_at, 1000000);

    // Verify the global cache has the second authorization lock
    assert_eq!(global_auth_lock_actions[1].mint, [1u8; 32]);
    assert_eq!(global_auth_lock_actions[1].amount, 2000000);
    assert_eq!(global_auth_lock_actions[1].expires_at, 2000000);

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
    ];

    let add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    );

    // Verify the third authority was added successfully
    assert!(add_result.is_ok());

    // Verify we now have 4 roles (global + root + second + third authority)
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    assert_eq!(swig_data.state.roles, 4);

    let auth_lock_actions = vec![
        ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [0u8; 32],
            amount: 3000000,
            expires_at: 3000000,
        }),
        ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [1u8; 32],
            amount: 2000000,
            expires_at: 500000,
        }),
    ];

    // Add authorization locks to the third authority
    let add_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        root_role_id,
        3, // authority_id 3 (the third authority)
        ManageAuthorizationLocksData::AddLock(auth_lock_actions),
    )?;
    let msg = solana_sdk::message::v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_lock_ix],
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
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e));

    // Verify the add lock transaction succeeded
    assert!(result.is_ok());

    // Verify global role cache was updated after adding locks to third authority
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

    let global_role = swig_data.get_role(0).unwrap().unwrap();
    let global_auth_lock_actions = global_role
        .get_all_actions_of_type::<AuthorizationLock>()
        .unwrap();

    // Global role should still have 2 authorization locks (same locks from both authorities)
    assert_eq!(global_auth_lock_actions.len(), 2);

    // Verify the global cache has the first authorization lock
    assert_eq!(global_auth_lock_actions[0].mint, [0u8; 32]);
    assert_eq!(global_auth_lock_actions[0].amount, 4000000);
    assert_eq!(global_auth_lock_actions[0].expires_at, 1000000);

    // Verify the global cache has the second authorization lock
    assert_eq!(global_auth_lock_actions[1].mint, [1u8; 32]);
    assert_eq!(global_auth_lock_actions[1].amount, 4000000);
    assert_eq!(global_auth_lock_actions[1].expires_at, 500000);

    // Verify both authorities have authorization locks
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

    // Check second authority (role 2)
    let second_role = swig_data.get_role(2).unwrap().unwrap();
    let second_auth_lock_actions = second_role
        .get_all_actions_of_type::<AuthorizationLock>()
        .unwrap();
    assert_eq!(second_auth_lock_actions.len(), 2);

    // Check third authority (role 3)
    let third_role = swig_data.get_role(3).unwrap().unwrap();
    let third_auth_lock_actions = third_role
        .get_all_actions_of_type::<AuthorizationLock>()
        .unwrap();
    assert_eq!(third_auth_lock_actions.len(), 2);

    // Verify global role cache has authorization locks from both authorities
    let global_role = swig_data.get_role(0).unwrap().unwrap();
    let global_auth_lock_actions = global_role
        .get_all_actions_of_type::<AuthorizationLock>()
        .unwrap();

    // Global role should have authorization locks from both authorities
    // Since both authorities have the same locks, the global cache should have 2 unique locks
    assert_eq!(global_auth_lock_actions.len(), 2);

    // Verify the global cache has the first authorization lock
    assert_eq!(global_auth_lock_actions[0].mint, [0u8; 32]);
    assert_eq!(global_auth_lock_actions[0].amount, 4000000);
    assert_eq!(global_auth_lock_actions[0].expires_at, 1000000);

    // Verify the global cache has the second authorization lock
    assert_eq!(global_auth_lock_actions[1].mint, [1u8; 32]);
    assert_eq!(global_auth_lock_actions[1].amount, 4000000);
    assert_eq!(global_auth_lock_actions[1].expires_at, 500000);

    // Remove the first authorization lock from the second authority
    let remove_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        root_role_id,
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
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e));

    // Verify the remove lock transaction succeeded
    assert!(result.is_ok());

    // Verify global role cache was updated after removing lock from second authority
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

    let global_role = swig_data.get_role(0).unwrap().unwrap();
    let global_auth_lock_actions_after_remove = global_role
        .get_all_actions_of_type::<AuthorizationLock>()
        .unwrap();

    // Global role should still have 2 authorization locks since third authority has both
    assert_eq!(global_auth_lock_actions_after_remove.len(), 2);

    // Verify the global cache still has both authorization locks
    assert_eq!(global_auth_lock_actions_after_remove[0].mint, [0u8; 32]);
    assert_eq!(global_auth_lock_actions_after_remove[0].amount, 3000000);
    assert_eq!(global_auth_lock_actions_after_remove[0].expires_at, 3000000);

    assert_eq!(global_auth_lock_actions_after_remove[1].mint, [1u8; 32]);
    assert_eq!(global_auth_lock_actions_after_remove[1].amount, 4000000);
    assert_eq!(global_auth_lock_actions_after_remove[1].expires_at, 500000);

    // Verify the authorization lock was removed correctly from the second authority
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

    // Check second authority now has only 1 authorization lock
    let second_role = swig_data.get_role(2).unwrap().unwrap();
    let second_auth_lock_actions_after = second_role
        .get_all_actions_of_type::<AuthorizationLock>()
        .unwrap();
    assert_eq!(second_auth_lock_actions_after.len(), 1);
    assert_eq!(second_auth_lock_actions_after[0].mint, [1u8; 32]);

    // Check third authority still has 2 authorization locks (unchanged)
    let third_role = swig_data.get_role(3).unwrap().unwrap();
    let third_auth_lock_actions_after = third_role
        .get_all_actions_of_type::<AuthorizationLock>()
        .unwrap();
    assert_eq!(third_auth_lock_actions_after.len(), 2);

    // Verify global role cache still has authorization locks
    // Since the third authority still has both locks, the global cache should still have 2 locks
    let global_role = swig_data.get_role(0).unwrap().unwrap();
    let global_auth_lock_actions_after = global_role
        .get_all_actions_of_type::<AuthorizationLock>()
        .unwrap();

    // Global role should still have 2 authorization locks since third authority has both
    assert_eq!(global_auth_lock_actions_after.len(), 2);

    // Verify the global cache still has both authorization locks
    assert_eq!(global_auth_lock_actions_after[0].mint, [0u8; 32]);
    assert_eq!(global_auth_lock_actions_after[0].amount, 3000000);
    assert_eq!(global_auth_lock_actions_after[0].expires_at, 3000000);

    assert_eq!(global_auth_lock_actions_after[1].mint, [1u8; 32]);
    assert_eq!(global_auth_lock_actions_after[1].amount, 4000000);
    assert_eq!(global_auth_lock_actions_after[1].expires_at, 500000);

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
    let initial_actions = vec![
        ClientAction::All(All {}),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
    ];

    let add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        initial_actions,
    );

    // Verify the authority was added successfully
    assert!(add_result.is_ok());

    // Verify initial state
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

    // Verify we have 3 roles (global + root + second authority)
    assert_eq!(swig_data.state.roles, 3);

    let auth_lock_actions = vec![
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

    // Add authorization locks to the second authority
    let add_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        1,
        2, // authority_id 2 (the second authority)
        ManageAuthorizationLocksData::AddLock(auth_lock_actions),
    )?;
    let msg = solana_sdk::message::v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_lock_ix],
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
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e));

    // Verify the add lock transaction succeeded
    assert!(result.is_ok());

    // Verify the authorization locks were added correctly
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

    let role = swig_data.get_role(2).unwrap().unwrap();
    let auth_lock_actions_before = role.get_all_actions_of_type::<AuthorizationLock>().unwrap();

    // Should have 2 authorization lock actions
    assert_eq!(auth_lock_actions_before.len(), 2);

    // Verify the first authorization lock
    assert_eq!(auth_lock_actions_before[0].mint, [0u8; 32]);
    assert_eq!(auth_lock_actions_before[0].amount, 1000000);
    assert_eq!(auth_lock_actions_before[0].expires_at, 1000000);

    // Verify the second authorization lock
    assert_eq!(auth_lock_actions_before[1].mint, [1u8; 32]);
    assert_eq!(auth_lock_actions_before[1].amount, 2000000);
    assert_eq!(auth_lock_actions_before[1].expires_at, 2000000);

    // Verify global role cache was updated with the authorization locks
    let global_role = swig_data.get_role(0).unwrap().unwrap();
    let global_auth_lock_actions_before = global_role
        .get_all_actions_of_type::<AuthorizationLock>()
        .unwrap();

    // Global role should have the same authorization locks as the second authority
    assert_eq!(global_auth_lock_actions_before.len(), 2);

    // Verify the global cache has the first authorization lock
    assert_eq!(global_auth_lock_actions_before[0].mint, [0u8; 32]);
    assert_eq!(global_auth_lock_actions_before[0].amount, 1000000);
    assert_eq!(global_auth_lock_actions_before[0].expires_at, 1000000);

    // Verify the global cache has the second authorization lock
    assert_eq!(global_auth_lock_actions_before[1].mint, [1u8; 32]);
    assert_eq!(global_auth_lock_actions_before[1].amount, 2000000);
    assert_eq!(global_auth_lock_actions_before[1].expires_at, 2000000);

    // Get role_id for the root authority
    let role_id = swig_data
        .lookup_role_id(root_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();

    // Verify we got the correct role ID
    assert_eq!(role_id, 1);

    // Update the first authorization lock with new values
    let update_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
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
        &[update_lock_ix],
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
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e));

    // Verify the update lock transaction succeeded
    assert!(result.is_ok());

    // Verify the authorization lock was updated correctly
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

    let role = swig_data.get_role(2).unwrap().unwrap();
    let role_actions = role.get_all_actions().unwrap();

    // Should still have the same number of actions (All + ManageAuthorizationLocks + 2 AuthorizationLocks)
    assert_eq!(role_actions.len(), 4);

    let authlock_actions = role.get_all_actions_of_type::<AuthorizationLock>().unwrap();

    // Should still have 2 authorization lock actions
    assert_eq!(authlock_actions.len(), 2);

    // Verify the first authorization lock was updated
    assert_eq!(authlock_actions[0].mint, [0u8; 32]);
    assert_eq!(authlock_actions[0].amount, 20);
    assert_eq!(authlock_actions[0].expires_at, 20);

    // Verify the second authorization lock remains unchanged
    assert_eq!(authlock_actions[1].mint, [1u8; 32]);
    assert_eq!(authlock_actions[1].amount, 2000000);
    assert_eq!(authlock_actions[1].expires_at, 2000000);

    // Verify global role cache was updated after the lock update
    let global_role = swig_data.get_role(0).unwrap().unwrap();
    let global_auth_lock_actions_after = global_role
        .get_all_actions_of_type::<AuthorizationLock>()
        .unwrap();

    // Global role should still have 2 authorization locks
    assert_eq!(global_auth_lock_actions_after.len(), 2);

    // Verify the global cache has the updated first authorization lock
    assert_eq!(global_auth_lock_actions_after[0].mint, [0u8; 32]);
    assert_eq!(global_auth_lock_actions_after[0].amount, 20);
    assert_eq!(global_auth_lock_actions_after[0].expires_at, 20);

    // Verify the global cache has the unchanged second authorization lock
    assert_eq!(global_auth_lock_actions_after[1].mint, [1u8; 32]);
    assert_eq!(global_auth_lock_actions_after[1].amount, 2000000);
    assert_eq!(global_auth_lock_actions_after[1].expires_at, 2000000);

    Ok(())
}
