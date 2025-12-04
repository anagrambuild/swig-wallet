#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.

mod common;

use common::*;
use litesvm_token::spl_token::{self, instruction::TokenInstruction};
use solana_sdk::{
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::TransactionError,
    transaction::VersionedTransaction,
};
use swig_interface::{
    AuthorityConfig, ClientAction, SignV2Instruction, UpdateAuthorityData,
    UpdateAuthorityInstruction,
};
use swig_state::{
    action::{
        all::All, authlock::AuthorizationLock, manage_authlock::ManageAuthorizationLocks,
        manage_authority::ManageAuthority, program_all::ProgramAll, sol_limit::SolLimit,
        token_limit::TokenLimit, Permission,
    },
    authority::AuthorityType,
    swig::{swig_wallet_address_seeds, SwigWithRoles},
};

/// Helper function to update authority with Ed25519 root authority
// pub fn manage_authorization_locks_with_ed25519(
//     context: &mut SwigTestContext,
//     swig_pubkey: &Pubkey,
//     existing_ed25519_authority: &Keypair,
//     authority_to_update_id: u32,
//     new_actions: Vec<ClientAction>,
// ) -> anyhow::Result<litesvm::types::TransactionMetadata> {
//     context.svm.expire_blockhash();
//     let payer_pubkey = context.default_payer.pubkey();
//     let swig_account = context
//         .svm
//         .get_account(swig_pubkey)
//         .ok_or(anyhow::anyhow!("Swig account not found"))?;
//     let swig = SwigWithRoles::from_bytes(&swig_account.data)
//         .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
//     let role_id = swig
//         .lookup_role_id(existing_ed25519_authority.pubkey().as_ref())
//         .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
//         .unwrap();

//     let manage_authorization_locks_ix =
//         ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
//             *swig_pubkey,
//             payer_pubkey,
//             existing_ed25519_authority.pubkey(),
//             role_id,
//             authority_to_update_id,
//             ManageAuthorizationLocksData::AddLock(new_actions),
//         )?;

//     let msg = solana_sdk::message::v0::Message::try_compile(
//         &payer_pubkey,
//         &[manage_authorization_locks_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )
//     .map_err(|e| anyhow::anyhow!("Failed to compile message {:?}", e))?;

//     let tx = solana_sdk::transaction::VersionedTransaction::try_new(
//         solana_sdk::message::VersionedMessage::V0(msg),
//         &[&context.default_payer, existing_ed25519_authority],
//     )
//     .map_err(|e| anyhow::anyhow!("Failed to create transaction {:?}", e))?;

//     let result = context
//         .svm
//         .send_transaction(tx)
//         .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e))?;

//     Ok(result)
// }

#[test_log::test]
fn test_authlock_add_authority_with_manage_authlock() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    let (swig_key, swig_create_txn) =
        create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    )
    .unwrap();
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 3);
    assert_eq!(swig.state.role_counter, 3);
    let role_2 = swig.get_role(2).unwrap().unwrap();
    assert_eq!(role_2.authority.authority_type(), AuthorityType::Ed25519);
    assert!(!role_2.authority.session_based());
    assert_eq!(
        role_2.position.authority_type().unwrap(),
        AuthorityType::Ed25519
    );
    assert_eq!(role_2.position.authority_length(), 32);
    assert_eq!(role_2.position.num_actions(), 1);
    let action = role_2.get_action::<ManageAuthorizationLocks>(&[]).unwrap();
    assert!(action.is_some());
    let actions = role_2.get_all_actions().unwrap();
    assert!(actions.len() == 1);
    assert!(actions[0].permission().unwrap() == Permission::ManageAuthorizationLocks);
}

#[test_log::test]
fn test_authlock_add_authority_with_manage_authlock_and_authorization_lock() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    let (swig_key, swig_create_txn) =
        create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    let result = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 1_000_000,
                expires_at: 1000000,
            }),
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [1u8; 32],
                amount: 2_000_000,
                expires_at: 2000000,
            }),
        ],
    );

    assert!(result.is_err());

    // Sucess case with only manage authorization locks
    let result = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );
    assert!(result.is_ok());

    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 3);
    assert_eq!(swig.state.role_counter, 3);
    let role_2 = swig.get_role(2).unwrap().unwrap();
    assert_eq!(role_2.authority.authority_type(), AuthorityType::Ed25519);
    assert!(!role_2.authority.session_based());
    assert_eq!(
        role_2.position.authority_type().unwrap(),
        AuthorityType::Ed25519
    );
    assert_eq!(role_2.position.authority_length(), 32);
    assert_eq!(role_2.position.num_actions(), 1);
    let action = role_2.get_action::<ManageAuthorizationLocks>(&[]).unwrap();
    assert!(action.is_some());

    /// UPDATE AUTHORITY WITH AUTHORIZATION LOCKS
    /// updating the authority role with authorization locks
    let new_actions: Vec<ClientAction> = vec![
        ClientAction::SolLimit(SolLimit { amount: 1000000 }),
        ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [0u8; 32],
            amount: 1_000_000,
            expires_at: 1000000,
        }),
        ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [1u8; 32],
            amount: 2_000_000,
            expires_at: 2000000,
        }),
    ];

    // Update the second authority (ID 1) to replace all actions
    let result = update_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        2, // authority_id 2 (the second authority we just added)
        new_actions,
    );

    println!("result: {:?}", result);
    assert!(result.is_err());

    /// updating the authority role with authorization locks
    let new_actions: Vec<ClientAction> = vec![
        ClientAction::SolLimit(SolLimit { amount: 1000000 }),
        ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [0u8; 32],
            amount: 1_000_000,
            expires_at: 1000000,
        }),
        ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [1u8; 32],
            amount: 2_000_000,
            expires_at: 2000000,
        }),
    ];

    let update_authority_data = UpdateAuthorityData::AddActions(new_actions);

    // Update the second authority (ID 1) to replace all actions
    let result = update_authority_with_ed25519_root_with_remove_actions(
        &mut context,
        &swig_key,
        &swig_authority,
        2, // authority_id 2 (the second authority we just added)
        update_authority_data,
    );

    println!("result: {:?}", result);
    assert!(result.is_err());

    /// updating the authority role with authorization locks
    let new_actions: Vec<ClientAction> = vec![
        ClientAction::SolLimit(SolLimit { amount: 1000000 }),
        ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [0u8; 32],
            amount: 1_000_000,
            expires_at: 1000000,
        }),
        ClientAction::AuthorizationLock(AuthorizationLock {
            mint: [1u8; 32],
            amount: 2_000_000,
            expires_at: 2000000,
        }),
    ];

    let update_authority_data = UpdateAuthorityData::ReplaceAll(new_actions);

    // Update the second authority (ID 1) to replace all actions
    let result = update_authority_with_ed25519_root_with_remove_actions(
        &mut context,
        &swig_key,
        &swig_authority,
        2, // authority_id 2 (the second authority we just added)
        update_authority_data,
    );

    println!("result: {:?}", result);
    assert!(result.is_err());

    /// updating the authority role with authorization locks
    let new_actions: Vec<ClientAction> = vec![
        ClientAction::SolLimit(SolLimit { amount: 1000000 }),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
    ];

    let update_authority_data = UpdateAuthorityData::AddActions(new_actions);

    // Update the second authority (ID 1) to replace all actions
    let result = update_authority_with_ed25519_root_with_remove_actions(
        &mut context,
        &swig_key,
        &swig_authority,
        2, // authority_id 2 (the second authority we just added)
        update_authority_data,
    );

    println!("result: {:?}", result);
    assert!(result.is_ok());
}

// #[test]
// fn test_manage_authorization_locks_ed25519_add_lock() -> anyhow::Result<()> {
//     let mut context = setup_test_context()?;

//     // Create initial wallet with Ed25519 authority
//     let root_authority = Keypair::new();
//     let id = [1u8; 32]; // Use a fixed ID for testing
//     let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

//     // Add a second authority that we can update (since we can't update root
//     // authority ID 0)
//     let second_authority = Keypair::new();
//     let second_authority_pubkey = second_authority.pubkey();
//     let authority_config = AuthorityConfig {
//         authority_type: AuthorityType::Ed25519,
//         authority: second_authority_pubkey.as_ref(),
//     };
//     let initial_actions = vec![
//         ClientAction::ProgramAll(ProgramAll {}),
//         ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
//         ClientAction::SolLimit(SolLimit {
//             amount: 4 * 1_000_000,
//         }),
//     ];

//     let add_result = add_authority_with_ed25519_root(
//         &mut context,
//         &swig,
//         &root_authority,
//         authority_config,
//         initial_actions,
//     );

//     // Verify the authority was added successfully
//     assert!(add_result.is_ok());

//     // Verify initial state - check that the second authority has the expected actions
//     let swig_account = context.svm.get_account(&swig).unwrap();
//     let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
//         .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

//     // Verify we have 3 roles (global + root + second authority)
//     assert_eq!(swig_data.state.roles, 3);

//     // Get the second authority role (ID 2) and verify its initial actions
//     let second_role = swig_data.get_role(2).unwrap().unwrap();
//     let second_role_actions = second_role.get_all_actions().unwrap();
//     assert_eq!(second_role_actions.len(), 3); // Should have 3 initial actions

//     // Create new authorization lock actions to add
//     let new_actions = vec![
//         ClientAction::AuthorizationLock(AuthorizationLock {
//             mint: [0u8; 32],
//             amount: 1_500_000,
//             expires_at: 1000000,
//         }),
//         ClientAction::AuthorizationLock(AuthorizationLock {
//             mint: [1u8; 32],
//             amount: 2000000,
//             expires_at: 2000000,
//         }),
//     ];

//     // Add authorization locks to the second authority
//     let result = manage_authorization_locks_with_ed25519(
//         &mut context,
//         &swig,
//         &root_authority,
//         2, // authority_id 2 (the second authority we just added)
//         new_actions,
//     );

//     // Verify the transaction succeeded
//     assert!(result.is_ok());

//     // Verify the authorization locks were added correctly to the second authority
//     let swig_account = context.svm.get_account(&swig).unwrap();
//     let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
//         .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

//     let second_role = swig_data.get_role(2).unwrap().unwrap();
//     let auth_lock_actions = second_role
//         .get_all_actions_of_type::<AuthorizationLock>()
//         .unwrap();

//     // Should have 2 authorization lock actions
//     assert_eq!(auth_lock_actions.len(), 2);

//     // Verify the first authorization lock
//     assert_eq!(auth_lock_actions[0].mint, [0u8; 32]);
//     assert_eq!(auth_lock_actions[0].amount, 1500000);
//     assert_eq!(auth_lock_actions[0].expires_at, 1000000);

//     // Verify the second authorization lock
//     assert_eq!(auth_lock_actions[1].mint, [1u8; 32]);
//     assert_eq!(auth_lock_actions[1].amount, 2000000);
//     assert_eq!(auth_lock_actions[1].expires_at, 2000000);

//     // Verify global role cache was updated with the authorization locks
//     let global_role = swig_data.get_role(0).unwrap().unwrap();
//     let global_auth_lock_actions = global_role
//         .get_all_actions_of_type::<AuthorizationLock>()
//         .unwrap();

//     // Global role should have the same authorization locks as the second authority
//     assert_eq!(global_auth_lock_actions.len(), 2);

//     // Verify the global cache has the first authorization lock
//     assert_eq!(global_auth_lock_actions[0].mint, [0u8; 32]);
//     assert_eq!(global_auth_lock_actions[0].amount, 1500000);
//     assert_eq!(global_auth_lock_actions[0].expires_at, 1000000);

//     // Verify the global cache has the second authorization lock
//     assert_eq!(global_auth_lock_actions[1].mint, [1u8; 32]);
//     assert_eq!(global_auth_lock_actions[1].amount, 2000000);
//     assert_eq!(global_auth_lock_actions[1].expires_at, 2000000);

//     // Derive wallet PDA and airdrop SOL to it
//     let swig_wallet_address =
//         Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;
//     context
//         .svm
//         .airdrop(&swig_wallet_address, 5_000_000)
//         .unwrap();

//     // Also fund the secondary authority for fees
//     context
//         .svm
//         .airdrop(&second_authority.pubkey(), 2_000_000)
//         .unwrap();

//     // Test 1: Create a SOL transaction that keeps balance above the lock (should succeed)
//     // Balance: 5_000_000, Lock: 1_500_000, Rent exempt: ~890_000
//     // Effective balance for check: 5_000_000 - 890_000 = 4_110_000
//     // Max we can transfer: 4_110_000 - 1_500_000 = 2_610_000
//     // Let's transfer 2_000_000 (leaves 2_000_000 - 890_000 = 1_110_000 after rent, which is < 1_500_000??)
//     // Actually, after transfer, remaining balance is 3_000_000, so effective is 3_000_000 - 890_000 = 2_110_000, which is >= 1_500_000
//     let transfer_amount = 1_900_000;

//     let transfer_ix = system_instruction::transfer(
//         &swig_wallet_address,
//         &context.default_payer.pubkey(),
//         transfer_amount,
//     );

//     let sign_ix = SignV2Instruction::new_ed25519(
//         swig,
//         swig_wallet_address,
//         second_authority.pubkey(),
//         transfer_ix,
//         2,
//     )?;

//     let message = v0::Message::try_compile(
//         &second_authority.pubkey(),
//         &[sign_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )?;

//     let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&second_authority])?;

//     let swig_wallet_balance = context.svm.get_balance(&swig_wallet_address).unwrap();
//     println!("swig_wallet_balance: {}", swig_wallet_balance);

//     let result = context.svm.send_transaction(tx);

//     println!("result: {:?}", result);
//     // This should succeed because balance after transfer (2_000_000) >= lock (1_500_000)
//     assert!(result.is_ok());

//     // Test 2: Create a SOL transaction that would go below the lock (should fail)
//     // After first transfer, balance should be around 3_000_000 (5_000_000 - 2_000_000)
//     // Rent exempt: ~890_000
//     // Effective balance: 3_000_000 - 890_000 = 2_110_000
//     // Max we can transfer: 2_110_000 - 1_500_000 = 610_000
//     // Let's try to transfer 700_000 (would leave effective balance 1_410_000, which is < 1_500_000)
//     let swig_wallet_balance = context.svm.get_balance(&swig_wallet_address).unwrap();

//     let transfer_amount = swig_wallet_balance - 1500000 + 1;

//     let transfer_ix = system_instruction::transfer(
//         &swig_wallet_address,
//         &context.default_payer.pubkey(),
//         transfer_amount,
//     );

//     let sign_ix = SignV2Instruction::new_ed25519(
//         swig,
//         swig_wallet_address,
//         second_authority.pubkey(),
//         transfer_ix,
//         2,
//     )?;

//     let message = v0::Message::try_compile(
//         &second_authority.pubkey(),
//         &[sign_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )?;

//     let swig_wallet_balance = context.svm.get_balance(&swig_wallet_address).unwrap();
//     println!("swig_wallet_balance: {}", swig_wallet_balance);
//     let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&second_authority])?;
//     let result = context.svm.send_transaction(tx);

//     println!("result: {:?}", result);
//     // This should fail with the specific authorization lock error
//     assert!(result.is_err());
//     if let Err(e) = result {
//         // Should get the authorization lock exceeded error
//         assert!(matches!(
//             e.err,
//             TransactionError::InstructionError(_, InstructionError::Custom(3033))
//         ));
//     }

//     Ok(())
// }

// #[test]
// fn test_manage_authorization_locks_ed25519_remove_lock() -> anyhow::Result<()> {
//     let mut context = setup_test_context()?;

//     // Create initial wallet with Ed25519 authority
//     let root_authority = Keypair::new();
//     let id = [3u8; 32]; // Use a different ID for this test
//     let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

//     // Add a second authority that we can update
//     let second_authority = Keypair::new();
//     let second_authority_pubkey = second_authority.pubkey();
//     let authority_config = AuthorityConfig {
//         authority_type: AuthorityType::Ed25519,
//         authority: second_authority_pubkey.as_ref(),
//     };
//     let initial_actions = vec![
//         ClientAction::All(All {}),
//         ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
//     ];

//     let add_result = add_authority_with_ed25519_root(
//         &mut context,
//         &swig,
//         &root_authority,
//         authority_config,
//         initial_actions,
//     );

//     // Verify the authority was added successfully
//     assert!(add_result.is_ok());

//     // Verify initial state
//     let swig_account = context.svm.get_account(&swig).unwrap();
//     let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
//         .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

//     // Verify we have 3 roles (global + root + second authority)
//     assert_eq!(swig_data.state.roles, 3);

//     let auth_lock_actions = vec![
//         ClientAction::AuthorizationLock(AuthorizationLock {
//             mint: [0u8; 32],
//             amount: 1000000,
//             expires_at: 1000000,
//         }),
//         ClientAction::AuthorizationLock(AuthorizationLock {
//             mint: [1u8; 32],
//             amount: 2000000,
//             expires_at: 2000000,
//         }),
//     ];

//     let root_role_id = 1;

//     // Add authorization locks to the second authority
//     let add_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
//         swig,
//         context.default_payer.pubkey(),
//         root_authority.pubkey(),
//         root_role_id,
//         2, // authority_id 2 (the second authority)
//         ManageAuthorizationLocksData::AddLock(auth_lock_actions),
//     )?;
//     let msg = solana_sdk::message::v0::Message::try_compile(
//         &context.default_payer.pubkey(),
//         &[add_lock_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )?;
//     let tx = solana_sdk::transaction::VersionedTransaction::try_new(
//         solana_sdk::message::VersionedMessage::V0(msg),
//         &[&context.default_payer, &root_authority],
//     )?;
//     let result = context
//         .svm
//         .send_transaction(tx)
//         .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e));

//     // Verify the add lock transaction succeeded
//     assert!(result.is_ok());

//     // Verify the authorization locks were added correctly
//     let swig_account = context.svm.get_account(&swig).unwrap();
//     let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
//         .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

//     let role = swig_data.get_role(2).unwrap().unwrap();
//     let auth_lock_actions_before = role.get_all_actions_of_type::<AuthorizationLock>().unwrap();

//     // Should have 2 authorization lock actions
//     assert_eq!(auth_lock_actions_before.len(), 2);

//     // Verify the first authorization lock
//     assert_eq!(auth_lock_actions_before[0].mint, [0u8; 32]);
//     assert_eq!(auth_lock_actions_before[0].amount, 1000000);
//     assert_eq!(auth_lock_actions_before[0].expires_at, 1000000);

//     // Verify the second authorization lock
//     assert_eq!(auth_lock_actions_before[1].mint, [1u8; 32]);
//     assert_eq!(auth_lock_actions_before[1].amount, 2000000);
//     assert_eq!(auth_lock_actions_before[1].expires_at, 2000000);

//     // Verify global role cache was updated with the authorization locks
//     let global_role = swig_data.get_role(0).unwrap().unwrap();
//     let global_auth_lock_actions_before = global_role
//         .get_all_actions_of_type::<AuthorizationLock>()
//         .unwrap();

//     // Global role should have the same authorization locks as the second authority
//     assert_eq!(global_auth_lock_actions_before.len(), 2);

//     // Verify the global cache has the first authorization lock
//     assert_eq!(global_auth_lock_actions_before[0].mint, [0u8; 32]);
//     assert_eq!(global_auth_lock_actions_before[0].amount, 1000000);
//     assert_eq!(global_auth_lock_actions_before[0].expires_at, 1000000);

//     // Verify the global cache has the second authorization lock
//     assert_eq!(global_auth_lock_actions_before[1].mint, [1u8; 32]);
//     assert_eq!(global_auth_lock_actions_before[1].amount, 2000000);
//     assert_eq!(global_auth_lock_actions_before[1].expires_at, 2000000);

//     // Remove the first authorization lock
//     let remove_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
//         swig,
//         context.default_payer.pubkey(),
//         root_authority.pubkey(),
//         root_role_id,
//         2, // authority_id 2 (the second authority)
//         ManageAuthorizationLocksData::RemoveLock(vec![[0u8; 32]]),
//     )?;

//     let msg = solana_sdk::message::v0::Message::try_compile(
//         &context.default_payer.pubkey(),
//         &[remove_lock_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )?;

//     let tx = solana_sdk::transaction::VersionedTransaction::try_new(
//         solana_sdk::message::VersionedMessage::V0(msg),
//         &[&context.default_payer, &root_authority],
//     )?;

//     let result = context
//         .svm
//         .send_transaction(tx)
//         .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e));

//     // Verify the remove lock transaction succeeded
//     assert!(result.is_ok());

//     // Verify the authorization lock was removed correctly
//     let swig_account = context.svm.get_account(&swig).unwrap();
//     let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
//         .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

//     let role = swig_data.get_role(2).unwrap().unwrap();
//     let auth_lock_actions_after = role.get_all_actions_of_type::<AuthorizationLock>().unwrap();

//     // Should now have only 1 authorization lock action (the second one)
//     assert_eq!(auth_lock_actions_after.len(), 1);

//     // Verify the remaining authorization lock is the second one
//     assert_eq!(auth_lock_actions_after[0].mint, [1u8; 32]);
//     assert_eq!(auth_lock_actions_after[0].amount, 2000000);
//     assert_eq!(auth_lock_actions_after[0].expires_at, 2000000);

//     // Verify global role cache was updated after removal
//     let global_role = swig_data.get_role(0).unwrap().unwrap();
//     let global_auth_lock_actions_after = global_role
//         .get_all_actions_of_type::<AuthorizationLock>()
//         .unwrap();

//     // Global role should now have only 1 authorization lock (the second one)
//     assert_eq!(global_auth_lock_actions_after.len(), 1);

//     // Verify the global cache has the remaining authorization lock
//     assert_eq!(global_auth_lock_actions_after[0].mint, [1u8; 32]);
//     assert_eq!(global_auth_lock_actions_after[0].amount, 2000000);
//     assert_eq!(global_auth_lock_actions_after[0].expires_at, 2000000);

//     Ok(())
// }

// #[test]
// fn test_manage_authorization_locks_remove_locks() -> anyhow::Result<()> {
//     let mut context = setup_test_context()?;

//     // Create initial wallet with Ed25519 authority
//     let root_authority = Keypair::new();
//     let id = [3u8; 32]; // Use a different ID for this test
//     let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

//     // Add a second authority that we can update
//     let second_authority = Keypair::new();
//     let second_authority_pubkey = second_authority.pubkey();
//     let authority_config = AuthorityConfig {
//         authority_type: AuthorityType::Ed25519,
//         authority: second_authority_pubkey.as_ref(),
//     };
//     let initial_actions = vec![
//         ClientAction::All(All {}),
//         ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
//     ];

//     let add_result = add_authority_with_ed25519_root(
//         &mut context,
//         &swig,
//         &root_authority,
//         authority_config,
//         initial_actions,
//     );

//     // Verify the authority was added successfully
//     assert!(add_result.is_ok());

//     // Verify initial state
//     let swig_account = context.svm.get_account(&swig).unwrap();
//     let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
//         .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

//     // Verify we have 3 roles (global + root + second authority)
//     assert_eq!(swig_data.state.roles, 3);

//     let auth_lock_actions = vec![
//         ClientAction::AuthorizationLock(AuthorizationLock {
//             mint: [0u8; 32],
//             amount: 1000000,
//             expires_at: 1000000,
//         }),
//         ClientAction::AuthorizationLock(AuthorizationLock {
//             mint: [1u8; 32],
//             amount: 2000000,
//             expires_at: 2000000,
//         }),
//     ];

//     let root_role_id = 1;

//     // Add authorization locks to the second authority
//     let add_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
//         swig,
//         context.default_payer.pubkey(),
//         root_authority.pubkey(),
//         root_role_id,
//         2, // authority_id 2 (the second authority)
//         ManageAuthorizationLocksData::AddLock(auth_lock_actions),
//     )?;
//     let msg = solana_sdk::message::v0::Message::try_compile(
//         &context.default_payer.pubkey(),
//         &[add_lock_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )?;
//     let tx = solana_sdk::transaction::VersionedTransaction::try_new(
//         solana_sdk::message::VersionedMessage::V0(msg),
//         &[&context.default_payer, &root_authority],
//     )?;
//     let result = context.svm.send_transaction(tx);

//     // Verify the add lock transaction succeeded
//     assert!(result.is_ok());

//     // Verify global role cache was updated after adding locks to second authority
//     let swig_account = context.svm.get_account(&swig).unwrap();
//     let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
//         .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

//     let global_role = swig_data.get_role(0).unwrap().unwrap();
//     let global_auth_lock_actions = global_role
//         .get_all_actions_of_type::<AuthorizationLock>()
//         .unwrap();

//     // Global role should have the authorization locks from the second authority
//     assert_eq!(global_auth_lock_actions.len(), 2);

//     // Verify the global cache has the first authorization lock
//     assert_eq!(global_auth_lock_actions[0].mint, [0u8; 32]);
//     assert_eq!(global_auth_lock_actions[0].amount, 1000000);
//     assert_eq!(global_auth_lock_actions[0].expires_at, 1000000);

//     // Verify the global cache has the second authorization lock
//     assert_eq!(global_auth_lock_actions[1].mint, [1u8; 32]);
//     assert_eq!(global_auth_lock_actions[1].amount, 2000000);
//     assert_eq!(global_auth_lock_actions[1].expires_at, 2000000);

//     // Add a third authority that we can update
//     let third_authority = Keypair::new();
//     let third_authority_pubkey = third_authority.pubkey();
//     let authority_config = AuthorityConfig {
//         authority_type: AuthorityType::Ed25519,
//         authority: third_authority_pubkey.as_ref(),
//     };
//     let actions = vec![
//         ClientAction::All(All {}),
//         ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
//     ];

//     let add_result = add_authority_with_ed25519_root(
//         &mut context,
//         &swig,
//         &root_authority,
//         authority_config,
//         actions,
//     );

//     // Verify the third authority was added successfully
//     assert!(add_result.is_ok());

//     // Verify we now have 4 roles (global + root + second + third authority)
//     let swig_account = context.svm.get_account(&swig).unwrap();
//     let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
//         .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
//     assert_eq!(swig_data.state.roles, 4);

//     let auth_lock_actions = vec![
//         ClientAction::AuthorizationLock(AuthorizationLock {
//             mint: [0u8; 32],
//             amount: 3000000,
//             expires_at: 3000000,
//         }),
//         ClientAction::AuthorizationLock(AuthorizationLock {
//             mint: [1u8; 32],
//             amount: 2000000,
//             expires_at: 500000,
//         }),
//     ];

//     // Add authorization locks to the third authority
//     let add_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
//         swig,
//         context.default_payer.pubkey(),
//         root_authority.pubkey(),
//         root_role_id,
//         3, // authority_id 3 (the third authority)
//         ManageAuthorizationLocksData::AddLock(auth_lock_actions),
//     )?;
//     let msg = solana_sdk::message::v0::Message::try_compile(
//         &context.default_payer.pubkey(),
//         &[add_lock_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )?;
//     let tx = solana_sdk::transaction::VersionedTransaction::try_new(
//         solana_sdk::message::VersionedMessage::V0(msg),
//         &[&context.default_payer, &root_authority],
//     )?;
//     let result = context
//         .svm
//         .send_transaction(tx)
//         .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e));

//     // Verify the add lock transaction succeeded
//     assert!(result.is_ok());

//     // Verify global role cache was updated after adding locks to third authority
//     let swig_account = context.svm.get_account(&swig).unwrap();
//     let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
//         .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

//     let global_role = swig_data.get_role(0).unwrap().unwrap();
//     let global_auth_lock_actions = global_role
//         .get_all_actions_of_type::<AuthorizationLock>()
//         .unwrap();

//     // Global role should still have 2 authorization locks (same locks from both authorities)
//     assert_eq!(global_auth_lock_actions.len(), 2);

//     // Verify the global cache has the first authorization lock
//     assert_eq!(global_auth_lock_actions[0].mint, [0u8; 32]);
//     assert_eq!(global_auth_lock_actions[0].amount, 4000000);
//     assert_eq!(global_auth_lock_actions[0].expires_at, 1000000);

//     // Verify the global cache has the second authorization lock
//     assert_eq!(global_auth_lock_actions[1].mint, [1u8; 32]);
//     assert_eq!(global_auth_lock_actions[1].amount, 4000000);
//     assert_eq!(global_auth_lock_actions[1].expires_at, 500000);

//     // Verify both authorities have authorization locks
//     let swig_account = context.svm.get_account(&swig).unwrap();
//     let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
//         .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

//     // Check second authority (role 2)
//     let second_role = swig_data.get_role(2).unwrap().unwrap();
//     let second_auth_lock_actions = second_role
//         .get_all_actions_of_type::<AuthorizationLock>()
//         .unwrap();
//     assert_eq!(second_auth_lock_actions.len(), 2);

//     // Check third authority (role 3)
//     let third_role = swig_data.get_role(3).unwrap().unwrap();
//     let third_auth_lock_actions = third_role
//         .get_all_actions_of_type::<AuthorizationLock>()
//         .unwrap();
//     assert_eq!(third_auth_lock_actions.len(), 2);

//     // Verify global role cache has authorization locks from both authorities
//     let global_role = swig_data.get_role(0).unwrap().unwrap();
//     let global_auth_lock_actions = global_role
//         .get_all_actions_of_type::<AuthorizationLock>()
//         .unwrap();

//     // Global role should have authorization locks from both authorities
//     // Since both authorities have the same locks, the global cache should have 2 unique locks
//     assert_eq!(global_auth_lock_actions.len(), 2);

//     // Verify the global cache has the first authorization lock
//     assert_eq!(global_auth_lock_actions[0].mint, [0u8; 32]);
//     assert_eq!(global_auth_lock_actions[0].amount, 4000000);
//     assert_eq!(global_auth_lock_actions[0].expires_at, 1000000);

//     // Verify the global cache has the second authorization lock
//     assert_eq!(global_auth_lock_actions[1].mint, [1u8; 32]);
//     assert_eq!(global_auth_lock_actions[1].amount, 4000000);
//     assert_eq!(global_auth_lock_actions[1].expires_at, 500000);

//     // Remove the first authorization lock from the second authority
//     let remove_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
//         swig,
//         context.default_payer.pubkey(),
//         root_authority.pubkey(),
//         root_role_id,
//         2, // authority_id 2 (the second authority)
//         ManageAuthorizationLocksData::RemoveLock(vec![[0u8; 32]]),
//     )?;

//     let msg = solana_sdk::message::v0::Message::try_compile(
//         &context.default_payer.pubkey(),
//         &[remove_lock_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )?;

//     let tx = solana_sdk::transaction::VersionedTransaction::try_new(
//         solana_sdk::message::VersionedMessage::V0(msg),
//         &[&context.default_payer, &root_authority],
//     )?;

//     let result = context
//         .svm
//         .send_transaction(tx)
//         .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e));

//     // Verify the remove lock transaction succeeded
//     assert!(result.is_ok());

//     // Verify global role cache was updated after removing lock from second authority
//     let swig_account = context.svm.get_account(&swig).unwrap();
//     let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
//         .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

//     let global_role = swig_data.get_role(0).unwrap().unwrap();
//     let global_auth_lock_actions_after_remove = global_role
//         .get_all_actions_of_type::<AuthorizationLock>()
//         .unwrap();

//     // Global role should still have 2 authorization locks since third authority has both
//     assert_eq!(global_auth_lock_actions_after_remove.len(), 2);

//     // Verify the global cache still has both authorization locks
//     assert_eq!(global_auth_lock_actions_after_remove[0].mint, [0u8; 32]);
//     assert_eq!(global_auth_lock_actions_after_remove[0].amount, 3000000);
//     assert_eq!(global_auth_lock_actions_after_remove[0].expires_at, 3000000);

//     assert_eq!(global_auth_lock_actions_after_remove[1].mint, [1u8; 32]);
//     assert_eq!(global_auth_lock_actions_after_remove[1].amount, 4000000);
//     assert_eq!(global_auth_lock_actions_after_remove[1].expires_at, 500000);

//     // Verify the authorization lock was removed correctly from the second authority
//     let swig_account = context.svm.get_account(&swig).unwrap();
//     let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
//         .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

//     // Check second authority now has only 1 authorization lock
//     let second_role = swig_data.get_role(2).unwrap().unwrap();
//     let second_auth_lock_actions_after = second_role
//         .get_all_actions_of_type::<AuthorizationLock>()
//         .unwrap();
//     assert_eq!(second_auth_lock_actions_after.len(), 1);
//     assert_eq!(second_auth_lock_actions_after[0].mint, [1u8; 32]);

//     // Check third authority still has 2 authorization locks (unchanged)
//     let third_role = swig_data.get_role(3).unwrap().unwrap();
//     let third_auth_lock_actions_after = third_role
//         .get_all_actions_of_type::<AuthorizationLock>()
//         .unwrap();
//     assert_eq!(third_auth_lock_actions_after.len(), 2);

//     // Verify global role cache still has authorization locks
//     // Since the third authority still has both locks, the global cache should still have 2 locks
//     let global_role = swig_data.get_role(0).unwrap().unwrap();
//     let global_auth_lock_actions_after = global_role
//         .get_all_actions_of_type::<AuthorizationLock>()
//         .unwrap();

//     // Global role should still have 2 authorization locks since third authority has both
//     assert_eq!(global_auth_lock_actions_after.len(), 2);

//     // Verify the global cache still has both authorization locks
//     assert_eq!(global_auth_lock_actions_after[0].mint, [0u8; 32]);
//     assert_eq!(global_auth_lock_actions_after[0].amount, 3000000);
//     assert_eq!(global_auth_lock_actions_after[0].expires_at, 3000000);

//     assert_eq!(global_auth_lock_actions_after[1].mint, [1u8; 32]);
//     assert_eq!(global_auth_lock_actions_after[1].amount, 4000000);
//     assert_eq!(global_auth_lock_actions_after[1].expires_at, 500000);

//     Ok(())
// }

// #[test]
// fn test_manage_authorization_locks_ed25519_update_lock() -> anyhow::Result<()> {
//     let mut context = setup_test_context()?;

//     // Create initial wallet with Ed25519 authority
//     let root_authority = Keypair::new();
//     let id = [3u8; 32]; // Use a different ID for this test
//     let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

//     // Add a second authority that we can update
//     let second_authority = Keypair::new();
//     let second_authority_pubkey = second_authority.pubkey();
//     let authority_config = AuthorityConfig {
//         authority_type: AuthorityType::Ed25519,
//         authority: second_authority_pubkey.as_ref(),
//     };
//     let initial_actions = vec![
//         ClientAction::All(All {}),
//         ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
//     ];

//     let add_result = add_authority_with_ed25519_root(
//         &mut context,
//         &swig,
//         &root_authority,
//         authority_config,
//         initial_actions,
//     );

//     // Verify the authority was added successfully
//     assert!(add_result.is_ok());

//     // Verify initial state
//     let swig_account = context.svm.get_account(&swig).unwrap();
//     let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
//         .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

//     // Verify we have 3 roles (global + root + second authority)
//     assert_eq!(swig_data.state.roles, 3);

//     let auth_lock_actions = vec![
//         ClientAction::AuthorizationLock(AuthorizationLock {
//             mint: [0u8; 32],
//             amount: 1000000,
//             expires_at: 1000000,
//         }),
//         ClientAction::AuthorizationLock(AuthorizationLock {
//             mint: [1u8; 32],
//             amount: 2000000,
//             expires_at: 2000000,
//         }),
//     ];

//     // Add authorization locks to the second authority
//     let add_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
//         swig,
//         context.default_payer.pubkey(),
//         root_authority.pubkey(),
//         1,
//         2, // authority_id 2 (the second authority)
//         ManageAuthorizationLocksData::AddLock(auth_lock_actions),
//     )?;
//     let msg = solana_sdk::message::v0::Message::try_compile(
//         &context.default_payer.pubkey(),
//         &[add_lock_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )?;
//     let tx = solana_sdk::transaction::VersionedTransaction::try_new(
//         solana_sdk::message::VersionedMessage::V0(msg),
//         &[&context.default_payer, &root_authority],
//     )?;
//     let result = context
//         .svm
//         .send_transaction(tx)
//         .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e));

//     // Verify the add lock transaction succeeded
//     assert!(result.is_ok());

//     // Verify the authorization locks were added correctly
//     let swig_account = context.svm.get_account(&swig).unwrap();
//     let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
//         .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

//     let role = swig_data.get_role(2).unwrap().unwrap();
//     let auth_lock_actions_before = role.get_all_actions_of_type::<AuthorizationLock>().unwrap();

//     // Should have 2 authorization lock actions
//     assert_eq!(auth_lock_actions_before.len(), 2);

//     // Verify the first authorization lock
//     assert_eq!(auth_lock_actions_before[0].mint, [0u8; 32]);
//     assert_eq!(auth_lock_actions_before[0].amount, 1000000);
//     assert_eq!(auth_lock_actions_before[0].expires_at, 1000000);

//     // Verify the second authorization lock
//     assert_eq!(auth_lock_actions_before[1].mint, [1u8; 32]);
//     assert_eq!(auth_lock_actions_before[1].amount, 2000000);
//     assert_eq!(auth_lock_actions_before[1].expires_at, 2000000);

//     // Verify global role cache was updated with the authorization locks
//     let global_role = swig_data.get_role(0).unwrap().unwrap();
//     let global_auth_lock_actions_before = global_role
//         .get_all_actions_of_type::<AuthorizationLock>()
//         .unwrap();

//     // Global role should have the same authorization locks as the second authority
//     assert_eq!(global_auth_lock_actions_before.len(), 2);

//     // Verify the global cache has the first authorization lock
//     assert_eq!(global_auth_lock_actions_before[0].mint, [0u8; 32]);
//     assert_eq!(global_auth_lock_actions_before[0].amount, 1000000);
//     assert_eq!(global_auth_lock_actions_before[0].expires_at, 1000000);

//     // Verify the global cache has the second authorization lock
//     assert_eq!(global_auth_lock_actions_before[1].mint, [1u8; 32]);
//     assert_eq!(global_auth_lock_actions_before[1].amount, 2000000);
//     assert_eq!(global_auth_lock_actions_before[1].expires_at, 2000000);

//     // Get role_id for the root authority
//     let role_id = swig_data
//         .lookup_role_id(root_authority.pubkey().as_ref())
//         .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
//         .unwrap();

//     // Verify we got the correct role ID
//     assert_eq!(role_id, 1);

//     // Update the first authorization lock with new values
//     let update_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
//         swig,
//         context.default_payer.pubkey(),
//         root_authority.pubkey(),
//         role_id,
//         2, // authority_id 2 (the second authority)
//         ManageAuthorizationLocksData::UpdateLock(vec![ClientAction::AuthorizationLock(
//             AuthorizationLock {
//                 mint: [0u8; 32],
//                 amount: 20,
//                 expires_at: 20,
//             },
//         )]),
//     )?;

//     let msg = solana_sdk::message::v0::Message::try_compile(
//         &context.default_payer.pubkey(),
//         &[update_lock_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )?;

//     let tx = solana_sdk::transaction::VersionedTransaction::try_new(
//         solana_sdk::message::VersionedMessage::V0(msg),
//         &[&context.default_payer, &root_authority],
//     )?;

//     let result = context
//         .svm
//         .send_transaction(tx)
//         .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e));

//     // Verify the update lock transaction succeeded
//     assert!(result.is_ok());

//     // Verify the authorization lock was updated correctly
//     let swig_account = context.svm.get_account(&swig).unwrap();
//     let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
//         .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

//     let role = swig_data.get_role(2).unwrap().unwrap();
//     let role_actions = role.get_all_actions().unwrap();

//     // Should still have the same number of actions (All + ManageAuthorizationLocks + 2 AuthorizationLocks)
//     assert_eq!(role_actions.len(), 4);

//     let authlock_actions = role.get_all_actions_of_type::<AuthorizationLock>().unwrap();

//     // Should still have 2 authorization lock actions
//     assert_eq!(authlock_actions.len(), 2);

//     // Verify the first authorization lock was updated
//     assert_eq!(authlock_actions[0].mint, [0u8; 32]);
//     assert_eq!(authlock_actions[0].amount, 20);
//     assert_eq!(authlock_actions[0].expires_at, 20);

//     // Verify the second authorization lock remains unchanged
//     assert_eq!(authlock_actions[1].mint, [1u8; 32]);
//     assert_eq!(authlock_actions[1].amount, 2000000);
//     assert_eq!(authlock_actions[1].expires_at, 2000000);

//     // Verify global role cache was updated after the lock update
//     let global_role = swig_data.get_role(0).unwrap().unwrap();
//     let global_auth_lock_actions_after = global_role
//         .get_all_actions_of_type::<AuthorizationLock>()
//         .unwrap();

//     // Global role should still have 2 authorization locks
//     assert_eq!(global_auth_lock_actions_after.len(), 2);

//     // Verify the global cache has the updated first authorization lock
//     assert_eq!(global_auth_lock_actions_after[0].mint, [0u8; 32]);
//     assert_eq!(global_auth_lock_actions_after[0].amount, 20);
//     assert_eq!(global_auth_lock_actions_after[0].expires_at, 20);

//     // Verify the global cache has the unchanged second authorization lock
//     assert_eq!(global_auth_lock_actions_after[1].mint, [1u8; 32]);
//     assert_eq!(global_auth_lock_actions_after[1].amount, 2000000);
//     assert_eq!(global_auth_lock_actions_after[1].expires_at, 2000000);

//     Ok(())
// }

// #[test]
// fn test_manage_authorization_locks_token_mint() -> anyhow::Result<()> {
//     let mut context = setup_test_context()?;

//     // Create initial wallet with Ed25519 authority
//     let root_authority = Keypair::new();
//     let id = [4u8; 32];
//     let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id)?;

//     // Setup token mint
//     let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer)?;

//     // Add a second authority that we can update
//     let second_authority = Keypair::new();
//     let second_authority_pubkey = second_authority.pubkey();
//     let authority_config = AuthorityConfig {
//         authority_type: AuthorityType::Ed25519,
//         authority: second_authority_pubkey.as_ref(),
//     };

//     let initial_actions = vec![
//         ClientAction::ProgramAll(ProgramAll {}),
//         ClientAction::SolLimit(SolLimit { amount: 2 * 10000 }),
//         ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
//         ClientAction::TokenLimit(TokenLimit {
//             token_mint: mint_pubkey.to_bytes(),
//             current_amount: 10000,
//         }),
//     ];

//     let add_result = add_authority_with_ed25519_root(
//         &mut context,
//         &swig,
//         &root_authority,
//         authority_config,
//         initial_actions,
//     );

//     // Verify the authority was added successfully
//     assert!(add_result.is_ok());

//     // Derive swig wallet address
//     let swig_wallet_address =
//         Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

//     // Setup ATA for the swig wallet address
//     let swig_ata = setup_ata(
//         &mut context.svm,
//         &mint_pubkey,
//         &swig_wallet_address,
//         &context.default_payer,
//     )?;

//     // Mint tokens to the swig ATA
//     let mint_amount = 10000;
//     mint_to(
//         &mut context.svm,
//         &mint_pubkey,
//         &context.default_payer,
//         &swig_ata,
//         mint_amount,
//     )?;

//     // Create authorization lock for the token mint
//     let mint_bytes = mint_pubkey.to_bytes();
//     let auth_lock_actions = vec![ClientAction::AuthorizationLock(AuthorizationLock {
//         mint: mint_bytes,
//         amount: 3000,
//         expires_at: 1000000,
//     })];

//     let root_role_id = 1;

//     // Add authorization lock to the second authority
//     let add_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
//         swig,
//         context.default_payer.pubkey(),
//         root_authority.pubkey(),
//         root_role_id,
//         2, // authority_id 2 (the second authority)
//         ManageAuthorizationLocksData::AddLock(auth_lock_actions),
//     )?;

//     let msg = solana_sdk::message::v0::Message::try_compile(
//         &context.default_payer.pubkey(),
//         &[add_lock_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )?;

//     let tx = solana_sdk::transaction::VersionedTransaction::try_new(
//         solana_sdk::message::VersionedMessage::V0(msg),
//         &[&context.default_payer, &root_authority],
//     )?;

//     let result = context.svm.send_transaction(tx);

//     // Verify the add lock transaction succeeded
//     assert!(result.is_ok());

//     // Verify the authorization lock was added correctly
//     let swig_account = context.svm.get_account(&swig).unwrap();
//     let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
//         .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

//     let role = swig_data.get_role(2).unwrap().unwrap();
//     let auth_lock_actions = role.get_all_actions_of_type::<AuthorizationLock>().unwrap();

//     // Should have 1 authorization lock action
//     assert_eq!(auth_lock_actions.len(), 1);

//     // Verify the authorization lock
//     assert_eq!(auth_lock_actions[0].mint, mint_bytes);
//     assert_eq!(auth_lock_actions[0].amount, 3000);
//     assert_eq!(auth_lock_actions[0].expires_at, 1000000);

//     // Verify global role cache was updated with the authorization locks
//     let global_role = swig_data.get_role(0).unwrap().unwrap();
//     let global_auth_lock_actions = global_role
//         .get_all_actions_of_type::<AuthorizationLock>()
//         .unwrap();

//     // Global role should have the same authorization lock as the second authority
//     assert_eq!(global_auth_lock_actions.len(), 1);

//     // Verify the global cache has the authorization lock
//     assert_eq!(global_auth_lock_actions[0].mint, mint_bytes);
//     assert_eq!(global_auth_lock_actions[0].amount, 3000);
//     assert_eq!(global_auth_lock_actions[0].expires_at, 1000000);

//     // Verify the lock was saved to persistent storage by reading it back
//     let swig_account_after = context.svm.get_account(&swig).unwrap();
//     let swig_data_after = SwigWithRoles::from_bytes(&swig_account_after.data)
//         .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
//     let global_role_after = swig_data_after.get_role(0).unwrap().unwrap();
//     let global_auth_lock_actions_after = global_role_after
//         .get_all_actions_of_type::<AuthorizationLock>()
//         .unwrap();
//     assert_eq!(global_auth_lock_actions_after.len(), 1);
//     assert_eq!(global_auth_lock_actions_after[0].mint, mint_bytes);
//     assert_eq!(global_auth_lock_actions_after[0].amount, 3000);

//     // Setup recipient ATA for token transfers
//     let recipient = Keypair::new();
//     let recipient_ata = setup_ata(
//         &mut context.svm,
//         &mint_pubkey,
//         &recipient.pubkey(),
//         &context.default_payer,
//     )?;

//     // Fund the second authority for fees
//     context
//         .svm
//         .airdrop(&second_authority.pubkey(), 2_000_000)
//         .unwrap();

//     // Expire blockhash to get fresh one
//     context.svm.expire_blockhash();

//     // Test 1: Transfer that would violate the auth lock (should fail)
//     // Balance: 10000, Lock: 3000
//     // Max transfer: 10000 - 3000 = 7000
//     // Let's try to transfer 7001 (should fail)
//     let transfer_amount = 7001;

//     let transfer_ix = Instruction {
//         program_id: spl_token::id(),
//         accounts: vec![
//             AccountMeta::new(swig_ata, false),
//             AccountMeta::new(recipient_ata, false),
//             AccountMeta::new(swig_wallet_address, false),
//         ],
//         data: TokenInstruction::Transfer {
//             amount: transfer_amount,
//         }
//         .pack(),
//     };

//     let sign_ix = SignV2Instruction::new_ed25519(
//         swig,
//         swig_wallet_address,
//         second_authority.pubkey(),
//         transfer_ix,
//         2,
//     )?;

//     let message = v0::Message::try_compile(
//         &second_authority.pubkey(),
//         &[sign_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )?;

//     let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&second_authority])?;
//     let result = context.svm.send_transaction(tx);

//     // Check the actual balance after the failed transfer attempt
//     let swig_ata_account = context.svm.get_account(&swig_ata).unwrap();
//     let balance_after: u64 = u64::from_le_bytes(
//         swig_ata_account
//             .data
//             .get(64..72)
//             .unwrap()
//             .try_into()
//             .unwrap(),
//     );
//     println!("Token balance after transfer attempt: {}", balance_after);

//     assert!(result.is_err());
//     if let Err(e) = result {
//         assert!(matches!(
//             e.err,
//             TransactionError::InstructionError(_, InstructionError::Custom(3033))
//         ));
//     }

//     // Test 2: Transfer within the limit (should succeed)
//     // Balance: 10000, Lock: 3000
//     // Max transfer: 10000 - 3000 = 7000
//     // Let's transfer 5000 (leaves 5000 which is >= 3000)
//     let transfer_amount = 5000;

//     let swig_ata_data = context.svm.get_account(&swig_ata).unwrap().data;
//     let current_token_balance: u64 =
//         u64::from_le_bytes(swig_ata_data.get(64..72).unwrap().try_into().unwrap());
//     println!("current token balance: {}", current_token_balance);

//     let transfer_ix = spl_token::instruction::transfer(
//         &spl_token::ID,
//         &swig_ata,
//         &recipient_ata,
//         &swig_wallet_address,
//         &[],
//         transfer_amount,
//     )
//     .unwrap();

//     let sign_ix = SignV2Instruction::new_ed25519(
//         swig,
//         swig_wallet_address,
//         second_authority.pubkey(),
//         transfer_ix,
//         2,
//     )?;

//     let message = v0::Message::try_compile(
//         &second_authority.pubkey(),
//         &[sign_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )?;

//     let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&second_authority])?;
//     let result = context.svm.send_transaction(tx);

//     println!("result: {:?}", result);
//     // This should succeed
//     assert!(result.is_ok());

//     // Verify the balance decreased correctly
//     let swig_ata_account = context.svm.get_account(&swig_ata).unwrap();
//     let remaining_balance: u64 = u64::from_le_bytes(
//         swig_ata_account
//             .data
//             .get(64..72)
//             .unwrap()
//             .try_into()
//             .unwrap(),
//     );
//     assert_eq!(remaining_balance, 5000);

//     Ok(())
// }
