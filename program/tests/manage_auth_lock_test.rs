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
    let actions = vec![
        ClientAction::ProgramAll(ProgramAll {}),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
        ClientAction::SolLimit(SolLimit {
            amount: 2 * 1000000,
        }),
    ];

    let _add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        authority_config,
        actions,
    )?;

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

    for i in 0..swig_data.state.roles {
        let role = swig_data.get_role(i as u32).unwrap().unwrap();
        println!("role: {:?}", role.position.id());
        let role_actions = role.get_all_actions().unwrap();
        for action in role_actions {
            println!("=> action: {:?}", action.permission());
        }
    }

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

    for i in 0..swig_data.state.roles {
        let role = swig_data.get_role(i as u32).unwrap().unwrap();
        let role_actions = role.get_all_actions().unwrap();
        for action in role_actions {
            println!("=> action: {:?}", action.permission());
        }
    }

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

    // Now create a sol transaction that spends less than locked SOL
    let transfer_amount = 1000000;

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
    println!("result: {:?}", result);
    assert!(result.is_ok());

    // Now create a sol transaction that spends more than locked SOL
    let transfer_amount = 1000000 + 1;

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
    println!("result: {:?}", result);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err().err,
        TransactionError::InstructionError(_, InstructionError::Custom(3033))
    ));

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
    assert!(result.is_ok());
    println!("Transaction logs: {:?}", result.unwrap().logs);

    // Get role_id for the root authority
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role = swig_data.get_role(2).unwrap().unwrap();
    let auth_lock_actions = role.get_all_actions_of_type::<AuthorizationLock>().unwrap();
    for action in auth_lock_actions {
        println!("auth_lock_action mint: {:?}", action.mint);
        println!("auth_lock_action amount: {:?}", action.amount);
        println!("auth_lock_action expires_at: {:?}", action.expires_at);
    }
    println!("global authority role id: {:?}", 0);
    let role = swig_data.get_role(0).unwrap().unwrap();
    let auth_lock_actions = role.get_all_actions_of_type::<AuthorizationLock>().unwrap();
    for action in auth_lock_actions {
        println!("auth_lock_action mint: {:?}", action.mint);
        println!("auth_lock_action amount: {:?}", action.amount);
        println!("auth_lock_action expires_at: {:?}", action.expires_at);
    }

    // Remove the lock
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
    println!("result: {:?}", result);
    assert!(result.is_ok());

    println!("Transaction logs: {:?}", result.unwrap().logs);

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role = swig_data.get_role(2).unwrap().unwrap();
    let auth_lock_actions = role.get_all_actions_of_type::<AuthorizationLock>().unwrap();
    for action in auth_lock_actions {
        println!("auth_lock_action mint: {:?}", action.mint);
        println!("auth_lock_action amount: {:?}", action.amount);
        println!("auth_lock_action expires_at: {:?}", action.expires_at);
    }
    println!("global authority role id: {:?}", 0);
    let role = swig_data.get_role(0).unwrap().unwrap();
    let auth_lock_actions = role.get_all_actions_of_type::<AuthorizationLock>().unwrap();
    for action in auth_lock_actions {
        println!("auth_lock_action mint: {:?}", action.mint);
        println!("auth_lock_action amount: {:?}", action.amount);
        println!("auth_lock_action expires_at: {:?}", action.expires_at);
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

    let remove_lock_ix = ManageAuthorizationLocksV1Instruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        1,
        2, // authority_id 2 (the second authority)
        ManageAuthorizationLocksData::AddLock(auth_lock_actions),
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
    assert!(result.is_ok());
    println!("Transaction logs: {:?}", result.unwrap().logs);

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
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e));
    assert!(result.is_ok());

    println!("Transaction logs: {:?}", result.unwrap().logs);

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
