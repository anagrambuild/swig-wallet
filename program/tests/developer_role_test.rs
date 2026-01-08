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
    transaction::{TransactionError, VersionedTransaction},
};
use swig_developer_state::DeveloperAccount;
use swig_interface::{AuthorityConfig, ClientAction, RoleType, SignV2DeveloperInstruction};
use swig_state::SwigAuthenticateError;
use swig_state::{
    action::{manage_authority::ManageAuthority, program_all::ProgramAll, sol_limit::SolLimit},
    authority::{authorities_to_mask, AuthorityType},
    swig::{swig_wallet_address_seeds, SwigWithRoles},
};

#[test_log::test]
fn test_developer_created_add_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    let developer = Keypair::new();
    let developer_account = create_developer_account(&mut context, &developer.pubkey()).unwrap();

    let developer_account_data = context.svm.get_account(&developer_account).unwrap();
    let developer_account_data =
        DeveloperAccount::from_bytes(&developer_account_data.data).unwrap();
    println!("developer_account_data: {:?}", developer_account_data);

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

    let result = add_authority_with_ed25519_root_and_role_type(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit {
            amount: 1000000000000000000,
        })],
        RoleType::Developer,
        &developer,
        developer_account,
    )
    .unwrap();
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 2);
    assert_eq!(swig.state.role_counter, 2);
    let role_0 = swig.get_role(0).unwrap().unwrap();
    assert_eq!(role_0.authority.authority_type(), AuthorityType::Ed25519);
    assert!(!role_0.authority.session_based());
    assert_eq!(
        role_0.position.authority_type().unwrap(),
        AuthorityType::Ed25519
    );
    assert_eq!(role_0.position.authority_length(), 32);
    assert_eq!(role_0.position.num_actions(), 1);
}

#[test_log::test]
fn test_developer_role_invalid_developer_signer() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    let developer = Keypair::new();
    let developer_account = create_developer_account(&mut context, &developer.pubkey()).unwrap();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Use a different keypair that doesn't match the developer account's signers
    let wrong_developer = Keypair::new();
    context
        .svm
        .airdrop(&wrong_developer.pubkey(), 10_000_000_000)
        .unwrap();

    let result = add_authority_with_ed25519_root_and_role_type(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit {
            amount: 1000000000000000000,
        })],
        RoleType::Developer,
        &wrong_developer, // Wrong developer signer
        developer_account,
    );

    // Verify the operation failed
    assert!(
        result.is_err(),
        "Adding authority with invalid developer signer should fail"
    );
    let error = result.unwrap_err();
    assert!(error.to_string().contains(
        &(SwigAuthenticateError::PermissionDeniedInvalidDeveloperSigner as u32).to_string()
    ));
}

#[test_log::test]
fn test_developer_role_invalid_developer_role_type() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    let developer = Keypair::new();
    // Create developer account with authority_type_mask that doesn't include Developer role type
    // Developer role type is 1, so we'll create a mask that only includes other role types
    // For example, only include Regular (0) and IDP (2), but not Developer (1)
    let authority_type_mask = (1 << 0) | (1 << 2); // Regular and IDP, but not Developer
    let developer_account = create_developer_account_with_custom_properties(
        &mut context,
        developer.pubkey(),
        100000, // Future expiry slot
        authority_type_mask,
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let result = add_authority_with_ed25519_root_and_role_type(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit {
            amount: 1000000000000000000,
        })],
        RoleType::Developer, // Trying to create Developer role, but mask doesn't allow it
        &developer,
        developer_account,
    );

    // Verify the operation failed
    assert!(
        result.is_err(),
        "Adding authority with invalid developer role type should fail"
    );
    let error = result.unwrap_err();
    assert!(error.to_string().contains(
        &(SwigAuthenticateError::PermissionDeniedInvalidDeveloperRoleType as u32).to_string()
    ));
}

#[test_log::test]
fn test_developer_role_expired_subscription() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    let developer = Keypair::new();
    // Set expiry to 0, which will be in the past by the time we execute the transaction
    // Since slots start at some value and increment, 0 should definitely be expired
    let expired_slot = 0;

    let authority_type_mask = authorities_to_mask(vec![AuthorityType::Ed25519]);
    let developer_account = create_developer_account_with_custom_properties(
        &mut context,
        developer.pubkey(),
        expired_slot, // Expired subscription
        authority_type_mask,
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    context.svm.warp_to_slot(101);

    let result = add_authority_with_ed25519_root_and_role_type(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit {
            amount: 1000000000000000000,
        })],
        RoleType::Developer,
        &developer,
        developer_account,
    );

    let error = result.unwrap_err();

    // check if error log conatins the permission code number 3035
    assert!(error.to_string().contains(
        &(SwigAuthenticateError::PermissionDeniedExpiredSubscription as u32).to_string()
    ));
}

#[test_log::test]
fn test_developer_role_transfer_sol_to_dapp_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    let dapp_authority = Keypair::new();
    let developer_account =
        create_developer_account(&mut context, &dapp_authority.pubkey()).unwrap();
    println!("developer: {:?}", dapp_authority.pubkey());
    println!("developer_account: {:?}", developer_account.to_bytes());

    let developer_account_data = context.svm.get_account(&developer_account).unwrap();
    let developer_account_data =
        DeveloperAccount::from_bytes(&developer_account_data.data).unwrap();
    println!("developer_account_data: {:?}", developer_account_data);

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    let (swig_key, swig_create_txn) =
        create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    let result = add_authority_with_ed25519_root_and_role_type(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: dapp_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::SolLimit(SolLimit {
                amount: 1_000_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
        RoleType::Developer,
        &dapp_authority,
        developer_account,
    )
    .unwrap();

    //// GOING TO TRANSFER SOL FROM SWIG TO DAPP AUTHORITY
    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // Create a simple transfer instruction from swig_wallet_address
    let transfer_amount = 100_000_000; // 0.1 SOL
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    // Create SignV2 instruction with the swig_wallet_address
    let sign_v2_ix = SignV2DeveloperInstruction::new_ed25519(
        swig_key,
        swig_wallet_address,
        dapp_authority.pubkey(),
        transfer_ix,
        1, // role_id 1 for dapp authority
        developer_account,
    )
    .unwrap();

    // Build and execute transaction
    let transfer_message = v0::Message::try_compile(
        &dapp_authority.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&dapp_authority])
            .unwrap();

    let initial_recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    let initial_swig_wallet_address_balance = context
        .svm
        .get_account(&swig_wallet_address)
        .unwrap()
        .lamports;

    // Execute the transaction
    let result = context.svm.send_transaction(transfer_tx);
    assert!(result.is_ok());

    let final_recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    let final_swig_wallet_address_balance = context
        .svm
        .get_account(&swig_wallet_address)
        .unwrap()
        .lamports;

    assert_eq!(
        final_recipient_balance,
        initial_recipient_balance + transfer_amount
    );
    assert_eq!(
        final_swig_wallet_address_balance,
        initial_swig_wallet_address_balance - transfer_amount
    );
}

#[test_log::test]
fn test_developer_role_sign_invalid_developer_account() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    let dapp_authority = Keypair::new();
    let developer_account =
        create_developer_account(&mut context, &dapp_authority.pubkey()).unwrap();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    // Add developer authority
    add_authority_with_ed25519_root_and_role_type(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: dapp_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::SolLimit(SolLimit {
                amount: 1_000_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
        RoleType::Developer,
        &dapp_authority,
        developer_account,
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // Create a fake/wrong developer account
    let wrong_developer_account = Keypair::new().pubkey();
    context
        .svm
        .airdrop(&wrong_developer_account, 10_000_000_000)
        .unwrap();

    // Create a simple transfer instruction
    let transfer_amount = 100_000_000; // 0.1 SOL
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    // Create SignV2 instruction with wrong developer account
    let sign_v2_ix = SignV2DeveloperInstruction::new_ed25519(
        swig_key,
        swig_wallet_address,
        dapp_authority.pubkey(),
        transfer_ix,
        1,                       // role_id 1 for dapp authority
        wrong_developer_account, // Wrong developer account
    )
    .unwrap();

    // Build and execute transaction
    let transfer_message = v0::Message::try_compile(
        &dapp_authority.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&dapp_authority])
            .unwrap();

    // Execute the transaction - should fail
    let result = context.svm.send_transaction(transfer_tx);
    assert!(
        result.is_err(),
        "Signing with invalid developer account should fail"
    );
    let error = result.unwrap_err();
    let expected_error_code = SwigAuthenticateError::PermissionDeniedInvalidDeveloperAccount as u32;
    match error.err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => {
            assert_eq!(
                code, expected_error_code,
                "Expected error code {} (PermissionDeniedInvalidDeveloperAccount), got {}",
                expected_error_code, code
            );
        },
        err => panic!("Expected InstructionError::Custom, got {:?}", err),
    }
}

#[test_log::test]
fn test_developer_role_sign_expired_subscription() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    let dapp_authority = Keypair::new();
    // Set expiry to 0, which will be in the past by the time we execute the transaction
    let expired_slot = 0;
    let authority_type_mask = authorities_to_mask(vec![AuthorityType::Ed25519]);
    let developer_account = create_developer_account_with_custom_properties(
        &mut context,
        dapp_authority.pubkey(),
        expired_slot, // Expired subscription
        authority_type_mask,
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    // Add developer authority
    add_authority_with_ed25519_root_and_role_type(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: dapp_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::SolLimit(SolLimit {
                amount: 1_000_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
        RoleType::Developer,
        &dapp_authority,
        developer_account,
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // Warp to a slot after expiry
    context.svm.warp_to_slot(101);

    // Create a simple transfer instruction
    let transfer_amount = 100_000_000; // 0.1 SOL
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    // Create SignV2 instruction
    let sign_v2_ix = SignV2DeveloperInstruction::new_ed25519(
        swig_key,
        swig_wallet_address,
        dapp_authority.pubkey(),
        transfer_ix,
        1, // role_id 1 for dapp authority
        developer_account,
    )
    .unwrap();

    // Build and execute transaction
    let transfer_message = v0::Message::try_compile(
        &dapp_authority.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&dapp_authority])
            .unwrap();

    // Execute the transaction - should fail
    let result = context.svm.send_transaction(transfer_tx);
    assert!(
        result.is_err(),
        "Signing with expired subscription should fail"
    );
    let error = result.unwrap_err();
    let expected_error_code = SwigAuthenticateError::PermissionDeniedExpiredSubscription as u32;
    match error.err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => {
            assert_eq!(
                code, expected_error_code,
                "Expected error code {} (PermissionDeniedExpiredSubscription), got {}",
                expected_error_code, code
            );
        },
        err => panic!("Expected InstructionError::Custom, got {:?}", err),
    }
}
