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
    program_pack::Pack,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state_x::{
    action::{
        all::All, authorization_lock::AuthorizationLock, token_limit::TokenLimit, Action,
        Permission,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, SwigWithRoles},
    Transmutable,
};

#[test_log::test]
fn test_authorization_lock_prevents_transfer_below_locked_amount() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Setup token infrastructure
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let mint_pubkey_2 = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Mint 1000 tokens to swig account
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create multiple authorization locks for the same token mint that should be
    // combined First lock: 300 tokens until slot 200
    let auth_lock_1 = AuthorizationLock::new(mint_pubkey.to_bytes(), 300, 200, 1);
    // Second lock: 200 tokens until slot 150
    let auth_lock_2 = AuthorizationLock::new(mint_pubkey.to_bytes(), 200, 150, 1);
    // Combined they should lock 500 tokens total until slot 200 (latest expiry)

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint_pubkey.to_bytes(),
                current_amount: 1000,
            }), // Give permission to transfer tokens
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint_pubkey_2.to_bytes(),
                current_amount: 1000,
            }), // Give permission to transfer tokens
            ClientAction::AuthorizationLock(auth_lock_1),
            ClientAction::AuthorizationLock(auth_lock_2),
        ],
    )
    .unwrap();

    context.svm.warp_to_slot(100); // Before expiry

    // Try to transfer 600 tokens (would leave 400, below combined locked amount of
    // 500) This should fail because the combined authorization locks require
    // 500 tokens minimum
    let token_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer { amount: 600 }.pack(),
    };

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix,
        1,
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    let res = context.svm.send_transaction(transfer_tx);

    if (!res.is_err()) {
        println!("{}", res.clone().unwrap().pretty_logs());
    }
    assert!(res.is_err());

    let full_res = res.unwrap_err();

    println!("{}", full_res.meta.pretty_logs());

    // Should fail with authorization lock violation error (3021)
    if let TransactionError::InstructionError(_, InstructionError::Custom(err_code)) = full_res.err
    {
        assert_eq!(
            err_code, 3021,
            "Should fail with authorization lock violation"
        );
    } else {
        panic!("Expected authorization lock violation error");
    }

    // Verify no tokens were transferred
    let swig_token_account = context.svm.get_account(&swig_ata).unwrap();
    let swig_balance = spl_token::state::Account::unpack(&swig_token_account.data).unwrap();
    assert_eq!(swig_balance.amount, 1000);
}

#[test_log::test]
fn test_authorization_lock_allows_transfer_above_locked_amount() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Setup token infrastructure
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Mint 1000 tokens to swig account
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create authorization lock that requires minimum 500 tokens, expires at slot
    // 200
    let auth_lock = AuthorizationLock::new(mint_pubkey.to_bytes(), 500, 200, 1);

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint_pubkey.to_bytes(),
                current_amount: 1000,
            }), // Give permission to transfer tokens
            ClientAction::AuthorizationLock(auth_lock),
        ],
    )
    .unwrap();

    context.svm.warp_to_slot(100); // Before expiry

    // Try to transfer 400 tokens (would leave 600, above locked amount of 500)
    let token_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer { amount: 400 }.pack(),
    };

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix,
        1,
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    let res = context.svm.send_transaction(transfer_tx);
    if (res.is_err()) {
        println!("{}", res.clone().unwrap().pretty_logs());
    }
    assert!(res.is_ok());

    // Verify tokens were transferred correctly
    let swig_token_account = context.svm.get_account(&swig_ata).unwrap();
    let swig_balance = spl_token::state::Account::unpack(&swig_token_account.data).unwrap();
    assert_eq!(swig_balance.amount, 600); // 1000 - 400

    let recipient_token_account = context.svm.get_account(&recipient_ata).unwrap();
    let recipient_balance =
        spl_token::state::Account::unpack(&recipient_token_account.data).unwrap();
    assert_eq!(recipient_balance.amount, 400);
}

#[test_log::test]
fn test_authorization_lock_expires_allows_all_transfers() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Setup token infrastructure
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Mint 1000 tokens to swig account
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create authorization lock that requires minimum 500 tokens, expires at slot
    // 200
    let auth_lock = AuthorizationLock::new(mint_pubkey.to_bytes(), 500, 200, 1);

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint_pubkey.to_bytes(),
                current_amount: 1000,
            }), // Give permission to transfer tokens
            ClientAction::AuthorizationLock(auth_lock),
        ],
    )
    .unwrap();

    context.svm.warp_to_slot(250); // After expiry (200)

    // Try to transfer 900 tokens (would leave 100, below locked amount of 500)
    // This should succeed because the lock has expired
    let token_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer { amount: 900 }.pack(),
    };

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix,
        1,
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    let res = context.svm.send_transaction(transfer_tx);

    if (res.is_err()) {
        println!("{}", res.clone().unwrap().pretty_logs());
    }
    assert!(res.is_ok());

    // Verify tokens were transferred correctly (lock expired, so transfer allowed)
    let swig_token_account = context.svm.get_account(&swig_ata).unwrap();
    let swig_balance = spl_token::state::Account::unpack(&swig_token_account.data).unwrap();
    assert_eq!(swig_balance.amount, 100); // 1000 - 900

    let recipient_token_account = context.svm.get_account(&recipient_ata).unwrap();
    let recipient_balance =
        spl_token::state::Account::unpack(&recipient_token_account.data).unwrap();
    assert_eq!(recipient_balance.amount, 900);
}

#[test_log::test]
fn test_authorization_lock_with_all_permission_cant_bypass_lock() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Setup token infrastructure
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Mint 1000 tokens to swig account
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add authorization lock to a different role
    let third_authority = Keypair::new();
    context
        .svm
        .airdrop(&third_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let auth_lock = AuthorizationLock::new(mint_pubkey.to_bytes(), 500, 200, 1);
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::All(All)],
    )
    .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: third_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::AuthorizationLock(auth_lock), /* Only authorization lock, no transfer
                                                         * permissions */
        ],
    )
    .unwrap();

    context.svm.warp_to_slot(100); // Before expiry

    // Try to transfer 900 tokens using All permission (should succeed despite lock)
    let token_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer { amount: 900 }.pack(),
    };

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix,
        1, // Authority with All permission
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    let res = context.svm.send_transaction(transfer_tx);
    assert!(res.is_err());

    let full_res = res.unwrap_err();

    println!("{}", full_res.meta.pretty_logs());

    // Should fail with authorization lock violation error (3021)
    if let TransactionError::InstructionError(_, InstructionError::Custom(err_code)) = full_res.err
    {
        assert_eq!(
            err_code, 3021,
            "Should fail with authorization lock violation"
        );
    } else {
        panic!("Expected authorization lock violation error");
    }
}

#[test_log::test]
fn test_multiple_authorization_locks_combine_for_same_token() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Setup token infrastructure
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Mint 1000 tokens to swig account
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create three authorization locks for the same token mint:
    // Lock 1: 100 tokens until slot 150 (expires first)
    // Lock 2: 200 tokens until slot 200
    // Lock 3: 50 tokens until slot 300 (expires last)
    // Total combined: 350 tokens until slot 300
    let auth_lock_1 = AuthorizationLock::new(mint_pubkey.to_bytes(), 100, 150, 1);
    let auth_lock_2 = AuthorizationLock::new(mint_pubkey.to_bytes(), 200, 150, 1);
    let auth_lock_3 = AuthorizationLock::new(mint_pubkey.to_bytes(), 50, 150, 1);

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint_pubkey.to_bytes(),
                current_amount: 1000,
            }), // Give permission to transfer tokens
            ClientAction::AuthorizationLock(auth_lock_1),
            ClientAction::AuthorizationLock(auth_lock_2),
            ClientAction::AuthorizationLock(auth_lock_3),
        ],
    )
    .unwrap();

    context.svm.warp_to_slot(100); // Before any expiry

    // Try to transfer 700 tokens (would leave 300, below combined locked amount of
    // 350)
    let token_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer { amount: 700 }.pack(),
    };

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix,
        1,
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    let res = context.svm.send_transaction(transfer_tx);
    assert!(res.is_err());
    // println!("{}", res.clone().unwrap().pretty_logs());

    // Should fail with authorization lock violation - combined locks require 350
    // tokens minimum
    let full_res = res.unwrap_err();

    println!("{}", full_res.meta.pretty_logs());
    assert_eq!(
        full_res.err,
        TransactionError::InstructionError(0, InstructionError::Custom(3021))
    );

    // Now try a transfer that should succeed (leaves 400 tokens, above 350 minimum)
    context.svm.warp_to_slot(100); // Still before any expiry

    let token_ix_2 = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer { amount: 600 }.pack(),
    };

    let sign_ix_2 = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix_2,
        1,
    )
    .unwrap();

    let transfer_message_2 = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix_2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx_2 = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message_2),
        &[&second_authority],
    )
    .unwrap();

    let res_2 = context.svm.send_transaction(transfer_tx_2);
    if res_2.is_err() {
        println!("{}", res_2.clone().unwrap_err().meta.pretty_logs());
    }
    assert!(res_2.is_ok());

    // Verify the transfer succeeded (1000 - 600 = 400 remaining)
    let swig_token_account = context.svm.get_account(&swig_ata).unwrap();
    let swig_balance = spl_token::state::Account::unpack(&swig_token_account.data).unwrap();
    assert_eq!(swig_balance.amount, 400);
}

#[test_log::test]
fn test_expired_authorization_locks_automatically_removed() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Setup token infrastructure
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Mint 1000 tokens to swig account
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create authorization lock that requires minimum 500 tokens, expires at slot
    // 200
    let auth_lock = AuthorizationLock::new(mint_pubkey.to_bytes(), 500, 200, 1);

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint_pubkey.to_bytes(),
                current_amount: 1000,
            }), // Give permission to transfer tokens
            ClientAction::AuthorizationLock(auth_lock),
        ],
    )
    .unwrap();

    // First verify the lock works before expiry
    context.svm.warp_to_slot(100); // Before expiry

    // Try to transfer 600 tokens (would leave 400, below locked amount of 500)
    // This should fail because of the authorization lock
    let token_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer { amount: 600 }.pack(),
    };

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix.clone(),
        1,
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    let res = context.svm.send_transaction(transfer_tx);
    assert!(
        res.is_err(),
        "Transfer should fail due to authorization lock"
    );

    // Should fail with authorization lock violation error (3021)
    if let TransactionError::InstructionError(_, InstructionError::Custom(err_code)) =
        res.unwrap_err().err
    {
        assert_eq!(
            err_code, 3021,
            "Should fail with authorization lock violation"
        );
    } else {
        panic!("Expected authorization lock violation error");
    }

    let swig_account_data = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account_data.data).unwrap();

    // Count authorization lock actions in role 1 (the second authority that had the
    // lock)
    let mut auth_lock_count = 0;
    if let Ok(Some(role)) = swig_with_roles.get_role(1) {
        let mut cursor = 0;
        while cursor < role.actions.len() {
            if cursor + Action::LEN > role.actions.len() {
                break;
            }

            if let Ok(action_header) =
                unsafe { Action::load_unchecked(&role.actions[cursor..cursor + Action::LEN]) }
            {
                cursor += Action::LEN;
                let action_len = action_header.length() as usize;

                if cursor + action_len > role.actions.len() {
                    break;
                }

                println!(
                    "action_header.permission(): {:?}",
                    action_header.permission()
                );
                // Check if this is an authorization lock
                if action_header.permission().ok() == Some(Permission::AuthorizationLock) {
                    auth_lock_count += 1;
                }

                cursor += action_len;
            } else {
                break;
            }
        }
    }

    // Now advance time past the lock's expiry
    context.svm.warp_to_slot(250); // After expiry (200)

    // Try the same transfer again - it should now succeed because the expired lock
    // should be automatically removed
    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix,
        1,
    )
    .unwrap();

    context.svm.expire_blockhash();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    let res = context.svm.send_transaction(transfer_tx);
    if res.is_err() {
        println!("{}", res.clone().unwrap_err().meta.pretty_logs());
    }

    println!("{}", res.clone().unwrap().pretty_logs());
    assert!(
        res.is_ok(),
        "Transfer should succeed after lock expiry - expired lock should be automatically removed"
    );

    // CRITICAL: Verify that the authorization lock was actually removed from the
    // swig account data after expiry
    let swig_account_data = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account_data.data).unwrap();

    // Count authorization lock actions in role 1 (the second authority that had the
    // lock)
    let mut auth_lock_count = 0;
    if let Ok(Some(role)) = swig_with_roles.get_role(1) {
        let mut cursor = 0;
        while cursor < role.actions.len() {
            if cursor + Action::LEN > role.actions.len() {
                break;
            }

            if let Ok(action_header) =
                unsafe { Action::load_unchecked(&role.actions[cursor..cursor + Action::LEN]) }
            {
                cursor += Action::LEN;
                let action_len = action_header.length() as usize;

                if cursor + action_len > role.actions.len() {
                    break;
                }

                println!(
                    "action_header.permission(): {:?}",
                    action_header.permission()
                );
                // Check if this is an authorization lock
                if action_header.permission().ok() == Some(Permission::AuthorizationLock) {
                    auth_lock_count += 1;
                }

                cursor += action_len;
            } else {
                break;
            }
        }
    }

    // The authorization lock should have been removed, so count should be 0
    assert_eq!(
        auth_lock_count, 0,
        "Authorization lock should have been removed from the account data after expiry"
    );

    // Also verify that the role's action count decreased
    if let Ok(Some(role)) = swig_with_roles.get_role(1) {
        // Role should now have only 1 action (TokenLimit), the AuthorizationLock should
        // be gone
        assert_eq!(
            role.position.num_actions(),
            1,
            "Role should have 1 action after expired lock removal (only TokenLimit should remain)"
        );
    }

    println!(
        "✅ Verified that expired authorization lock was physically removed from swig account data"
    );

    // Additional verification: Test a second transfer that would have failed with
    // the lock
    let token_ix_2 = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer { amount: 350 }.pack(),
    };

    let sign_ix_2 = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix_2,
        1,
    )
    .unwrap();

    let transfer_message_2 = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix_2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx_2 = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message_2),
        &[&second_authority],
    )
    .unwrap();

    let res_2 = context.svm.send_transaction(transfer_tx_2);
    if res_2.is_err() {
        println!("{}", res_2.clone().unwrap_err().meta.pretty_logs());
    }

    assert!(
        res_2.is_ok(),
        "Second transfer should also succeed since expired lock was removed"
    );

    // Final balance verification: should have 50 tokens left (400 - 350)
    let final_token_account = context.svm.get_account(&swig_ata).unwrap();
    let final_balance = spl_token::state::Account::unpack(&final_token_account.data).unwrap();
    assert_eq!(final_balance.amount, 50);

    println!(
        "✅ All verifications passed - expired authorization lock functionality works correctly"
    );
}
