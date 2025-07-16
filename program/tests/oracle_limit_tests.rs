#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.

mod common;

use std::str::FromStr;

use common::*;
use litesvm::LiteSVM;
use litesvm_token::spl_token;
use solana_program::{pubkey::Pubkey, system_instruction};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    signature::{Keypair, Signer},
    transaction::{Transaction, VersionedTransaction},
};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state::{
    action::{
        all::All,
        oracle_limits::{BaseAsset, OracleTokenLimit},
        program_all::ProgramAll,
        sol_limit::SolLimit,
        token_limit::TokenLimit,
        Permission,
    },
    authority::AuthorityType,
    role::Role,
    swig::SwigWithRoles,
};

/// Test 1: Verify oracle limit permission is added correctly
#[test_log::test]
fn test_oracle_limit_permission_add() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create a swig wallet
    let id = rand::random::<[u8; 32]>();
    let oracle_program = Keypair::new();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Create secondary authority
    let secondary_authority = Keypair::new();
    context
        .svm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add multiple permissions: Oracle Token Limit (200 USDC) and SOL Limit (1 SOL)
    let oracle_limit = OracleTokenLimit::new(
        BaseAsset::USDC,
        200_000_000, // 200 USDC
        false,
    );

    let sol_limit = SolLimit {
        amount: 1_000_000_000, // 1 SOL
    };

    // Add authority with multiple permissions
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::OracleTokenLimit(oracle_limit),
            ClientAction::SolLimit(sol_limit),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    )
    .unwrap();

    // Verify permissions were added correctly
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role_id = swig
        .lookup_role_id(secondary_authority.pubkey().as_ref())
        .unwrap()
        .unwrap();
    let role = swig.get_role(role_id).unwrap().unwrap();

    // Verify both permissions exist
    assert_eq!(role.position.num_actions(), 3, "Should have 3 actions");

    let oracle_action = role
        .get_action::<OracleTokenLimit>(&[BaseAsset::USDC as u8])
        .unwrap()
        .unwrap();
    assert_eq!(oracle_action.value_limit, 200_000_000);
    assert_eq!(oracle_action.base_asset_type, BaseAsset::USDC as u8);

    let sol_action = role.get_action::<SolLimit>(&[]).unwrap().unwrap();
    assert_eq!(sol_action.amount, 1_000_000_000);
}

/// Test 2: Test SOL transfers with oracle limits
#[test_log::test]
fn test_oracle_limit_sol_transfer() {
    let mut context = setup_test_context().unwrap();
    load_sample_scope_data(&mut context.svm, &context.default_payer).unwrap();

    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create wallet and setup
    let id = rand::random::<[u8; 32]>();
    let oracle_program = Keypair::new();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let secondary_authority = Keypair::new();
    context
        .svm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add oracle limit permission (200 USDC limit)
    let oracle_limit = OracleTokenLimit::new(
        BaseAsset::USDC,
        200_000_000, // 200 USDC limit
        false,
    );

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::OracleTokenLimit(oracle_limit),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    )
    .unwrap();

    // Fund swig wallet
    context.svm.airdrop(&swig_key, 20_000_000_000).unwrap();

    // Test 1: Transfer below limit (1 SOL ≈ 150 USDC at mock price)
    let transfer_ix =
        system_instruction::transfer(&swig_key, &secondary_authority.pubkey(), 1_000_000_000);
    let mut sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix,
        1,
    )
    .unwrap();

    sign_ix.accounts.extend(vec![
        AccountMeta::new_readonly(
            Pubkey::from_str("Chpu5ZgfWX5ZzVpUx9Xvv4WPM75Xd7zPJNDPsFnCpLpk").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::from_str("3NJYftD5sjVfxSnUdZ1wVML8f3aC6mp1CXCL6L7TnU8C").unwrap(),
            false,
        ),
    ]);

    let message = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&secondary_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    println!("result: {:?}", result);
    assert!(result.is_ok(), "Transfer below limit should succeed");
    println!(
        "Compute units consumed for below limit transfer: {}",
        result.unwrap().compute_units_consumed
    );

    // Test 2: Transfer above limit (2 SOL ≈ 300 USDC at mock price)
    let transfer_ix =
        system_instruction::transfer(&swig_key, &secondary_authority.pubkey(), 2_000_000_000);
    let mut sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix,
        1,
    )
    .unwrap();

    sign_ix.accounts.extend(vec![
        AccountMeta::new_readonly(
            Pubkey::from_str("Chpu5ZgfWX5ZzVpUx9Xvv4WPM75Xd7zPJNDPsFnCpLpk").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::from_str("3NJYftD5sjVfxSnUdZ1wVML8f3aC6mp1CXCL6L7TnU8C").unwrap(),
            false,
        ),
    ]);

    let message = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&secondary_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(result.is_err(), "Transfer above limit should fail");
    assert_eq!(
        result.unwrap_err().err,
        solana_sdk::transaction::TransactionError::InstructionError(
            0,
            solana_sdk::instruction::InstructionError::Custom(3028)
        ),
        "Expected error code 3028"
    );
}

/// Test 3: Test token transfers with oracle limits
#[test_log::test]
fn test_oracle_limit_token_transfer() {
    let mut context = setup_test_context().unwrap();
    let mint = load_sample_scope_data(&mut context.svm, &context.default_payer).unwrap();
    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create wallet and setup
    let id = rand::random::<[u8; 32]>();
    let oracle_program = Keypair::new();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let secondary_authority = Keypair::new();
    context
        .svm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add oracle limit permission (300 USDC limit)
    let oracle_limit = OracleTokenLimit::new(
        BaseAsset::USDC,
        300_000_000, // 300 USDC with 6 decimals
        false,
    );

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::OracleTokenLimit(oracle_limit),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    )
    .unwrap();

    let mint_pubkey = mint;
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_key,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &secondary_authority.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Fund swig's token account with 10 tokens
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        100_000_000_000, // 10 tokens with 9 decimals
    )
    .unwrap();

    // Test 1: Transfer below limit (0.5 tokens ≈ 0.75 USDC at mock price of 1.5 USDC per token)
    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::id(),
        &swig_ata,
        &recipient_ata,
        &swig_key,
        &[],
        500_000_000, // 0.5 tokens with 9 decimals
    )
    .unwrap();

    let mut sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix,
        1,
    )
    .unwrap();

    sign_ix.accounts.extend(vec![
        AccountMeta::new_readonly(
            Pubkey::from_str("Chpu5ZgfWX5ZzVpUx9Xvv4WPM75Xd7zPJNDPsFnCpLpk").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::from_str("3NJYftD5sjVfxSnUdZ1wVML8f3aC6mp1CXCL6L7TnU8C").unwrap(),
            false,
        ),
    ]);

    let message = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&secondary_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(result.is_ok(), "Transfer below limit should succeed");
    println!(
        "Compute units consumed for below limit transfer: {}",
        result.unwrap().compute_units_consumed
    );

    // Test 2: Transfer above limit (2.5 tokens ≈ 3.75 USDC at mock price)
    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::id(),
        &swig_ata,
        &recipient_ata,
        &swig_key,
        &[],
        2_500_000_000, // 2.5 tokens with 9 decimals
    )
    .unwrap();

    let mut sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix,
        1,
    )
    .unwrap();

    sign_ix.accounts.extend(vec![
        AccountMeta::new_readonly(
            Pubkey::from_str("Chpu5ZgfWX5ZzVpUx9Xvv4WPM75Xd7zPJNDPsFnCpLpk").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::from_str("3NJYftD5sjVfxSnUdZ1wVML8f3aC6mp1CXCL6L7TnU8C").unwrap(),
            false,
        ),
    ]);

    let message = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&secondary_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(result.is_err(), "Transfer above limit should fail");
    assert_eq!(
        result.unwrap_err().err,
        solana_sdk::transaction::TransactionError::InstructionError(
            0,
            solana_sdk::instruction::InstructionError::Custom(3028)
        ),
        "Expected error code 3028"
    );
}

/// Test 4: Test SOL transfers with oracle limits and passthrough enabled
#[test_log::test]
fn test_oracle_limit_sol_passthrough() {
    let mut context = setup_test_context().unwrap();
    load_sample_scope_data(&mut context.svm, &context.default_payer).unwrap();

    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create wallet and setup
    let id = rand::random::<[u8; 32]>();
    let oracle_program = Keypair::new();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let secondary_authority = Keypair::new();
    context
        .svm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add oracle limit permission (200 USDC limit) with passthrough enabled
    let oracle_limit = OracleTokenLimit::new(
        BaseAsset::USDC,
        200_000_000, // 200 USDC limit
        true,
    );

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::OracleTokenLimit(oracle_limit),
            ClientAction::SolLimit(SolLimit {
                amount: 100_000_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    )
    .unwrap();

    // Fund swig wallet
    context.svm.airdrop(&swig_key, 20_000_000_000).unwrap();

    // Test 1: Transfer below limit (1 SOL ≈ 150 USDC at mock price)
    let transfer_ix =
        system_instruction::transfer(&swig_key, &secondary_authority.pubkey(), 1_000_000_000);
    let mut sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix,
        1,
    )
    .unwrap();

    sign_ix.accounts.extend(vec![
        AccountMeta::new_readonly(
            Pubkey::from_str("Chpu5ZgfWX5ZzVpUx9Xvv4WPM75Xd7zPJNDPsFnCpLpk").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::from_str("3NJYftD5sjVfxSnUdZ1wVML8f3aC6mp1CXCL6L7TnU8C").unwrap(),
            false,
        ),
    ]);

    let message = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&secondary_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(result.is_ok(), "Transfer below limit should succeed");
    println!(
        "Compute units consumed for below limit transfer: {}",
        result.unwrap().compute_units_consumed
    );

    // Test 2: Transfer above limit (2 SOL ≈ 300 USDC at mock price)
    let transfer_ix =
        system_instruction::transfer(&swig_key, &secondary_authority.pubkey(), 2_000_000_000);
    let mut sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix,
        1,
    )
    .unwrap();

    sign_ix.accounts.extend(vec![
        AccountMeta::new_readonly(
            Pubkey::from_str("Chpu5ZgfWX5ZzVpUx9Xvv4WPM75Xd7zPJNDPsFnCpLpk").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::from_str("3NJYftD5sjVfxSnUdZ1wVML8f3aC6mp1CXCL6L7TnU8C").unwrap(),
            false,
        ),
    ]);

    let message = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&secondary_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(result.is_err(), "Transfer above limit should fail");
    assert_eq!(
        result.unwrap_err().err,
        solana_sdk::transaction::TransactionError::InstructionError(
            0,
            solana_sdk::instruction::InstructionError::Custom(3028)
        ),
        "Expected error code 3028"
    );
}

/// Test 5: Test token transfers with oracle limits and passthrough enabled
#[test_log::test]
fn test_oracle_limit_passthrough() {
    let mut context = setup_test_context().unwrap();
    let mint = load_sample_scope_data(&mut context.svm, &context.default_payer).unwrap();
    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create wallet and setup
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let secondary_authority = Keypair::new();
    context
        .svm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add oracle limit permission (300 USDC limit) with passthrough enabled
    let oracle_limit = OracleTokenLimit::new(
        BaseAsset::USDC,
        300_000_000, // 300 USDC with 6 decimals
        true,
    );

    let mint_pubkey = mint;

    // Setup token accounts
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_key,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &secondary_authority.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    let mint_bytes = mint_pubkey.to_bytes();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::OracleTokenLimit(oracle_limit),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint_bytes,
                current_amount: 600_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    )
    .unwrap();

    // Fund swig's token account with 10 tokens
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        10_000_000_000, // 10 tokens with 9 decimals
    )
    .unwrap();

    // Test 1: Transfer below limit (0.5 tokens ≈ 0.75 USDC at mock price of 1.5 USDC per token)
    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::id(),
        &swig_ata,
        &recipient_ata,
        &swig_key,
        &[],
        500_000_000, // 0.5 tokens with 9 decimals
    )
    .unwrap();

    let mut sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix,
        1,
    )
    .unwrap();

    sign_ix.accounts.extend(vec![
        AccountMeta::new_readonly(
            Pubkey::from_str("Chpu5ZgfWX5ZzVpUx9Xvv4WPM75Xd7zPJNDPsFnCpLpk").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::from_str("3NJYftD5sjVfxSnUdZ1wVML8f3aC6mp1CXCL6L7TnU8C").unwrap(),
            false,
        ),
    ]);

    let message = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&secondary_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    println!("Result: {:?}", result);
    assert!(result.is_ok(), "Transfer below limit should succeed");
    println!(
        "Compute units consumed for below limit transfer: {}",
        result.unwrap().compute_units_consumed
    );

    // Test 2: Transfer above limit (2.5 tokens ≈ 3.75 USDC at mock price)
    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::id(),
        &swig_ata,
        &recipient_ata,
        &swig_key,
        &[],
        2_500_000_000, // 2.5 tokens with 9 decimals
    )
    .unwrap();

    let mut sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix,
        1,
    )
    .unwrap();

    sign_ix.accounts.extend(vec![
        AccountMeta::new_readonly(
            Pubkey::from_str("Chpu5ZgfWX5ZzVpUx9Xvv4WPM75Xd7zPJNDPsFnCpLpk").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::from_str("3NJYftD5sjVfxSnUdZ1wVML8f3aC6mp1CXCL6L7TnU8C").unwrap(),
            false,
        ),
    ]);

    let message = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&secondary_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(result.is_err(), "Transfer above limit should fail");
    assert_eq!(
        result.unwrap_err().err,
        solana_sdk::transaction::TransactionError::InstructionError(
            0,
            solana_sdk::instruction::InstructionError::Custom(3028)
        ),
        "Expected error code 3028"
    );
}

// fn create_alt_and_add(context: &mut SwigTestContext) -> Result<Pubkey, anyhow::Error> {
//     // Create the lookup table
//     let (create_lookup_table_ix, lookup_table_address) =
//         solana_sdk::address_lookup_table::instruction::create_lookup_table(
//             context.default_payer.pubkey(),
//             context.default_payer.pubkey(),
//             0,
//         );

//     let tx = Transaction::new_signed_with_payer(
//         &[create_lookup_table_ix],
//         Some(&context.default_payer.pubkey()),
//         &[&context.default_payer],
//         context.svm.latest_blockhash(),
//     );

//     context.svm.send_transaction(tx).unwrap();

//     // Add addresses to the lookup table
//     let addresses_to_add = vec![
//         Pubkey::from_str("3NJYftD5sjVfxSnUdZ1wVML8f3aC6mp1CXCL6L7TnU8C").unwrap(),
//         Pubkey::from_str("AxaxyeDT8JnWERSaTKvFXvPKkEdxnamKSqpWbsSjYg1g").unwrap(),
//     ];

//     let extend_lookup_table_ix = solana_sdk::address_lookup_table::instruction::extend_lookup_table(
//         lookup_table_address,
//         context.default_payer.pubkey(),
//         Some(context.default_payer.pubkey()),
//         addresses_to_add,
//     );

//     let tx = Transaction::new_signed_with_payer(
//         &[extend_lookup_table_ix],
//         Some(&context.default_payer.pubkey()),
//         &[&context.default_payer],
//         context.svm.latest_blockhash(),
//     );

//     context.svm.send_transaction(tx).unwrap();

//     println!("ALT address: {:?}", lookup_table_address);
//     Ok(lookup_table_address)
// }
