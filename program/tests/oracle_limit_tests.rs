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
            Pubkey::from_str("FbeuRDWwLvZWEU3HNtaLoYKagw9rH1NvmjpRMpjMwhDw").unwrap(),
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
            Pubkey::from_str("FbeuRDWwLvZWEU3HNtaLoYKagw9rH1NvmjpRMpjMwhDw").unwrap(),
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
            solana_sdk::instruction::InstructionError::Custom(3029)
        ),
        "Expected error code 3029"
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

    let oracle_mint = mint;
    let swig_ata = setup_ata(
        &mut context.svm,
        &oracle_mint,
        &swig_key,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &oracle_mint,
        &secondary_authority.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Fund swig's token account with 10 tokens
    mint_to(
        &mut context.svm,
        &oracle_mint,
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
            Pubkey::from_str("FbeuRDWwLvZWEU3HNtaLoYKagw9rH1NvmjpRMpjMwhDw").unwrap(),
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
            Pubkey::from_str("FbeuRDWwLvZWEU3HNtaLoYKagw9rH1NvmjpRMpjMwhDw").unwrap(),
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
            solana_sdk::instruction::InstructionError::Custom(3029)
        ),
        "Expected error code 3029"
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
            Pubkey::from_str("FbeuRDWwLvZWEU3HNtaLoYKagw9rH1NvmjpRMpjMwhDw").unwrap(),
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
            Pubkey::from_str("FbeuRDWwLvZWEU3HNtaLoYKagw9rH1NvmjpRMpjMwhDw").unwrap(),
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
            solana_sdk::instruction::InstructionError::Custom(3029)
        ),
        "Expected error code 3029"
    );
}

/// Test 5: Test token transfers with oracle limits and passthrough enabled
#[test_log::test]
fn test_oracle_limit_token_passthrough() {
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

    let oracle_mint = mint;

    // Setup token accounts
    let swig_ata = setup_ata(
        &mut context.svm,
        &oracle_mint,
        &swig_key,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &oracle_mint,
        &secondary_authority.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    let mint_bytes = oracle_mint.to_bytes();

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
        &oracle_mint,
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
            Pubkey::from_str("FbeuRDWwLvZWEU3HNtaLoYKagw9rH1NvmjpRMpjMwhDw").unwrap(),
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
            Pubkey::from_str("FbeuRDWwLvZWEU3HNtaLoYKagw9rH1NvmjpRMpjMwhDw").unwrap(),
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
            solana_sdk::instruction::InstructionError::Custom(3029)
        ),
        "Expected error code 3029"
    );
}

#[test_log::test]
fn test_oracle_stale_price() {
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

    // Test 1: Transfer with stale price
    advance_slot(&mut context, 150);

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
            Pubkey::from_str("FbeuRDWwLvZWEU3HNtaLoYKagw9rH1NvmjpRMpjMwhDw").unwrap(),
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
    assert!(result.is_err(), "Transfer with stale price should fail");
    assert_eq!(
        result.unwrap_err().err,
        solana_sdk::transaction::TransactionError::InstructionError(
            0,
            solana_sdk::instruction::InstructionError::Custom(63)
        ),
        "Expected error code 63"
    );
}

/// This test compares the baseline performance of:
/// 1. A regular SOL transfer (outside of swig)
/// 2. A SOL transfer using swig without oracle
/// 3. A SOL transfer using swig with oracle limit
/// It measures and compares compute units consumption and accounts used
#[test_log::test]
fn test_oracle_sol_transfer_performance_comparison() {
    let mut context = setup_test_context().unwrap();

    // Setup oracle data
    load_sample_scope_data(&mut context.svm, &context.default_payer).unwrap();

    // Setup payers and recipients
    let swig_authority = Keypair::new();
    let secondary_authority = Keypair::new();
    let regular_sender = Keypair::new();
    let recipient = Keypair::new();

    // Airdrop to participants
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&regular_sender.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // Setup swig account
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Fund swig wallet with SOL
    context.svm.airdrop(&swig, 20_000_000_000).unwrap();

    // Add secondary authority with oracle limit permission (1000 USDC limit)
    let oracle_limit = OracleTokenLimit::new(
        BaseAsset::USDC,
        1_000_000_000, // 1000 USDC with 6 decimals
        false,
    );

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
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

    // Measure regular SOL transfer performance
    let transfer_amount = 1_000_000_000; // 1 SOL

    let regular_transfer_ix = system_instruction::transfer(
        &regular_sender.pubkey(),
        &recipient.pubkey(),
        transfer_amount,
    );

    let regular_transfer_message = v0::Message::try_compile(
        &regular_sender.pubkey(),
        &[regular_transfer_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let regular_tx_accounts = regular_transfer_message.account_keys.len();

    let regular_transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(regular_transfer_message),
        &[regular_sender],
    )
    .unwrap();

    let regular_transfer_result = context.svm.send_transaction(regular_transfer_tx).unwrap();
    let regular_transfer_cu = regular_transfer_result.compute_units_consumed;

    println!("Regular SOL transfer CU: {}", regular_transfer_cu);
    println!("Regular SOL transfer accounts: {}", regular_tx_accounts);

    // Measure swig SOL transfer performance (without oracle)
    let swig_transfer_ix =
        system_instruction::transfer(&swig, &recipient.pubkey(), transfer_amount);

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        swig_authority.pubkey(),
        swig_authority.pubkey(),
        swig_transfer_ix,
        0, // authority role id
    )
    .unwrap();

    let swig_transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let swig_tx_accounts = swig_transfer_message.account_keys.len();

    let swig_transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(swig_transfer_message),
        &[swig_authority],
    )
    .unwrap();

    let swig_transfer_result = context.svm.send_transaction(swig_transfer_tx).unwrap();
    let swig_transfer_cu = swig_transfer_result.compute_units_consumed;
    println!("Swig SOL transfer CU: {}", swig_transfer_cu);
    println!("Swig SOL transfer accounts: {}", swig_tx_accounts);

    // Measure swig SOL transfer performance (with oracle)
    let swig_oracle_transfer_ix =
        system_instruction::transfer(&swig, &recipient.pubkey(), transfer_amount);

    let mut swig_oracle_sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        swig_oracle_transfer_ix,
        1, // secondary authority role id
    )
    .unwrap();

    // Add oracle accounts
    swig_oracle_sign_ix.accounts.extend(vec![
        AccountMeta::new_readonly(
            Pubkey::from_str("FbeuRDWwLvZWEU3HNtaLoYKagw9rH1NvmjpRMpjMwhDw").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::from_str("3NJYftD5sjVfxSnUdZ1wVML8f3aC6mp1CXCL6L7TnU8C").unwrap(),
            false,
        ),
    ]);

    let swig_oracle_transfer_message = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[swig_oracle_sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let swig_oracle_tx_accounts = swig_oracle_transfer_message.account_keys.len();

    let swig_oracle_transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(swig_oracle_transfer_message),
        &[secondary_authority],
    )
    .unwrap();

    let swig_oracle_transfer_result = context
        .svm
        .send_transaction(swig_oracle_transfer_tx)
        .unwrap();
    println!(
        "swig_oracle_transfer_result: {:?}",
        swig_oracle_transfer_result
    );
    let swig_oracle_transfer_cu = swig_oracle_transfer_result.compute_units_consumed;
    println!("Swig oracle SOL transfer CU: {}", swig_oracle_transfer_cu);
    println!(
        "Swig oracle SOL transfer accounts: {}",
        swig_oracle_tx_accounts
    );

    // Compare results
    let swig_cu_difference = swig_transfer_cu as i64 - regular_transfer_cu as i64;
    let swig_account_difference = swig_tx_accounts as i64 - regular_tx_accounts as i64;
    let oracle_cu_difference = swig_oracle_transfer_cu as i64 - regular_transfer_cu as i64;
    let oracle_account_difference = swig_oracle_tx_accounts as i64 - regular_tx_accounts as i64;
    let oracle_overhead = swig_oracle_transfer_cu as i64 - swig_transfer_cu as i64;

    println!("\n=== SOL Transfer Performance Comparison ===");
    println!("Regular SOL transfer:");
    println!(
        "  CU: {} | Accounts: {}",
        regular_transfer_cu, regular_tx_accounts
    );

    println!("\nSwig SOL transfer (without oracle):");
    println!(
        "  CU: {} | Accounts: {}",
        swig_transfer_cu, swig_tx_accounts
    );
    println!(
        "  Overhead: {} CU ({:.2}%) | {} accounts",
        swig_cu_difference,
        (swig_cu_difference as f64 / regular_transfer_cu as f64) * 100.0,
        swig_account_difference
    );

    println!("\nSwig SOL transfer (with oracle):");
    println!(
        "  CU: {} | Accounts: {}",
        swig_oracle_transfer_cu, swig_oracle_tx_accounts
    );
    println!(
        "  Total overhead: {} CU ({:.2}%) | {} accounts",
        oracle_cu_difference,
        (oracle_cu_difference as f64 / regular_transfer_cu as f64) * 100.0,
        oracle_account_difference
    );
    println!(
        "  Oracle overhead: {} CU ({:.2}%) | 2 accounts",
        oracle_overhead,
        (oracle_overhead as f64 / regular_transfer_cu as f64) * 100.0
    );

    // Assertions for performance limits
    // Swig overhead should be reasonable
    assert!(
        swig_transfer_cu - regular_transfer_cu <= 3777,
        "Swig overhead too high"
    );

    // Oracle overhead should be reasonable (additional oracle processing)
    assert!(
        swig_oracle_transfer_cu - swig_transfer_cu <= 12000,
        "Oracle overhead too high"
    );

    // Total oracle overhead should be reasonable
    assert!(
        swig_oracle_transfer_cu - regular_transfer_cu <= 12000,
        "Total oracle overhead too high"
    );
}

/// This test compares the baseline performance of:
/// 1. A regular token transfer (outside of swig)
/// 2. A token transfer using swig with oracle limit
/// It measures and compares compute units consumption and accounts used
#[test_log::test]
fn test_oracle_token_transfer_performance_comparison() {
    let mut context = setup_test_context().unwrap();

    // Setup oracle data
    let oracle_mint = load_sample_scope_data(&mut context.svm, &context.default_payer).unwrap();

    // Setup payers and recipients
    let swig_authority = Keypair::new();
    let secondary_authority = Keypair::new();
    let regular_sender = Keypair::new();
    let recipient = Keypair::new();

    // Airdrop to participants
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&regular_sender.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // Setup swig account
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Add secondary authority with oracle limit permission (1000 USDC limit)
    let oracle_limit = OracleTokenLimit::new(
        BaseAsset::USDC,
        1_000_000_000, // 1000 USDC with 6 decimals
        false,
    );

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
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

    // Setup token accounts
    let swig_ata = setup_ata(
        &mut context.svm,
        &oracle_mint,
        &swig,
        &context.default_payer,
    )
    .unwrap();

    let regular_sender_ata = setup_ata(
        &mut context.svm,
        &oracle_mint,
        &regular_sender.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    let recipient_ata = setup_ata(
        &mut context.svm,
        &oracle_mint,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Mint tokens to both sending accounts
    let initial_token_amount = 1000;
    mint_to(
        &mut context.svm,
        &oracle_mint,
        &context.default_payer,
        &swig_ata,
        initial_token_amount,
    )
    .unwrap();

    mint_to(
        &mut context.svm,
        &oracle_mint,
        &context.default_payer,
        &regular_sender_ata,
        initial_token_amount,
    )
    .unwrap();

    // Measure regular token transfer performance
    let transfer_amount = 100;
    let token_program_id = spl_token::ID;

    let regular_transfer_ix = spl_token::instruction::transfer(
        &token_program_id,
        &regular_sender_ata,
        &recipient_ata,
        &regular_sender.pubkey(),
        &[],
        transfer_amount,
    )
    .unwrap();

    let regular_transfer_message = v0::Message::try_compile(
        &regular_sender.pubkey(),
        &[regular_transfer_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let regular_tx_accounts = regular_transfer_message.account_keys.len();

    let regular_transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(regular_transfer_message),
        &[regular_sender],
    )
    .unwrap();

    let regular_transfer_result = context.svm.send_transaction(regular_transfer_tx).unwrap();
    let regular_transfer_cu = regular_transfer_result.compute_units_consumed;

    println!("Regular token transfer CU: {}", regular_transfer_cu);
    println!("Regular token transfer accounts: {}", regular_tx_accounts);

    // Measure swig token transfer performance (without oracle)
    let swig_transfer_ix = spl_token::instruction::transfer(
        &token_program_id,
        &swig_ata,
        &recipient_ata,
        &swig,
        &[],
        transfer_amount,
    )
    .unwrap();

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        swig_authority.pubkey(),
        swig_authority.pubkey(),
        swig_transfer_ix,
        0, // authority role id
    )
    .unwrap();

    let swig_transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let swig_tx_accounts = swig_transfer_message.account_keys.len();

    let swig_transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(swig_transfer_message),
        &[swig_authority],
    )
    .unwrap();

    let swig_transfer_result = context.svm.send_transaction(swig_transfer_tx).unwrap();
    let swig_transfer_cu = swig_transfer_result.compute_units_consumed;
    println!("Swig token transfer CU: {}", swig_transfer_cu);
    println!("Swig token transfer accounts: {}", swig_tx_accounts);

    // Measure swig token transfer performance (with oracle)
    let swig_oracle_transfer_ix = spl_token::instruction::transfer(
        &token_program_id,
        &swig_ata,
        &recipient_ata,
        &swig,
        &[],
        transfer_amount,
    )
    .unwrap();

    let mut swig_oracle_sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        swig_oracle_transfer_ix,
        1, // secondary authority role id
    )
    .unwrap();

    // Add oracle accounts
    swig_oracle_sign_ix.accounts.extend(vec![
        AccountMeta::new_readonly(
            Pubkey::from_str("FbeuRDWwLvZWEU3HNtaLoYKagw9rH1NvmjpRMpjMwhDw").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::from_str("3NJYftD5sjVfxSnUdZ1wVML8f3aC6mp1CXCL6L7TnU8C").unwrap(),
            false,
        ),
    ]);

    let swig_oracle_transfer_message = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[swig_oracle_sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let swig_oracle_tx_accounts = swig_oracle_transfer_message.account_keys.len();

    let swig_oracle_transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(swig_oracle_transfer_message),
        &[secondary_authority],
    )
    .unwrap();

    let swig_oracle_transfer_result = context
        .svm
        .send_transaction(swig_oracle_transfer_tx)
        .unwrap();
    let swig_oracle_transfer_cu = swig_oracle_transfer_result.compute_units_consumed;
    println!("Swig oracle token transfer CU: {}", swig_oracle_transfer_cu);
    println!(
        "Swig oracle token transfer accounts: {}",
        swig_oracle_tx_accounts
    );

    // Compare results
    let swig_cu_difference = swig_transfer_cu as i64 - regular_transfer_cu as i64;
    let swig_account_difference = swig_tx_accounts as i64 - regular_tx_accounts as i64;
    let oracle_cu_difference = swig_oracle_transfer_cu as i64 - regular_transfer_cu as i64;
    let oracle_account_difference = swig_oracle_tx_accounts as i64 - regular_tx_accounts as i64;
    let oracle_overhead = swig_oracle_transfer_cu as i64 - swig_transfer_cu as i64;

    println!("\n=== Performance Comparison ===");
    println!("Regular token transfer:");
    println!(
        "  CU: {} | Accounts: {}",
        regular_transfer_cu, regular_tx_accounts
    );

    println!("\nSwig token transfer (without oracle):");
    println!(
        "  CU: {} | Accounts: {}",
        swig_transfer_cu, swig_tx_accounts
    );
    println!(
        "  Overhead: {} CU ({:.2}%) | {} accounts",
        swig_cu_difference,
        (swig_cu_difference as f64 / regular_transfer_cu as f64) * 100.0,
        swig_account_difference
    );

    println!("\nSwig token transfer (with oracle):");
    println!(
        "  CU: {} | Accounts: {}",
        swig_oracle_transfer_cu, swig_oracle_tx_accounts
    );
    println!(
        "  Total overhead: {} CU ({:.2}%) | {} accounts",
        oracle_cu_difference,
        (oracle_cu_difference as f64 / regular_transfer_cu as f64) * 100.0,
        oracle_account_difference
    );
    println!(
        "  Oracle overhead: {} CU ({:.2}%) | 2 accounts",
        oracle_overhead,
        (oracle_overhead as f64 / regular_transfer_cu as f64) * 100.0
    );

    // Assertions for performance limits
    // Swig overhead should be reasonable
    assert!(
        swig_transfer_cu - regular_transfer_cu <= 3777,
        "Swig overhead too high"
    );

    // Oracle overhead should be reasonable (additional oracle processing)
    assert!(
        swig_oracle_transfer_cu - swig_transfer_cu <= 8000,
        "Oracle overhead too high"
    );

    // Total oracle overhead should be reasonable
    assert!(
        swig_oracle_transfer_cu - regular_transfer_cu <= 8777,
        "Total oracle overhead too high"
    );
}
