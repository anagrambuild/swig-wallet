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
        oracle_recurring_limit::OracleRecurringLimit,
        program_all::ProgramAll,
        sol_limit::SolLimit,
        sol_recurring_limit::SolRecurringLimit,
        token_limit::TokenLimit,
        token_recurring_limit::TokenRecurringLimit,
        Permission,
    },
    authority::AuthorityType,
    role::Role,
    swig::SwigWithRoles,
};

/// Test 1: Verify oracle recurring limit permission is added correctly
#[test_log::test]
fn test_oracle_recurring_limit_permission_add() {
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

    // Add multiple permissions: Oracle Recurring Limit (200 USDC per window) and SOL Limit (1 SOL)
    let oracle_recurring_limit = OracleRecurringLimit::new(
        BaseAsset::USDC,
        200_000_000, // 200 USDC
        1000,        // 1000 slots window
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
            ClientAction::OracleRecurringLimit(oracle_recurring_limit),
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

    let oracle_recurring_action = role
        .get_action::<OracleRecurringLimit>(&[BaseAsset::USDC as u8])
        .unwrap()
        .unwrap();

    assert_eq!(
        oracle_recurring_action.recurring_value_limit, 200_000_000,
        "Oracle recurring limit should be 200 USDC"
    );
    assert_eq!(
        oracle_recurring_action.window, 1000,
        "Window should be 1000 slots"
    );
    assert_eq!(
        oracle_recurring_action.last_reset, 0,
        "Last reset should be 0 initially"
    );
    assert_eq!(
        oracle_recurring_action.current_amount, 200_000_000,
        "Current amount should equal recurring limit initially"
    );
}

/// Test 2: Verify oracle recurring limit for SOL transfers
#[test_log::test]
fn test_oracle_recurring_limit_sol_transfer() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create a swig wallet
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Create secondary authority
    let secondary_authority = Keypair::new();
    context
        .svm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add oracle recurring limit permission (100 USDC per window)
    let oracle_recurring_limit = OracleRecurringLimit::new(
        BaseAsset::USDC,
        100_000_000, // 100 USDC
        1000,        // 1000 slots window
        false,
    );

    // Add authority with oracle recurring limit permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::OracleRecurringLimit(oracle_recurring_limit),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    )
    .unwrap();

    // Load oracle accounts
    let mint = load_sample_scope_data(&mut context.svm, &context.default_payer).unwrap();

    // Fund swig wallet
    context.svm.airdrop(&swig_key, 20_000_000_000).unwrap();

    // Test SOL transfer within limit (0.1 SOL ≈ 15 USDC at mock price)
    let transfer_ix = system_instruction::transfer(
        &swig_key,
        &secondary_authority.pubkey(),
        100_000_000, // 0.1 SOL
    );

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

    // This should succeed as it's within the oracle recurring limit
    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "SOL transfer should succeed within oracle recurring limit"
    );

    // Test SOL transfer that exceeds the limit (1 SOL ≈ 150 USDC at mock price)
    let transfer_ix2 = system_instruction::transfer(
        &swig_key,
        &secondary_authority.pubkey(),
        1_000_000_000, // 1 SOL
    );

    let mut sign_ix2 = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix2,
        1,
    )
    .unwrap();

    sign_ix2.accounts.extend(vec![
        AccountMeta::new_readonly(
            Pubkey::from_str("FbeuRDWwLvZWEU3HNtaLoYKagw9rH1NvmjpRMpjMwhDw").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::from_str("3NJYftD5sjVfxSnUdZ1wVML8f3aC6mp1CXCL6L7TnU8C").unwrap(),
            false,
        ),
    ]);

    let message2 = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx2 =
        VersionedTransaction::try_new(VersionedMessage::V0(message2), &[&secondary_authority])
            .unwrap();

    // This should fail as it exceeds the oracle recurring limit
    let result2 = context.svm.send_transaction(tx2);
    assert!(
        result2.is_err(),
        "SOL transfer should fail when exceeding oracle recurring limit"
    );
}

/// Test 3: Verify oracle recurring limit for token transfers
#[test_log::test]
fn test_oracle_recurring_limit_token_transfer() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create a swig wallet
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Create secondary authority
    let secondary_authority = Keypair::new();
    context
        .svm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add oracle recurring limit permission (50 USDC per window)
    let oracle_recurring_limit = OracleRecurringLimit::new(
        BaseAsset::USDC,
        50_000_000, // 50 USDC
        100,        // 100 slots window
        false,
    );

    // Add authority with oracle recurring limit permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::OracleRecurringLimit(oracle_recurring_limit),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    )
    .unwrap();

    // Load oracle accounts
    let mint = load_sample_scope_data(&mut context.svm, &context.default_payer).unwrap();

    // Setup token mint and accounts
    let swig_ata = setup_ata(&mut context.svm, &mint, &swig_key, &context.default_payer).unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint,
        &secondary_authority.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Mint tokens to swig account
    mint_to(
        &mut context.svm,
        &mint,
        &context.default_payer,
        &swig_ata,
        1_000_000_000, // 1000 tokens
    )
    .unwrap();

    // Test token transfer within limit (100 tokens ≈ 150 USDC at mock price of 1.5 USDC per token)
    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::id(),
        &swig_ata,
        &recipient_ata,
        &swig_key,
        &[],
        100_000_000, // 100 tokens
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

    // This should succeed as it's within the oracle recurring limit
    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Token transfer should succeed within oracle recurring limit"
    );

    // Move slot forward

    // Test token transfer that exceeds the limit (1000 tokens ≈ 1500 USDC at mock price)
    let transfer_ix2 = spl_token::instruction::transfer(
        &spl_token::id(),
        &swig_ata,
        &recipient_ata,
        &swig_key,
        &[],
        1_000_000_000, // 1000 tokens
    )
    .unwrap();

    let mut sign_ix2 = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix2,
        1,
    )
    .unwrap();

    sign_ix2.accounts.extend(vec![
        AccountMeta::new_readonly(
            Pubkey::from_str("FbeuRDWwLvZWEU3HNtaLoYKagw9rH1NvmjpRMpjMwhDw").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::from_str("3NJYftD5sjVfxSnUdZ1wVML8f3aC6mp1CXCL6L7TnU8C").unwrap(),
            false,
        ),
    ]);

    let message2 = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx2 =
        VersionedTransaction::try_new(VersionedMessage::V0(message2), &[&secondary_authority])
            .unwrap();

    // This should fail as it exceeds the oracle recurring limit
    let result2 = context.svm.send_transaction(tx2);
    assert!(
        result2.is_err(),
        "Token transfer should fail when exceeding oracle recurring limit"
    );
}

/// Test 4: Verify oracle recurring limit window reset functionality
#[test_log::test]
fn test_oracle_recurring_limit_window_reset() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create a swig wallet
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Create secondary authority
    let secondary_authority = Keypair::new();
    context
        .svm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add oracle recurring limit permission (100 USDC per window, 100 slots window)
    let oracle_recurring_limit = OracleRecurringLimit::new(
        BaseAsset::USDC,
        100_000_000, // 100 USDC
        3,           // 3 slots window (smaller to avoid stale price)
        false,
    );

    // Add authority with oracle recurring limit permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::OracleRecurringLimit(oracle_recurring_limit),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    )
    .unwrap();

    // Load oracle accounts
    let mint = load_sample_scope_data(&mut context.svm, &context.default_payer).unwrap();

    // Fund swig wallet
    context.svm.airdrop(&swig_key, 20_000_000_000).unwrap();

    // Use up most of the limit
    let transfer_ix = system_instruction::transfer(
        &swig_key,
        &secondary_authority.pubkey(),
        500_000_000, // 0.5 SOL (should use up most of 100 USDC limit)
    );

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
    assert!(result.is_ok(), "First SOL transfer should succeed");

    // Try to transfer more than remaining limit (should fail)
    let transfer_ix2 = system_instruction::transfer(
        &swig_key,
        &secondary_authority.pubkey(),
        50_000_000, // 0.05 SOL (should exceed remaining limit)
    );

    let mut sign_ix2 = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix2,
        1,
    )
    .unwrap();

    sign_ix2.accounts.extend(vec![
        AccountMeta::new_readonly(
            Pubkey::from_str("FbeuRDWwLvZWEU3HNtaLoYKagw9rH1NvmjpRMpjMwhDw").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::from_str("3NJYftD5sjVfxSnUdZ1wVML8f3aC6mp1CXCL6L7TnU8C").unwrap(),
            false,
        ),
    ]);

    let message2 = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx2 =
        VersionedTransaction::try_new(VersionedMessage::V0(message2), &[&secondary_authority])
            .unwrap();

    let result2 = context.svm.send_transaction(tx2);
    assert!(result2.is_err(), "Second transfer should fail due to limit");

    // Try the same transfer again (should succeed after window reset)
    let transfer_ix3 = system_instruction::transfer(
        &swig_key,
        &secondary_authority.pubkey(),
        51_000_000, // 0.05 SOL (should succeed after window reset)
    );

    let mut sign_ix3 = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix3,
        1,
    )
    .unwrap();

    sign_ix3.accounts.extend(vec![
        AccountMeta::new_readonly(
            Pubkey::from_str("FbeuRDWwLvZWEU3HNtaLoYKagw9rH1NvmjpRMpjMwhDw").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::from_str("3NJYftD5sjVfxSnUdZ1wVML8f3aC6mp1CXCL6L7TnU8C").unwrap(),
            false,
        ),
    ]);

    println!("slot: {:?}", advance_slot(&mut context, 4));

    let message3 = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix3],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx3 =
        VersionedTransaction::try_new(VersionedMessage::V0(message3), &[&secondary_authority])
            .unwrap();

    let result3 = context.svm.send_transaction(tx3);
    println!("result3: {:?}", result3);
    assert!(
        result3.is_ok(),
        "Transfer should succeed after window reset"
    );
}

/// Test 5: Verify oracle recurring limit with passthrough check
#[test_log::test]
fn test_oracle_recurring_limit_passthrough() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create a swig wallet
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Create secondary authority
    let secondary_authority = Keypair::new();
    context
        .svm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add oracle recurring limit permission with passthrough enabled
    let oracle_recurring_limit = OracleRecurringLimit::new(
        BaseAsset::USDC,
        100_000_000, // 100 USDC
        1000,        // 1000 slots window
        true,        // passthrough enabled
    );

    // Add SOL limit as well
    let sol_limit = SolLimit {
        amount: 500_000_000, // 0.5 SOL
    };

    // Add authority with both permissions
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::OracleRecurringLimit(oracle_recurring_limit),
            ClientAction::SolLimit(sol_limit),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    )
    .unwrap();

    // Load oracle accounts
    let mint = load_sample_scope_data(&mut context.svm, &context.default_payer).unwrap();

    // Fund swig wallet
    context.svm.airdrop(&swig_key, 20_000_000_000).unwrap();

    // Test transfer that passes oracle recurring limit but should be caught by SOL limit
    let transfer_ix = system_instruction::transfer(
        &swig_key,
        &secondary_authority.pubkey(),
        600_000_000, // 0.6 SOL (within oracle limit but exceeds SOL limit)
    );

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

    // This should fail due to SOL limit even though it passes oracle recurring limit
    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Transfer should fail due to SOL limit even with passthrough"
    );
}
