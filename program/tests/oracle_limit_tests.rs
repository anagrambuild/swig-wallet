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
use solana_sdk::address_lookup_table::state::AddressLookupTable;
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    message::{v0, AddressLookupTableAccount, VersionedMessage},
    signature::{Keypair, Signer},
    transaction::{Transaction, VersionedTransaction},
};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state_x::{
    action::{
        all::All,
        oracle_limits::{BaseAsset, OracleTokenLimit},
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
    assert_eq!(role.position.num_actions(), 2, "Should have 2 actions");

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
    load_sample_pyth_accounts(&mut context.svm);
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

    // Add oracle limit permission (1 USDC limit)
    let oracle_limit = OracleTokenLimit::new(
        BaseAsset::USDC,
        200_000_000, // 1 USDC limit
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
        vec![ClientAction::OracleTokenLimit(oracle_limit)],
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
            Pubkey::from_str("7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::from_str("AxaxyeDT8JnWERSaTKvFXvPKkEdxnamKSqpWbsSjYg1g").unwrap(),
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

    // Print logs for debugging
    match &result {
        Ok(tx_result) => {
            println!("Transaction logs:");
            for log in &tx_result.logs {
                println!("  {:?}", log);
            }
        },
        Err(err) => {
            println!("Transaction failed: {:?}", err);
        },
    }

    assert!(result.is_ok(), "Transfer below limit should succeed");

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
            Pubkey::from_str("7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::from_str("AxaxyeDT8JnWERSaTKvFXvPKkEdxnamKSqpWbsSjYg1g").unwrap(),
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
            solana_sdk::instruction::InstructionError::Custom(3022)
        ),
        "Expected error code 3022"
    );
}

/// Test 3: Test token transfers with oracle limits
#[test_log::test]
fn test_oracle_limit_token_transfer() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    load_sample_pyth_accounts(&mut context.svm);

    // Create wallet and setup
    let id = rand::random::<[u8; 32]>();
    let oracle_program = Keypair::new();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let secondary_authority = Keypair::new();
    context
        .svm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add oracle limit permission (3 USDC limit)
    let oracle_limit = OracleTokenLimit::new(
        BaseAsset::USDC,
        3_000_000, // 3 USDC with 6 decimals (native USDC decimals)
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
        vec![ClientAction::OracleTokenLimit(oracle_limit)],
    )
    .unwrap();

    // Setup token accounts
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
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

    // println!("Mint {:?}", mint_pubkey);
    // println!("transfer_ix: {:?}", &transfer_ix);

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix,
        1,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&secondary_authority])
        .unwrap();
    let swig_data = context.svm.get_account(&swig_key).unwrap();
    display_swig(swig_key, &swig_data);

    let result = context.svm.send_transaction(tx);

    // Print logs for debugging
    match &result {
        Ok(tx_result) => {
            println!("Transaction logs:");
            for log in &tx_result.logs {
                println!("  {:?}", log);
            }
        },
        Err(err) => {
            println!("Transaction failed: {:?}", err);
        },
    }

    assert!(result.is_ok(), "Transfer below limit should succeed");

    let swig_data = context.svm.get_account(&swig_key).unwrap();
    display_swig(swig_key, &swig_data);

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

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix,
        1,
    )
    .unwrap();

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
            solana_sdk::instruction::InstructionError::Custom(3022)
        ),
        "Expected error code 3022"
    );
}

/// Test 2: Test SOL transfers with oracle limits
#[test_log::test]
fn test_oracle_limit_sol_passthrough() {
    let mut context = setup_test_context().unwrap();
    load_sample_pyth_accounts(&mut context.svm);

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

    // Add oracle limit permission (1 USDC limit)
    let oracle_limit = OracleTokenLimit::new(
        BaseAsset::USDC,
        200_000_000, // 1 USDC limit
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
        ],
    )
    .unwrap();

    // Fund swig wallet
    context.svm.airdrop(&swig_key, 20_000_000_000).unwrap();

    let swig_data = context.svm.get_account(&swig_key).unwrap();
    display_swig(swig_key, &swig_data);

    let address_lookup_table_key = create_alt_and_add(&mut context).unwrap();

    let raw_account = context.svm.get_account(&address_lookup_table_key).unwrap();
    let address_lookup_table = AddressLookupTable::deserialize(&raw_account.data).unwrap();

    for address in address_lookup_table.addresses.to_vec() {
        println!("address: {:?}", &address.to_bytes());
    }

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

    // Add the addresses that were in lookup table to remaining accounts
    sign_ix.accounts.extend(vec![
        AccountMeta::new_readonly(
            Pubkey::from_str("7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::from_str("AxaxyeDT8JnWERSaTKvFXvPKkEdxnamKSqpWbsSjYg1g").unwrap(),
            false,
        ),
    ]);

    println!("sign_ix {:?}", &sign_ix);

    let address_lookup_table_account = AddressLookupTableAccount {
        key: address_lookup_table_key,
        addresses: address_lookup_table.addresses.to_vec(),
    };

    println!(
        "address_lookup_table_account: {:?}",
        &address_lookup_table_account
    );

    let message = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    println!("Message: {:?}", &message);

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&secondary_authority])
        .unwrap();

    println!("tx: {:?}", &tx);

    // read from json

    let pubkey = Pubkey::from_str("7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE").unwrap();
    let owner = Pubkey::from_str("rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ").unwrap();

    use base64;
    let mut data = Account {
        lamports: 1825020,
        data: base64::decode("IvEjY51+9M1gMUcENA3t3zcf1CRyFI8kjp0abRpesqw6zYt/1dayQwHvDYtv2izrpB2hXUCV0do5Kg0vjtDGx7wPTPrIwoC1bbLod+YDAAAA6QJ4AAAAAAD4////lZpJaAAAAACVmkloAAAAAMC2EeIDAAAALL2AAAAAAADcSaEUAAAAAAA=").unwrap(),
        owner,
        executable: false,
        rent_epoch: 18446744073709551615,
    };

    context.svm.set_account(pubkey, data);

    let result = context.svm.send_transaction(tx);
    if (result.is_ok()) {
        for log in &result.clone().unwrap().logs {
            println!("TX logs: {:?}", log);
        }
    } else {
        println!("result {:?}", &result);
    }
    assert!(&result.is_ok(), "Transfer below limit should succeed");

    let swig_data = context.svm.get_account(&swig_key).unwrap();
    display_swig(swig_key, &swig_data);

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

    // Add the addresses that were in lookup table to remaining accounts
    sign_ix.accounts.extend(vec![
        AccountMeta::new_readonly(
            Pubkey::from_str("7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::from_str("AxaxyeDT8JnWERSaTKvFXvPKkEdxnamKSqpWbsSjYg1g").unwrap(),
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
            solana_sdk::instruction::InstructionError::Custom(3022)
        ),
        "Expected error code 3022"
    );
}

/// Test 3: Test token transfers with oracle limits
#[test_log::test]
fn test_oracle_limit_passthrough() {
    let mut context = setup_test_context().unwrap();
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

    // Add oracle limit permission (3 USDC limit)
    let oracle_limit = OracleTokenLimit::new(
        BaseAsset::USDC,
        3_000_000, // 3 USDC with 6 decimals (native USDC decimals)
        true,
    );

    // Setup token accounts
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
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

    // println!("Mint {:?}", mint_pubkey);
    // println!("transfer_ix: {:?}", &transfer_ix);

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix,
        1,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix],
        // &[address_lookup_table_account],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    println!("msg {:?}", &message);

    let tx: VersionedTransaction =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&secondary_authority])
            .unwrap();

    println!("tx {:?}", &tx);
    let swig_data = context.svm.get_account(&swig_key).unwrap();
    display_swig(swig_key, &swig_data);

    let result = context.svm.send_transaction(tx);

    // Print logs for debugging
    match &result {
        Ok(tx_result) => {
            println!("Transaction logs:");
            for log in &tx_result.logs {
                println!("  {:?}", log);
            }
        },
        Err(err) => {
            println!("Transaction failed: {:?}", err);
        },
    }

    println!("mint: {:?}", &mint_bytes);
    assert!(result.is_ok(), "Transfer below limit should succeed");

    let swig_data = context.svm.get_account(&swig_key).unwrap();
    display_swig(swig_key, &swig_data);

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

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix,
        1,
    )
    .unwrap();

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
            solana_sdk::instruction::InstructionError::Custom(3022)
        ),
        "Expected error code 3022"
    );
}

use alloy_primitives::hex;
use solana_sdk::account::Account;
use swig_interface::program_id;
use swig_state_x::action::{
    manage_authority::ManageAuthority, program_scope::ProgramScope,
    sol_recurring_limit::SolRecurringLimit,
};
use swig_state_x::swig::swig_account_seeds;

pub fn display_swig(swig_pubkey: Pubkey, swig_account: &Account) -> Result<(), anyhow::Error> {
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();

    println!("╔══════════════════════════════════════════════════════════════════");
    println!("║ SWIG WALLET DETAILS");
    println!("╠══════════════════════════════════════════════════════════════════");
    println!("║ Account Address: {}", swig_pubkey);
    println!("║ Total Roles: {}", swig_with_roles.state.role_counter);
    println!(
        "║ Balance: {} SOL",
        swig_account.lamports as f64 / 1_000_000_000.0
    );

    println!("╠══════════════════════════════════════════════════════════════════");
    println!("║ ROLES & PERMISSIONS");
    println!("╠══════════════════════════════════════════════════════════════════");

    for i in 0..swig_with_roles.state.role_counter {
        let role = swig_with_roles.get_role(i).unwrap();

        if let Some(role) = role {
            println!("║");
            println!("║ Role ID: {}", i);
            println!(
                "║ ├─ Type: {}",
                if role.authority.session_based() {
                    "Session-based Authority"
                } else {
                    "Permanent Authority"
                }
            );
            println!("║ ├─ Authority Type: {:?}", role.authority.authority_type());
            println!(
                "║ ├─ Authority: {}",
                match role.authority.authority_type() {
                    AuthorityType::Ed25519 | AuthorityType::Ed25519Session => {
                        let authority = role.authority.identity().unwrap();
                        let authority = bs58::encode(authority).into_string();
                        authority
                    },
                    AuthorityType::Secp256k1 | AuthorityType::Secp256k1Session => {
                        let authority = role.authority.identity().unwrap();
                        let authority_hex = hex::encode([&[0x4].as_slice(), authority].concat());
                        // get eth address from public key
                        let mut hasher = solana_sdk::keccak::Hasher::default();
                        hasher.hash(authority_hex.as_bytes());
                        let hash = hasher.result();
                        let address = format!("0x{}", hex::encode(&hash.0[12..32]));
                        address
                    },
                    _ => todo!(),
                }
            );

            println!("║ ├─ Permissions:");

            let actions = role.get_all_actions().unwrap();
            println!("║ │  ├─ Actions length: {}", actions.len());
            for action in actions {
                println!("║ │  ├─ Action: {:?}", action);
            }

            // Check All permission
            if (Role::get_action::<All>(&role, &[]).unwrap()).is_some() {
                println!("║ │  ├─ Full Access (All Permissions)");
            }

            // Check Manage Authority permission
            if (Role::get_action::<ManageAuthority>(&role, &[]).unwrap()).is_some() {
                println!("║ │  ├─ Manage Authority");
            }

            // Check Sol Limit
            if let Some(action) = Role::get_action::<SolLimit>(&role, &[]).unwrap() {
                println!(
                    "║ │  ├─ SOL Limit: {} SOL",
                    action.amount as f64 / 1_000_000_000.0
                );
            }

            // Check Sol Recurring Limit
            if let Some(action) = Role::get_action::<SolRecurringLimit>(&role, &[]).unwrap() {
                println!("║ │  ├─ Recurring SOL Limit:");
                println!(
                    "║ │  │  ├─ Amount: {} SOL",
                    action.recurring_amount as f64 / 1_000_000_000.0
                );
                println!("║ │  │  ├─ Window: {} slots", action.window);
                println!(
                    "║ │  │  ├─ Current Usage: {} SOL",
                    action.current_amount as f64 / 1_000_000_000.0
                );
                println!("║ │  │  └─ Last Reset: Slot {}", action.last_reset);
            }

            // Check Program Scope
            if let Some(action) =
                Role::get_action::<ProgramScope>(&role, &spl_token::ID.to_bytes()).unwrap()
            {
                let program_id = Pubkey::from(action.program_id);
                let target_account = Pubkey::from(action.target_account);
                println!("║ │  ├─ Program Scope");
                println!("║ │  │  ├─ Program ID: {}", program_id);
                println!("║ │  │  ├─ Target Account: {}", target_account);
                println!(
                    "║ │  │  ├─ Scope Type: {}",
                    match action.scope_type {
                        0 => "Basic",
                        1 => "Limit",
                        2 => "Recurring Limit",
                        _ => "Unknown",
                    }
                );
                println!(
                    "║ │  │  ├─ Numeric Type: {}",
                    match action.numeric_type {
                        0 => "U64",
                        1 => "U128",
                        2 => "F64",
                        _ => "Unknown",
                    }
                );
                if action.scope_type > 0 {
                    println!("║ │  │  ├─ Limit: {} ", action.limit);
                    println!("║ │  │  ├─ Current Usage: {} ", action.current_amount);
                }
                if action.scope_type == 2 {
                    println!("║ │  │  ├─ Window: {} slots", action.window);
                    println!("║ │  │  ├─ Last Reset: Slot {}", action.last_reset);
                }
                println!("║ │  │  ");
            }

            // Oracle limits
            if let Some(action) = Role::get_action::<OracleTokenLimit>(&role, &[0u8]).unwrap() {
                println!("║ │  ├─ Oracle Token Limit:");
                println!(
                    "║ │  │  ├─ Base Asset: {}",
                    match action.base_asset_type {
                        0 => "USDC",
                        1 => "EURC",
                        _ => "Unknown",
                    }
                );
                println!(
                    "║ │  │  ├─ Value Limit: {} {}",
                    action.value_limit as f64 / 1_000_000.0, // Divide by 10^6 since USDC/EURC have 6 decimals
                    match action.base_asset_type {
                        0 => "USDC",
                        1 => "EURC",
                        _ => "Unknown",
                    }
                );
            }
            println!("║ │  ");
        }
    }

    println!("╚══════════════════════════════════════════════════════════════════");

    Ok(())
}

fn create_alt_and_add(context: &mut SwigTestContext) -> Result<Pubkey, anyhow::Error> {
    // Create the lookup table
    let (create_lookup_table_ix, lookup_table_address) =
        solana_sdk::address_lookup_table::instruction::create_lookup_table(
            context.default_payer.pubkey(),
            context.default_payer.pubkey(),
            0,
        );

    let tx = Transaction::new_signed_with_payer(
        &[create_lookup_table_ix],
        Some(&context.default_payer.pubkey()),
        &[&context.default_payer],
        context.svm.latest_blockhash(),
    );

    context.svm.send_transaction(tx).unwrap();

    // Add addresses to the lookup table
    let addresses_to_add = vec![
        Pubkey::from_str("7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE").unwrap(),
        Pubkey::from_str("AxaxyeDT8JnWERSaTKvFXvPKkEdxnamKSqpWbsSjYg1g").unwrap(),
    ];

    let extend_lookup_table_ix = solana_sdk::address_lookup_table::instruction::extend_lookup_table(
        lookup_table_address,
        context.default_payer.pubkey(),
        Some(context.default_payer.pubkey()),
        addresses_to_add,
    );

    let tx = Transaction::new_signed_with_payer(
        &[extend_lookup_table_ix],
        Some(&context.default_payer.pubkey()),
        &[&context.default_payer],
        context.svm.latest_blockhash(),
    );

    context.svm.send_transaction(tx).unwrap();

    println!("ALT address: {:?}", lookup_table_address);
    Ok(lookup_table_address)
}
