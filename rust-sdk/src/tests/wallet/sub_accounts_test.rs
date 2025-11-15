use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use solana_sdk::signature::{Keypair, Signer};
use solana_system_interface::instruction as system_instruction;
use spl_token::ID as TOKEN_PROGRAM_ID;
use swig_interface::program_id;
use swig_state::{
    authority::AuthorityType,
    swig::{sub_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
};

use super::*;
use crate::client_role::Ed25519ClientRole;

#[test_log::test]
fn test_sub_account_creation_and_setup() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Setup secondary authority
    let secondary_authority = Keypair::new();
    let secondary_role_id = 1;
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::SubAccount {
                sub_account: [0; 32],
            }],
        )
        .unwrap();

    // Switch to secondary authority and create sub-account
    swig_wallet
        .switch_authority(
            secondary_role_id,
            Box::new(Ed25519ClientRole::new(secondary_authority.pubkey())),
            Some(&secondary_authority),
        )
        .unwrap();

    let signature = swig_wallet.create_sub_account().unwrap();
    println!("Sub-account created with signature: {:?}", signature);

    // Verify sub-account creation
    let role_id_bytes = swig_wallet.get_current_role_id().unwrap().to_le_bytes();
    let (sub_account, _) = Pubkey::find_program_address(
        &swig_state::swig::sub_account_seeds(&[0; 32], &role_id_bytes),
        &swig_interface::program_id(),
    );
    println!("Sub-account address: {}", &sub_account);
}

#[test_log::test]
fn test_sub_account_sol_operations() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Setup secondary authority and create sub-account
    let secondary_authority = Keypair::new();
    let secondary_role_id = 1;
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::SubAccount {
                sub_account: [0; 32],
            }],
        )
        .unwrap();

    // Switch to secondary authority with explicit authority keypair
    swig_wallet
        .switch_authority(
            secondary_role_id,
            Box::new(Ed25519ClientRole::new(secondary_authority.pubkey())),
            Some(&secondary_authority),
        )
        .unwrap();

    // Create sub-account
    let signature = swig_wallet.create_sub_account().unwrap();
    println!("Created sub-account with signature: {:?}", signature);

    // Get sub-account address
    let role_id_bytes = swig_wallet.get_current_role_id().unwrap().to_le_bytes();

    println!("Swig ID: {:?}", [0; 32]);
    println!("Role ID: {:?}", swig_wallet.get_current_role_id().unwrap());
    println!("program_id: {:?}", swig_interface::program_id());
    let (sub_account, _) = Pubkey::find_program_address(
        &swig_state::swig::sub_account_seeds(&[0; 32], &role_id_bytes),
        &swig_interface::program_id(),
    );
    println!("Sub-account address: {}", &sub_account);

    // Fund accounts
    swig_wallet
        .litesvm()
        .airdrop(&sub_account, 100_000_000)
        .unwrap();

    let recipient = Keypair::new();
    swig_wallet
        .litesvm()
        .airdrop(&recipient.pubkey(), 1_000_000)
        .unwrap();

    swig_wallet
        .litesvm()
        .airdrop(&secondary_authority.pubkey(), 1_000_000)
        .unwrap();

    // Get initial balances
    let initial_balance = swig_wallet.litesvm().get_balance(&sub_account).unwrap();
    println!("Initial sub-account balance: {:?}", initial_balance);
    let initial_recipient_balance = swig_wallet
        .litesvm()
        .get_balance(&recipient.pubkey())
        .unwrap();
    println!("Initial recipient balance: {:?}", initial_recipient_balance);

    // Test transfer
    let transfer_ix = system_instruction::transfer(&sub_account, &recipient.pubkey(), 1_000_000);
    let signature = swig_wallet
        .sign_with_sub_account(vec![transfer_ix], None)
        .unwrap();
    println!("Transfer signature: {:?}", signature);

    // Verify the transfer
    let final_balance = swig_wallet.litesvm().get_balance(&sub_account).unwrap();
    let recipient_balance = swig_wallet
        .litesvm()
        .get_balance(&recipient.pubkey())
        .unwrap();
    assert_eq!(
        initial_balance - final_balance,
        1_000_000,
        "Transfer amount mismatch"
    );
    assert_eq!(
        recipient_balance,
        2_000_000, // Initial 1M + transferred 1M
        "Recipient balance mismatch"
    );

    // Test withdrawal
    let initial_balance = final_balance;

    // Switch back to main authority
    swig_wallet
        .switch_authority(
            0,
            Box::new(Ed25519ClientRole::new(main_authority.pubkey())),
            Some(&main_authority),
        )
        .unwrap();

    let signature = swig_wallet
        .withdraw_from_sub_account(sub_account, 500_000)
        .unwrap();
    println!("Withdrawal signature: {:?}", signature);

    // Verify the withdrawal
    let final_balance = swig_wallet.litesvm().get_balance(&sub_account).unwrap();
    assert_eq!(
        initial_balance - final_balance,
        500_000,
        "Withdrawal amount mismatch"
    );
}

#[test_log::test]
fn test_sub_account_token_operations() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Setup and create sub-account
    let secondary_authority = Keypair::new();
    let secondary_role_id = 1;
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::SubAccount {
                sub_account: [0; 32],
            }],
        )
        .unwrap();

    swig_wallet
        .switch_authority(
            secondary_role_id,
            Box::new(Ed25519ClientRole::new(secondary_authority.pubkey())),
            Some(&secondary_authority),
        )
        .unwrap();

    let signature = swig_wallet.create_sub_account().unwrap();
    let role_id_bytes = swig_wallet.get_current_role_id().unwrap().to_le_bytes();
    let (sub_account, _) = Pubkey::find_program_address(
        &swig_state::swig::sub_account_seeds(&[0; 32], &role_id_bytes),
        &swig_interface::program_id(),
    );

    use crate::tests::common::{mint_to, setup_ata, setup_mint};
    // Test token operations
    let mint = setup_mint(swig_wallet.litesvm(), &main_authority).unwrap();

    // Setup ATAs for sub-account and swig
    let sub_account_ata =
        setup_ata(swig_wallet.litesvm(), &mint, &sub_account, &main_authority).unwrap();
    // Derive swig_wallet_address PDA using the on-chain expected seeds (swig
    // account key)
    let swig_account = swig_wallet.get_swig_account().unwrap();
    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(swig_account.as_ref()),
        &swig_interface::program_id(),
    );
    let swig_token = setup_ata(
        swig_wallet.litesvm(),
        &mint,
        &swig_wallet_address,
        &main_authority,
    )
    .unwrap();

    // Mint some tokens to the sub-account ATA
    mint_to(
        swig_wallet.litesvm(),
        &mint,
        &main_authority,
        &sub_account_ata,
        10000,
    )
    .unwrap();

    swig_wallet
        .switch_authority(
            0,
            Box::new(Ed25519ClientRole::new(main_authority.pubkey())),
            Some(&main_authority),
        )
        .unwrap();
    let signature = swig_wallet
        .withdraw_token_from_sub_account(
            sub_account,
            sub_account_ata,
            swig_token,
            TOKEN_PROGRAM_ID,
            1000,
        )
        .unwrap();
    println!("Token withdrawal signature: {:?}", signature);
}

#[test_log::test]
fn test_sub_account_toggle_operations() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Setup and create sub-account
    let secondary_authority = Keypair::new();
    let secondary_role_id = 1;
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::SubAccount {
                sub_account: [0; 32],
            }],
        )
        .unwrap();

    swig_wallet
        .switch_authority(
            secondary_role_id,
            Box::new(Ed25519ClientRole::new(secondary_authority.pubkey())),
            Some(&secondary_authority),
        )
        .unwrap();

    let signature = swig_wallet.create_sub_account().unwrap();
    let role_id_bytes = swig_wallet.get_current_role_id().unwrap().to_le_bytes();
    let (sub_account, _) = Pubkey::find_program_address(
        &swig_state::swig::sub_account_seeds(&[0; 32], &role_id_bytes),
        &swig_interface::program_id(),
    );

    // swig_wallet
    //     .switch_authority(
    //         0,
    //         Box::new(Ed25519ClientRole::new(main_authority.pubkey())),
    //         Some(&main_authority),
    //     )
    //     .unwrap();

    // Test toggle operations
    let signature = swig_wallet
        .toggle_sub_account(sub_account, secondary_role_id, secondary_role_id, false)
        .unwrap();
    println!("Disable signature: {:?}", signature);

    let signature = swig_wallet
        .toggle_sub_account(sub_account, 1, 1, true)
        .unwrap();
    println!("Enable signature: {:?}", signature);
}

#[test_log::test]
fn test_secondary_authority_operations() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Setup secondary authority
    let secondary_authority = Keypair::new();
    let secondary_role_id = 1;
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::SubAccount {
                sub_account: [0; 32],
            }],
        )
        .unwrap();

    // Create sub-account with main authority
    swig_wallet
        .switch_authority(
            secondary_role_id,
            Box::new(Ed25519ClientRole::new(secondary_authority.pubkey())),
            Some(&secondary_authority),
        )
        .unwrap();

    let signature = swig_wallet.create_sub_account().unwrap();
    let role_id_bytes = swig_wallet.get_current_role_id().unwrap().to_le_bytes();
    let (sub_account, _) = Pubkey::find_program_address(
        &swig_state::swig::sub_account_seeds(&[0; 32], &role_id_bytes),
        &swig_interface::program_id(),
    );

    // Test secondary authority operations
    let recipient = Keypair::new();
    let transfer_ix = system_instruction::transfer(&sub_account, &recipient.pubkey(), 1_000_000);

    // Fund sub-account
    swig_wallet
        .litesvm()
        .airdrop(&sub_account, 100_000_000)
        .unwrap();

    let signature = swig_wallet
        .sign_with_sub_account(vec![transfer_ix], None)
        .unwrap();
    println!("Secondary authority signature: {:?}", signature);

    // Verify final state
    assert!(signature != solana_sdk::signature::Signature::default());
    assert_eq!(
        swig_wallet.get_current_role_id().unwrap(),
        secondary_role_id
    );
    assert!(swig_wallet.get_sub_account().unwrap().is_some());
}

#[test_log::test]
fn test_sub_account_error_cases() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Test Case 1: Non-existent sub-account operations
    let non_existent_sub_account = Pubkey::new_unique();
    let result = swig_wallet.withdraw_from_sub_account(non_existent_sub_account, 1000);
    assert!(matches!(
        result.unwrap_err(),
        SwigError::TransactionFailedWithLogs { .. }
    ));

    // Test Case 2: Authority without sub-account permissions
    let unauthorized_authority = Keypair::new();
    let recurring = RecurringConfig::new(100);
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &unauthorized_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 100_000_000,
                recurring: Some(recurring),
            }], // No sub-account permission
        )
        .unwrap();

    // Switch to unauthorized authority
    swig_wallet
        .switch_authority(
            1,
            Box::new(Ed25519ClientRole::new(unauthorized_authority.pubkey())),
            Some(&unauthorized_authority),
        )
        .unwrap();

    // Fund the unauthorized authority for transaction fees
    swig_wallet
        .litesvm()
        .airdrop(&unauthorized_authority.pubkey(), 100_000_000)
        .unwrap();

    // Test Case 3: Creating sub-account without permission
    let result = swig_wallet.create_sub_account();
    assert!(matches!(
        result.unwrap_err(),
        SwigError::TransactionFailedWithLogs { .. }
    ));

    // Test Case 4: Create valid sub-account with main authority
    // First, ensure main authority has sub-account permission
    // Add sub-account permission to main authority
    swig_wallet
        .switch_authority(
            0,
            Box::new(Ed25519ClientRole::new(main_authority.pubkey())),
            Some(&main_authority),
        )
        .unwrap();

    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &main_authority.pubkey().to_bytes(),
            vec![Permission::SubAccount {
                sub_account: [0; 32],
            }],
        )
        .unwrap();

    swig_wallet
        .switch_authority(
            2,
            Box::new(Ed25519ClientRole::new(main_authority.pubkey())),
            Some(&main_authority),
        )
        .unwrap();

    let signature = swig_wallet.create_sub_account().unwrap();
    println!("Created sub-account with signature: {:?}", signature);

    // Get sub-account address
    let sub_account_role_id = swig_wallet.get_current_role_id().unwrap();
    let role_id_bytes = sub_account_role_id.to_le_bytes();
    let (sub_account, _) = Pubkey::find_program_address(
        &swig_state::swig::sub_account_seeds(&[0; 32], &role_id_bytes),
        &swig_interface::program_id(),
    );

    // Fund the sub-account for withdrawal tests
    swig_wallet
        .litesvm()
        .airdrop(&sub_account, 1_000_000)
        .unwrap();

    // Test Case 5: Unauthorized operations on existing sub-account
    swig_wallet
        .switch_authority(
            1,
            Box::new(Ed25519ClientRole::new(unauthorized_authority.pubkey())),
            Some(&unauthorized_authority),
        )
        .unwrap();

    // Try to withdraw with unauthorized authority
    let result = swig_wallet.withdraw_from_sub_account(sub_account, 1000);
    assert!(matches!(
        result.unwrap_err(),
        SwigError::TransactionFailedWithLogs { .. }
    ));

    // Try to toggle with unauthorized authority
    let result = swig_wallet.toggle_sub_account(sub_account, sub_account_role_id, 1, false);
    assert!(matches!(
        result.unwrap_err(),
        SwigError::TransactionFailedWithLogs { .. }
    ));

    // Test Case 6: Invalid sub-account operations with main authority
    swig_wallet
        .switch_authority(
            0,
            Box::new(Ed25519ClientRole::new(main_authority.pubkey())),
            Some(&main_authority),
        )
        .unwrap();

    // Try to withdraw more than balance
    let result = swig_wallet.withdraw_from_sub_account(sub_account, u64::MAX);
    assert!(matches!(
        result.unwrap_err(),
        SwigError::TransactionFailedWithLogs { .. }
    ));
}
