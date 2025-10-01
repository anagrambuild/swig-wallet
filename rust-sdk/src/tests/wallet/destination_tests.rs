use solana_program::{system_instruction, system_program};
use solana_sdk::signature::{Keypair, Signer};

use super::*;
use crate::{
    client_role::Ed25519ClientRole,
    types::{Permission, RecurringConfig},
};

#[test_log::test]
fn should_add_sol_destination_limit() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let secondary_authority = Keypair::new();
    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let destination = Keypair::new().pubkey();
    let limit_amount = 500_000; // 0.0005 SOL

    // Setup secondary authority with SOL destination limit
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![
                Permission::Program {
                    program_id: system_program::ID,
                },
                Permission::SolDestination {
                    destination,
                    amount: limit_amount,
                    recurring: None,
                },
            ],
        )
        .unwrap();

    // Verify the authority was added
    assert_eq!(swig_wallet.get_role_count().unwrap(), 2);

    let role_id = swig_wallet
        .get_role_id(&secondary_authority.pubkey().to_bytes())
        .unwrap();
    assert_eq!(role_id, 1);
}

#[test_log::test]
fn should_add_sol_recurring_destination_limit() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let secondary_authority = Keypair::new();
    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let destination = Keypair::new().pubkey();
    let limit_amount = 500_000; // 0.0005 SOL
    let window = 1000; // 1000 slots

    // Setup secondary authority with SOL recurring destination limit
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![
                Permission::Program {
                    program_id: system_program::ID,
                },
                Permission::SolDestination {
                    destination,
                    amount: limit_amount,
                    recurring: Some(RecurringConfig::new(window)),
                },
            ],
        )
        .unwrap();

    // Verify the authority was added
    assert_eq!(swig_wallet.get_role_count().unwrap(), 2);

    let role_id = swig_wallet
        .get_role_id(&secondary_authority.pubkey().to_bytes())
        .unwrap();
    assert_eq!(role_id, 1);
}

#[test_log::test]
fn should_add_token_destination_limit() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let secondary_authority = Keypair::new();
    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let token_mint = Keypair::new().pubkey();
    let destination = Keypair::new().pubkey();
    let limit_amount = 1000; // 1000 tokens

    // Setup secondary authority with token destination limit
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![
                Permission::Program {
                    program_id: system_program::ID,
                },
                Permission::TokenDestination {
                    mint: token_mint,
                    destination,
                    amount: limit_amount,
                    recurring: None,
                },
            ],
        )
        .unwrap();

    // Verify the authority was added
    assert_eq!(swig_wallet.get_role_count().unwrap(), 2);

    let role_id = swig_wallet
        .get_role_id(&secondary_authority.pubkey().to_bytes())
        .unwrap();
    assert_eq!(role_id, 1);
}

#[test_log::test]
fn should_add_token_recurring_destination_limit() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let secondary_authority = Keypair::new();
    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let token_mint = Keypair::new().pubkey();
    let destination = Keypair::new().pubkey();
    let limit_amount = 1000; // 1000 tokens
    let window = 1000; // 1000 slots

    // Setup secondary authority with token recurring destination limit
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![
                Permission::Program {
                    program_id: system_program::ID,
                },
                Permission::TokenDestination {
                    mint: token_mint,
                    destination,
                    amount: limit_amount,
                    recurring: Some(RecurringConfig::new(window)),
                },
            ],
        )
        .unwrap();

    // Verify the authority was added
    assert_eq!(swig_wallet.get_role_count().unwrap(), 2);

    let role_id = swig_wallet
        .get_role_id(&secondary_authority.pubkey().to_bytes())
        .unwrap();
    assert_eq!(role_id, 1);
}

#[test_log::test]
fn should_add_multiple_destination_limits() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let secondary_authority = Keypair::new();
    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let destination1 = Keypair::new().pubkey();
    let destination2 = Keypair::new().pubkey();
    let token_mint = Keypair::new().pubkey();
    let token_destination = Keypair::new().pubkey();

    // Setup secondary authority with multiple destination limits
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![
                Permission::Program {
                    program_id: system_program::ID,
                },
                Permission::SolDestination {
                    destination: destination1,
                    amount: 500_000,
                    recurring: None,
                },
                Permission::SolDestination {
                    destination: destination2,
                    amount: 1_000_000,
                    recurring: Some(RecurringConfig::new(1000)),
                },
                Permission::TokenDestination {
                    mint: token_mint,
                    destination: token_destination,
                    amount: 1000,
                    recurring: None,
                },
            ],
        )
        .unwrap();

    // Verify the authority was added
    assert_eq!(swig_wallet.get_role_count().unwrap(), 2);

    let role_id = swig_wallet
        .get_role_id(&secondary_authority.pubkey().to_bytes())
        .unwrap();
    assert_eq!(role_id, 1);
}

#[test_log::test]
fn should_transfer_sol_within_destination_limit() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let secondary_authority = Keypair::new();
    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let destination = Keypair::new().pubkey();
    let limit_amount = 500_000; // 0.0005 SOL

    // Setup secondary authority with SOL destination limit
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![
                Permission::Program {
                    program_id: system_program::ID,
                },
                Permission::SolDestination {
                    destination,
                    amount: limit_amount,
                    recurring: None,
                },
            ],
        )
        .unwrap();

    swig_wallet
        .switch_authority(
            1,
            Box::new(Ed25519ClientRole::new(secondary_authority.pubkey())),
            Some(&secondary_authority),
        )
        .unwrap();

    let swig_account = swig_wallet.get_swig_account().unwrap();

    // Airdrop funds to swig account
    swig_wallet
        .litesvm()
        .airdrop(&swig_account, 5_000_000_000)
        .unwrap();

    // Transfer within destination limit
    let transfer_amount = 100_000; // 0.0001 SOL (within limit)
    let transfer_ix = system_instruction::transfer(&swig_account, &destination, transfer_amount);

    let signature = swig_wallet.sign(vec![transfer_ix], None).unwrap();
    println!("signature: {:?}", signature);

    // Verify transfer was successful
    assert!(signature != solana_sdk::signature::Signature::default());
    assert_eq!(swig_wallet.get_current_role_id().unwrap(), 1);
}

#[test_log::test]
fn should_fail_transfer_sol_beyond_destination_limit() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let secondary_authority = Keypair::new();
    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let destination = Keypair::new().pubkey();
    let limit_amount = 500_000; // 0.0005 SOL

    // Setup secondary authority with SOL destination limit
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![
                Permission::Program {
                    program_id: system_program::ID,
                },
                Permission::SolDestination {
                    destination,
                    amount: limit_amount,
                    recurring: None,
                },
            ],
        )
        .unwrap();

    swig_wallet
        .switch_authority(
            1,
            Box::new(Ed25519ClientRole::new(secondary_authority.pubkey())),
            Some(&secondary_authority),
        )
        .unwrap();

    let swig_account = swig_wallet.get_swig_account().unwrap();

    // Airdrop funds to swig account
    swig_wallet
        .litesvm()
        .airdrop(&swig_account, 5_000_000_000)
        .unwrap();

    // Attempt transfer beyond destination limit
    let transfer_amount = 1_000_000; // 0.001 SOL (beyond limit)
    let transfer_ix = system_instruction::transfer(&swig_account, &destination, transfer_amount);

    // This should fail due to destination limit
    assert!(swig_wallet.sign(vec![transfer_ix], None).is_err());
}

#[test_log::test]
fn should_transfer_sol_to_different_destination_without_limit() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let secondary_authority = Keypair::new();
    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let destination = Keypair::new().pubkey();
    let different_destination = Keypair::new().pubkey();
    let limit_amount = 500_000; // 0.0005 SOL

    // Setup secondary authority with SOL destination limit for specific destination
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![
                Permission::Program {
                    program_id: system_program::ID,
                },
                Permission::SolDestination {
                    destination,
                    amount: limit_amount,
                    recurring: None,
                },
            ],
        )
        .unwrap();

    swig_wallet
        .switch_authority(
            1,
            Box::new(Ed25519ClientRole::new(secondary_authority.pubkey())),
            Some(&secondary_authority),
        )
        .unwrap();

    let swig_account = swig_wallet.get_swig_account().unwrap();

    // Airdrop funds to swig account
    swig_wallet
        .litesvm()
        .airdrop(&swig_account, 5_000_000_000)
        .unwrap();

    // Transfer to different destination (should not be limited)
    let transfer_amount = 1_000_000; // 0.001 SOL
    let transfer_ix =
        system_instruction::transfer(&swig_account, &different_destination, transfer_amount);

    // This should fail because there's no general SOL permission, only
    // destination-specific
    assert!(swig_wallet.sign(vec![transfer_ix], None).is_err());
}

#[test_log::test]
fn should_combine_destination_and_general_limits() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let secondary_authority = Keypair::new();
    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let destination = Keypair::new().pubkey();
    let different_destination = Keypair::new().pubkey();
    let destination_limit = 500_000; // 0.0005 SOL
    let general_limit = 2_000_000; // 0.002 SOL

    // Setup secondary authority with both destination and general SOL limits
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![
                Permission::Program {
                    program_id: system_program::ID,
                },
                Permission::Sol {
                    amount: general_limit,
                    recurring: None,
                },
                Permission::SolDestination {
                    destination,
                    amount: destination_limit,
                    recurring: None,
                },
            ],
        )
        .unwrap();

    swig_wallet
        .switch_authority(
            1,
            Box::new(Ed25519ClientRole::new(secondary_authority.pubkey())),
            Some(&secondary_authority),
        )
        .unwrap();

    let swig_account = swig_wallet.get_swig_account().unwrap();

    // Airdrop funds to swig account
    swig_wallet
        .litesvm()
        .airdrop(&swig_account, 5_000_000_000)
        .unwrap();

    // Transfer to the specific destination (should be limited by destination limit)
    let transfer_amount = 100_000; // 0.0001 SOL (within destination limit)
    let transfer_ix = system_instruction::transfer(&swig_account, &destination, transfer_amount);

    let signature = swig_wallet.sign(vec![transfer_ix], None).unwrap();
    println!("signature: {:?}", signature);

    // Verify transfer was successful
    assert!(signature != solana_sdk::signature::Signature::default());
    assert_eq!(swig_wallet.get_current_role_id().unwrap(), 1);

    // Transfer to different destination should fail because destination limits
    // exist but no specific limit for this destination
    let transfer_amount = 1_500_000; // 0.0015 SOL
    let transfer_ix =
        system_instruction::transfer(&swig_account, &different_destination, transfer_amount);

    // This should fail because when destination limits exist, you can only transfer
    // to destinations with specific limits
    assert!(swig_wallet.sign(vec![transfer_ix], None).is_err());
}
