use solana_sdk::{signature::Keypair, signer::Signer};

use super::*;
use crate::types::Permission::{self, ProgramAll};
use solana_program::{pubkey::Pubkey, system_instruction, system_program};

#[test_log::test]
fn should_add_oracle_limit_permission() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut wallet = create_test_wallet(litesvm, &main_authority);

    // Add secondary authority with OracleLimit (USD, 250_000_000 = 250 USD, passthrough=false)
    let secondary = Keypair::new();
    wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary.pubkey().to_bytes(),
            vec![Permission::OracleLimit {
                base_asset_type: 0, // USD
                value_limit: 250_000_000,
                passthrough_check: false,
                recurring: None,
            }],
        )
        .unwrap();

    // Verify authority added and oracle permission present
    assert_eq!(wallet.get_role_count().unwrap(), 2);
    let role_id = wallet.get_role_id(&secondary.pubkey().to_bytes()).unwrap();
    let perms = wallet.get_role_permissions(role_id).unwrap();
    assert!(perms.iter().any(|p| matches!(
        p,
        Permission::OracleLimit { base_asset_type, value_limit, passthrough_check, recurring }
            if *base_asset_type == 0 && *value_limit == 250_000_000 && !*passthrough_check
    )));
}

#[test_log::test]
fn should_add_oracle_recurring_limit_permission() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut wallet = create_test_wallet(litesvm, &main_authority);

    // Add secondary authority with OracleTokenLimit (EUR, 300_000_000 per window, window=1000)
    let secondary = Keypair::new();
    wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary.pubkey().to_bytes(),
            vec![Permission::OracleLimit {
                base_asset_type: 1, // EUR
                value_limit: 300_000_000,
                passthrough_check: true,
                recurring: Some(RecurringConfig::new(1000)),
            }],
        )
        .unwrap();

    // Verify authority added and oracle recurring permission present
    assert_eq!(wallet.get_role_count().unwrap(), 2);
    let role_id = wallet.get_role_id(&secondary.pubkey().to_bytes()).unwrap();
    let perms = wallet.get_role_permissions(role_id).unwrap();
    println!("perms: {:?}", perms);
    assert!(perms.iter().any(|p| matches!(
        p,
        Permission::OracleLimit { base_asset_type, value_limit, passthrough_check, recurring }
            if *base_asset_type == 1 && *value_limit == 300_000_000 && *passthrough_check && recurring.is_some()
    )));
}

#[test_log::test]
fn should_send_with_oracle_limit_permission() {
    let (mut litesvm, main_authority) = setup_test_environment();
    load_sample_scope_data(&mut litesvm, &main_authority).unwrap();

    let mut swig_wallet = create_test_wallet_v2(litesvm, &main_authority);

    // Fund the swig wallet PDA
    let swig_wallet_address = swig_wallet.get_swig_wallet_address().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_wallet_address, 5_000_000_000)
        .unwrap();

    // Prepare a transfer from wallet PDA to recipient
    let secondary_authority = Keypair::new();
    swig_wallet
        .litesvm()
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![
                Permission::OracleLimit {
                    base_asset_type: 0,
                    value_limit: 250_000_000,
                    passthrough_check: false,
                    recurring: None,
                },
                Permission::ProgramAll,
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

    let transfer_ix = system_instruction::transfer(
        &swig_wallet_address,
        &secondary_authority.pubkey(),
        1_000_000_000,
    );

    swig_wallet.display_swig().unwrap();

    let sig = swig_wallet.sign_v2(vec![transfer_ix], None).unwrap();

    swig_wallet.display_swig().unwrap();

    // test if the oracle limit fails if exceeded
    let transfer_ix = system_instruction::transfer(
        &swig_wallet_address,
        &secondary_authority.pubkey(),
        1_000_000_000,
    );

    let sig = swig_wallet.sign_v2(vec![transfer_ix], None);
    assert!(sig.is_err());

    swig_wallet.display_swig().unwrap();
}

#[test_log::test]
fn should_send_with_oracle_recurring_limit_permission() {
    let (mut litesvm, main_authority) = setup_test_environment();
    load_sample_scope_data(&mut litesvm, &main_authority).unwrap();

    let mut swig_wallet = create_test_wallet_v2(litesvm, &main_authority);

    // Fund the swig wallet PDA
    let swig_wallet_address = swig_wallet.get_swig_wallet_address().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_wallet_address, 5_000_000_000)
        .unwrap();

    // Prepare a transfer from wallet PDA to recipient
    let secondary_authority = Keypair::new();
    swig_wallet
        .litesvm()
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![
                Permission::OracleLimit {
                    base_asset_type: 0,
                    value_limit: 250_000_000,
                    recurring: Some(RecurringConfig::new(5)),
                    passthrough_check: false,
                },
                Permission::ProgramAll,
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

    let first_passing_transfer_ix = system_instruction::transfer(
        &swig_wallet_address,
        &secondary_authority.pubkey(),
        1_000_000_000,
    );

    swig_wallet.display_swig().unwrap();

    let sig = swig_wallet
        .sign_v2(vec![first_passing_transfer_ix], None)
        .unwrap();

    swig_wallet.display_swig().unwrap();

    // test if the oracle limit fails if exceeded
    let second_failing_transfer_ix = system_instruction::transfer(
        &swig_wallet_address,
        &secondary_authority.pubkey(),
        1_000_000_000,
    );

    let sig = swig_wallet.sign_v2(vec![second_failing_transfer_ix.clone()], None);
    assert!(sig.is_err());

    advance_slot(&mut swig_wallet.litesvm(), 10);

    let third_passing_transfer_ix = system_instruction::transfer(
        &swig_wallet_address,
        &secondary_authority.pubkey(),
        500_000_001,
    );

    let sig = swig_wallet
        .sign_v2(vec![third_passing_transfer_ix], None)
        .unwrap();

    swig_wallet.display_swig().unwrap();
}

pub fn advance_slot(svm: &mut LiteSVM, slots: u64) -> u64 {
    use solana_client::rpc_client::RpcClient;

    let client = RpcClient::new("https://api.mainnet-beta.solana.com".to_string());
    let slot = client.get_slot().unwrap();
    let new_slot = slot + slots;
    svm.warp_to_slot(new_slot);
    new_slot
}
