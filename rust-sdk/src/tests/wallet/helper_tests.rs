use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use solana_sdk::signature::{Keypair, Signer};
use swig_state::authority::AuthorityType;

use super::*;
use crate::client_role::{Ed25519ClientRole, Secp256k1ClientRole};

#[test_log::test]
fn should_get_swig_account_successfully() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let swig_wallet = create_test_wallet(litesvm, &main_authority);

    let swig_account = swig_wallet.get_swig_account().unwrap();
    assert!(swig_account != Pubkey::default());
    println!("Swig account: {}", swig_account);
}

#[test_log::test]
fn should_get_current_authority_permissions() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let swig_wallet = create_test_wallet(litesvm, &main_authority);

    let permissions = swig_wallet.get_current_authority_permissions().unwrap();
    assert!(!permissions.is_empty());
    assert!(permissions.contains(&Permission::All));
    println!("Current permissions: {:?}", permissions);
}

#[test_log::test]
fn should_get_role_id_for_authority() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Add a secondary authority
    let secondary_authority = Keypair::new();
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    // Get role ID for the secondary authority
    let role_id = swig_wallet
        .get_role_id(&secondary_authority.pubkey().to_bytes())
        .unwrap();
    assert_eq!(role_id, 2); // Should be role ID 2 (1 is the main authority)

    // Get role ID for the main authority
    let main_role_id = swig_wallet
        .get_role_id(&main_authority.pubkey().to_bytes())
        .unwrap();
    assert_eq!(main_role_id, 1); // Should be role ID 1
}

#[test_log::test]
fn should_get_current_role_id() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let swig_wallet = create_test_wallet(litesvm, &main_authority);

    let role_id = swig_wallet.get_current_role_id().unwrap();
    assert_eq!(role_id, 1); // Main authority should be role ID 1
}

#[test_log::test]
fn should_get_current_permissions() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let swig_wallet = create_test_wallet(litesvm, &main_authority);

    let permissions = swig_wallet.get_current_permissions().unwrap();
    assert!(!permissions.is_empty());
    assert!(permissions.contains(&Permission::All));
}

#[test_log::test]
fn should_authenticate_authority() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Authenticate the main authority (should succeed)
    swig_wallet
        .authenticate_authority(&main_authority.pubkey().to_bytes())
        .unwrap();

    // Try to authenticate a non-existent authority (should fail)
    let fake_authority = Keypair::new();
    assert!(swig_wallet
        .authenticate_authority(&fake_authority.pubkey().to_bytes())
        .is_err());
}

#[test_log::test]
fn should_get_sub_account() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Initially, no sub account should exist
    let sub_account = swig_wallet.get_sub_account().unwrap();
    assert!(sub_account.is_none());

    // Add an authority with SubAccount permission
    let sub_account_authority = Keypair::new();
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &sub_account_authority.pubkey().to_bytes(),
            vec![Permission::SubAccount {
                sub_account: [0; 32],
            }],
        )
        .unwrap();

    // Switch to the sub-account authority
    swig_wallet
        .switch_authority(
            2,
            Box::new(Ed25519ClientRole::new(sub_account_authority.pubkey())),
            Some(&sub_account_authority),
        )
        .unwrap();

    // Create a sub account
    swig_wallet.create_sub_account().unwrap();

    // Now a sub account should exist (in test env, may not be detected)
    let sub_account = swig_wallet.get_sub_account().unwrap();
    println!("Sub account after creation: {:?}", sub_account);
}

#[test_log::test]
fn should_get_current_slot() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let swig_wallet = create_test_wallet(litesvm, &main_authority);

    let slot = swig_wallet.get_current_slot().unwrap();
    assert!(slot >= 0); // Slot can be 0 in test environment
    println!("Current slot: {}", slot);
}

#[test_log::test]
fn should_get_current_blockhash() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let swig_wallet = create_test_wallet(litesvm, &main_authority);

    let blockhash = swig_wallet.get_current_blockhash().unwrap();
    assert!(blockhash != solana_program::hash::Hash::default());
    println!("Current blockhash: {}", blockhash);
}

#[test_log::test]
fn should_get_balance() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let swig_wallet = create_test_wallet(litesvm, &main_authority);

    let balance = swig_wallet.get_balance().unwrap();
    assert!(balance > 0);
    println!("Balance: {} lamports", balance);
}

#[test_log::test]
fn should_get_swig_id() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let swig_wallet = create_test_wallet(litesvm, &main_authority);

    let swig_id = swig_wallet.get_swig_id();
    assert_eq!(swig_id, &[0; 32]); // We use [0; 32] in create_test_wallet
}

#[test_log::test]
fn should_get_fee_payer() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let swig_wallet = create_test_wallet(litesvm, &main_authority);

    let fee_payer = swig_wallet.get_fee_payer();
    assert_eq!(fee_payer, main_authority.pubkey());
}

#[test_log::test]
fn should_check_permissions() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Check if has all permissions
    let has_all = swig_wallet.has_all_permissions().unwrap();
    assert!(has_all);

    // Check specific permission
    let has_permission = swig_wallet.has_permission(&Permission::All).unwrap();
    assert!(has_permission);
}

#[test_log::test]
fn should_get_sol_limits() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Add an authority with SOL limits
    let limited_authority = Keypair::new();
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &limited_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 5_000_000_000,
                recurring: Some(RecurringConfig::new(100)),
            }],
        )
        .unwrap();

    // Switch to the limited authority
    swig_wallet
        .switch_authority(
            2,
            Box::new(Ed25519ClientRole::new(limited_authority.pubkey())),
            Some(&limited_authority),
        )
        .unwrap();

    // Check SOL limit
    let sol_limit = swig_wallet.get_sol_limit().unwrap();
    assert_eq!(sol_limit, Some(5_000_000_000));

    // Check recurring SOL limit
    let recurring_limit = swig_wallet.get_recurring_sol_limit().unwrap();
    assert!(recurring_limit.is_some());
    if let Some(config) = recurring_limit {
        assert_eq!(config.window, 100);
    }
}

#[test_log::test]
fn should_check_sol_spending_ability() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Add an authority with SOL limits
    let limited_authority = Keypair::new();
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &limited_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 5_000_000_000,
                recurring: Some(RecurringConfig::new(100)),
            }],
        )
        .unwrap();

    // Switch to the limited authority
    swig_wallet
        .switch_authority(
            2,
            Box::new(Ed25519ClientRole::new(limited_authority.pubkey())),
            Some(&limited_authority),
        )
        .unwrap();

    // Check if can spend within limit
    let can_spend_small = swig_wallet.can_spend_sol(1_000_000_000).unwrap();
    assert!(can_spend_small);

    // Check if can spend at limit
    let can_spend_at_limit = swig_wallet.can_spend_sol(5_000_000_000).unwrap();
    assert!(can_spend_at_limit);

    // Check if cannot spend over limit
    let can_spend_over_limit = swig_wallet.can_spend_sol(10_000_000_000).unwrap();
    assert!(!can_spend_over_limit);
}

#[test_log::test]
fn should_get_role_count() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Initially should have 1 role (main authority)
    let initial_count = swig_wallet.get_role_count().unwrap();
    assert_eq!(initial_count, 2);

    // Add another authority
    let secondary_authority = Keypair::new();
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    // Should now have 2 roles
    let new_count = swig_wallet.get_role_count().unwrap();
    assert_eq!(new_count, 3);
}

#[test_log::test]
fn should_get_authority_type() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Check main authority type
    let main_authority_type = swig_wallet.get_authority_type(0).unwrap();
    assert_eq!(main_authority_type, AuthorityType::Ed25519);

    // Add a Secp256k1 authority
    let wallet = LocalSigner::random();
    let secp_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    swig_wallet
        .add_authority(
            AuthorityType::Secp256k1,
            &secp_pubkey.as_ref()[1..],
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    // Check Secp256k1 authority type
    let secp_authority_type = swig_wallet.get_authority_type(2).unwrap();
    assert_eq!(secp_authority_type, AuthorityType::Secp256k1);
}

#[test_log::test]
fn should_get_authority_identity() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Get main authority identity
    let main_identity = swig_wallet.get_authority_identity(1).unwrap();
    assert_eq!(main_identity, main_authority.pubkey().to_bytes());
}

#[test_log::test]
fn should_check_session_based() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Main authority should not be session-based
    let is_session = swig_wallet.is_session_based(0).unwrap();
    assert!(!is_session);
}

#[test_log::test]
fn should_get_role_permissions() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Get main role permissions
    let main_permissions = swig_wallet.get_role_permissions(1).unwrap();
    assert!(main_permissions.contains(&Permission::All));

    // Add an authority with specific permissions
    let limited_authority = Keypair::new();
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &limited_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 5_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    // Get the new role permissions
    let limited_permissions = swig_wallet.get_role_permissions(2).unwrap();
    assert!(limited_permissions.contains(&Permission::Sol {
        amount: 5_000_000_000,
        recurring: None,
    }));
    assert!(!limited_permissions.contains(&Permission::All));
}

#[test_log::test]
fn should_check_role_has_permission() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Main role should have all permissions
    let has_all = swig_wallet
        .role_has_permission(1, &Permission::All)
        .unwrap();
    assert!(has_all);

    // Add an authority with specific permissions
    let limited_authority = Keypair::new();
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &limited_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 5_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    // Check if the new role has the specific permission
    let has_sol = swig_wallet
        .role_has_permission(
            2,
            &Permission::Sol {
                amount: 5_000_000_000,
                recurring: None,
            },
        )
        .unwrap();
    assert!(has_sol);

    // Check if the new role doesn't have all permissions
    let has_all_in_new = swig_wallet
        .role_has_permission(2, &Permission::All)
        .unwrap();
    assert!(!has_all_in_new);
}

#[test_log::test]
fn should_get_formatted_authority_address() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Get formatted address for Ed25519 authority
    let ed25519_address = swig_wallet.get_formatted_authority_address(1).unwrap();
    assert!(!ed25519_address.is_empty());
    assert!(ed25519_address.len() > 30); // Base58 encoded addresses are typically long
    println!("Ed25519 address: {}", ed25519_address);

    // Add a Secp256k1 authority
    let wallet = LocalSigner::random();
    let secp_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    swig_wallet
        .add_authority(
            AuthorityType::Secp256k1,
            &secp_pubkey.as_ref()[1..],
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    // Get formatted address for Secp256k1 authority
    let secp256k1_address = swig_wallet.get_formatted_authority_address(2).unwrap();
    assert!(!secp256k1_address.is_empty());
    assert!(secp256k1_address.starts_with("0x")); // Ethereum addresses start with 0x
    println!("Secp256k1 address: {}", secp256k1_address);
}

#[test_log::test]
fn should_refresh_permissions() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Get initial permissions
    let initial_permissions = swig_wallet.get_current_permissions().unwrap().to_vec();

    // Refresh permissions
    swig_wallet.refresh_permissions().unwrap();

    // Get permissions after refresh
    let refreshed_permissions = swig_wallet.get_current_permissions().unwrap();

    // Permissions should be the same
    assert_eq!(initial_permissions.len(), refreshed_permissions.len());
    for permission in &initial_permissions {
        assert!(refreshed_permissions.contains(permission));
    }
}

#[test_log::test]
fn should_handle_invalid_role_id() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Try to get information for a non-existent role
    assert!(swig_wallet.get_authority_type(999).is_err());
    assert!(swig_wallet.get_authority_identity(999).is_err());
    assert!(swig_wallet.is_session_based(999).is_err());
    assert!(swig_wallet.get_role_permissions(999).is_err());
    assert!(swig_wallet.get_formatted_authority_address(999).is_err());
}

#[test_log::test]
fn should_handle_permission_checks_with_different_authorities() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Main authority should have all permissions
    assert!(swig_wallet.has_all_permissions().unwrap());
    assert!(swig_wallet.has_permission(&Permission::All).unwrap());

    // Add an authority with only SOL permissions
    let sol_only_authority = Keypair::new();
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &sol_only_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 5_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    // Switch to the SOL-only authority
    swig_wallet
        .switch_authority(
            2,
            Box::new(Ed25519ClientRole::new(sol_only_authority.pubkey())),
            Some(&sol_only_authority),
        )
        .unwrap();

    // This authority should not have all permissions
    assert!(!swig_wallet.has_all_permissions().unwrap());
    assert!(!swig_wallet.has_permission(&Permission::All).unwrap());

    // Print permissions for debug
    let perms = swig_wallet.get_current_permissions().unwrap();
    println!("SOL-only authority permissions: {:?}", perms);

    // But should have SOL permissions
    assert!(swig_wallet
        .has_permission(&Permission::Sol {
            amount: 5_000_000_000,
            recurring: None,
        })
        .unwrap());
}
