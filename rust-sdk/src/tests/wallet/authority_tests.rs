use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use solana_sdk::signature::{Keypair, Signer};
use swig_state::authority::AuthorityType;

use super::*;
use crate::{
    client_role::{Ed25519ClientRole, Secp256k1ClientRole},
    types::UpdateAuthorityData,
};

#[test_log::test]
fn should_manage_authorities_successfully() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Add secondary authority with SOL permission
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

    // Verify both authorities exist
    assert_eq!(swig_wallet.get_role_count().unwrap(), 3);
    assert!(swig_wallet
        .get_role_id(&secondary_authority.pubkey().to_bytes())
        .is_ok());

    // Remove secondary authority
    swig_wallet
        .remove_authority(&secondary_authority.pubkey().to_bytes())
        .unwrap();

    // Verify authority was removed
    assert_eq!(swig_wallet.get_role_count().unwrap(), 2);
    assert!(swig_wallet
        .get_role_id(&secondary_authority.pubkey().to_bytes())
        .is_err());

    // Add third authority with recurring permissions
    let third_authority = Keypair::new();

    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &third_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: Some(RecurringConfig::new(100)),
            }],
        )
        .unwrap();

    // Verify third authority was added
    assert_eq!(swig_wallet.get_role_count().unwrap(), 3);
    assert!(swig_wallet
        .get_role_id(&third_authority.pubkey().to_bytes())
        .is_ok());

    // Switch to third authority
    swig_wallet
        .switch_authority(
            3,
            Box::new(Ed25519ClientRole::new(third_authority.pubkey())),
            Some(&third_authority),
        )
        .unwrap();

    swig_wallet
        .authenticate_authority(&third_authority.pubkey().to_bytes())
        .unwrap();
}

#[test_log::test]
fn should_add_secp256k1_authority() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let wallet = LocalSigner::random();
    println!("wallet: {:?}", wallet.address());

    let secp_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    let sec1_bytes = wallet.credential().verifying_key().to_sec1_bytes();
    let secp1_pubkey = sec1_bytes.as_ref();

    let authority_hex = hex::encode([&[0x4].as_slice(), secp1_pubkey].concat());
    let mut hasher = solana_sdk::keccak::Hasher::default();
    hasher.hash(authority_hex.as_bytes());
    let hash = hasher.result();
    let address = format!("0x{}", hex::encode(&hash.0[12..32]));
    println!("address: {:?}", address);

    println!(
        "\t\tAuthority Public Key: 0x{} address {}",
        authority_hex, address
    );
    println!("secp_pubkey length: {:?}", secp_pubkey);
    println!("secp1_pubkey length: {:?}", secp1_pubkey);

    // Add secondary authority with SOL permission
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

    // Verify both authorities exist
    assert_eq!(swig_wallet.get_role_count().unwrap(), 3);
    assert!(swig_wallet.get_role_id(&secp_pubkey.as_ref()[1..]).is_ok());

    // Remove secondary authority
    swig_wallet
        .remove_authority(&secp_pubkey.as_ref()[1..])
        .unwrap();

    // Verify authority was removed
    assert_eq!(swig_wallet.get_role_count().unwrap(), 2);
    assert!(swig_wallet.get_role_id(&secp_pubkey.as_ref()[1..]).is_err());

    // Add third authority with recurring permissions
    let third_authority = Keypair::new();

    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &third_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: Some(RecurringConfig::new(100)),
            }],
        )
        .unwrap();

    // Verify third authority was added
    assert_eq!(swig_wallet.get_role_count().unwrap(), 3);
    assert!(swig_wallet
        .get_role_id(&third_authority.pubkey().to_bytes())
        .is_ok());

    // Switch to third authority
    swig_wallet
        .switch_authority(
            3,
            Box::new(Ed25519ClientRole::new(third_authority.pubkey())),
            Some(&third_authority),
        )
        .unwrap();

    swig_wallet
        .authenticate_authority(&third_authority.pubkey().to_bytes())
        .unwrap();
}

#[test_log::test]
fn should_switch_authority_and_payer() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let secondary_authority = Keypair::new();
    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Add and switch to secondary authority
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: Some(RecurringConfig::new(100)),
            }],
        )
        .unwrap();

    swig_wallet
        .switch_authority(
            2,
            Box::new(Ed25519ClientRole::new(secondary_authority.pubkey())),
            Some(&secondary_authority),
        )
        .unwrap();

    swig_wallet.switch_payer(&secondary_authority).unwrap();

    // Verify authority switch and payer change
    assert_eq!(swig_wallet.get_current_role_id().unwrap(), 2);
    assert_eq!(swig_wallet.get_fee_payer(), secondary_authority.pubkey());
}

#[test_log::test]
fn should_update_authority_replace_all() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let old_authority = Keypair::new();
    let new_authority = Keypair::new();

    // Add old authority with SOL permission
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &new_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    // Verify old authority exists
    assert_eq!(swig_wallet.get_role_count().unwrap(), 3);
    assert!(swig_wallet
        .get_role_id(&new_authority.pubkey().to_bytes())
        .is_ok());

    let new_permissions = vec![
        Permission::ManageAuthority {},
        Permission::Sol {
            amount: 5_000_000_000,
            recurring: None,
        },
    ];

    let update_data = UpdateAuthorityData::ReplaceAll(new_permissions);

    // Replace old authority with new authority
    swig_wallet.update_authority(1, update_data).unwrap();

    // Verify the replacement
    assert_eq!(swig_wallet.get_role_count().unwrap(), 3);

    let role_permissions = swig_wallet.get_role_permissions(1).unwrap();
    println!("role permissions: {:?}", role_permissions);
    assert_eq!(role_permissions.len(), 2);
    assert_eq!(role_permissions[0], Permission::ManageAuthority {});
    assert_eq!(
        role_permissions[1],
        Permission::Sol {
            amount: 5_000_000_000,
            recurring: None,
        }
    );
}

#[test_log::test]
fn should_update_authority_remove_actions_by_index() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let old_authority = Keypair::new();
    let new_authority = Keypair::new();

    // Add old authority with SOL permission
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &new_authority.pubkey().to_bytes(),
            vec![
                Permission::Sol {
                    amount: 10_000_000_000,
                    recurring: None,
                },
                Permission::ManageAuthority {},
            ],
        )
        .unwrap();

    assert_eq!(swig_wallet.get_role_count().unwrap(), 3);
    let role_permissions = swig_wallet.get_role_permissions(2).unwrap();
    assert_eq!(role_permissions.len(), 2);

    let update_data = UpdateAuthorityData::RemoveActionsByIndex(vec![1]);
    swig_wallet.update_authority(2, update_data).unwrap();

    let role_permissions = swig_wallet.get_role_permissions(2).unwrap();

    assert_eq!(swig_wallet.get_role_count().unwrap(), 3);

    assert_eq!(role_permissions.len(), 1);
    assert_eq!(
        role_permissions[0],
        Permission::Sol {
            amount: 10_000_000_000,
            recurring: None,
        }
    );
}

#[test_log::test]
fn should_update_authority_remove_actions_by_type() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let old_authority = Keypair::new();
    let new_authority = Keypair::new();

    // Add old authority with SOL permission
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &new_authority.pubkey().to_bytes(),
            vec![
                Permission::Sol {
                    amount: 10_000_000_000,
                    recurring: None,
                },
                Permission::ManageAuthority {},
            ],
        )
        .unwrap();

    assert_eq!(swig_wallet.get_role_count().unwrap(), 3);
    let role_permissions = swig_wallet.get_role_permissions(2).unwrap();
    assert_eq!(role_permissions.len(), 2);

    let update_data =
        UpdateAuthorityData::RemoveActionsByType(vec![Permission::ManageAuthority {}]);
    swig_wallet.update_authority(2, update_data).unwrap();

    let role_permissions = swig_wallet.get_role_permissions(2).unwrap();

    assert_eq!(swig_wallet.get_role_count().unwrap(), 3);

    assert_eq!(role_permissions.len(), 1);
    assert_eq!(
        role_permissions[0],
        Permission::Sol {
            amount: 10_000_000_000,
            recurring: None,
        }
    );
}

#[test_log::test]
fn should_update_authority_add_actions() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let old_authority = Keypair::new();
    let new_authority = Keypair::new();

    // Add old authority with SOL permission
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &new_authority.pubkey().to_bytes(),
            vec![Permission::ManageAuthority {}],
        )
        .unwrap();

    assert_eq!(swig_wallet.get_role_count().unwrap(), 3);
    let role_permissions = swig_wallet.get_role_permissions(1).unwrap();
    assert_eq!(role_permissions.len(), 1);

    let update_data = UpdateAuthorityData::AddActions(vec![Permission::Sol {
        amount: 10_000_000_000,
        recurring: None,
    }]);
    swig_wallet.update_authority(1, update_data).unwrap();

    let role_permissions = swig_wallet.get_role_permissions(1).unwrap();

    assert_eq!(swig_wallet.get_role_count().unwrap(), 3);

    assert_eq!(role_permissions.len(), 2);
    assert_eq!(
        role_permissions[1],
        Permission::Sol {
            amount: 10_000_000_000,
            recurring: None,
        }
    );
}
