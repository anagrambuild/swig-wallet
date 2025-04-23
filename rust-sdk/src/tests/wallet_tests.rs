use super::*;
use crate::{
    error::SwigError, instruction_builder::AuthorityManager, types::Permission, RecurringConfig,
    SwigWallet,
};
use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use litesvm::LiteSVM;
use solana_program::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use swig_interface::swig;
use swig_state_x::authority::AuthorityType;
use swig_state_x::{
    authority::{
        ed25519::{CreateEd25519SessionAuthority, Ed25519SessionAuthority},
        secp256k1::{CreateSecp256k1SessionAuthority, Secp256k1SessionAuthority},
    },
    swig::{swig_account_seeds, SwigWithRoles},
    IntoBytes,
};

// Test helper functions
fn setup_test_environment() -> (LiteSVM, Keypair) {
    let mut litesvm = LiteSVM::new();
    let main_authority = Keypair::new();

    litesvm
        .add_program_from_file(Pubkey::new_from_array(swig::ID), "../target/deploy/swig.so")
        .map_err(|_| anyhow::anyhow!("Failed to load program"))
        .unwrap();
    litesvm
        .airdrop(&main_authority.pubkey(), 10_000_000_000)
        .unwrap();

    (litesvm, main_authority)
}

fn create_test_wallet(litesvm: LiteSVM, authority: &Keypair) -> SwigWallet {
    SwigWallet::new(
        [0; 32],
        AuthorityManager::Ed25519(authority.pubkey()),
        authority,
        authority,
        "http://localhost:8899".to_string(),
        litesvm,
    )
    .unwrap()
}

mod wallet_creation_tests {
    use super::*;

    #[test]
    fn should_create_ed25519_wallet() {
        let (litesvm, main_authority) = setup_test_environment();
        let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
        swig_wallet.display_swig().unwrap();

        let swig_pubkey = swig_wallet.get_swig_account().unwrap();
        let swig_data = swig_wallet.litesvm().get_account(&swig_pubkey).unwrap();
        let swig_with_roles = SwigWithRoles::from_bytes(&swig_data.data).unwrap();

        assert_eq!(swig_with_roles.state.id, [0; 32]);
    }

    #[test]
    fn should_create_secp256k1_wallet() {
        let (mut litesvm, main_authority) = setup_test_environment();
        let wallet = LocalSigner::random();
        let secp_pubkey = wallet
            .credential()
            .verifying_key()
            .to_encoded_point(false)
            .to_bytes();

        let sign_fn = move |payload: &[u8]| -> [u8; 65] {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&payload[..32]);
            let hash = B256::from(hash);
            let tsig = wallet
                .sign_hash_sync(&hash)
                .map_err(|_| SwigError::InvalidSecp256k1)
                .unwrap()
                .as_bytes();
            let mut sig = [0u8; 65];
            sig.copy_from_slice(&tsig);
            sig
        };

        let swig_wallet = SwigWallet::new(
            [0; 32],
            AuthorityManager::Secp256k1(secp_pubkey, Box::new(sign_fn)),
            &main_authority,
            &main_authority,
            "http://localhost:8899".to_string(),
            litesvm,
        )
        .unwrap();

        swig_wallet.display_swig().unwrap();
    }
}

mod session_authority_tests {
    use super::*;

    #[test]
    fn should_create_ed25519_session_authority() {
        let (mut litesvm, main_authority) = setup_test_environment();
        let session_key = Keypair::new();

        let mut swig_wallet = SwigWallet::new(
            [0; 32],
            AuthorityManager::Ed25519Session(CreateEd25519SessionAuthority::new(
                main_authority.pubkey().to_bytes(),
                session_key.pubkey().to_bytes(),
                100,
            )),
            &main_authority,
            &main_authority,
            "http://localhost:8899".to_string(),
            litesvm,
        )
        .unwrap();

        let swig_pubkey = swig_wallet.get_swig_account().unwrap();
        swig_wallet
            .litesvm()
            .airdrop(&swig_pubkey, 10_000_000_000)
            .unwrap();

        let new_session_key = Keypair::new();
        swig_wallet
            .create_session(new_session_key.pubkey(), 100)
            .unwrap();

        swig_wallet.display_swig().unwrap();
    }

    #[test]
    fn should_create_secp256k1_session_authority() {
        let (mut litesvm, main_authority) = setup_test_environment();
        let wallet = LocalSigner::random();
        let secp_pubkey = wallet
            .credential()
            .verifying_key()
            .to_encoded_point(false)
            .to_bytes();

        let sign_fn = move |payload: &[u8]| -> [u8; 65] {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&payload[..32]);
            let hash = B256::from(hash);
            wallet.sign_hash_sync(&hash).unwrap().as_bytes()
        };

        let swig_wallet = SwigWallet::new(
            [0; 32],
            AuthorityManager::Secp256k1Session(
                CreateSecp256k1SessionAuthority::new(
                    secp_pubkey[1..].try_into().unwrap(),
                    [0; 32],
                    100,
                ),
                Box::new(sign_fn),
            ),
            &main_authority,
            &main_authority,
            "http://localhost:8899".to_string(),
            litesvm,
        )
        .unwrap();

        swig_wallet.display_swig().unwrap();
    }
}

mod authority_management_tests {
    use super::*;

    #[test]
    fn should_manage_authorities_successfully() {
        let (mut litesvm, main_authority) = setup_test_environment();
        let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
        let secondary_authority = Keypair::new();

        // Add secondary authority with SOL permission
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
        swig_wallet.display_swig().unwrap();

        // Remove secondary authority
        swig_wallet
            .remove_authority(&secondary_authority.pubkey().to_bytes())
            .unwrap();

        swig_wallet.display_swig().unwrap();

        // Add third authority with recurring permissions
        let third_authority = Keypair::new();
        swig_wallet
            .authenticate_authority(&third_authority.pubkey().to_bytes())
            .unwrap();

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

        swig_wallet.display_swig().unwrap();

        // Switch to third authority
        swig_wallet
            .switch_authority(1, third_authority.pubkey())
            .unwrap();

        swig_wallet
            .authenticate_authority(&third_authority.pubkey().to_bytes())
            .unwrap();
    }

    #[test]
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
            .switch_authority(1, secondary_authority.pubkey())
            .unwrap();

        swig_wallet.switch_payer(&secondary_authority).unwrap();
        swig_wallet.display_swig().unwrap();
    }
}

mod transfer_tests {
    use super::*;
    use solana_program::system_instruction;

    #[test]
    fn should_transfer_within_limits() {
        let (mut litesvm, main_authority) = setup_test_environment();
        let secondary_authority = Keypair::new();
        litesvm
            .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
            .unwrap();

        let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

        // Setup secondary authority with permissions
        swig_wallet
            .add_authority(
                AuthorityType::Ed25519,
                &secondary_authority.pubkey().to_bytes(),
                vec![Permission::Sol {
                    amount: 1_000_000_000,
                    recurring: None,
                }],
            )
            .unwrap();

        swig_wallet
            .switch_authority(1, secondary_authority.pubkey())
            .unwrap();
        swig_wallet.switch_payer(&secondary_authority).unwrap();

        let swig_account = swig_wallet.get_swig_account().unwrap();
        let recipient = Keypair::new();

        // Airdrop funds to swig account
        swig_wallet
            .litesvm()
            .airdrop(&swig_account, 5_000_000_000)
            .unwrap();

        // Transfer within limits
        let transfer_ix =
            system_instruction::transfer(&swig_account, &recipient.pubkey(), 100_000_000);

        assert!(swig_wallet.sign(vec![transfer_ix], None).is_ok());
        swig_wallet.display_swig().unwrap();
    }

    #[test]
    fn should_fail_transfer_beyond_limits() {
        let (mut litesvm, main_authority) = setup_test_environment();
        let secondary_authority = Keypair::new();
        litesvm
            .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
            .unwrap();

        let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

        // Add secondary authority with limited SOL permission
        swig_wallet
            .add_authority(
                AuthorityType::Ed25519,
                &secondary_authority.pubkey().to_bytes(),
                vec![Permission::Sol {
                    amount: 1_000_000_000,
                    recurring: None,
                }],
            )
            .unwrap();

        swig_wallet
            .switch_authority(1, secondary_authority.pubkey())
            .unwrap();
        swig_wallet.switch_payer(&secondary_authority).unwrap();

        // Attempt transfer beyond limits
        let recipient = Keypair::new();
        let transfer_ix = system_instruction::transfer(
            &swig_wallet.get_swig_account().unwrap(),
            &recipient.pubkey(),
            2_000_000_000, // Amount greater than permission limit
        );

        assert!(swig_wallet.sign(vec![transfer_ix], None).is_err());
    }
}
