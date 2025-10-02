pub mod authority_tests;
pub mod creation_tests;
pub mod destination_tests;
pub mod helper_tests;
pub mod program_all_tests;
pub mod program_scope_test;
pub mod secp256r1_test;
pub mod secp_tests;
pub mod session_tests;
pub mod sign_v1_tests;
pub mod sign_v2_tests;
pub mod sub_accounts_test;

use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use litesvm::LiteSVM;
use solana_program::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use swig_interface::swig;
use swig_state::{
    authority::{
        ed25519::{CreateEd25519SessionAuthority, Ed25519SessionAuthority},
        secp256k1::{CreateSecp256k1SessionAuthority, Secp256k1SessionAuthority},
        AuthorityType,
    },
    swig::{swig_account_seeds, SwigWithRoles},
    IntoBytes,
};

use super::*;
use crate::{
    client_role::{
        Ed25519ClientRole, Ed25519SessionClientRole, Secp256k1ClientRole,
        Secp256k1SessionClientRole, Secp256r1ClientRole,
    },
    error::SwigError,
    types::Permission,
    RecurringConfig, SwigWallet,
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

fn create_test_wallet(mut litesvm: LiteSVM, authority: &Keypair) -> SwigWallet {
    create_test_wallet_with_version(litesvm, authority, true)
}

fn create_test_wallet_v2(mut litesvm: LiteSVM, authority: &Keypair) -> SwigWallet {
    create_test_wallet_with_version(litesvm, authority, false)
}

fn create_test_wallet_with_version(
    mut litesvm: LiteSVM,
    authority: &Keypair,
    convert_to_v1: bool,
) -> SwigWallet {
    // First create the wallet
    let mut wallet = SwigWallet::new(
        [0; 32],
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        authority,
        "http://localhost:8899".to_string(),
        Some(authority),
        litesvm,
    )
    .unwrap();

    // Convert the swig account to V1 for tests that use SignV1
    if convert_to_v1 {
        convert_wallet_to_v1(&mut wallet);
    }

    wallet
}

fn convert_wallet_to_v1(wallet: &mut SwigWallet) {
    use swig_state::swig::Swig;
    use swig_state::Transmutable;

    let swig_key = wallet.get_swig();

    let litesvm = wallet.litesvm();
    let mut account = litesvm
        .get_account(&swig_key)
        .expect("Swig account should exist");

    if account.data.len() >= Swig::LEN {
        let last_8_start = Swig::LEN - 8;
        let reserved_lamports: u64 = 256;
        account.data[last_8_start..Swig::LEN].copy_from_slice(&reserved_lamports.to_le_bytes());
    }

    litesvm
        .set_account(swig_key, account)
        .expect("Failed to update account");
}
