pub mod authority_tests;
pub mod creation_tests;
pub mod program_scope_test;
pub mod session_tests;
pub mod transfer_tests;
use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use litesvm::LiteSVM;
use solana_program::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use swig_interface::swig;
use swig_state_x::{
    authority::{
        ed25519::{CreateEd25519SessionAuthority, Ed25519SessionAuthority},
        secp256k1::{CreateSecp256k1SessionAuthority, Secp256k1SessionAuthority},
        AuthorityType,
    },
    swig::{swig_account_seeds, SwigWithRoles},
    IntoBytes,
};

use crate::{
    error::SwigError, instruction_builder::AuthorityManager, types::Permission, RecurringConfig,
    SwigWallet,
};

use super::*;

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
