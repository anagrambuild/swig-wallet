pub mod authority_tests;
pub mod creation_tests;
pub mod destination_tests;
pub mod helper_tests;
pub mod oracle_tests;
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
    use swig_state::{swig::Swig, Transmutable};

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

use crate::tests::common::{mint_to, setup_ata, setup_mint};
use oracle_mapping_state::{DataLen, MintMapping, ScopeMappingRegistry};
use solana_client::rpc_client::RpcClient;
use solana_sdk::account::Account;
use std::str::FromStr;

pub fn load_sample_scope_data(svm: &mut LiteSVM, payer: &Keypair) -> anyhow::Result<(Pubkey)> {
    let pubkey = Pubkey::from_str("3NJYftD5sjVfxSnUdZ1wVML8f3aC6mp1CXCL6L7TnU8C").unwrap();
    let owner = Pubkey::from_str("HFn8GnPADiny6XqUoWE8uRPPxb29ikn4yTuPa9MF2fWJ").unwrap();

    let client = RpcClient::new("https://api.mainnet-beta.solana.com".to_string());
    let mut scope_account = client.get_account(&pubkey).unwrap();

    let mut data = Account {
        lamports: 200_700_000,
        data: scope_account.data,
        owner,
        executable: false,
        rent_epoch: 18446744073709551615,
    };

    svm.set_account(pubkey, data).unwrap();

    let mapping_pubkey = Pubkey::from_str("FbeuRDWwLvZWEU3HNtaLoYKagw9rH1NvmjpRMpjMwhDw").unwrap();
    let owner_pubkey = Pubkey::from_str("9WM51wrB9xpRzFgYJHocYNnx4DF6G6ee2eB44ZGoZ8vg").unwrap();

    let mint = setup_mint(svm, &payer).unwrap();

    let devnet_client = RpcClient::new("https://api.devnet.solana.com".to_string());
    let scope_mapping_registry_acc = devnet_client.get_account(&mapping_pubkey).unwrap();

    let mut scope_mapping_data = scope_mapping_registry_acc.data.clone();
    let mut scope_mapping_registry = ScopeMappingRegistry::from_bytes(
        scope_mapping_data[..ScopeMappingRegistry::LEN]
            .try_into()
            .unwrap(),
    )
    .unwrap();

    // Create new mint mapping
    let new_mint_mapping = MintMapping::new(
        mint.to_bytes(),
        Some([0, u16::MAX, u16::MAX]),
        None,
        None,
        9,
    );

    let mapping_mint_data = new_mint_mapping.to_bytes();
    let mapping = &mapping_mint_data[..new_mint_mapping.serialized_size() as usize];

    let insertion_offset =
        ScopeMappingRegistry::LEN + scope_mapping_registry.last_mapping_offset as usize;

    scope_mapping_data.resize(insertion_offset + mapping.len(), 0);

    scope_mapping_data[insertion_offset..insertion_offset + mapping.len()].copy_from_slice(mapping);

    scope_mapping_registry.total_mappings += 1;
    scope_mapping_registry.last_mapping_offset += mapping.len() as u16;

    scope_mapping_data[..ScopeMappingRegistry::LEN]
        .copy_from_slice(&scope_mapping_registry.to_bytes());

    let data = Account {
        lamports: scope_mapping_registry_acc.lamports + 10000000,
        data: scope_mapping_data,
        owner: owner_pubkey,
        executable: false,
        rent_epoch: 18446744073709551615,
    };

    svm.set_account(mapping_pubkey, data).unwrap();

    // sync litesvm slot to mainnet slot
    let slot = client.get_slot().unwrap();
    svm.warp_to_slot(slot);

    Ok(mint)
}
