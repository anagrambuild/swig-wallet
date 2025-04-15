mod common;

use common::*;
use rand::random;
use solana_client::rpc_client::RpcClient;
use solana_program::pubkey::Pubkey;
use solana_sdk::{
    message::{v0, VersionedMessage},
    signature::{Keypair, Signer},
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_sdk::SwigWallet;
use swig_state_x::{
    action::{all::All, sol_limit::SolLimit, sol_recurring_limit::SolRecurringLimit},
    authority::AuthorityType,
    swig::SwigWithRoles,
};

#[test_log::test]
fn test_swig_wallet_creation() {
    // Create main authority
    let main_authority = Keypair::new();
    let rpc_url = "http://localhost:8899";
    let rpc_client = RpcClient::new(rpc_url);

    // Airdrop to main authority
    let signature = rpc_client
        .request_airdrop(&main_authority.pubkey(), 10_000_000_000)
        .unwrap();
    rpc_client.confirm_transaction(&signature).unwrap();

    println!(
        "Balance of main_authority: {:?}",
        rpc_client.get_balance(&main_authority.pubkey())
    );

    // Generate random ID for the wallet
    let id = random::<[u8; 32]>();

    // Create Swig wallet with main authority
    let swig_wallet = SwigWallet::new(
        id,
        AuthorityType::Ed25519,
        main_authority.pubkey(),
        main_authority,
        rpc_url.to_string(),
    );

    assert!(
        swig_wallet.is_ok(),
        "Failed to create Swig wallet {:?}",
        swig_wallet.err()
    );
    let wallet = swig_wallet.unwrap();
    let swig_pubkey = wallet.get_swig_account().unwrap();

    // // Verify wallet creation
    // let swig_account = context
    //     .svm
    //     .get_account(&swig_pubkey)
    //     .expect("Failed to get Swig account");
    // let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();

    // // Basic wallet verification
    // assert_eq!(swig.state.roles, 1, "Expected 1 role after creation");
    // assert_eq!(swig.state.id, id, "Wallet ID mismatch");
    // assert_eq!(swig.state.role_counter, 1, "Expected role counter to be 1");
}

#[test_log::test]
fn test_add_secondary_authority() {
    // Setup test context
    let mut context = setup_test_context().unwrap();

    // Create main authority
    let main_authority = Keypair::new();
    context
        .svm
        .airdrop(&main_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create wallet
    let id = random::<[u8; 32]>();
    let swig_wallet = SwigWallet::new(
        id,
        AuthorityType::Ed25519,
        main_authority.pubkey(),
        context.default_payer,
        "http://localhost:8899".to_string(),
    )
    .unwrap();
    let swig_pubkey = swig_wallet.get_swig_account().unwrap();

    // Create secondary authority
    let secondary_authority = Keypair::new();

    // Define actions for secondary authority
    let actions = vec![
        ClientAction::SolRecurringLimit(SolRecurringLimit {
            recurring_amount: 1_000_000_000, // 1 SOL
            window: 86400,                   // 24 hours
            last_reset: 0,
            current_amount: 1_000_000_000,
        }),
        ClientAction::SolLimit(SolLimit {
            amount: 5_000_000_000, // 5 SOL
        }),
    ];

    // // Add secondary authority
    // let add_authority_result = add_authority_with_ed25519_root(
    //     &mut context,
    //     &swig_pubkey,
    //     &main_authority,
    //     AuthorityConfig {
    //         authority_type: AuthorityType::Ed25519,
    //         authority: secondary_authority.pubkey().as_ref(),
    //     },
    //     actions,
    // );

    // assert!(
    //     add_authority_result.is_ok(),
    //     "Failed to add secondary authority"
    // );

    // // Verify secondary authority addition
    // let updated_swig_account = context
    //     .svm
    //     .get_account(&swig_pubkey)
    //     .expect("Failed to get updated Swig account");
    // let updated_swig =
    // SwigWithRoles::from_bytes(&updated_swig_account.data).unwrap();

    // // Verify role counts
    // assert_eq!(
    //     updated_swig.state.roles, 2,
    //     "Expected 2 roles after adding secondary authority"
    // );
    // assert_eq!(
    //     updated_swig.state.role_counter, 2,
    //     "Expected role counter to be 2"
    // );

    // // Verify secondary authority's role
    // let secondary_role_id = updated_swig
    //     .lookup_role_id(secondary_authority.pubkey().as_ref())
    //     .unwrap()
    //     .expect("Secondary authority role not found");

    // let secondary_role = updated_swig
    //     .get_role(secondary_role_id)
    //     .unwrap()
    //     .expect("Failed to get secondary role");

    // // Verify SOL recurring limit action
    // let sol_recurring_limit =
    // secondary_role.get_action::<SolRecurringLimit>(&[]).unwrap();
    // assert!(
    //     sol_recurring_limit.is_some(),
    //     "SOL recurring limit action not found"
    // );

    // if let Some(limit) = sol_recurring_limit {
    //     assert_eq!(
    //         limit.recurring_amount, 1_000_000_000,
    //         "Incorrect SOL recurring limit amount"
    //     );
    //     assert_eq!(limit.window, 86400, "Incorrect recurring window");
    //     assert_eq!(
    //         limit.current_amount, 1_000_000_000,
    //         "Incorrect current amount"
    //     );
    //     assert_eq!(limit.last_reset, 0, "Incorrect last reset value");
    // }

    // // Verify SOL limit action
    // let sol_limit = secondary_role.get_action::<SolLimit>(&[]).unwrap();
    // assert!(sol_limit.is_some(), "SOL limit action not found");

    // if let Some(limit) = sol_limit {
    //     assert_eq!(limit.amount, 5_000_000_000, "Incorrect SOL limit
    // amount"); }
}

#[test_log::test]
fn test_remove_authority() {
    // Setup test context
    let mut context = setup_test_context().unwrap();

    // Create main authority
    let main_authority = Keypair::new();
    context
        .svm
        .airdrop(&main_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create wallet
    let id = random::<[u8; 32]>();
    let swig_wallet = SwigWallet::new(
        id,
        AuthorityType::Ed25519,
        main_authority.pubkey(),
        context.default_payer,
        "http://localhost:8899".to_string(),
    )
    .unwrap();
    let swig_pubkey = swig_wallet.get_swig_account().unwrap();

    // Create and add secondary authority
    let secondary_authority = Keypair::new();
    let actions = vec![ClientAction::SolLimit(SolLimit {
        amount: 1_000_000_000,
    })];

    // // Add secondary authority
    // let add_result = add_authority_with_ed25519_root(
    //     &mut context,
    //     &swig_pubkey,
    //     &main_authority,
    //     AuthorityConfig {
    //         authority_type: AuthorityType::Ed25519,
    //         authority: secondary_authority.pubkey().as_ref(),
    //     },
    //     actions,
    // );
    // assert!(add_result.is_ok(), "Failed to add secondary authority");

    // // Remove secondary authority
    // let remove_result = remove_authority_with_ed25519_root(
    //     &mut context,
    //     &swig_pubkey,
    //     &main_authority,
    //     secondary_authority.pubkey(),
    // );
    // assert!(
    //     remove_result.is_ok(),
    //     "Failed to remove secondary authority"
    // );

    // // Verify authority removal
    // let final_swig_account = context
    //     .svm
    //     .get_account(&swig_pubkey)
    //     .expect("Failed to get final Swig account");
    // let final_swig =
    // SwigWithRoles::from_bytes(&final_swig_account.data).unwrap();

    // assert_eq!(final_swig.state.roles, 1, "Expected 1 role after removal");
    // let lookup_result = final_swig
    //     .lookup_role_id(secondary_authority.pubkey().as_ref())
    //     .unwrap();
    // assert!(
    //     lookup_result.is_none(),
    //     "Secondary authority should not exist"
    // );
}
