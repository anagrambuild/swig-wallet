//! SDK-level integration tests for V2 sub-accounts via the `SwigWallet` API.
use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use solana_sdk::{
    account::Account,
    program_pack::Pack,
    signature::{Keypair, Signer},
};
use swig_state::{
    authority::AuthorityType,
    swig::{sub_account_v2_asset_seeds, sub_account_v2_state_seeds},
};

use super::*;
use crate::client_role::{Ed25519ClientRole, Secp256k1ClientRole, Secp256r1ClientRole};

/// Adds a creator authority (SubAccountV2Create), switches to it, and creates a
/// V2 sub-account. Returns (secondary_keypair, subacc_id, asset_pda).
fn create_v2_setup<'a>(swig_wallet: &mut SwigWallet<'a>, secondary: &'a Keypair) -> (u32, Pubkey) {
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary.pubkey().to_bytes(),
            vec![Permission::SubAccountV2Create],
        )
        .unwrap();
    swig_wallet
        .switch_authority(
            1,
            Box::new(Ed25519ClientRole::new(secondary.pubkey())),
            Some(secondary),
        )
        .unwrap();
    let (_sig, subacc_id) = swig_wallet.create_sub_account_v2().unwrap();
    let (asset, _) = Pubkey::find_program_address(
        &sub_account_v2_asset_seeds(swig_wallet.get_swig_id(), &subacc_id.to_le_bytes()),
        &swig_interface::program_id(),
    );
    (subacc_id, asset)
}

fn setup_v2_tokens(
    swig_wallet: &mut SwigWallet<'_>,
    payer: &Keypair,
    asset: &Pubkey,
    amount: u64,
) -> (Pubkey, Pubkey) {
    use crate::tests::common::{mint_to, setup_ata, setup_mint};

    let mint = setup_mint(swig_wallet.litesvm(), payer).unwrap();
    let source_token = setup_ata(swig_wallet.litesvm(), &mint, asset, payer).unwrap();
    let wallet_address = swig_wallet.get_swig_wallet_address().unwrap();
    let destination_token =
        setup_ata(swig_wallet.litesvm(), &mint, &wallet_address, payer).unwrap();
    mint_to(swig_wallet.litesvm(), &mint, payer, &source_token, amount).unwrap();
    (source_token, destination_token)
}

fn token_balance(swig_wallet: &mut SwigWallet<'_>, token_account: &Pubkey) -> u64 {
    let account = swig_wallet.litesvm().get_account(token_account).unwrap();
    spl_token::state::Account::unpack(&account.data)
        .unwrap()
        .amount
}

#[test_log::test]
fn test_v2_creation_and_counter() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let secondary = Keypair::new();

    assert_eq!(swig_wallet.get_sub_account_v2_counter().unwrap(), 0);
    let (subacc_id, _asset) = create_v2_setup(&mut swig_wallet, &secondary);
    assert_eq!(subacc_id, 0);
    assert_eq!(swig_wallet.get_sub_account_v2_counter().unwrap(), 1);
    assert!(swig_wallet.get_sub_account_v2(0).unwrap().is_some());
    assert!(swig_wallet.get_sub_account_v2(5).unwrap().is_none());
}

#[test_log::test]
fn test_v2_lookup_rejects_prefunded_uninitialized_state() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let id_le = 0u32.to_le_bytes();
    let (state, _) = Pubkey::find_program_address(
        &sub_account_v2_state_seeds(swig_wallet.get_swig_id(), &id_le),
        &swig_interface::program_id(),
    );
    swig_wallet
        .litesvm()
        .set_account(
            state,
            Account {
                lamports: 1,
                data: Vec::new(),
                owner: solana_system_interface::program::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    assert!(matches!(
        swig_wallet.get_sub_account_v2(0),
        Err(SwigError::InvalidSwigData)
    ));
}

#[test_log::test]
fn test_v2_lookup_rejects_invalid_enabled_byte() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let secondary = Keypair::new();
    let (subacc_id, _asset) = create_v2_setup(&mut swig_wallet, &secondary);
    let (state, _) = Pubkey::find_program_address(
        &sub_account_v2_state_seeds(swig_wallet.get_swig_id(), &subacc_id.to_le_bytes()),
        &swig_interface::program_id(),
    );

    let mut state_account = swig_wallet.litesvm().get_account(&state).unwrap();
    state_account.data[3] = 2;
    swig_wallet
        .litesvm()
        .set_account(state, state_account)
        .unwrap();

    assert!(matches!(
        swig_wallet.get_sub_account_v2(subacc_id),
        Err(SwigError::InvalidSwigData)
    ));
}

#[test_log::test]
fn test_v2_sign_and_withdraw() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let secondary = Keypair::new();
    let (subacc_id, asset) = create_v2_setup(&mut swig_wallet, &secondary);

    swig_wallet.litesvm().airdrop(&asset, 100_000_000).unwrap();
    let recipient = Keypair::new();

    // Sign a transfer out of the asset PDA.
    let transfer =
        solana_system_interface::instruction::transfer(&asset, &recipient.pubkey(), 1_000_000);
    swig_wallet
        .sign_with_sub_account_v2(subacc_id, vec![transfer], None)
        .unwrap();
    assert_eq!(
        swig_wallet
            .litesvm()
            .get_balance(&recipient.pubkey())
            .unwrap(),
        1_000_000
    );

    // Withdraw SOL back to the swig wallet address.
    let before = swig_wallet.litesvm().get_balance(&asset).unwrap();
    swig_wallet
        .withdraw_from_sub_account_v2(subacc_id, 500_000)
        .unwrap();
    let after = swig_wallet.litesvm().get_balance(&asset).unwrap();
    assert_eq!(before - after, 500_000);
}

#[test_log::test]
fn test_v2_ed25519_token_withdraw() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let creator = Keypair::new();
    let (subacc_id, asset) = create_v2_setup(&mut swig_wallet, &creator);
    let (source_token, destination_token) =
        setup_v2_tokens(&mut swig_wallet, &main_authority, &asset, 10_000);

    swig_wallet
        .withdraw_token_from_sub_account_v2(
            subacc_id,
            source_token,
            destination_token,
            spl_token::ID,
            4_000,
        )
        .unwrap();
    assert_eq!(token_balance(&mut swig_wallet, &source_token), 6_000);
    assert_eq!(token_balance(&mut swig_wallet, &destination_token), 4_000);
}

#[test_log::test]
fn test_v2_toggle_blocks_ops() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let secondary = Keypair::new();
    let (subacc_id, asset) = create_v2_setup(&mut swig_wallet, &secondary);
    swig_wallet.litesvm().airdrop(&asset, 100_000_000).unwrap();

    // Disable the sub-account.
    swig_wallet.toggle_sub_account_v2(subacc_id, false).unwrap();

    // Withdrawing from a disabled sub-account must fail.
    assert!(swig_wallet
        .withdraw_from_sub_account_v2(subacc_id, 1_000)
        .is_err());

    // Re-enable and withdraw succeeds (distinct amount to avoid a duplicate tx).
    swig_wallet.toggle_sub_account_v2(subacc_id, true).unwrap();
    assert!(swig_wallet
        .withdraw_from_sub_account_v2(subacc_id, 2_000)
        .is_ok());
}

#[test_log::test]
fn test_v2_all_authority_cannot_create() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let secondary = Keypair::new();

    // Grant only All — not SubAccountV2Create.
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary.pubkey().to_bytes(),
            vec![Permission::All],
        )
        .unwrap();
    swig_wallet
        .switch_authority(
            1,
            Box::new(Ed25519ClientRole::new(secondary.pubkey())),
            Some(&secondary),
        )
        .unwrap();

    assert!(
        swig_wallet.create_sub_account_v2().is_err(),
        "All alone must not create a V2 sub-account"
    );
}

#[test_log::test]
fn test_v2_secp256k1_sign() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // An ed25519 creator makes sub-account 0.
    let creator = Keypair::new();
    let (subacc_id, asset) = create_v2_setup(&mut swig_wallet, &creator);

    // Grant a Secp256k1 authority scoped Sign{0} (sharing, done by root).
    swig_wallet
        .switch_authority(
            0,
            Box::new(Ed25519ClientRole::new(main_authority.pubkey())),
            Some(&main_authority),
        )
        .unwrap();
    let secp_wallet = PrivateKeySigner::random();
    let secp_pubkey = secp_wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes()
        .as_ref()[1..]
        .to_vec();
    swig_wallet
        .add_authority(
            AuthorityType::Secp256k1,
            &secp_pubkey,
            vec![Permission::SubAccountV2Sign { subacc_id }],
        )
        .unwrap();

    // Switch to the Secp256k1 authority (role 2) and sign.
    let secp_role = swig_wallet.get_role_id(&secp_pubkey).unwrap();
    let signing_fn = Box::new(move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        secp_wallet
            .sign_hash_sync(&B256::from(hash))
            .unwrap()
            .as_bytes()
    });
    swig_wallet
        .switch_authority(
            secp_role,
            Box::new(Secp256k1ClientRole::new(
                secp_pubkey.clone().into(),
                signing_fn,
            )),
            None,
        )
        .unwrap();

    swig_wallet.litesvm().airdrop(&asset, 100_000_000).unwrap();
    let recipient = Keypair::new();
    let transfer =
        solana_system_interface::instruction::transfer(&asset, &recipient.pubkey(), 1_000_000);
    swig_wallet
        .sign_with_sub_account_v2(subacc_id, vec![transfer], None)
        .unwrap();
    assert_eq!(
        swig_wallet
            .litesvm()
            .get_balance(&recipient.pubkey())
            .unwrap(),
        1_000_000
    );
}

#[test_log::test]
fn test_v2_secp256k1_create_and_token_withdraw() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let secp_wallet = PrivateKeySigner::random();
    let secp_pubkey = secp_wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes()
        .as_ref()[1..]
        .to_vec();
    swig_wallet
        .add_authority(
            AuthorityType::Secp256k1,
            &secp_pubkey,
            vec![Permission::SubAccountV2Create],
        )
        .unwrap();
    let secp_role = swig_wallet.get_role_id(&secp_pubkey).unwrap();
    let signing_fn = Box::new(move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        secp_wallet
            .sign_hash_sync(&B256::from(hash))
            .unwrap()
            .as_bytes()
    });
    swig_wallet
        .switch_authority(
            secp_role,
            Box::new(Secp256k1ClientRole::new(
                secp_pubkey.clone().into(),
                signing_fn,
            )),
            None,
        )
        .unwrap();

    let (_signature, subacc_id) = swig_wallet.create_sub_account_v2().unwrap();
    let asset = swig_wallet.get_sub_account_v2(subacc_id).unwrap().unwrap();
    let (source_token, destination_token) =
        setup_v2_tokens(&mut swig_wallet, &main_authority, &asset, 10_000);
    swig_wallet
        .withdraw_token_from_sub_account_v2(
            subacc_id,
            source_token,
            destination_token,
            spl_token::ID,
            4_000,
        )
        .unwrap();
    assert_eq!(token_balance(&mut swig_wallet, &source_token), 6_000);
    assert_eq!(token_balance(&mut swig_wallet, &destination_token), 4_000);
}

#[test_log::test]
fn test_v2_secp256r1_create_and_token_withdraw() {
    use solana_secp256r1_program::sign_message;

    use crate::tests::common::create_test_secp256r1_keypair;

    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let (signing_key, public_key) = create_test_secp256r1_keypair();
    swig_wallet
        .add_authority(
            AuthorityType::Secp256r1,
            &public_key,
            vec![Permission::SubAccountV2Create],
        )
        .unwrap();
    let role_id = swig_wallet.get_role_id(&public_key).unwrap();
    let signing_fn = Box::new(move |message_hash: &[u8]| -> [u8; 64] {
        sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap()
    });
    swig_wallet
        .switch_authority(
            role_id,
            Box::new(Secp256r1ClientRole::new(public_key, signing_fn)),
            None,
        )
        .unwrap();

    let (_signature, subacc_id) = swig_wallet.create_sub_account_v2().unwrap();
    let asset = swig_wallet.get_sub_account_v2(subacc_id).unwrap().unwrap();
    let (source_token, destination_token) =
        setup_v2_tokens(&mut swig_wallet, &main_authority, &asset, 10_000);
    swig_wallet
        .withdraw_token_from_sub_account_v2(
            subacc_id,
            source_token,
            destination_token,
            spl_token::ID,
            4_000,
        )
        .unwrap();
    assert_eq!(token_balance(&mut swig_wallet, &source_token), 6_000);
    assert_eq!(token_balance(&mut swig_wallet, &destination_token), 4_000);
}

// ------------------------------------------------------------ session roles

/// Adds an Ed25519 session authority holding `permissions`, opens a session on
/// it, and leaves the wallet acting as that session. Returns the role id.
///
/// Session roles build their V2 instructions with the Ed25519 builders using
/// the session key as the authority, so the wallet has to sign as the session
/// key once the session is live.
fn start_ed25519_session<'a>(
    swig_wallet: &mut SwigWallet<'a>,
    main_payer: &'a Keypair,
    session_root: &'a Keypair,
    session_key: &'a Keypair,
    permissions: Vec<Permission>,
) -> u32 {
    let create_authority =
        CreateEd25519SessionAuthority::new(session_root.pubkey().to_bytes(), [0; 32], 100);
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519Session,
            create_authority.into_bytes().unwrap(),
            permissions,
        )
        .unwrap();

    let role_id = swig_wallet
        .get_role_id(&session_root.pubkey().to_bytes())
        .unwrap();

    // Act as the session role with the root key to open the session.
    swig_wallet
        .switch_authority(
            role_id,
            Box::new(Ed25519SessionClientRole::new(create_authority)),
            Some(session_root),
        )
        .unwrap();
    // `create_session` signs with the fee payer alone rather than
    // fee_payer + authority, so the session root has to be the payer for it.
    swig_wallet
        .litesvm()
        .airdrop(&session_root.pubkey(), 10_000_000_000)
        .unwrap();
    let original_payer = main_payer;
    swig_wallet.switch_payer(session_root).unwrap();
    swig_wallet
        .create_session(session_key.pubkey(), 100)
        .unwrap();
    swig_wallet.switch_payer(original_payer).unwrap();

    // Re-point the client role at the now-live session key and sign as it.
    swig_wallet
        .switch_authority(
            role_id,
            Box::new(Ed25519SessionClientRole::new(
                CreateEd25519SessionAuthority::new(
                    session_root.pubkey().to_bytes(),
                    session_key.pubkey().to_bytes(),
                    100,
                ),
            )),
            Some(session_key),
        )
        .unwrap();
    role_id
}

#[test_log::test]
fn test_v2_ed25519_session_create_and_sol_withdraw() {
    let (litesvm, main_authority) = setup_test_environment();
    let session_root = Keypair::new();
    let session_key = Keypair::new();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    start_ed25519_session(
        &mut swig_wallet,
        &main_authority,
        &session_root,
        &session_key,
        vec![Permission::SubAccountV2Create],
    );

    let (_signature, subacc_id) = swig_wallet.create_sub_account_v2().unwrap();
    let asset = swig_wallet.get_sub_account_v2(subacc_id).unwrap().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&asset, 1_000_000_000)
        .unwrap();

    let wallet_address = swig_wallet.get_swig_wallet_address().unwrap();
    let before = swig_wallet
        .litesvm()
        .get_account(&wallet_address)
        .unwrap()
        .lamports;
    swig_wallet
        .withdraw_from_sub_account_v2(subacc_id, 250_000_000)
        .unwrap();
    assert_eq!(
        swig_wallet
            .litesvm()
            .get_account(&wallet_address)
            .unwrap()
            .lamports,
        before + 250_000_000
    );
}

/// Regression for the session roles missing a token-withdraw impl: they used to
/// fall through to the trait default and return "unsupported".
#[test_log::test]
fn test_v2_ed25519_session_token_withdraw() {
    let (litesvm, main_authority) = setup_test_environment();
    let session_root = Keypair::new();
    let session_key = Keypair::new();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    start_ed25519_session(
        &mut swig_wallet,
        &main_authority,
        &session_root,
        &session_key,
        vec![Permission::SubAccountV2Create],
    );

    let (_signature, subacc_id) = swig_wallet.create_sub_account_v2().unwrap();
    let asset = swig_wallet.get_sub_account_v2(subacc_id).unwrap().unwrap();
    let (source_token, destination_token) =
        setup_v2_tokens(&mut swig_wallet, &main_authority, &asset, 10_000);

    swig_wallet
        .withdraw_token_from_sub_account_v2(
            subacc_id,
            source_token,
            destination_token,
            spl_token::ID,
            4_000,
        )
        .unwrap();
    assert_eq!(token_balance(&mut swig_wallet, &source_token), 6_000);
    assert_eq!(token_balance(&mut swig_wallet, &destination_token), 4_000);
}

#[test_log::test]
fn test_v2_ed25519_session_toggle_blocks_ops() {
    let (litesvm, main_authority) = setup_test_environment();
    let session_root = Keypair::new();
    let session_key = Keypair::new();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    start_ed25519_session(
        &mut swig_wallet,
        &main_authority,
        &session_root,
        &session_key,
        vec![Permission::SubAccountV2Create],
    );

    let (_signature, subacc_id) = swig_wallet.create_sub_account_v2().unwrap();
    let asset = swig_wallet.get_sub_account_v2(subacc_id).unwrap().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&asset, 1_000_000_000)
        .unwrap();

    swig_wallet.toggle_sub_account_v2(subacc_id, false).unwrap();
    assert!(
        swig_wallet
            .withdraw_from_sub_account_v2(subacc_id, 1_000)
            .is_err(),
        "a disabled sub-account must reject withdrawals from a session role"
    );

    // Distinct amount so the retry is not a byte-identical, already-processed tx.
    swig_wallet.toggle_sub_account_v2(subacc_id, true).unwrap();
    swig_wallet
        .withdraw_from_sub_account_v2(subacc_id, 2_000)
        .unwrap();
}
