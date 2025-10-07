use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use solana_program::{pubkey::Pubkey, system_instruction, system_program};
use solana_sdk::signature::{Keypair, Signer};

use super::*;
use crate::client_role::{Ed25519ClientRole, Secp256k1ClientRole, Secp256r1ClientRole};

#[test_log::test]
fn should_sign_v2_transfer_with_ed25519_within_limits() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet_v2(litesvm, &main_authority);

    // Fund the swig wallet PDA
    let swig_wallet_address = swig_wallet.get_swig_wallet_address().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_wallet_address, 5_000_000_000)
        .unwrap();

    // Prepare a transfer from wallet PDA to recipient
    let recipient = Keypair::new();
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), 100_000_000);

    let sig = swig_wallet.sign_v2(vec![transfer_ix], None).unwrap();
    assert!(sig != solana_sdk::signature::Signature::default());
    assert_eq!(swig_wallet.get_current_role_id().unwrap(), 0);
}

#[test_log::test]
fn should_sign_v2_fail_transfer_beyond_limits() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let secondary_authority = Keypair::new();
    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = create_test_wallet_v2(litesvm, &main_authority);

    // Add limited SOL permission and system program permission
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![
                Permission::Program {
                    program_id: system_program::ID,
                },
                Permission::Sol {
                    amount: 1_000_000_000,
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
    swig_wallet.switch_payer(&secondary_authority).unwrap();

    // Fund the swig wallet PDA
    let swig_wallet_address = swig_wallet.get_swig_wallet_address().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();

    // Attempt transfer beyond limits (2_000_000_000 > 1_000_000_000)
    let recipient = Keypair::new();
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), 2_000_000_000);

    assert!(swig_wallet.sign_v2(vec![transfer_ix], None).is_err());
}

#[test_log::test]
fn should_sign_v2_transfer_between_swig_accounts() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut sender_wallet = create_test_wallet_v2(litesvm, &main_authority);

    // Create a second swig wallet (different swig id) as recipient
    let other_auth = Keypair::new();
    let mut other_litesvm = LiteSVM::new();
    other_litesvm
        .add_program_from_file(Pubkey::new_from_array(swig::ID), "../target/deploy/swig.so")
        .unwrap();
    other_litesvm
        .airdrop(&other_auth.pubkey(), 10_000_000_000)
        .unwrap();
    let mut recipient_wallet = SwigWallet::new(
        [1; 32],
        Box::new(Ed25519ClientRole::new(other_auth.pubkey())),
        &other_auth,
        "http://localhost:8899".to_string(),
        Some(&other_auth),
        other_litesvm,
    )
    .unwrap();

    let sender_wallet_address = sender_wallet.get_swig_wallet_address().unwrap();
    sender_wallet
        .litesvm()
        .airdrop(&sender_wallet_address, 5_000_000_000)
        .unwrap();

    let recipient_swig = recipient_wallet.get_swig_account().unwrap();
    let transfer_ix =
        system_instruction::transfer(&sender_wallet_address, &recipient_swig, 1_000_000_000);

    let res = sender_wallet.sign_v2(vec![transfer_ix], None);
    assert!(res.is_ok());
}

#[test_log::test]
fn should_sign_v2_with_different_payer_and_authority() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let different_payer = Keypair::new();
    litesvm
        .airdrop(&different_payer.pubkey(), 2_000_000_000)
        .unwrap();

    // Create wallet with main authority, then switch payer
    let mut swig_wallet = create_test_wallet_v2(litesvm, &main_authority);
    swig_wallet.switch_payer(&different_payer).unwrap();

    // Fund PDA and transfer
    let swig_wallet_address = swig_wallet.get_swig_wallet_address().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_wallet_address, 1_000_000_000)
        .unwrap();

    let recipient = Keypair::new();
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), 100_000);
    let res = swig_wallet.sign_v2(vec![transfer_ix], None);
    assert!(res.is_ok());
}

#[test_log::test]
fn should_sign_v2_with_secp256k1_authority_transfers_sol() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet_v2(litesvm, &main_authority);

    // Add secp256k1 authority with SOL and program permissions
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
            vec![
                Permission::Program {
                    program_id: system_program::ID,
                },
                Permission::Sol {
                    amount: 1_000_000_000,
                    recurring: None,
                },
            ],
        )
        .unwrap();

    // Switch authority to secp256k1 role with signing fn
    let wallet_clone = wallet.clone();
    let signing_fn = move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet_clone.sign_hash_sync(&hash).unwrap().as_bytes()
    };
    swig_wallet
        .switch_authority(
            1,
            Box::new(Secp256k1ClientRole::new(secp_pubkey, Box::new(signing_fn))),
            None,
        )
        .unwrap();

    // Fund PDA and transfer
    let swig_wallet_address = swig_wallet.get_swig_wallet_address().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_wallet_address, 1_000_000_000)
        .unwrap();

    let recipient = Keypair::new();
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), 222_222);
    let res = swig_wallet.sign_v2(vec![transfer_ix], None);
    assert!(res.is_ok());
}

#[test_log::test]
fn should_sign_v2_secp256r1_transfer() {
    use solana_secp256r1_program::sign_message;

    use crate::tests::common::create_test_secp256r1_keypair;

    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet_v2(litesvm, &main_authority);

    // Create secp256r1 authority and add
    let (signing_key, public_key) = create_test_secp256r1_keypair();
    let authority_fn = move |message_hash: &[u8]| -> [u8; 64] {
        sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap()
    };

    swig_wallet
        .add_authority(
            AuthorityType::Secp256r1,
            &public_key,
            vec![
                Permission::Program {
                    program_id: system_program::ID,
                },
                Permission::Sol {
                    amount: 1_000_000_000,
                    recurring: None,
                },
            ],
        )
        .unwrap();

    swig_wallet
        .switch_authority(
            1,
            Box::new(Secp256r1ClientRole::new(public_key, Box::new(authority_fn))),
            None,
        )
        .unwrap();

    // Fund PDA and transfer
    let swig_wallet_address = swig_wallet.get_swig_wallet_address().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_wallet_address, 1_000_000_000)
        .unwrap();

    let recipient = Keypair::new();
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), 111_111);
    let res = swig_wallet.sign_v2(vec![transfer_ix], None);
    assert!(res.is_ok());
}

#[test_log::test]
fn should_sign_v2_token_recurring_limit_enforced() {
    use litesvm_token::spl_token;

    use crate::tests::common::{mint_to, setup_ata, setup_mint};

    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet_v2(litesvm, &main_authority);

    // Fund wallet PDA and mint tokens
    let swig_wallet_address = swig_wallet.get_swig_wallet_address().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_wallet_address, 1_000_000_000)
        .unwrap();

    let payer = swig_wallet.get_fee_payer();
    let mint_pubkey = setup_mint(swig_wallet.litesvm(), &main_authority).unwrap();
    let swig_ata = swig_wallet.create_wallet_ata(&mint_pubkey).unwrap();
    let recipient = Keypair::new();
    let recipient_ata = setup_ata(
        swig_wallet.litesvm(),
        &mint_pubkey,
        &recipient.pubkey(),
        &main_authority,
    )
    .unwrap();
    mint_to(
        swig_wallet.litesvm(),
        &mint_pubkey,
        &main_authority,
        &swig_ata,
        1000,
    )
    .unwrap();

    // Add second authority with token recurring limit and token program permission
    let second_authority = Keypair::new();
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &second_authority.pubkey().to_bytes(),
            vec![
                Permission::Token {
                    mint: mint_pubkey,
                    amount: 500,
                    recurring: Some(RecurringConfig::new(100)),
                },
                Permission::Program {
                    program_id: spl_token::id(),
                },
            ],
        )
        .unwrap();

    // Switch to the limited token authority
    swig_wallet
        .switch_authority(
            1,
            Box::new(Ed25519ClientRole::new(second_authority.pubkey())),
            Some(&second_authority),
        )
        .unwrap();

    // First transfer within limit
    let amount1 = 300u64;
    let token_ix1 = solana_sdk::instruction::Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(swig_ata, false),
            solana_sdk::instruction::AccountMeta::new(recipient_ata, false),
            solana_sdk::instruction::AccountMeta::new(swig_wallet_address, false),
        ],
        data: spl_token::instruction::TokenInstruction::Transfer { amount: amount1 }.pack(),
    };
    let res1 = swig_wallet.sign_v2(vec![token_ix1], None);
    println!("res1: {:?}", res1);
    assert!(res1.is_ok());

    // Second transfer exceeding remaining limit should fail
    let amount2 = 300u64; // remaining is 200
    let token_ix2 = solana_sdk::instruction::Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(swig_ata, false),
            solana_sdk::instruction::AccountMeta::new(recipient_ata, false),
            solana_sdk::instruction::AccountMeta::new(swig_wallet_address, false),
        ],
        data: spl_token::instruction::TokenInstruction::Transfer { amount: amount2 }.pack(),
    };
    let res2 = swig_wallet.sign_v2(vec![token_ix2], None);
    assert!(res2.is_err());
}
