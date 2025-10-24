use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use solana_program::pubkey::Pubkey;
use solana_sdk::{
    message::{v0, VersionedMessage},
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};

use super::*;
use crate::client_role::{Ed25519ClientRole, Secp256k1ClientRole};

#[test_log::test]
fn test_sign_v2_with_ed25519_authority_transfers_sol() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [9u8; 32];
    let authority = Keypair::new();
    let payer_kp = context.default_payer.insecure_clone();
    let payer = &payer_kp;
    let role_id = 1;

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        payer.pubkey(),
        role_id,
    );

    // Create swig (also creates wallet address PDA)
    let ix = builder.build_swig_account().unwrap();
    let msg = v0::Message::try_compile(&payer.pubkey(), &[ix], &[], context.svm.latest_blockhash())
        .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer]).unwrap();
    context.svm.send_transaction(tx).unwrap();

    let swig_key = builder.get_swig_account().unwrap();
    let swig_wallet_address = builder.swig_wallet_address();

    // Fund the swig wallet address PDA
    context
        .svm
        .airdrop(&swig_wallet_address, 1_000_000_000)
        .unwrap();

    // Prepare a transfer from wallet address PDA to recipient
    let recipient = Keypair::new();
    let transfer_amount = 123_456;
    let transfer_ix = solana_program::system_instruction::transfer(
        &swig_wallet_address,
        &recipient.pubkey(),
        transfer_amount,
    );

    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    let sign_ixs = builder
        .sign_v2_instruction(vec![transfer_ix], Some(current_slot))
        .unwrap();

    let msg = v0::Message::try_compile(
        &payer.pubkey(),
        &sign_ixs,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &authority],
    )
    .unwrap();

    let res = context.svm.send_transaction(tx);
    assert!(
        res.is_ok(),
        "sign_v2 ed25519 transfer failed: {:?}",
        res.err()
    );

    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(recipient_account.lamports, transfer_amount);
}

#[test_log::test]
fn test_sign_v2_with_secp256k1_authority_transfers_sol() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [7u8; 32];
    let payer_kp = context.default_payer.insecure_clone();
    let payer = &payer_kp;
    let role_id = 1;

    let wallet = LocalSigner::random();
    let secp_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    let wallet_clone = wallet.clone();
    let signing_fn = move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet_clone.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Secp256k1ClientRole::new(secp_pubkey, Box::new(signing_fn))),
        payer.pubkey(),
        role_id,
    );

    // Create swig
    let ix = builder.build_swig_account().unwrap();
    let msg = v0::Message::try_compile(&payer.pubkey(), &[ix], &[], context.svm.latest_blockhash())
        .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer]).unwrap();
    context.svm.send_transaction(tx).unwrap();

    let swig_wallet_address = builder.swig_wallet_address();
    context
        .svm
        .airdrop(&swig_wallet_address, 1_000_000_000)
        .unwrap();

    let recipient = Keypair::new();
    let transfer_amount = 222_222;
    let transfer_ix = solana_program::system_instruction::transfer(
        &swig_wallet_address,
        &recipient.pubkey(),
        transfer_amount,
    );

    context.svm.warp_to_slot(100);

    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    println!("current_slot: {:?}", current_slot);
    let sign_ixs = builder
        .sign_v2_instruction(vec![transfer_ix], Some(current_slot))
        .unwrap();

    let msg = v0::Message::try_compile(
        &payer.pubkey(),
        &sign_ixs,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&context.default_payer])
        .unwrap();

    let res = context.svm.send_transaction(tx);
    assert!(
        res.is_ok(),
        "sign_v2 secp256k1 transfer failed: {:?}",
        res.err()
    );

    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(recipient_account.lamports, transfer_amount);
}

use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    sysvar::clock::Clock,
};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state::{
    action::{
        all::All, program::Program, sol_limit::SolLimit, token_recurring_limit::TokenRecurringLimit,
    },
    authority::AuthorityType,
};

#[test_log::test]
fn test_sign_v2_with_additional_authority_and_sol_limit() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let payer_kp = context.default_payer.insecure_clone();
    let payer = &payer_kp;
    let role_id = 1;

    let mut builder = SwigInstructionBuilder::new(
        [2u8; 32],
        Box::new(Ed25519ClientRole::new(swig_authority.pubkey())),
        payer.pubkey(),
        role_id,
    );

    // Create swig and fund wallet PDA
    {
        let ix = builder.build_swig_account().unwrap();
        let msg =
            v0::Message::try_compile(&payer.pubkey(), &[ix], &[], context.svm.latest_blockhash())
                .unwrap();
        let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer]).unwrap();
        context.svm.send_transaction(tx).unwrap();
    }
    let swig = builder.get_swig_account().unwrap();
    let swig_wallet_address = builder.swig_wallet_address();
    context
        .svm
        .airdrop(&swig_wallet_address, 1_000_000_000)
        .unwrap();

    // Add second authority with SOL limit and system program permission
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::SolLimit(SolLimit { amount: 100_000 }),
            ClientAction::Program(Program {
                program_id: solana_sdk::system_program::ID.to_bytes(),
            }),
        ],
    )
    .unwrap();

    // Use second authority to transfer within limit
    let recipient = Keypair::new();
    let amount = 50_000u64;
    let transfer_ix = solana_program::system_instruction::transfer(
        &swig_wallet_address,
        &recipient.pubkey(),
        amount,
    );
    let mut builder2 = SwigInstructionBuilder::new(
        [2u8; 32],
        Box::new(Ed25519ClientRole::new(second_authority.pubkey())),
        payer.pubkey(),
        2,
    );
    builder2.switch_payer(payer.pubkey()).unwrap();
    let ixs = builder2
        .sign_v2_instruction(
            vec![transfer_ix],
            Some(context.svm.get_sysvar::<Clock>().slot),
        )
        .unwrap();
    let msg = v0::Message::try_compile(&payer.pubkey(), &ixs, &[], context.svm.latest_blockhash())
        .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();
    let result = context.svm.send_transaction(tx);
    assert!(result.is_ok(), "transfer within limit should succeed");
}

#[test_log::test]
fn test_sign_v2_fail_with_insufficient_sol_limit() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let payer_kp = context.default_payer.insecure_clone();
    let payer = &payer_kp;
    let role_id = 1;

    let mut builder = SwigInstructionBuilder::new(
        [3u8; 32],
        Box::new(Ed25519ClientRole::new(swig_authority.pubkey())),
        payer.pubkey(),
        role_id,
    );

    // Create swig and fund wallet PDA
    {
        let ix = builder.build_swig_account().unwrap();
        let msg =
            v0::Message::try_compile(&payer.pubkey(), &[ix], &[], context.svm.latest_blockhash())
                .unwrap();
        let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer]).unwrap();
        context.svm.send_transaction(tx).unwrap();
    }
    let swig = builder.get_swig_account().unwrap();
    let swig_wallet_address = builder.swig_wallet_address();
    context
        .svm
        .airdrop(&swig_wallet_address, 1_000_000_000)
        .unwrap();

    // Add limited second authority
    let second_authority = Keypair::new();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::SolLimit(SolLimit { amount: 1_000 }),
            ClientAction::Program(Program {
                program_id: solana_sdk::system_program::ID.to_bytes(),
            }),
        ],
    )
    .unwrap();

    let recipient = Keypair::new();
    let amount = 1_001u64;
    let transfer_ix = solana_program::system_instruction::transfer(
        &swig_wallet_address,
        &recipient.pubkey(),
        amount,
    );
    let mut builder2 = SwigInstructionBuilder::new(
        [3u8; 32],
        Box::new(Ed25519ClientRole::new(second_authority.pubkey())),
        second_authority.pubkey(),
        2,
    );
    let ixs = builder2
        .sign_v2_instruction(
            vec![transfer_ix],
            Some(context.svm.get_sysvar::<Clock>().slot),
        )
        .unwrap();
    let msg = v0::Message::try_compile(
        &second_authority.pubkey(),
        &ixs,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&second_authority]).unwrap();
    let res = context.svm.send_transaction(tx);
    assert!(res.is_err(), "transfer exceeding limit should fail");
}

#[test_log::test]
fn test_sign_v2_transfer_between_swig_accounts() {
    let mut context = setup_test_context().unwrap();
    let payer_kp = context.default_payer.insecure_clone();
    let payer = &payer_kp;

    // Sender swig
    let sender_auth = Keypair::new();
    let mut sender_builder = SwigInstructionBuilder::new(
        [4u8; 32],
        Box::new(Ed25519ClientRole::new(sender_auth.pubkey())),
        payer.pubkey(),
        1,
    );
    {
        let ix = sender_builder.build_swig_account().unwrap();
        let msg =
            v0::Message::try_compile(&payer.pubkey(), &[ix], &[], context.svm.latest_blockhash())
                .unwrap();
        let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer]).unwrap();
        context.svm.send_transaction(tx).unwrap();
    }
    let sender_swig = sender_builder.get_swig_account().unwrap();
    let sender_wallet = sender_builder.swig_wallet_address();
    context.svm.airdrop(&sender_wallet, 5_000_000_000).unwrap();

    // Recipient swig
    let recipient_auth = Keypair::new();
    let mut recipient_builder = SwigInstructionBuilder::new(
        [5u8; 32],
        Box::new(Ed25519ClientRole::new(recipient_auth.pubkey())),
        payer.pubkey(),
        1,
    );
    {
        let ix = recipient_builder.build_swig_account().unwrap();
        let msg =
            v0::Message::try_compile(&payer.pubkey(), &[ix], &[], context.svm.latest_blockhash())
                .unwrap();
        let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer]).unwrap();
        context.svm.send_transaction(tx).unwrap();
    }
    let recipient_swig = recipient_builder.get_swig_account().unwrap();

    let transfer_ix = solana_program::system_instruction::transfer(
        &sender_wallet,
        &recipient_swig,
        1_000_000_000,
    );
    let ixs = sender_builder
        .sign_v2_instruction(
            vec![transfer_ix],
            Some(context.svm.get_sysvar::<Clock>().slot),
        )
        .unwrap();
    let msg = v0::Message::try_compile(&payer.pubkey(), &ixs, &[], context.svm.latest_blockhash())
        .unwrap();
    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer, &sender_auth]).unwrap();
    let res = context.svm.send_transaction(tx);
    assert!(res.is_ok(), "transfer between swig accounts should succeed");
}

#[test_log::test]
fn test_sign_v2_different_payer_and_authority() {
    let mut context = setup_test_context().unwrap();
    let payer_kp = context.default_payer.insecure_clone();
    let payer = &payer_kp;
    let swig_authority = Keypair::new();
    let different_payer = Keypair::new();
    println!("different_payer: {:?}", different_payer.pubkey());
    println!("swig_authority: {:?}", swig_authority.pubkey());
    println!("payer: {:?}", payer.pubkey());
    context
        .svm
        .airdrop(&different_payer.pubkey(), 2_000_000_000)
        .unwrap();

    let mut builder = SwigInstructionBuilder::new(
        [6u8; 32],
        Box::new(Ed25519ClientRole::new(swig_authority.pubkey())),
        different_payer.pubkey(),
        1,
    );
    {
        let ix = builder.build_swig_account().unwrap();
        let msg = v0::Message::try_compile(
            &different_payer.pubkey(),
            &[ix],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap();
        let tx =
            VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&different_payer]).unwrap();
        context.svm.send_transaction(tx).unwrap();
    }
    let swig_wallet_address = builder.swig_wallet_address();
    println!("swig_account: {:?}", builder.get_swig_account().unwrap());
    println!("swig_wallet_address: {:?}", swig_wallet_address);

    context
        .svm
        .airdrop(&swig_wallet_address, 1_000_000_000)
        .unwrap();

    let recipient = Keypair::new();
    let amount = 100_000u64;
    let transfer_ix = solana_program::system_instruction::transfer(
        &swig_wallet_address,
        &recipient.pubkey(),
        amount,
    );
    let ixs = builder
        .sign_v2_instruction(
            vec![transfer_ix],
            Some(context.svm.get_sysvar::<Clock>().slot),
        )
        .unwrap();
    let msg = v0::Message::try_compile(
        &different_payer.pubkey(),
        &ixs,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&different_payer, &swig_authority],
    )
    .unwrap();
    let res = context.svm.send_transaction(tx);
    assert!(res.is_ok(), "different payer and authority should succeed");
}

#[test_log::test]
fn test_sign_v2_secp256r1_transfer() {
    let mut context = setup_test_context().unwrap();
    let (signing_key, public_key) = create_test_secp256r1_keypair();

    use openssl::ec::EcKey;
    let authority_fn = move |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        let signature =
            sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap();
        signature
    };

    let payer_kp = context.default_payer.insecure_clone();
    let payer = &payer_kp;
    let mut builder = SwigInstructionBuilder::new(
        [8u8; 32],
        Box::new(crate::client_role::Secp256r1ClientRole::new(
            public_key,
            Box::new(authority_fn),
        )),
        payer.pubkey(),
        1,
    );
    {
        let ix = builder.build_swig_account().unwrap();
        let msg =
            v0::Message::try_compile(&payer.pubkey(), &[ix], &[], context.svm.latest_blockhash())
                .unwrap();
        let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer]).unwrap();
        context.svm.send_transaction(tx).unwrap();
    }
    let swig_wallet_address = builder.swig_wallet_address();
    context
        .svm
        .airdrop(&swig_wallet_address, 1_000_000_000)
        .unwrap();

    let swig_account = builder.get_swig_account().unwrap();
    let swig_data = context.svm.get_account(&swig_account).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_data.data).unwrap();
    let role_id = swig_with_roles
        .lookup_role_id(&public_key)
        .unwrap()
        .unwrap();
    let role = swig_with_roles.get_role(role_id).unwrap().unwrap();
    let secp_authority = role
        .authority
        .as_any()
        .downcast_ref::<swig_state::authority::secp256r1::Secp256r1Authority>()
        .unwrap();
    println!("secp_authority: {:?}", secp_authority);

    let recipient = Keypair::new();
    let amount = 111_111u64;
    let transfer_ix = solana_program::system_instruction::transfer(
        &swig_wallet_address,
        &recipient.pubkey(),
        amount,
    );
    let ixs = builder
        .sign_v2_instruction(
            vec![transfer_ix],
            Some(context.svm.get_sysvar::<Clock>().slot),
        )
        .unwrap();
    let msg = v0::Message::try_compile(&payer.pubkey(), &ixs, &[], context.svm.latest_blockhash())
        .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer]).unwrap();
    let res = context.svm.send_transaction(tx);
    println!("res: {:?}", res);
    assert!(res.is_ok(), "secp256r1 sign_v2 transfer should succeed");
}

#[test_log::test]
fn test_sign_v2_token_recurring_limit() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let payer_kp = context.default_payer.insecure_clone();
    let payer = &payer_kp;
    let mut builder = SwigInstructionBuilder::new(
        [10u8; 32],
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        payer.pubkey(),
        0,
    );
    // Create swig
    {
        let ix = builder.build_swig_account().unwrap();
        let msg =
            v0::Message::try_compile(&payer.pubkey(), &[ix], &[], context.svm.latest_blockhash())
                .unwrap();
        let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer]).unwrap();
        context.svm.send_transaction(tx).unwrap();
    }
    let swig = builder.get_swig_account().unwrap();
    let swig_wallet_address = builder.swig_wallet_address();
    context
        .svm
        .airdrop(&swig_wallet_address, 1_000_000_000)
        .unwrap();

    // Setup token infra
    let mint_pubkey = setup_mint(&mut context.svm, &payer).unwrap();
    let swig_ata = setup_ata(&mut context.svm, &mint_pubkey, &swig_wallet_address, &payer).unwrap();
    let recipient = Keypair::new();
    let recipient_ata =
        setup_ata(&mut context.svm, &mint_pubkey, &recipient.pubkey(), &payer).unwrap();
    mint_to(&mut context.svm, &mint_pubkey, &payer, &swig_ata, 1000).unwrap();

    // Add second authority with token recurring limit and token program permission
    let second_authority = Keypair::new();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::TokenRecurringLimit(TokenRecurringLimit {
                token_mint: mint_pubkey.to_bytes(),
                window: 100,
                limit: 500,
                current: 500,
                last_reset: 0,
            }),
            ClientAction::Program(Program {
                program_id: litesvm_token::spl_token::id().to_bytes(),
            }),
        ],
    )
    .unwrap();

    // First transfer within limit
    let amount1 = 300u64;
    let token_ix1 = Instruction {
        program_id: litesvm_token::spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig_wallet_address, false),
        ],
        data: litesvm_token::spl_token::instruction::TokenInstruction::Transfer { amount: amount1 }
            .pack(),
    };
    let mut builder2 = SwigInstructionBuilder::new(
        [10u8; 32],
        Box::new(Ed25519ClientRole::new(second_authority.pubkey())),
        payer.pubkey(),
        2,
    );
    let ixs1 = builder2
        .sign_v2_instruction(
            vec![token_ix1],
            Some(context.svm.get_sysvar::<Clock>().slot),
        )
        .unwrap();
    let msg1 =
        v0::Message::try_compile(&payer.pubkey(), &ixs1, &[], context.svm.latest_blockhash())
            .unwrap();
    let tx1 =
        VersionedTransaction::try_new(VersionedMessage::V0(msg1), &[payer, &second_authority])
            .unwrap();
    assert!(context.svm.send_transaction(tx1).is_ok());

    // Second transfer exceeding limit should fail
    let amount2 = 300u64;
    let token_ix2 = Instruction {
        program_id: litesvm_token::spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig_wallet_address, false),
        ],
        data: litesvm_token::spl_token::instruction::TokenInstruction::Transfer { amount: amount2 }
            .pack(),
    };
    let ixs2 = builder2
        .sign_v2_instruction(
            vec![token_ix2],
            Some(context.svm.get_sysvar::<Clock>().slot),
        )
        .unwrap();
    let msg2 =
        v0::Message::try_compile(&payer.pubkey(), &ixs2, &[], context.svm.latest_blockhash())
            .unwrap();
    let tx2 =
        VersionedTransaction::try_new(VersionedMessage::V0(msg2), &[payer, &second_authority])
            .unwrap();
    assert!(context.svm.send_transaction(tx2).is_err());
}
