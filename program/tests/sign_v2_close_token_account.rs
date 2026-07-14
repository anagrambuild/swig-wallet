#![cfg(not(feature = "program_scope_test"))]
//! Regression tests for closing pre-existing token accounts through SignV2.

mod common;

use common::*;
use litesvm_token::spl_token;
use solana_sdk::{
    instruction::InstructionError,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{AuthorityConfig, ClientAction, SignV2Instruction};
use swig_state::{
    action::{close_swig_authority::CloseSwigAuthority, program::Program, token_limit::TokenLimit},
    authority::AuthorityType,
    swig::{swig_wallet_address_seeds, SwigWithRoles},
    SwigAuthenticateError,
};

const TOKEN_LIMIT_AMOUNT: u64 = 100;

fn token_limit_remaining(
    context: &Context,
    swig_pubkey: &Pubkey,
    role_id: u32,
    mint: &Pubkey,
) -> u64 {
    let swig_account = context.svm.get_account(swig_pubkey).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig.get_role(role_id).unwrap().unwrap();
    role.get_action::<TokenLimit>(mint.as_ref())
        .unwrap()
        .unwrap()
        .current_amount
}

#[test_log::test]
fn sign_v2_closes_token_account_with_close_permission_without_consuming_token_limit() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let close_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();
    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(swig_pubkey.as_ref()),
        &program_id(),
    );
    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let token_account = setup_ata(
        &mut context.svm,
        &mint,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: close_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::Program(Program {
                program_id: spl_token::ID.to_bytes(),
            }),
            ClientAction::CloseSwigAuthority(CloseSwigAuthority),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint.to_bytes(),
                current_amount: TOKEN_LIMIT_AMOUNT,
            }),
        ],
    )
    .unwrap();

    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();
    let token_account_rent = context.svm.get_account(&token_account).unwrap().lamports;
    let close_ix = spl_token::instruction::close_account(
        &spl_token::ID,
        &token_account,
        &destination.pubkey(),
        &swig_wallet_address,
        &[],
    )
    .unwrap();
    let sign_ix = SignV2Instruction::new_ed25519(
        swig_pubkey,
        swig_wallet_address,
        close_authority.pubkey(),
        close_ix,
        1,
    )
    .unwrap();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, &close_authority],
    )
    .unwrap();

    context.svm.send_transaction(transaction).unwrap();

    let closed_account = context.svm.get_account(&token_account);
    assert!(
        closed_account.is_none() || closed_account.unwrap().lamports == 0,
        "token account should be closed"
    );
    assert_eq!(
        context
            .svm
            .get_account(&destination.pubkey())
            .map(|account| account.lamports)
            .unwrap_or(0),
        token_account_rent
    );
    assert_eq!(
        token_limit_remaining(&context, &swig_pubkey, 1, &mint),
        TOKEN_LIMIT_AMOUNT
    );
}

#[test_log::test]
fn sign_v2_rejects_token_account_close_without_permission_and_rolls_back_state() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let restricted_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();
    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(swig_pubkey.as_ref()),
        &program_id(),
    );
    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let token_account = setup_ata(
        &mut context.svm,
        &mint,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: restricted_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::Program(Program {
                program_id: spl_token::ID.to_bytes(),
            }),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint.to_bytes(),
                current_amount: TOKEN_LIMIT_AMOUNT,
            }),
        ],
    )
    .unwrap();

    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();
    let token_account_before = context.svm.get_account(&token_account).unwrap();
    let close_ix = spl_token::instruction::close_account(
        &spl_token::ID,
        &token_account,
        &destination.pubkey(),
        &swig_wallet_address,
        &[],
    )
    .unwrap();
    let sign_ix = SignV2Instruction::new_ed25519(
        swig_pubkey,
        swig_wallet_address,
        restricted_authority.pubkey(),
        close_ix,
        1,
    )
    .unwrap();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, &restricted_authority],
    )
    .unwrap();

    let error = context.svm.send_transaction(transaction).unwrap_err();
    assert_eq!(
        error.err,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(
                SwigAuthenticateError::PermissionDeniedMissingPermission as u32
            ),
        )
    );

    let token_account_after = context.svm.get_account(&token_account).unwrap();
    assert_eq!(token_account_after, token_account_before);
    assert_eq!(
        context
            .svm
            .get_account(&destination.pubkey())
            .map(|account| account.lamports)
            .unwrap_or(0),
        0
    );
    assert_eq!(
        token_limit_remaining(&context, &swig_pubkey, 1, &mint),
        TOKEN_LIMIT_AMOUNT
    );
}
