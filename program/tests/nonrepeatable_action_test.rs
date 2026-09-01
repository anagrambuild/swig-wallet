#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use solana_sdk::{
    instruction::{Instruction, InstructionError},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{
    AddAuthorityInstruction, AuthorityConfig, ClientAction, CreateInstruction, UpdateAuthorityData,
    UpdateAuthorityInstruction,
};
use swig_state::{
    action::{
        all::All, manage_authority::ManageAuthority, sol_limit::SolLimit,
        sol_recurring_limit::SolRecurringLimit, token_limit::TokenLimit,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds},
    SwigStateError,
};

fn send_payer(
    context: &mut SwigTestContext,
    instruction: Instruction,
) -> Result<(), TransactionError> {
    context.svm.expire_blockhash();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[instruction],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[context.default_payer.insecure_clone()],
    )
    .unwrap();
    context
        .svm
        .send_transaction(transaction)
        .map(|_| ())
        .map_err(|error| error.err)
}

fn send_admin(
    context: &mut SwigTestContext,
    authority: &Keypair,
    instruction: Instruction,
) -> Result<(), TransactionError> {
    context.svm.expire_blockhash();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[instruction],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[
            context.default_payer.insecure_clone(),
            authority.insecure_clone(),
        ],
    )
    .unwrap();
    context
        .svm
        .send_transaction(transaction)
        .map(|_| ())
        .map_err(|error| error.err)
}

fn assert_duplicate_nonrepeatable(result: Result<(), TransactionError>) {
    assert_eq!(
        result,
        Err(TransactionError::InstructionError(
            0,
            InstructionError::Custom(SwigStateError::DuplicateNonRepeatableAction as u32),
        )),
    );
}

fn assert_swig_unchanged(
    context: &SwigTestContext,
    swig: &Pubkey,
    before_data: &[u8],
    before_lamports: u64,
) {
    let after = context.svm.get_account(swig).unwrap();
    assert_eq!(after.data, before_data);
    assert_eq!(after.lamports, before_lamports);
}

#[test]
fn create_rejects_duplicate_nonrepeatable_actions() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig, bump) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let (wallet, wallet_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let instruction = CreateInstruction::new(
        swig,
        bump,
        context.default_payer.pubkey(),
        wallet,
        wallet_bump,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: root.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {}), ClientAction::All(All {})],
        id,
    )
    .unwrap();

    assert_duplicate_nonrepeatable(send_payer(&mut context, instruction));
    assert!(context.svm.get_account(&swig).is_none());
}

#[test]
fn add_rejects_duplicate_nonrepeatable_actions_without_changing_the_swig() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random::<[u8; 32]>()).unwrap();
    let new_authority = Keypair::new();
    let before = context.svm.get_account(&swig).unwrap();
    let instruction = AddAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root.pubkey(),
        0,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::SolLimit(SolLimit { amount: 10 }),
            ClientAction::SolLimit(SolLimit { amount: 20 }),
        ],
    )
    .unwrap();

    assert_duplicate_nonrepeatable(send_admin(&mut context, &root, instruction));
    assert_swig_unchanged(&context, &swig, &before.data, before.lamports);

    let repeatable_authority = Keypair::new();
    let repeatable = AddAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root.pubkey(),
        0,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: repeatable_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::TokenLimit(TokenLimit {
                token_mint: [1; 32],
                current_amount: 10,
            }),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: [2; 32],
                current_amount: 20,
            }),
        ],
    )
    .unwrap();
    assert_eq!(send_admin(&mut context, &root, repeatable), Ok(()));

    let distinct_authority = Keypair::new();
    let distinct = AddAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root.pubkey(),
        0,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: distinct_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::SolLimit(SolLimit { amount: 10 }),
            ClientAction::SolRecurringLimit(SolRecurringLimit {
                recurring_amount: 20,
                window: 1,
                last_reset: 0,
                current_amount: 20,
            }),
        ],
    )
    .unwrap();
    assert_eq!(send_admin(&mut context, &root, distinct), Ok(()));
}

#[test]
fn update_rejects_duplicate_nonrepeatable_actions_for_replace_and_add() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random::<[u8; 32]>()).unwrap();
    let target = Keypair::new();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: target.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    let before_replace = context.svm.get_account(&swig).unwrap();
    let replace = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root.pubkey(),
        0,
        1,
        UpdateAuthorityData::ReplaceAll(vec![
            ClientAction::SolLimit(SolLimit { amount: 10 }),
            ClientAction::SolLimit(SolLimit { amount: 20 }),
        ]),
    )
    .unwrap();
    assert_duplicate_nonrepeatable(send_admin(&mut context, &root, replace));
    assert_swig_unchanged(
        &context,
        &swig,
        &before_replace.data,
        before_replace.lamports,
    );

    let replace_with_one = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root.pubkey(),
        0,
        1,
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::SolLimit(SolLimit { amount: 10 })]),
    )
    .unwrap();
    assert_eq!(send_admin(&mut context, &root, replace_with_one), Ok(()));

    let before_add = context.svm.get_account(&swig).unwrap();
    let add = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root.pubkey(),
        0,
        1,
        UpdateAuthorityData::AddActions(vec![ClientAction::SolLimit(SolLimit { amount: 20 })]),
    )
    .unwrap();
    assert_duplicate_nonrepeatable(send_admin(&mut context, &root, add));
    assert_swig_unchanged(&context, &swig, &before_add.data, before_add.lamports);
}
