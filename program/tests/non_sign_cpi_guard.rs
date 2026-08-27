#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    signature::Keypair,
    signer::Signer,
    sysvar::instructions,
    transaction::{TransactionError, VersionedTransaction},
};
use swig::error::SwigError;
use swig_interface::{
    AuthorityConfig, ClientAction, CreateInstruction, SetRentClaimerV1Instruction,
};
use swig_state::{
    action::all::All,
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds},
};

const TEST_PROGRAM_ID: solana_sdk::pubkey::Pubkey =
    solana_sdk::pubkey!("BXAu5ZWHnGun2XZjUZ9nqwiZ5dNVmofPGYdMC4rx4qLV");
const TEST_PROGRAM_PATH: &str = "../target/deploy/test_program_authority.so";
const ALLOWED_OUTER_PREFIX: [u8; 8] = *b"swigcpi1";
const BLOCKED_OUTER_PREFIX: [u8; 8] = *b"swigcpi2";

fn deploy_test_program(context: &mut SwigTestContext, program_id: solana_sdk::pubkey::Pubkey) {
    let program_data = std::fs::read(TEST_PROGRAM_PATH)
        .expect("build test-program-authority with cargo build-sbf before running this test");
    context
        .svm
        .add_program(program_id, &program_data)
        .expect("deploy test-program-authority");
}

fn create_instruction(
    payer: solana_sdk::pubkey::Pubkey,
    id: [u8; 32],
) -> (
    Instruction,
    solana_sdk::pubkey::Pubkey,
    solana_sdk::pubkey::Pubkey,
) {
    let (swig, swig_bump) =
        solana_sdk::pubkey::Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let (wallet, wallet_bump) = solana_sdk::pubkey::Pubkey::find_program_address(
        &swig_wallet_address_seeds(swig.as_ref()),
        &program_id(),
    );
    let instruction = CreateInstruction::new(
        swig,
        swig_bump,
        payer,
        wallet,
        wallet_bump,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: payer.as_ref(),
        },
        vec![ClientAction::All(All {})],
        id,
    )
    .unwrap();
    (instruction, swig, wallet)
}

fn wrap_non_sign_cpi(
    mut inner_instruction: Instruction,
    outer_program_id: solana_sdk::pubkey::Pubkey,
    outer_prefix: [u8; 8],
) -> Instruction {
    inner_instruction
        .accounts
        .push(AccountMeta::new_readonly(instructions::ID, false));

    let mut accounts = Vec::with_capacity(inner_instruction.accounts.len() + 1);
    accounts.push(AccountMeta::new_readonly(program_id(), false));
    accounts.extend(inner_instruction.accounts);

    let mut data = Vec::with_capacity(outer_prefix.len() + inner_instruction.data.len());
    data.extend_from_slice(&outer_prefix);
    data.extend_from_slice(&inner_instruction.data);

    Instruction {
        program_id: outer_program_id,
        accounts,
        data,
    }
}

fn send_instruction(
    context: &mut SwigTestContext,
    instruction: Instruction,
    additional_signer: Option<&Keypair>,
) -> Result<(), Box<litesvm::types::FailedTransactionMetadata>> {
    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[instruction],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let transaction = match additional_signer {
        Some(signer) => {
            VersionedTransaction::try_new(message, &[&context.default_payer, signer]).unwrap()
        },
        None => VersionedTransaction::try_new(message, &[&context.default_payer]).unwrap(),
    };
    context
        .svm
        .send_transaction(transaction)
        .map(|_| ())
        .map_err(Box::new)
}

fn assert_cpi_rejected(result: Result<(), Box<litesvm::types::FailedTransactionMetadata>>) {
    let error = result.expect_err("non-allowlisted inbound CPI must fail");
    assert_eq!(
        error.err,
        TransactionError::InstructionError(0, InstructionError::Custom(SwigError::Cpi as u32),)
    );
}

#[test_log::test]
fn direct_non_sign_instruction_remains_allowed() {
    let mut context = setup_test_context().unwrap();
    let (_, swig, wallet) = create_instruction(context.default_payer.pubkey(), [1u8; 32]);
    let payer = context.default_payer.insecure_clone();

    create_swig_ed25519(&mut context, &payer, [1u8; 32]).unwrap();

    assert!(context.svm.get_account(&swig).is_some());
    assert!(context.svm.get_account(&wallet).is_some());
}

#[test_log::test]
fn non_allowlisted_outer_instruction_cannot_cpi_into_create() {
    let mut context = setup_test_context().unwrap();
    deploy_test_program(&mut context, TEST_PROGRAM_ID);
    let (inner, swig, wallet) = create_instruction(context.default_payer.pubkey(), [2u8; 32]);
    let outer = wrap_non_sign_cpi(inner, TEST_PROGRAM_ID, BLOCKED_OUTER_PREFIX);

    assert_cpi_rejected(send_instruction(&mut context, outer, None));
    assert!(context.svm.get_account(&swig).is_none());
    assert!(context.svm.get_account(&wallet).is_none());
}

#[cfg(feature = "test_inbound_cpi_allowlist")]
#[test_log::test]
fn exact_allowlisted_outer_and_inner_instruction_can_cpi() {
    let mut context = setup_test_context().unwrap();
    deploy_test_program(&mut context, TEST_PROGRAM_ID);
    let (inner, swig, wallet) = create_instruction(context.default_payer.pubkey(), [3u8; 32]);
    let outer = wrap_non_sign_cpi(inner, TEST_PROGRAM_ID, ALLOWED_OUTER_PREFIX);

    send_instruction(&mut context, outer, None).unwrap();
    assert!(context.svm.get_account(&swig).is_some());
    assert!(context.svm.get_account(&wallet).is_some());
}

#[cfg(feature = "test_inbound_cpi_allowlist")]
#[test_log::test]
fn allowlisted_prefix_from_another_program_is_rejected() {
    let mut context = setup_test_context().unwrap();
    let other_program_id = solana_sdk::pubkey::Pubkey::new_unique();
    deploy_test_program(&mut context, other_program_id);
    let (inner, swig, wallet) = create_instruction(context.default_payer.pubkey(), [4u8; 32]);
    let outer = wrap_non_sign_cpi(inner, other_program_id, ALLOWED_OUTER_PREFIX);

    assert_cpi_rejected(send_instruction(&mut context, outer, None));
    assert!(context.svm.get_account(&swig).is_none());
    assert!(context.svm.get_account(&wallet).is_none());
}

#[cfg(feature = "test_inbound_cpi_allowlist")]
#[test_log::test]
fn allowlisted_outer_instruction_cannot_invoke_another_swig_instruction() {
    let mut context = setup_test_context().unwrap();
    deploy_test_program(&mut context, TEST_PROGRAM_ID);
    let root = Keypair::new();
    let (swig, _) = create_swig_ed25519(&mut context, &root, [5u8; 32]).unwrap();
    let before = context.svm.get_account(&swig).unwrap();
    let inner = SetRentClaimerV1Instruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        root.pubkey(),
        0,
        Keypair::new().pubkey().to_bytes(),
    )
    .unwrap();
    let outer = wrap_non_sign_cpi(inner, TEST_PROGRAM_ID, ALLOWED_OUTER_PREFIX);

    assert_cpi_rejected(send_instruction(&mut context, outer, Some(&root)));
    assert_eq!(context.svm.get_account(&swig).unwrap(), before);
}
