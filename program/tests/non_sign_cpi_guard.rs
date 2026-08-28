#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    signature::{Keypair, Signature},
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig::error::SwigError;
use swig_interface::{
    AuthorityConfig, ClientAction, CreateInstruction, SetRentClaimerV1Instruction,
};
use swig_state::{
    action::all::All,
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds, Swig},
    tail::rent_claimer,
};

const TEST_PROGRAM_ID: solana_sdk::pubkey::Pubkey =
    solana_sdk::pubkey!("BXAu5ZWHnGun2XZjUZ9nqwiZ5dNVmofPGYdMC4rx4qLV");
const TEST_PROGRAM_PATH: &str = "../target/deploy/test_program_authority.so";
const INVOKE_SWIG_NON_SIGN: [u8; 8] = *b"swigcpi1";
const PRODUCTION_ALLOWED_SIGNER: solana_sdk::pubkey::Pubkey =
    solana_sdk::pubkey!("X4o2kSLzqEQjnAzhq3L3BW92aawMV2n2F37EXd2GMpy");

fn deploy_test_program(context: &mut SwigTestContext) {
    let program_data = std::fs::read(TEST_PROGRAM_PATH)
        .expect("build test-program-authority with cargo build-sbf before running this test");
    context
        .svm
        .add_program(TEST_PROGRAM_ID, &program_data)
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

fn wrap_non_sign_cpi(inner_instruction: Instruction) -> Instruction {
    let mut accounts = Vec::with_capacity(inner_instruction.accounts.len() + 1);
    accounts.push(AccountMeta::new_readonly(program_id(), false));
    accounts.extend(inner_instruction.accounts);

    let mut data = Vec::with_capacity(INVOKE_SWIG_NON_SIGN.len() + inner_instruction.data.len());
    data.extend_from_slice(&INVOKE_SWIG_NON_SIGN);
    data.extend_from_slice(&inner_instruction.data);

    Instruction {
        program_id: TEST_PROGRAM_ID,
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
    let error = result.expect_err("inbound CPI without an allowlisted signer must fail");
    assert_eq!(
        error.err,
        TransactionError::InstructionError(0, InstructionError::Custom(SwigError::Cpi as u32),)
    );
}

fn setup_test_context_without_signature_verification() -> SwigTestContext {
    let SwigTestContext { svm, default_payer } = setup_test_context().unwrap();
    SwigTestContext {
        svm: svm.with_sigverify(false),
        default_payer,
    }
}

/// Sends a structurally valid transaction while skipping LiteSVM's
/// cryptographic signature verification. The message header still marks every
/// requested signer exactly as the Solana runtime would, which lets the program
/// boundary be tested against the production public key without its private
/// key.
fn send_instruction_without_signature_verification(
    context: &mut SwigTestContext,
    instruction: Instruction,
) -> Result<(), Box<litesvm::types::FailedTransactionMetadata>> {
    assert!(!context.svm.get_sigverify());
    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[instruction],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let signatures =
        vec![Signature::default(); usize::from(message.header().num_required_signatures)];
    context
        .svm
        .send_transaction(VersionedTransaction {
            signatures,
            message,
        })
        .map(|_| ())
        .map_err(Box::new)
}

#[test]
fn production_allowlisted_signer_is_on_curve() {
    assert!(PRODUCTION_ALLOWED_SIGNER.is_on_curve());
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
fn non_allowlisted_signer_cannot_cpi_into_create() {
    let mut context = setup_test_context().unwrap();
    deploy_test_program(&mut context);
    let (inner, swig, wallet) = create_instruction(context.default_payer.pubkey(), [2u8; 32]);
    let outer = wrap_non_sign_cpi(inner);

    assert_cpi_rejected(send_instruction(&mut context, outer, None));
    assert!(context.svm.get_account(&swig).is_none());
    assert!(context.svm.get_account(&wallet).is_none());
}

#[test_log::test]
fn allowlisted_key_without_signer_privilege_is_rejected() {
    let mut context = setup_test_context().unwrap();
    deploy_test_program(&mut context);
    context.svm.airdrop(&PRODUCTION_ALLOWED_SIGNER, 1).unwrap();
    let (mut inner, swig, wallet) = create_instruction(context.default_payer.pubkey(), [3u8; 32]);
    inner
        .accounts
        .push(AccountMeta::new_readonly(PRODUCTION_ALLOWED_SIGNER, false));
    let outer = wrap_non_sign_cpi(inner);

    assert_cpi_rejected(send_instruction(&mut context, outer, None));
    assert!(context.svm.get_account(&swig).is_none());
    assert!(context.svm.get_account(&wallet).is_none());
}

#[test_log::test]
fn allowlisted_signer_can_cpi_into_create() {
    let mut context = setup_test_context_without_signature_verification();
    deploy_test_program(&mut context);
    context
        .svm
        .airdrop(&PRODUCTION_ALLOWED_SIGNER, 10_000_000_000)
        .unwrap();
    let (inner, swig, wallet) = create_instruction(PRODUCTION_ALLOWED_SIGNER, [4u8; 32]);
    let outer = wrap_non_sign_cpi(inner);

    send_instruction_without_signature_verification(&mut context, outer).unwrap();
    assert!(context.svm.get_account(&swig).is_some());
    assert!(context.svm.get_account(&wallet).is_some());
}

#[test_log::test]
fn allowlisted_signer_can_cpi_into_another_non_sign_instruction() {
    let mut context = setup_test_context_without_signature_verification();
    deploy_test_program(&mut context);
    context
        .svm
        .airdrop(&PRODUCTION_ALLOWED_SIGNER, 10_000_000_000)
        .unwrap();
    let (create, swig, _) = create_instruction(PRODUCTION_ALLOWED_SIGNER, [5u8; 32]);
    send_instruction_without_signature_verification(&mut context, create).unwrap();
    let claimer = Keypair::new().pubkey();
    let inner = SetRentClaimerV1Instruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        PRODUCTION_ALLOWED_SIGNER,
        0,
        claimer.to_bytes(),
    )
    .unwrap();
    let outer = wrap_non_sign_cpi(inner);

    send_instruction_without_signature_verification(&mut context, outer).unwrap();

    let account = context.svm.get_account(&swig).unwrap();
    let parts = Swig::split_parts(&account.data).unwrap();
    assert_eq!(
        rent_claimer::read_strict(parts.tail).unwrap(),
        Some(&claimer.to_bytes())
    );
}
