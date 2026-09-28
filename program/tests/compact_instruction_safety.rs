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
use swig::{actions::sign_v2::SignV2Args, error::SwigError};
use swig_compact_instructions::InstructionError as CompactInstructionError;
use swig_interface::SignV2Instruction;
use swig_state::{
    swig::{swig_account_seeds, swig_wallet_address_seeds},
    IntoBytes, Transmutable,
};

const TRANSFER_AMOUNT: u64 = 100_000;

struct Fixture {
    context: SwigTestContext,
    authority: Keypair,
    swig: Pubkey,
    wallet: Pubkey,
    recipient: Pubkey,
}

fn setup_fixture() -> Fixture {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let recipient = Keypair::new().pubkey();
    context
        .svm
        .airdrop(&authority.pubkey(), 20_000_000_000)
        .unwrap();
    context.svm.airdrop(&recipient, 1_000_000).unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;
    create_swig_ed25519(&mut context, &authority, id).unwrap();

    let fund =
        solana_system_interface::instruction::transfer(&authority.pubkey(), &wallet, 1_000_000_000);
    let message = v0::Message::try_compile(
        &authority.pubkey(),
        &[fund],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transaction =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&authority]).unwrap();
    context.svm.send_transaction(transaction).unwrap();

    Fixture {
        context,
        authority,
        swig,
        wallet,
        recipient,
    }
}

fn transfer_instruction(fixture: &Fixture) -> Instruction {
    let transfer = solana_system_interface::instruction::transfer(
        &fixture.wallet,
        &fixture.recipient,
        TRANSFER_AMOUNT,
    );
    SignV2Instruction::new_ed25519(
        fixture.swig,
        fixture.wallet,
        fixture.authority.pubkey(),
        transfer,
        0,
    )
    .unwrap()
}

fn send(fixture: &mut Fixture, instruction: Instruction) -> Result<u64, TransactionError> {
    let message = v0::Message::try_compile(
        &fixture.authority.pubkey(),
        &[instruction],
        &[],
        fixture.context.svm.latest_blockhash(),
    )
    .unwrap();
    let transaction =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&fixture.authority])
            .unwrap();
    fixture
        .context
        .svm
        .send_transaction(transaction)
        .map(|metadata| metadata.compute_units_consumed)
        .map_err(|metadata| metadata.err)
}

#[test_log::test]
fn compact_data_length_at_odd_offset_executes() {
    let mut fixture = setup_fixture();
    let instruction = transfer_instruction(&fixture);
    let compact_payload = &instruction.data[SignV2Args::LEN..instruction.data.len() - 1];

    assert_eq!(compact_payload[0], 1);
    assert_eq!(compact_payload[2], 2);
    let data_len_offset = 1 + 1 + 1 + compact_payload[2] as usize;
    assert_eq!(data_len_offset % 2, 1);

    let wallet_before = fixture.context.svm.get_balance(&fixture.wallet).unwrap();
    let recipient_before = fixture.context.svm.get_balance(&fixture.recipient).unwrap();
    send(&mut fixture, instruction).unwrap();

    assert_eq!(
        fixture.context.svm.get_balance(&fixture.wallet).unwrap(),
        wallet_before - TRANSFER_AMOUNT
    );
    assert_eq!(
        fixture.context.svm.get_balance(&fixture.recipient).unwrap(),
        recipient_before + TRANSFER_AMOUNT
    );
}

#[test_log::test]
fn compact_system_transfer_requires_two_accounts() {
    let mut fixture = setup_fixture();
    let mut instruction = transfer_instruction(&fixture);
    let payload_start = SignV2Args::LEN;
    let program_index = instruction.data[payload_start + 1];
    let from_index = instruction.data[payload_start + 3];
    let transfer_data = solana_system_interface::instruction::transfer(
        &fixture.wallet,
        &fixture.recipient,
        TRANSFER_AMOUNT,
    )
    .data;
    let mut compact_payload = vec![1, program_index, 1, from_index];
    compact_payload.extend((transfer_data.len() as u16).to_le_bytes());
    compact_payload.extend(transfer_data);
    let args = SignV2Args::new(0, compact_payload.len() as u16);
    instruction.data = [args.into_bytes().unwrap(), &compact_payload, &[2]].concat();

    let wallet_before = fixture.context.svm.get_balance(&fixture.wallet).unwrap();
    let recipient_before = fixture.context.svm.get_balance(&fixture.recipient).unwrap();
    let error = send(&mut fixture, instruction).unwrap_err();

    assert_eq!(
        error,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(CompactInstructionError::InvalidAccountCount as u32),
        )
    );
    assert_eq!(
        fixture.context.svm.get_balance(&fixture.wallet).unwrap(),
        wallet_before
    );
    assert_eq!(
        fixture.context.svm.get_balance(&fixture.recipient).unwrap(),
        recipient_before
    );
}

#[test_log::test]
fn compact_instruction_rejects_account_count_above_capacity() {
    let mut fixture = setup_fixture();
    let mut instruction = transfer_instruction(&fixture);
    let program_index = instruction.data[SignV2Args::LEN + 1];
    let mut compact_payload = vec![1, program_index, u8::MAX];
    compact_payload.extend([0; u8::MAX as usize]);
    compact_payload.extend(0u16.to_le_bytes());
    let args = SignV2Args::new(0, compact_payload.len() as u16);
    instruction.data = [args.into_bytes().unwrap(), &compact_payload, &[2]].concat();

    let wallet_before = fixture.context.svm.get_balance(&fixture.wallet).unwrap();
    let recipient_before = fixture.context.svm.get_balance(&fixture.recipient).unwrap();
    let error = send(&mut fixture, instruction).unwrap_err();

    assert_eq!(
        error,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(SwigError::InstructionExecutionError as u32),
        )
    );
    assert_eq!(
        fixture.context.svm.get_balance(&fixture.wallet).unwrap(),
        wallet_before
    );
    assert_eq!(
        fixture.context.svm.get_balance(&fixture.recipient).unwrap(),
        recipient_before
    );
}
