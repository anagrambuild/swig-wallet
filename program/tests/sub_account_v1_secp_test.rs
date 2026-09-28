#![cfg(not(feature = "program_scope_test"))]

mod common;

use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use common::*;
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    nid::Nid,
    pkey::Private,
};
use solana_sdk::{
    clock::Clock,
    instruction::Instruction,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig::actions::{
    create_sub_account_v1::CreateSubAccountV1Args, sub_account_sign_v1::SubAccountSignV1Args,
    toggle_sub_account_v1::ToggleSubAccountV1Args, transfer_assets_v1::TransferAssetsV1Args,
    withdraw_from_sub_account_v1::WithdrawFromSubAccountV1Args,
};
use swig_interface::{
    AuthorityConfig, ClientAction, CreateInstruction, CreateSubAccountInstruction,
    SubAccountSignInstruction, ToggleSubAccountInstruction, TransferAssetsV1Instruction,
    WithdrawFromSubAccountInstruction,
};
use swig_state::{
    action::{all::All, sub_account::SubAccount},
    authority::{secp256k1::Secp256k1Authority, secp256r1::Secp256r1Authority, AuthorityType},
    swig::{sub_account_seeds, swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
    Transmutable,
};

const ROOT_ROLE_ID: u32 = 0;
const SECP256K1_AUTHORITY_PAYLOAD_LEN: usize = 77;
const SECP256R1_AUTHORITY_PAYLOAD_LEN: usize = 17;

fn secp256k1_signer(wallet: &PrivateKeySigner) -> impl FnMut(&[u8]) -> [u8; 65] + '_ {
    move |payload: &[u8]| {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(payload);
        wallet.sign_hash_sync(&B256::from(hash)).unwrap().as_bytes()
    }
}

fn secp256r1_signer(signing_key: &EcKey<Private>) -> impl FnMut(&[u8]) -> [u8; 64] + '_ {
    move |message_hash: &[u8]| {
        solana_secp256r1_program::sign_message(
            message_hash,
            &signing_key.private_key_to_der().unwrap(),
        )
        .unwrap()
    }
}

fn secp256r1_key() -> (EcKey<Private>, [u8; 33]) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let signing_key = EcKey::generate(&group).unwrap();
    let mut key_context = BigNumContext::new().unwrap();
    let public_key = signing_key
        .public_key()
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut key_context)
        .unwrap()
        .try_into()
        .unwrap();
    (signing_key, public_key)
}

fn assert_secp256k1_payload(
    instruction: &Instruction,
    payload_offset: usize,
    current_slot: u64,
    counter: u32,
) {
    let payload = &instruction.data[payload_offset..];
    assert_eq!(payload.len(), SECP256K1_AUTHORITY_PAYLOAD_LEN);
    assert_eq!(&payload[..8], &current_slot.to_le_bytes());
    assert_eq!(&payload[8..12], &counter.to_le_bytes());
}

fn assert_secp256r1_payload(
    instructions: &[Instruction],
    payload_offset: usize,
    current_slot: u64,
    counter: u32,
) {
    assert_eq!(instructions.len(), 2);
    let instruction = &instructions[1];
    let payload = &instruction.data[payload_offset..];
    let instructions_sysvar_index = instruction
        .accounts
        .iter()
        .position(|account| account.pubkey == solana_sdk::sysvar::instructions::ID)
        .unwrap();

    assert_eq!(payload.len(), SECP256R1_AUTHORITY_PAYLOAD_LEN);
    assert_eq!(&payload[..8], &current_slot.to_le_bytes());
    assert_eq!(&payload[8..12], &counter.to_le_bytes());
    assert_eq!(usize::from(payload[12]), instructions_sysvar_index);
    assert_eq!(&payload[13..], &[0u8; 4]);
}

fn sub_account_sign_payload_offset(instruction: &Instruction) -> usize {
    let args = unsafe {
        SubAccountSignV1Args::load_unchecked(&instruction.data[..SubAccountSignV1Args::LEN])
            .unwrap()
    };
    SubAccountSignV1Args::LEN + usize::from(args.instruction_payload_len)
}

fn send(context: &mut SwigTestContext, instructions: Vec<Instruction>) -> anyhow::Result<()> {
    let payer = context.default_payer.pubkey();
    let message =
        v0::Message::try_compile(&payer, &instructions, &[], context.svm.latest_blockhash())?;
    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[context.default_payer.insecure_clone()],
    )?;
    context
        .svm
        .send_transaction(transaction)
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("transaction failed: {error:?}"))
}

fn create_swig(
    context: &mut SwigTestContext,
    id: [u8; 32],
    authority_type: AuthorityType,
    authority: &[u8],
) -> anyhow::Result<Pubkey> {
    let payer = context.default_payer.pubkey();
    let (swig, bump) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let (wallet_address, wallet_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let instruction = CreateInstruction::new(
        swig,
        bump,
        payer,
        wallet_address,
        wallet_bump,
        AuthorityConfig {
            authority_type,
            authority,
        },
        vec![
            ClientAction::All(All {}),
            ClientAction::SubAccount(SubAccount::new_for_creation()),
        ],
        id,
    )?;
    send(context, vec![instruction])?;
    Ok(swig)
}

fn secp256k1_odometer(context: &SwigTestContext, swig: &Pubkey) -> u32 {
    let data = context.svm.get_account(swig).unwrap().data;
    let swig = SwigWithRoles::from_bytes(&data).unwrap();
    let role = swig.get_role(ROOT_ROLE_ID).unwrap().unwrap();
    role.authority
        .as_any()
        .downcast_ref::<Secp256k1Authority>()
        .unwrap()
        .signature_odometer
}

fn secp256r1_odometer(context: &SwigTestContext, swig: &Pubkey) -> u32 {
    let data = context.svm.get_account(swig).unwrap().data;
    let swig = SwigWithRoles::from_bytes(&data).unwrap();
    let role = swig.get_role(ROOT_ROLE_ID).unwrap().unwrap();
    role.authority
        .as_any()
        .downcast_ref::<Secp256r1Authority>()
        .unwrap()
        .signature_odometer
}

#[test_log::test]
fn test_secp256k1_create_sub_account_v1_builder() {
    let mut context = setup_test_context().unwrap();
    context.svm.warp_to_slot(10);
    let wallet = LocalSigner::random();
    let encoded_key = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();
    let authority = &encoded_key[1..];
    let id = rand::random::<[u8; 32]>();
    let swig = create_swig(&mut context, id, AuthorityType::Secp256k1, authority).unwrap();
    let (sub_account, bump) = Pubkey::find_program_address(
        &sub_account_seeds(&id, &ROOT_ROLE_ID.to_le_bytes()),
        &program_id(),
    );
    let signer = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(payload);
        wallet.sign_hash_sync(&B256::from(hash)).unwrap().as_bytes()
    };
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let counter = secp256k1_odometer(&context, &swig) + 1;
    let instruction = CreateSubAccountInstruction::new_with_secp256k1_authority(
        swig,
        context.default_payer.pubkey(),
        signer,
        current_slot,
        counter,
        sub_account,
        ROOT_ROLE_ID,
        bump,
    )
    .unwrap();

    assert_eq!(instruction.data.len(), CreateSubAccountV1Args::LEN + 77);
    assert_eq!(
        &instruction.data[CreateSubAccountV1Args::LEN + 8..CreateSubAccountV1Args::LEN + 12],
        &counter.to_le_bytes()
    );
    send(&mut context, vec![instruction]).unwrap();

    assert!(context.svm.get_account(&sub_account).is_some());
    assert_eq!(secp256k1_odometer(&context, &swig), counter);
}

#[test_log::test]
fn test_secp256r1_create_sub_account_v1_builder() {
    let mut context = setup_test_context().unwrap();
    context.svm.warp_to_slot(10);
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let signing_key = EcKey::generate(&group).unwrap();
    let mut key_context = BigNumContext::new().unwrap();
    let public_key: [u8; 33] = signing_key
        .public_key()
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut key_context)
        .unwrap()
        .try_into()
        .unwrap();
    let id = rand::random::<[u8; 32]>();
    let swig = create_swig(&mut context, id, AuthorityType::Secp256r1, &public_key).unwrap();
    let (sub_account, bump) = Pubkey::find_program_address(
        &sub_account_seeds(&id, &ROOT_ROLE_ID.to_le_bytes()),
        &program_id(),
    );
    let signer = |message_hash: &[u8]| -> [u8; 64] {
        solana_secp256r1_program::sign_message(
            message_hash,
            &signing_key.private_key_to_der().unwrap(),
        )
        .unwrap()
    };
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let counter = secp256r1_odometer(&context, &swig) + 1;
    let instructions = CreateSubAccountInstruction::new_with_secp256r1_authority(
        swig,
        context.default_payer.pubkey(),
        signer,
        current_slot,
        counter,
        sub_account,
        ROOT_ROLE_ID,
        bump,
        &public_key,
    )
    .unwrap();
    let instruction = &instructions[1];
    let authority_payload = &instruction.data[CreateSubAccountV1Args::LEN..];

    assert_eq!(authority_payload.len(), 17);
    assert_eq!(&authority_payload[13..], &[0u8; 4]);
    send(&mut context, instructions).unwrap();

    assert!(context.svm.get_account(&sub_account).is_some());
    assert_eq!(secp256r1_odometer(&context, &swig), counter);
}

#[test]
fn test_v1_secp_authority_builder_matrix() {
    let current_slot = 42;
    let counter = 7;
    let role_id = ROOT_ROLE_ID;
    let swig = Pubkey::new_unique();
    let payer = Pubkey::new_unique();
    let sub_account = Pubkey::new_unique();
    let swig_wallet_address = Pubkey::new_unique();
    let sub_account_token = Pubkey::new_unique();
    let swig_token = Pubkey::new_unique();
    let token_program = Pubkey::new_unique();
    let recipient = Pubkey::new_unique();
    let wallet = LocalSigner::random();
    let (signing_key, public_key) = secp256r1_key();
    let inner_instruction =
        solana_system_interface::instruction::transfer(&sub_account, &recipient, 1);

    let create_k1 = CreateSubAccountInstruction::new_with_secp256k1_authority(
        swig,
        payer,
        secp256k1_signer(&wallet),
        current_slot,
        counter,
        sub_account,
        role_id,
        1,
    )
    .unwrap();
    assert_secp256k1_payload(
        &create_k1,
        CreateSubAccountV1Args::LEN,
        current_slot,
        counter,
    );

    let withdraw_sol_k1 = WithdrawFromSubAccountInstruction::new_with_secp256k1_authority(
        swig,
        payer,
        secp256k1_signer(&wallet),
        current_slot,
        counter,
        sub_account,
        swig_wallet_address,
        role_id,
        1,
    )
    .unwrap();
    assert_secp256k1_payload(
        &withdraw_sol_k1,
        WithdrawFromSubAccountV1Args::LEN,
        current_slot,
        counter,
    );

    let withdraw_token_k1 = WithdrawFromSubAccountInstruction::new_token_with_secp256k1_authority(
        swig,
        payer,
        secp256k1_signer(&wallet),
        current_slot,
        counter,
        sub_account,
        swig_wallet_address,
        sub_account_token,
        swig_token,
        token_program,
        role_id,
        1,
    )
    .unwrap();
    assert_secp256k1_payload(
        &withdraw_token_k1,
        WithdrawFromSubAccountV1Args::LEN,
        current_slot,
        counter,
    );

    let sign_k1 = SubAccountSignInstruction::new_with_secp256k1_authority(
        swig,
        sub_account,
        secp256k1_signer(&wallet),
        current_slot,
        counter,
        role_id,
        vec![inner_instruction.clone()],
    )
    .unwrap();
    let sign_k1_payload_offset = sub_account_sign_payload_offset(&sign_k1);
    assert_secp256k1_payload(&sign_k1, sign_k1_payload_offset, current_slot, counter);

    let toggle_k1 = ToggleSubAccountInstruction::new_with_secp256k1_authority(
        swig,
        payer,
        secp256k1_signer(&wallet),
        current_slot,
        counter,
        sub_account,
        role_id,
        role_id,
        true,
    )
    .unwrap();
    assert_secp256k1_payload(
        &toggle_k1,
        ToggleSubAccountV1Args::LEN,
        current_slot,
        counter,
    );

    let transfer_k1 = TransferAssetsV1Instruction::new_with_secp256k1_authority(
        swig,
        swig_wallet_address,
        payer,
        secp256k1_signer(&wallet),
        current_slot,
        counter,
        role_id,
    )
    .unwrap();
    assert_secp256k1_payload(
        &transfer_k1,
        TransferAssetsV1Args::LEN,
        current_slot,
        counter,
    );

    let create_r1 = CreateSubAccountInstruction::new_with_secp256r1_authority(
        swig,
        payer,
        secp256r1_signer(&signing_key),
        current_slot,
        counter,
        sub_account,
        role_id,
        1,
        &public_key,
    )
    .unwrap();
    assert_secp256r1_payload(
        &create_r1,
        CreateSubAccountV1Args::LEN,
        current_slot,
        counter,
    );

    let withdraw_sol_r1 = WithdrawFromSubAccountInstruction::new_with_secp256r1_authority(
        swig,
        payer,
        secp256r1_signer(&signing_key),
        current_slot,
        counter,
        sub_account,
        swig_wallet_address,
        role_id,
        1,
        &public_key,
    )
    .unwrap();
    assert_secp256r1_payload(
        &withdraw_sol_r1,
        WithdrawFromSubAccountV1Args::LEN,
        current_slot,
        counter,
    );

    let withdraw_token_r1 = WithdrawFromSubAccountInstruction::new_token_with_secp256r1_authority(
        swig,
        payer,
        secp256r1_signer(&signing_key),
        current_slot,
        counter,
        sub_account,
        swig_wallet_address,
        sub_account_token,
        swig_token,
        token_program,
        role_id,
        1,
        &public_key,
    )
    .unwrap();
    assert_secp256r1_payload(
        &withdraw_token_r1,
        WithdrawFromSubAccountV1Args::LEN,
        current_slot,
        counter,
    );

    let sign_r1 = SubAccountSignInstruction::new_with_secp256r1_authority(
        swig,
        sub_account,
        secp256r1_signer(&signing_key),
        current_slot,
        counter,
        role_id,
        vec![inner_instruction],
        &public_key,
    )
    .unwrap();
    let sign_r1_payload_offset = sub_account_sign_payload_offset(&sign_r1[1]);
    assert_secp256r1_payload(&sign_r1, sign_r1_payload_offset, current_slot, counter);

    let toggle_r1 = ToggleSubAccountInstruction::new_with_secp256r1_authority(
        swig,
        payer,
        secp256r1_signer(&signing_key),
        current_slot,
        counter,
        sub_account,
        role_id,
        role_id,
        true,
        &public_key,
    )
    .unwrap();
    assert_secp256r1_payload(
        &toggle_r1,
        ToggleSubAccountV1Args::LEN,
        current_slot,
        counter,
    );

    let transfer_r1 = TransferAssetsV1Instruction::new_with_secp256r1_authority(
        swig,
        swig_wallet_address,
        payer,
        secp256r1_signer(&signing_key),
        current_slot,
        counter,
        role_id,
        &public_key,
    )
    .unwrap();
    assert_secp256r1_payload(
        &transfer_r1,
        TransferAssetsV1Args::LEN,
        current_slot,
        counter,
    );
}
