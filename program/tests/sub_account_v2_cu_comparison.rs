#![cfg(not(feature = "program_scope_test"))]
//! Compute-unit comparison for the first and twentieth V2 sub-accounts owned
//! by one Ed25519 authority.

mod common;

use common::*;
use litesvm::types::TransactionMetadata;
use solana_sdk::{
    instruction::Instruction,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{
    AuthorityConfig, ClientAction, CreateSubAccountV2Instruction, SubAccountSignV2Instruction,
    ToggleSubAccountV2Instruction, WithdrawFromSubAccountV2Instruction,
};
use swig_state::{
    action::sub_account_v2::SubAccountV2Create,
    authority::AuthorityType,
    swig::{sub_account_v2_asset_seeds, sub_account_v2_state_seeds, swig_wallet_address_seeds},
};

const CREATOR_ROLE_ID: u32 = 1;
const LAST_SUBACCOUNT_ID: u32 = 19;

#[derive(Clone, Copy)]
struct SubAccountAddresses {
    state: Pubkey,
    asset: Pubkey,
}

#[derive(Clone, Copy)]
struct ComputeUnitPair {
    first: u64,
    last: u64,
}

#[test]
fn compare_ed25519_sub_account_v2_compute_units() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let creator = Keypair::new();
    context.svm.airdrop(&root.pubkey(), 10_000_000_000).unwrap();
    context
        .svm
        .airdrop(&creator.pubkey(), 10_000_000_000)
        .unwrap();

    let swig_id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, swig_id).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: creator.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccountV2Create(SubAccountV2Create)],
    )
    .unwrap();

    let mut first_addresses = None;
    let mut last_addresses = None;
    let mut create_first = None;
    let mut create_last = None;

    for subacc_id in 0..=LAST_SUBACCOUNT_ID {
        let addresses = sub_account_addresses(&swig_id, subacc_id);
        let state_bump = Pubkey::find_program_address(
            &sub_account_v2_state_seeds(&swig_id, &subacc_id.to_le_bytes()),
            &program_id(),
        )
        .1;
        let asset_bump = Pubkey::find_program_address(
            &sub_account_v2_asset_seeds(&swig_id, &subacc_id.to_le_bytes()),
            &program_id(),
        )
        .1;
        let create = CreateSubAccountV2Instruction::new_with_ed25519_authority(
            swig,
            creator.pubkey(),
            creator.pubkey(),
            addresses.state,
            addresses.asset,
            CREATOR_ROLE_ID,
            state_bump,
            asset_bump,
        )
        .unwrap();
        let consumed = send(&mut context, &creator, create).compute_units_consumed;
        context
            .svm
            .airdrop(&addresses.asset, 1_000_000_000)
            .unwrap();

        if subacc_id == 0 {
            first_addresses = Some(addresses);
            create_first = Some(consumed);
        } else if subacc_id == LAST_SUBACCOUNT_ID {
            last_addresses = Some(addresses);
            create_last = Some(consumed);
        }
    }

    let first_addresses = first_addresses.unwrap();
    let last_addresses = last_addresses.unwrap();
    let create = ComputeUnitPair {
        first: create_first.unwrap(),
        last: create_last.unwrap(),
    };

    let sign = ComputeUnitPair {
        first: send_sign(&mut context, &creator, swig, first_addresses, 0),
        last: send_sign(
            &mut context,
            &creator,
            swig,
            last_addresses,
            LAST_SUBACCOUNT_ID,
        ),
    };

    let swig_wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;
    let withdraw = ComputeUnitPair {
        first: send_withdraw(
            &mut context,
            &creator,
            swig,
            swig_wallet,
            first_addresses,
            0,
        ),
        last: send_withdraw(
            &mut context,
            &creator,
            swig,
            swig_wallet,
            last_addresses,
            LAST_SUBACCOUNT_ID,
        ),
    };

    let toggle = ComputeUnitPair {
        first: send_toggle(&mut context, &creator, swig, first_addresses.state, 0),
        last: send_toggle(
            &mut context,
            &creator,
            swig,
            last_addresses.state,
            LAST_SUBACCOUNT_ID,
        ),
    };

    println!("| **Ed25519 operation** | **Subaccount 0** | **Subaccount 19** | **Increase** |");
    println!("| --- | ---: | ---: | ---: |");
    print_row("Create", create);
    print_row("Sign", sign);
    print_row("Withdraw", withdraw);
    print_row("Toggle", toggle);
}

fn sub_account_addresses(swig_id: &[u8; 32], subacc_id: u32) -> SubAccountAddresses {
    let id = subacc_id.to_le_bytes();
    SubAccountAddresses {
        state: Pubkey::find_program_address(
            &sub_account_v2_state_seeds(swig_id, &id),
            &program_id(),
        )
        .0,
        asset: Pubkey::find_program_address(
            &sub_account_v2_asset_seeds(swig_id, &id),
            &program_id(),
        )
        .0,
    }
}

fn send(context: &mut SwigTestContext, payer: &Keypair, ix: Instruction) -> TransactionMetadata {
    context.svm.expire_blockhash();
    let message =
        v0::Message::try_compile(&payer.pubkey(), &[ix], &[], context.svm.latest_blockhash())
            .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[payer]).unwrap();
    context.svm.send_transaction(tx).unwrap()
}

fn send_sign(
    context: &mut SwigTestContext,
    creator: &Keypair,
    swig: Pubkey,
    addresses: SubAccountAddresses,
    subacc_id: u32,
) -> u64 {
    let recipient = Keypair::new();
    let transfer = solana_system_interface::instruction::transfer(
        &addresses.asset,
        &recipient.pubkey(),
        1_000,
    );
    let sign = SubAccountSignV2Instruction::new_with_ed25519_authority(
        swig,
        addresses.state,
        addresses.asset,
        creator.pubkey(),
        CREATOR_ROLE_ID,
        subacc_id,
        vec![transfer],
    )
    .unwrap();
    send(context, creator, sign).compute_units_consumed
}

fn send_withdraw(
    context: &mut SwigTestContext,
    creator: &Keypair,
    swig: Pubkey,
    swig_wallet: Pubkey,
    addresses: SubAccountAddresses,
    subacc_id: u32,
) -> u64 {
    let withdraw = WithdrawFromSubAccountV2Instruction::new_with_ed25519_authority(
        swig,
        creator.pubkey(),
        creator.pubkey(),
        addresses.state,
        addresses.asset,
        swig_wallet,
        CREATOR_ROLE_ID,
        subacc_id,
        1_000,
    )
    .unwrap();
    send(context, creator, withdraw).compute_units_consumed
}

fn send_toggle(
    context: &mut SwigTestContext,
    creator: &Keypair,
    swig: Pubkey,
    state: Pubkey,
    subacc_id: u32,
) -> u64 {
    let toggle = ToggleSubAccountV2Instruction::new_with_ed25519_authority(
        swig,
        creator.pubkey(),
        creator.pubkey(),
        state,
        CREATOR_ROLE_ID,
        subacc_id,
        false,
    )
    .unwrap();
    send(context, creator, toggle).compute_units_consumed
}

fn print_row(operation: &str, pair: ComputeUnitPair) {
    assert!(
        pair.last >= pair.first,
        "{operation} unexpectedly used fewer compute units for subaccount 19"
    );
    let increase = pair.last - pair.first;
    let percent = ((increase as f64 / pair.first as f64) * 100.0).round() as u64;
    println!(
        "| {operation} | {} CU | {} CU | +{} / {percent}% |",
        with_thousands_separator(pair.first),
        with_thousands_separator(pair.last),
        with_thousands_separator(increase),
    );
}

fn with_thousands_separator(value: u64) -> String {
    let digits = value.to_string();
    let mut formatted = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index != 0 && (digits.len() - index).is_multiple_of(3) {
            formatted.push(',');
        }
        formatted.push(digit);
    }
    formatted
}
