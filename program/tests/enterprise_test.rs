#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.

mod common;

use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use common::*;
use litesvm_token::spl_token::{self, instruction::TokenInstruction};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    sysvar::{clock::Clock, rent::Rent},
    transaction::VersionedTransaction,
};
use swig_enterprise_state::EnterpriseState;
use swig_interface::{
    AddAuthorityInstruction, AuthorityConfig, ClientAction, SignV2Instruction, UpdateAuthorityData,
    UpdateAuthorityInstruction,
};
use swig_state::{
    action::{sol_limit::SolLimit, sol_recurring_limit::SolRecurringLimit},
    authority::{secp256k1::Secp256k1Authority, AuthorityType},
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
};

#[test]
fn test_create_enterprise() {
    println!(
        "\n\nTesting create enterprise connected wallet ==========================================="
    );
    let mut context = setup_enterprise_test_context().unwrap();
    let authority = Keypair::new();
    println!("Creating enterprise account with swig entity as authority");
    let enterprise_account = create_enterprise_account(&mut context).unwrap();

    println!(
        "enterprise account created: {:?}",
        enterprise_account.to_bytes()
    );
    let enterprise_account_info = context.svm.get_account(&enterprise_account).unwrap();

    // will be replaced with SIA
    let id = rand::random::<[u8; 32]>();
    let swig_created = create_swig_enterprise(&mut context, &authority, enterprise_account, id);
    assert!(swig_created.is_ok(), "{:?}", swig_created.err());

    let (swig_key, bench) = swig_created.unwrap();
    println!("Create Enterprise CU {:?}", bench.compute_units_consumed);
    println!("logs: {}", bench.pretty_logs());

    let swig = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig.data).unwrap();
    let role = swig.get_role(0).unwrap().unwrap(); // Role ID 0 is the enterprise owner
    assert_eq!(role.position.authority_type, AuthorityType::Ed25519 as u16);

    println!(
        "user swig global role authority: {:?}",
        role.authority.identity()
    );
    let enterprise_account_info = context.svm.get_account(&enterprise_account).unwrap();
    use swig_enterprise_state::EnterpriseState;
    let enterprise_state = EnterpriseState::from_bytes(&enterprise_account_info.data).unwrap();
}

#[test]
fn test_create_enterprise_with_subscription_expired() {
    println!(
        "\n\nTesting create enterprise with subscription expired ==========================================="
    );
    let mut context = setup_enterprise_test_context().unwrap();
    let authority = Keypair::new();
    let enterprise_account = create_enterprise_account(&mut context).unwrap();

    let enterprise_account_info = context.svm.get_account(&enterprise_account).unwrap();

    let enterprise_state = EnterpriseState::from_bytes(&enterprise_account_info.data).unwrap();
    println!(
        "enterprise state:: subscription expiry slot: {:?}",
        enterprise_state.swig_editable_config.payment_slot_validity
    );

    // will be replaced with SIA
    let id = rand::random::<[u8; 32]>();

    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + 100);

    println!("current slot: {:?}", context.svm.get_sysvar::<Clock>().slot);

    println!("Attempting to create swig enterprise with subscription expired");
    let swig_created = create_swig_enterprise(&mut context, &authority, enterprise_account, id);
    assert!(swig_created.is_err(), "{:?}", swig_created.err());
    println!("swig created error {:?}", swig_created.err());
}

#[test]
fn test_create_enterprise_with_max_wallets_exceeded() {
    println!(
        "\n\nTesting create enterprise with max wallets exceeded ==========================================="
    );
    let mut context = setup_enterprise_test_context().unwrap();
    let authority = Keypair::new();
    let enterprise_account = create_enterprise_account(&mut context).unwrap();

    let enterprise_account_info = context.svm.get_account(&enterprise_account).unwrap();
    let enterprise_state = EnterpriseState::from_bytes(&enterprise_account_info.data).unwrap();

    println!(
        "enterprise state:: active wallets limit: {:?}",
        enterprise_state.swig_editable_config.active_wallets_limit
    );
    println!(
        "enterprise state:: current active wallets: {:?}",
        enterprise_state.generic_config.active_accounts
    );

    println!("Creating first wallet with enterprise");
    // will be replaced with SIA
    let id = rand::random::<[u8; 32]>();
    let swig_created = create_swig_enterprise(&mut context, &authority, enterprise_account, id);
    assert!(swig_created.is_ok(), "{:?}", swig_created.err());

    let enterprise_account_info = context.svm.get_account(&enterprise_account).unwrap();
    let enterprise_state = EnterpriseState::from_bytes(&enterprise_account_info.data).unwrap();

    println!(
        "enterprise state:: current active wallets: {:?}",
        enterprise_state.generic_config.active_accounts
    );

    println!("Creating second wallet with enterprise");
    // will be replaced with SIA
    let id = rand::random::<[u8; 32]>();
    let swig_created = create_swig_enterprise(&mut context, &authority, enterprise_account, id);
    assert!(swig_created.is_ok(), "{:?}", swig_created.err());

    let enterprise_account_info = context.svm.get_account(&enterprise_account).unwrap();
    let enterprise_state = EnterpriseState::from_bytes(&enterprise_account_info.data).unwrap();

    println!(
        "enterprise state:: current active wallets: {:?}",
        enterprise_state.generic_config.active_accounts
    );

    println!("Creating third wallet with enterprise, MUST FAIL");
    // will be replaced with SIA
    let id = rand::random::<[u8; 32]>();
    let swig_created = create_swig_enterprise(&mut context, &authority, enterprise_account, id);
    assert!(swig_created.is_err(), "{:?}", swig_created.err());
    println!("swig created error {:?}", swig_created.err());
}

#[test]
fn test_create_enterprise_with_sol_transfer() {
    println!(
        "\n\nTesting create enterprise with sol transfer (valid and invalid subscription) ==========================================="
    );
    let mut context = setup_enterprise_test_context().unwrap();
    let authority = Keypair::new();
    let enterprise_account = create_enterprise_account(&mut context).unwrap();

    let enterprise_account_info = context.svm.get_account(&enterprise_account).unwrap();

    // will be replaced with SIA
    let id = rand::random::<[u8; 32]>();
    let (swig, bench) =
        create_swig_enterprise(&mut context, &authority, enterprise_account, id).unwrap();

    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&authority.pubkey(), 10_000_000_000)
        .unwrap();

    let transfer_amount = 100_000_000u64; // 0.1 SOL - within limit
    let recipient = Keypair::new();
    let inner_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);
    let sol_transfer_ix = SignV2Instruction::new_ed25519_enterprise(
        swig,
        swig_wallet_address,
        authority.pubkey(),
        inner_ix,
        1, // role_id
        enterprise_account,
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &authority.pubkey(),
        &[sol_transfer_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    println!("enterprise account: {:?}", enterprise_account.to_bytes());
    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&authority])
            .unwrap();

    let res = context.svm.send_transaction(transfer_tx).unwrap();
    println!("Transfer logs: {}", res.pretty_logs());

    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + 100);

    context.svm.expire_blockhash();

    let transfer_amount = 100_000_000u64; // 0.1 SOL - within limit
    let recipient = Keypair::new();
    let inner_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);
    let sol_transfer_ix = SignV2Instruction::new_ed25519_enterprise(
        swig,
        swig_wallet_address,
        authority.pubkey(),
        inner_ix,
        1, // role_id
        enterprise_account,
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &authority.pubkey(),
        &[sol_transfer_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    println!("enterprise account: {:?}", enterprise_account.to_bytes());
    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&authority])
            .unwrap();

    let res = context.svm.send_transaction(transfer_tx);
    assert!(res.is_err(), "Transfer should fail");
    println!("Transfer error: {:?}", res.err());
}

#[test]
fn test_create_enterprise_add_authority() {
    println!(
        "\n\nTesting create enterprise and add authority connected wallet ==========================================="
    );
    let mut context = setup_enterprise_test_context().unwrap();
    let authority = Keypair::new();
    context
        .svm
        .airdrop(&authority.pubkey(), 10_000_000_000)
        .unwrap();
    let enterprise_account = create_enterprise_account(&mut context).unwrap();

    // will be replaced with SIA
    let id = rand::random::<[u8; 32]>();
    let swig_created = create_swig_enterprise(&mut context, &authority, enterprise_account, id);
    assert!(swig_created.is_ok(), "{:?}", swig_created.err());

    let (swig_key, bench) = swig_created.unwrap();

    let swig = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig.data).unwrap();
    let role = swig.get_role(0).unwrap().unwrap(); // Role ID 0 is the enterprise owner
    assert_eq!(role.position.authority_type, AuthorityType::Ed25519 as u16);

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    use crate::ClientAction::ProgramCurated;

    let program_curated_action = swig_state::action::program_curated::ProgramCurated::new();

    let add_authority_ix = AddAuthorityInstruction::new_with_ed25519_authority_enterprise(
        swig_key,
        authority.pubkey(),
        authority.pubkey(),
        1,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramCurated(program_curated_action),
            ClientAction::SolRecurringLimit(SolRecurringLimit {
                window: 100,
                recurring_amount: 100,
                current_amount: 100,
                last_reset: 0,
            }),
        ],
        enterprise_account,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &authority.pubkey(),
        &[add_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&authority]).unwrap();

    let res = context.svm.send_transaction(tx);
    assert!(res.is_err(), "Add authority should fail as we are adding sol recurring limit without enterprise having the permission");

    let program_curated_action = swig_state::action::program_curated::ProgramCurated::new();

    let add_authority_ix = AddAuthorityInstruction::new_with_ed25519_authority_enterprise(
        swig_key,
        authority.pubkey(),
        authority.pubkey(),
        1,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramCurated(program_curated_action),
            ClientAction::SolLimit(SolLimit {
                amount: 100_000_000,
            }),
        ],
        enterprise_account,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &authority.pubkey(),
        &[add_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&authority]).unwrap();

    let res = context.svm.send_transaction(tx);
    assert!(res.is_ok(), "Add authority should succeed");
}

#[test]
fn test_create_enterprise_update_authority() {
    println!(
        "\n\nTesting create enterprise and add authority connected wallet ==========================================="
    );
    let mut context = setup_enterprise_test_context().unwrap();
    let authority = Keypair::new();
    context
        .svm
        .airdrop(&authority.pubkey(), 10_000_000_000)
        .unwrap();
    let enterprise_account = create_enterprise_account(&mut context).unwrap();

    // will be replaced with SIA
    let id = rand::random::<[u8; 32]>();
    let swig_created = create_swig_enterprise(&mut context, &authority, enterprise_account, id);
    assert!(swig_created.is_ok(), "{:?}", swig_created.err());

    let (swig_key, bench) = swig_created.unwrap();

    let swig = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig.data).unwrap();
    let role = swig.get_role(0).unwrap().unwrap(); // Role ID 0 is the enterprise owner
    assert_eq!(role.position.authority_type, AuthorityType::Ed25519 as u16);

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    use crate::ClientAction::ProgramCurated;

    let program_curated_action = swig_state::action::program_curated::ProgramCurated::new();

    let add_authority_ix = AddAuthorityInstruction::new_with_ed25519_authority_enterprise(
        swig_key,
        authority.pubkey(),
        authority.pubkey(),
        1,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramCurated(program_curated_action),
            ClientAction::SolLimit(SolLimit {
                amount: 100_000_000,
            }),
        ],
        enterprise_account,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &authority.pubkey(),
        &[add_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&authority]).unwrap();

    let res = context.svm.send_transaction(tx);
    assert!(res.is_ok(), "Add authority should succeed");

    let update_authority_ix = UpdateAuthorityInstruction::new_with_ed25519_authority_enterprise(
        swig_key,
        authority.pubkey(),
        authority.pubkey(),
        1,
        2,
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::SolRecurringLimit(SolRecurringLimit {
            window: 100,
            recurring_amount: 100,
            current_amount: 100,
            last_reset: 0,
        })]),
        enterprise_account,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &authority.pubkey(),
        &[update_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&authority]).unwrap();

    let res = context.svm.send_transaction(tx);
    assert!(res.is_err(), "Update authority should fail as we are replacing sol limit without enterprise having the permission");

    let update_authority_ix = UpdateAuthorityInstruction::new_with_ed25519_authority_enterprise(
        swig_key,
        authority.pubkey(),
        authority.pubkey(),
        1,
        2,
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::SolLimit(SolLimit {
            amount: 100_000_000,
        })]),
        enterprise_account,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &authority.pubkey(),
        &[update_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&authority]).unwrap();

    let res = context.svm.send_transaction(tx);
    assert!(res.is_ok(), "Update authority should succeed");
    println!("Update authority logs: {}", res.unwrap().pretty_logs());
}
