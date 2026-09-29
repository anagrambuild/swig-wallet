#![cfg(not(feature = "program_scope_test"))]
//! Authority isolation: keep outer signer forwarding (ATA create, protocols)
//! but revert if the Ed25519 authority's personal SOL is drained to a wallet
//! or their existing ATAs lose tokens / change owner.

mod common;

use common::*;
use litesvm_token::spl_token::{self, instruction::TokenInstruction};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    rent::Rent,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig::{actions::sign_v2::SignV2Args, error::SwigError};
use swig_interface::{
    compact_instructions, AuthorityConfig, ClientAction, SignV2Instruction,
    SubAccountSignInstruction,
};
use swig_state::{
    action::{sol_limit::SolLimit, sub_account::SubAccount},
    authority::AuthorityType,
    swig::swig_wallet_address_seeds,
    IntoBytes,
};

const PERSONAL_TOKEN_BALANCE: u64 = 1_000;
const STOLEN_AMOUNT: u64 = 400;

fn isolation_error() -> TransactionError {
    TransactionError::InstructionError(
        0,
        InstructionError::Custom(SwigError::PermissionDeniedAuthorityExternalAssetChange as u32),
    )
}

fn token_amount(context: &Context, token_account: &Pubkey) -> u64 {
    let account = context.svm.get_account(token_account).unwrap();
    spl_token::state::Account::unpack(&account.data)
        .unwrap()
        .amount
}

fn drain_alice_personal_ata_via_sign_v2(
    context: &mut Context,
    swig: Pubkey,
    swig_wallet_address: Pubkey,
    alice: &Keypair,
    role_id: u32,
) {
    let attacker = Keypair::new();
    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let alice_ata = setup_ata(
        &mut context.svm,
        &mint,
        &alice.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    let attacker_ata = setup_ata(
        &mut context.svm,
        &mint,
        &attacker.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint,
        &context.default_payer,
        &alice_ata,
        PERSONAL_TOKEN_BALANCE,
    )
    .unwrap();

    let inner_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(alice_ata, false),
            AccountMeta::new(attacker_ata, false),
            AccountMeta::new_readonly(alice.pubkey(), true),
        ],
        data: TokenInstruction::Transfer {
            amount: STOLEN_AMOUNT,
        }
        .pack(),
    };
    let sign_v2_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        alice.pubkey(),
        inner_ix,
        role_id,
    )
    .unwrap();
    let message = v0::Message::try_compile(
        &alice.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[alice]).unwrap();
    let err = context.svm.send_transaction(tx).unwrap_err();
    assert_eq!(err.err, isolation_error());
    assert_eq!(token_amount(context, &alice_ata), PERSONAL_TOKEN_BALANCE);
    assert_eq!(token_amount(context, &attacker_ata), 0);
}

#[test_log::test]
fn sign_v2_blocks_ed25519_root_personal_token_drain() {
    let mut context = setup_test_context().unwrap();
    let alice = Keypair::new();
    context
        .svm
        .airdrop(&alice.pubkey(), 10_000_000_000)
        .unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &alice, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    drain_alice_personal_ata_via_sign_v2(&mut context, swig, swig_wallet_address, &alice, 0);
}

#[test_log::test]
fn sign_v2_blocks_limited_role_personal_token_drain() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let alice = Keypair::new();
    context.svm.airdrop(&root.pubkey(), 10_000_000_000).unwrap();
    context
        .svm
        .airdrop(&alice.pubkey(), 10_000_000_000)
        .unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: alice.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1_000_000 })],
    )
    .unwrap();

    drain_alice_personal_ata_via_sign_v2(&mut context, swig, swig_wallet_address, &alice, 1);
}

#[test_log::test]
fn sign_v2_blocks_inner_approve_of_alice_personal_token_account() {
    let mut context = setup_test_context().unwrap();
    let alice = Keypair::new();
    let attacker = Keypair::new();
    context
        .svm
        .airdrop(&alice.pubkey(), 10_000_000_000)
        .unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &alice, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let alice_ata = setup_ata(
        &mut context.svm,
        &mint,
        &alice.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint,
        &context.default_payer,
        &alice_ata,
        PERSONAL_TOKEN_BALANCE,
    )
    .unwrap();

    let inner_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(alice_ata, false),
            AccountMeta::new_readonly(attacker.pubkey(), false),
            AccountMeta::new_readonly(alice.pubkey(), true),
        ],
        data: TokenInstruction::Approve {
            amount: STOLEN_AMOUNT,
        }
        .pack(),
    };
    let sign_v2_ix =
        SignV2Instruction::new_ed25519(swig, swig_wallet_address, alice.pubkey(), inner_ix, 0)
            .unwrap();
    let message = v0::Message::try_compile(
        &alice.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&alice]).unwrap();
    let err = context.svm.send_transaction(tx).unwrap_err();
    assert_eq!(err.err, isolation_error());
    let account = context.svm.get_account(&alice_ata).unwrap();
    let token = spl_token::state::Account::unpack(&account.data).unwrap();
    assert_eq!(token.amount, PERSONAL_TOKEN_BALANCE);
    assert_eq!(token.delegated_amount, 0);
}

fn setup_alice_mint_and_swig(context: &mut Context, alice: &Keypair) -> (Pubkey, Pubkey, Pubkey) {
    context
        .svm
        .airdrop(&alice.pubkey(), 10_000_000_000)
        .unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(context, alice, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let mint = litesvm_token::CreateMint::new(&mut context.svm, alice)
        .decimals(9)
        .token_program_id(&spl_token::ID)
        .send()
        .unwrap();
    (swig, swig_wallet_address, mint)
}

#[test_log::test]
fn sign_v2_blocks_inner_mint_to_from_alice_mint() {
    let mut context = setup_test_context().unwrap();
    let alice = Keypair::new();
    let attacker = Keypair::new();
    let (swig, swig_wallet_address, mint) = setup_alice_mint_and_swig(&mut context, &alice);
    let attacker_ata = setup_ata(
        &mut context.svm,
        &mint,
        &attacker.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    let inner_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(mint, false),
            AccountMeta::new(attacker_ata, false),
            AccountMeta::new_readonly(alice.pubkey(), true),
        ],
        data: TokenInstruction::MintTo { amount: 1_000 }.pack(),
    };
    let sign_v2_ix =
        SignV2Instruction::new_ed25519(swig, swig_wallet_address, alice.pubkey(), inner_ix, 0)
            .unwrap();
    let message = v0::Message::try_compile(
        &alice.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&alice]).unwrap();
    let err = context.svm.send_transaction(tx).unwrap_err();
    assert_eq!(err.err, isolation_error());
    assert_eq!(token_amount(&context, &attacker_ata), 0);
}

#[test_log::test]
fn sign_v2_blocks_inner_set_authority_on_alice_mint() {
    let mut context = setup_test_context().unwrap();
    let alice = Keypair::new();
    let attacker = Keypair::new();
    let (swig, swig_wallet_address, mint) = setup_alice_mint_and_swig(&mut context, &alice);
    let inner_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(mint, false),
            AccountMeta::new_readonly(alice.pubkey(), true),
        ],
        data: TokenInstruction::SetAuthority {
            authority_type: spl_token::instruction::AuthorityType::MintTokens,
            new_authority: Some(attacker.pubkey()).into(),
        }
        .pack(),
    };
    let sign_v2_ix =
        SignV2Instruction::new_ed25519(swig, swig_wallet_address, alice.pubkey(), inner_ix, 0)
            .unwrap();
    let message = v0::Message::try_compile(
        &alice.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&alice]).unwrap();
    let err = context.svm.send_transaction(tx).unwrap_err();
    assert_eq!(err.err, isolation_error());
}

#[test_log::test]
fn sign_v2_blocks_inner_system_transfer_from_alice() {
    let mut context = setup_test_context().unwrap();
    let alice = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&alice.pubkey(), 10_000_000_000)
        .unwrap();
    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &alice, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let amount = 500_000_000;
    let inner_ix = solana_system_interface::instruction::transfer(
        &alice.pubkey(),
        &recipient.pubkey(),
        amount,
    );
    let sign_v2_ix =
        SignV2Instruction::new_ed25519(swig, swig_wallet_address, alice.pubkey(), inner_ix, 0)
            .unwrap();
    let message = v0::Message::try_compile(
        &alice.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&alice]).unwrap();
    let err = context.svm.send_transaction(tx).unwrap_err();
    assert_eq!(err.err, isolation_error());
    assert_eq!(
        context
            .svm
            .get_account(&recipient.pubkey())
            .unwrap()
            .lamports,
        1_000_000
    );
}

#[test_log::test]
fn sign_v2_blocks_inner_sol_deposit_into_wallet_pda() {
    let mut context = setup_test_context().unwrap();
    let alice = Keypair::new();
    context
        .svm
        .airdrop(&alice.pubkey(), 10_000_000_000)
        .unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &alice, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let wallet_before = context.svm.get_balance(&swig_wallet_address).unwrap();

    let amount = 500_000_000;
    let inner_ix = solana_system_interface::instruction::transfer(
        &alice.pubkey(),
        &swig_wallet_address,
        amount,
    );
    let sign_v2_ix =
        SignV2Instruction::new_ed25519(swig, swig_wallet_address, alice.pubkey(), inner_ix, 0)
            .unwrap();
    let message = v0::Message::try_compile(
        &alice.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&alice]).unwrap();
    let err = context.svm.send_transaction(tx).unwrap_err();
    assert_eq!(err.err, isolation_error());
    assert_eq!(
        context.svm.get_balance(&swig_wallet_address).unwrap(),
        wallet_before
    );
}

#[test_log::test]
fn sign_v2_blocks_inner_system_transfer_from_distinct_fee_payer() {
    let mut context = setup_test_context().unwrap();
    let alice = Keypair::new();
    let fee_payer = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&alice.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&fee_payer.pubkey(), 10_000_000_000)
        .unwrap();
    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &alice, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let amount = 500_000_000;
    let inner_ix = solana_system_interface::instruction::transfer(
        &fee_payer.pubkey(),
        &recipient.pubkey(),
        amount,
    );
    let sign_v2_ix =
        SignV2Instruction::new_ed25519(swig, swig_wallet_address, alice.pubkey(), inner_ix, 0)
            .unwrap();
    let message = v0::Message::try_compile(
        &fee_payer.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&fee_payer, &alice])
        .unwrap();
    let err = context.svm.send_transaction(tx).unwrap_err();
    assert_eq!(err.err, isolation_error());
    assert_eq!(
        context
            .svm
            .get_account(&recipient.pubkey())
            .unwrap()
            .lamports,
        1_000_000
    );
}

#[test_log::test]
fn sign_v2_blocks_inner_system_transfer_from_fifth_outer_signer() {
    let mut context = setup_test_context().unwrap();
    let alice = Keypair::new();
    let extra: [Keypair; 4] = std::array::from_fn(|_| Keypair::new());
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&alice.pubkey(), 10_000_000_000)
        .unwrap();
    for signer in &extra {
        context
            .svm
            .airdrop(&signer.pubkey(), 10_000_000_000)
            .unwrap();
    }
    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &alice, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let amount = 500_000_000;
    let inner_ix = solana_system_interface::instruction::transfer(
        &extra[3].pubkey(),
        &recipient.pubkey(),
        amount,
    );
    let initial_accounts = vec![
        AccountMeta::new(swig, false),
        AccountMeta::new(swig_wallet_address, false),
        AccountMeta::new_readonly(alice.pubkey(), true),
        AccountMeta::new_readonly(extra[0].pubkey(), true),
        AccountMeta::new_readonly(extra[1].pubkey(), true),
        AccountMeta::new_readonly(extra[2].pubkey(), true),
        AccountMeta::new(extra[3].pubkey(), true),
        AccountMeta::new(recipient.pubkey(), false),
    ];
    let (final_accounts, compact_ixs) =
        compact_instructions(swig_wallet_address, initial_accounts, vec![inner_ix]).unwrap();
    let instruction_payload = compact_ixs.into_bytes().unwrap();
    let sign_args = SignV2Args::new(0, instruction_payload.len() as u16);
    let mut sign_ix_data = Vec::new();
    sign_ix_data.extend_from_slice(sign_args.into_bytes().unwrap());
    sign_ix_data.extend_from_slice(&instruction_payload);
    sign_ix_data.push(2);
    let sign_v2_ix = Instruction {
        program_id: swig::ID.into(),
        accounts: final_accounts,
        data: sign_ix_data,
    };
    let message = v0::Message::try_compile(
        &alice.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&alice, &extra[0], &extra[1], &extra[2], &extra[3]],
    )
    .unwrap();
    let err = context.svm.send_transaction(tx).unwrap_err();
    assert_eq!(err.err, isolation_error());
    assert_eq!(
        context
            .svm
            .get_account(&recipient.pubkey())
            .unwrap()
            .lamports,
        1_000_000
    );
}

#[test_log::test]
fn sign_v2_blocks_inner_token_drain_from_distinct_fee_payer() {
    let mut context = setup_test_context().unwrap();
    let alice = Keypair::new();
    let fee_payer = Keypair::new();
    let attacker = Keypair::new();
    context
        .svm
        .airdrop(&alice.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&fee_payer.pubkey(), 10_000_000_000)
        .unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &alice, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let payer_ata = setup_ata(
        &mut context.svm,
        &mint,
        &fee_payer.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    let attacker_ata = setup_ata(
        &mut context.svm,
        &mint,
        &attacker.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint,
        &context.default_payer,
        &payer_ata,
        PERSONAL_TOKEN_BALANCE,
    )
    .unwrap();
    let inner_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(payer_ata, false),
            AccountMeta::new(attacker_ata, false),
            AccountMeta::new_readonly(fee_payer.pubkey(), true),
        ],
        data: TokenInstruction::Transfer {
            amount: STOLEN_AMOUNT,
        }
        .pack(),
    };
    let sign_v2_ix =
        SignV2Instruction::new_ed25519(swig, swig_wallet_address, alice.pubkey(), inner_ix, 0)
            .unwrap();
    let message = v0::Message::try_compile(
        &fee_payer.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&fee_payer, &alice])
        .unwrap();
    let err = context.svm.send_transaction(tx).unwrap_err();
    assert_eq!(err.err, isolation_error());
    assert_eq!(token_amount(&context, &payer_ata), PERSONAL_TOKEN_BALANCE);
    assert_eq!(token_amount(&context, &attacker_ata), 0);
}

#[test_log::test]
fn sign_v2_allows_inner_ata_create_paid_by_alice() {
    let mut context = setup_test_context().unwrap();
    let alice = Keypair::new();
    let owner = Keypair::new();
    context
        .svm
        .airdrop(&alice.pubkey(), 10_000_000_000)
        .unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &alice, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let associated_token_program_id = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
        .parse::<Pubkey>()
        .unwrap();
    let owner_ata = Pubkey::find_program_address(
        &[
            &owner.pubkey().to_bytes(),
            &spl_token::id().to_bytes(),
            &mint.to_bytes(),
        ],
        &associated_token_program_id,
    )
    .0;

    let create_ata_ix = Instruction {
        program_id: associated_token_program_id,
        accounts: vec![
            AccountMeta::new(alice.pubkey(), true),
            AccountMeta::new(owner_ata, false),
            AccountMeta::new_readonly(owner.pubkey(), false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(spl_token::id(), false),
        ],
        data: vec![],
    };
    let sign_v2_ix =
        SignV2Instruction::new_ed25519(swig, swig_wallet_address, alice.pubkey(), create_ata_ix, 0)
            .unwrap();
    let message = v0::Message::try_compile(
        &alice.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&alice]).unwrap();
    context
        .svm
        .send_transaction(tx)
        .expect("ATA create paid by Alice should succeed");
    let ata = context
        .svm
        .get_account(&owner_ata)
        .expect("ATA should exist");
    assert_eq!(ata.owner, spl_token::id());
}

#[test_log::test]
fn sub_account_sign_limits_personal_sol_spending_to_creation_rent() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let alice = Keypair::new();
    let attacker = Keypair::new();
    context.svm.airdrop(&root.pubkey(), 10_000_000_000).unwrap();
    context
        .svm
        .airdrop(&alice.pubkey(), 10_000_000_000)
        .unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: alice.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccount(SubAccount::new_for_creation())],
    )
    .unwrap();
    let sub_account = create_sub_account(&mut context, &swig, &alice, 1, id).unwrap();
    context.svm.airdrop(&sub_account, 5_000_000_000).unwrap();

    let associated_token_program_id = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
        .parse::<Pubkey>()
        .unwrap();
    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let attacker_ata = Pubkey::find_program_address(
        &[
            &attacker.pubkey().to_bytes(),
            &spl_token::id().to_bytes(),
            &mint.to_bytes(),
        ],
        &associated_token_program_id,
    )
    .0;
    let create_attacker_ata = Instruction {
        program_id: associated_token_program_id,
        accounts: vec![
            AccountMeta::new(alice.pubkey(), true),
            AccountMeta::new(attacker_ata, false),
            AccountMeta::new_readonly(attacker.pubkey(), false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(spl_token::id(), false),
        ],
        data: vec![],
    };
    let extra_lamports = 500_000_000;
    let fund_attacker_ata = solana_system_interface::instruction::transfer(
        &alice.pubkey(),
        &attacker_ata,
        extra_lamports,
    );
    let sign_ix = SubAccountSignInstruction::new_with_ed25519_authority(
        swig,
        sub_account,
        alice.pubkey(),
        1,
        vec![create_attacker_ata.clone(), fund_attacker_ata],
    )
    .unwrap();
    let message = v0::Message::try_compile(
        &alice.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&alice]).unwrap();
    let err = context.svm.send_transaction(tx).unwrap_err();
    assert_eq!(err.err, isolation_error());
    assert!(context.svm.get_account(&attacker_ata).is_none());

    context.svm.expire_blockhash();
    let sign_ix = SubAccountSignInstruction::new_with_ed25519_authority(
        swig,
        sub_account,
        alice.pubkey(),
        1,
        vec![create_attacker_ata],
    )
    .unwrap();
    let message = v0::Message::try_compile(
        &alice.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&alice]).unwrap();
    context.svm.send_transaction(tx).unwrap();
    let account = context.svm.get_account(&attacker_ata).unwrap();
    assert_eq!(account.owner, spl_token::id());

    context.svm.expire_blockhash();
    let native_mint = spl_token::state::Mint {
        mint_authority: COption::None,
        supply: 0,
        decimals: spl_token::native_mint::DECIMALS,
        is_initialized: true,
        freeze_authority: COption::None,
    };
    let mut native_mint_data = vec![0; spl_token::state::Mint::LEN];
    spl_token::state::Mint::pack(native_mint, &mut native_mint_data).unwrap();
    context
        .svm
        .set_account(
            spl_token::native_mint::ID,
            Account {
                lamports: Rent::default().minimum_balance(spl_token::state::Mint::LEN),
                data: native_mint_data,
                owner: spl_token::id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    let wsol_ata = Pubkey::find_program_address(
        &[
            &alice.pubkey().to_bytes(),
            &spl_token::id().to_bytes(),
            &spl_token::native_mint::ID.to_bytes(),
        ],
        &associated_token_program_id,
    )
    .0;
    let create_wsol_ata = Instruction {
        program_id: associated_token_program_id,
        accounts: vec![
            AccountMeta::new(alice.pubkey(), true),
            AccountMeta::new(wsol_ata, false),
            AccountMeta::new_readonly(alice.pubkey(), false),
            AccountMeta::new_readonly(spl_token::native_mint::ID, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(spl_token::id(), false),
        ],
        data: vec![],
    };
    let fund_wsol =
        solana_system_interface::instruction::transfer(&alice.pubkey(), &wsol_ata, extra_lamports);
    let sync_wsol = spl_token::instruction::sync_native(&spl_token::id(), &wsol_ata).unwrap();
    let sign_ix = SubAccountSignInstruction::new_with_ed25519_authority(
        swig,
        sub_account,
        alice.pubkey(),
        1,
        vec![create_wsol_ata, fund_wsol, sync_wsol],
    )
    .unwrap();
    let message = v0::Message::try_compile(
        &alice.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&alice]).unwrap();
    let error = context.svm.send_transaction(tx).unwrap_err();
    assert_eq!(error.err, isolation_error());
    assert!(context.svm.get_account(&wsol_ata).is_none());

    context.svm.expire_blockhash();
    let attacker_wsol_ata = Pubkey::find_program_address(
        &[
            &attacker.pubkey().to_bytes(),
            &spl_token::id().to_bytes(),
            &spl_token::native_mint::ID.to_bytes(),
        ],
        &associated_token_program_id,
    )
    .0;
    let create_attacker_wsol_ata = Instruction {
        program_id: associated_token_program_id,
        accounts: vec![
            AccountMeta::new(alice.pubkey(), true),
            AccountMeta::new(attacker_wsol_ata, false),
            AccountMeta::new_readonly(attacker.pubkey(), true),
            AccountMeta::new_readonly(spl_token::native_mint::ID, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(spl_token::id(), false),
        ],
        data: vec![],
    };
    let fund_attacker_wsol = solana_system_interface::instruction::transfer(
        &alice.pubkey(),
        &attacker_wsol_ata,
        extra_lamports,
    );
    let sync_attacker_wsol =
        spl_token::instruction::sync_native(&spl_token::id(), &attacker_wsol_ata).unwrap();
    let sign_ix = SubAccountSignInstruction::new_with_ed25519_authority(
        swig,
        sub_account,
        alice.pubkey(),
        1,
        vec![
            create_attacker_wsol_ata,
            fund_attacker_wsol,
            sync_attacker_wsol,
        ],
    )
    .unwrap();
    let message = v0::Message::try_compile(
        &alice.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&alice, &attacker]).unwrap();
    let err = context.svm.send_transaction(tx).unwrap_err();
    assert_eq!(err.err, isolation_error());
    assert!(context.svm.get_account(&attacker_wsol_ata).is_none());
}

#[test_log::test]
fn sub_account_sign_blocks_personal_token_drain() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let alice = Keypair::new();
    let attacker = Keypair::new();
    context.svm.airdrop(&root.pubkey(), 10_000_000_000).unwrap();
    context
        .svm
        .airdrop(&alice.pubkey(), 10_000_000_000)
        .unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: alice.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccount(SubAccount::new_for_creation())],
    )
    .unwrap();
    let sub_account = create_sub_account(&mut context, &swig, &alice, 1, id).unwrap();
    context.svm.airdrop(&sub_account, 5_000_000_000).unwrap();

    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let alice_ata = setup_ata(
        &mut context.svm,
        &mint,
        &alice.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    let attacker_ata = setup_ata(
        &mut context.svm,
        &mint,
        &attacker.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint,
        &context.default_payer,
        &alice_ata,
        PERSONAL_TOKEN_BALANCE,
    )
    .unwrap();

    let inner_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(alice_ata, false),
            AccountMeta::new(attacker_ata, false),
            AccountMeta::new_readonly(alice.pubkey(), true),
        ],
        data: TokenInstruction::Transfer {
            amount: STOLEN_AMOUNT,
        }
        .pack(),
    };
    assert!(
        sub_account_sign(&mut context, &swig, &sub_account, &alice, 1, vec![inner_ix]).is_err()
    );
    assert_eq!(token_amount(&context, &alice_ata), PERSONAL_TOKEN_BALANCE);
    assert_eq!(token_amount(&context, &attacker_ata), 0);
}

#[test_log::test]
fn sub_account_sign_blocks_inner_system_transfer_from_alice() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let alice = Keypair::new();
    let recipient = Keypair::new();
    context.svm.airdrop(&root.pubkey(), 10_000_000_000).unwrap();
    context
        .svm
        .airdrop(&alice.pubkey(), 10_000_000_000)
        .unwrap();
    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: alice.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccount(SubAccount::new_for_creation())],
    )
    .unwrap();
    let sub_account = create_sub_account(&mut context, &swig, &alice, 1, id).unwrap();
    context.svm.airdrop(&sub_account, 5_000_000_000).unwrap();

    let amount = 500_000_000;
    let inner_ix = solana_system_interface::instruction::transfer(
        &alice.pubkey(),
        &recipient.pubkey(),
        amount,
    );
    assert!(
        sub_account_sign(&mut context, &swig, &sub_account, &alice, 1, vec![inner_ix]).is_err()
    );
    assert_eq!(
        context
            .svm
            .get_account(&recipient.pubkey())
            .unwrap()
            .lamports,
        1_000_000
    );
}

#[test]
fn nested_idempotent_ata_creation_allows_rent_and_receipts() {
    const COMPOSER: Pubkey = Pubkey::from_str_const("BXAu5ZWHnGun2XZjUZ9nqwiZ5dNVmofPGYdMC4rx4qLV");
    let ata_program = Pubkey::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
    for depth in [0, 1] {
        for prefunded in [false, true] {
            let mut context = setup_test_context().unwrap();
            context
                .svm
                .add_program_from_file(COMPOSER, "../target/deploy/test_program_authority.so")
                .unwrap();
            let alice = Keypair::new();
            let (swig, _) = create_swig_ed25519(&mut context, &alice, rand::random()).unwrap();
            context
                .svm
                .airdrop(&alice.pubkey(), 10_000_000_000)
                .unwrap();
            let wallet = Pubkey::find_program_address(
                &swig_wallet_address_seeds(swig.as_ref()),
                &program_id(),
            )
            .0;
            context.svm.airdrop(&wallet, 1_000_000_000).unwrap();
            let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
            let owner = alice.pubkey();
            let ata = Pubkey::find_program_address(
                &[owner.as_ref(), spl_token::ID.as_ref(), mint.as_ref()],
                &ata_program,
            )
            .0;
            let rent = context
                .svm
                .minimum_balance_for_rent_exemption(spl_token::state::Account::LEN);
            let pre_balance = if prefunded {
                context.svm.minimum_balance_for_rent_exemption(0)
            } else {
                0
            };
            if prefunded {
                context.svm.airdrop(&ata, pre_balance).unwrap();
            }
            let mut data = b"nestdata".to_vec();
            data.push(depth);
            let inner = Instruction {
                program_id: COMPOSER,
                accounts: vec![
                    AccountMeta::new(alice.pubkey(), true),
                    AccountMeta::new(ata, false),
                    AccountMeta::new_readonly(owner, false),
                    AccountMeta::new_readonly(mint, false),
                    AccountMeta::new_readonly(solana_system_interface::program::ID, false),
                    AccountMeta::new_readonly(spl_token::ID, false),
                    AccountMeta::new_readonly(ata_program, false),
                    AccountMeta::new_readonly(COMPOSER, false),
                ],
                data,
            };
            for repeat in [false, true] {
                context.svm.expire_blockhash();
                let alice_before = context.svm.get_account(&alice.pubkey()).unwrap().lamports;
                let ix =
                    SignV2Instruction::new_ed25519(swig, wallet, alice.pubkey(), inner.clone(), 0)
                        .unwrap();
                let message = v0::Message::try_compile(
                    &context.default_payer.pubkey(),
                    &[ix],
                    &[],
                    context.svm.latest_blockhash(),
                )
                .unwrap();
                let tx = VersionedTransaction::try_new(
                    VersionedMessage::V0(message),
                    &[&context.default_payer, &alice],
                )
                .unwrap();
                let receipt = context.svm.send_transaction(tx).unwrap();
                assert!(receipt
                    .logs
                    .iter()
                    .any(|line| line == &format!("Program {ata_program} success")));
                let created = context.svm.get_account(&ata).unwrap();
                assert_eq!(created.owner, spl_token::ID);
                assert_eq!(created.lamports, rent);
                assert_eq!(
                    alice_before - context.svm.get_account(&alice.pubkey()).unwrap().lamports,
                    if repeat { 0 } else { rent - pre_balance }
                );
            }
            // Receiving SOL from the wallet still works with the same signer.
            let before = context.svm.get_account(&alice.pubkey()).unwrap().lamports;
            let inner =
                solana_system_interface::instruction::transfer(&wallet, &alice.pubkey(), 10);
            let ix =
                SignV2Instruction::new_ed25519(swig, wallet, alice.pubkey(), inner, 0).unwrap();
            let message = v0::Message::try_compile(
                &context.default_payer.pubkey(),
                &[ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap();
            let tx = VersionedTransaction::try_new(
                VersionedMessage::V0(message),
                &[&context.default_payer, &alice],
            )
            .unwrap();
            context.svm.send_transaction(tx).unwrap();
            assert_eq!(
                context.svm.get_account(&alice.pubkey()).unwrap().lamports,
                before + 10
            );
        }
    }
}

#[test]
fn new_account_keypair_can_sign_creation_with_personal_rent_payer() {
    let mut context = setup_test_context().unwrap();
    let alice = Keypair::new();
    let created = Keypair::new();
    let (swig, _) = create_swig_ed25519(&mut context, &alice, rand::random()).unwrap();
    context.svm.airdrop(&alice.pubkey(), 1_000_000_000).unwrap();
    let wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;
    let rent = context.svm.minimum_balance_for_rent_exemption(64);
    let owner = Pubkey::new_unique();
    let inner = solana_system_interface::instruction::create_account(
        &alice.pubkey(),
        &created.pubkey(),
        rent,
        64,
        &owner,
    );
    let before = context.svm.get_account(&alice.pubkey()).unwrap().lamports;
    let ix = SignV2Instruction::new_ed25519(swig, wallet, alice.pubkey(), inner, 0).unwrap();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, &alice, &created],
    )
    .unwrap();
    context.svm.send_transaction(tx).unwrap();
    let account = context.svm.get_account(&created.pubkey()).unwrap();
    assert_eq!(account.owner, owner);
    assert_eq!(account.data.len(), 64);
    assert_eq!(account.lamports, rent);
    assert_eq!(
        before - context.svm.get_account(&alice.pubkey()).unwrap().lamports,
        rent
    );
}
