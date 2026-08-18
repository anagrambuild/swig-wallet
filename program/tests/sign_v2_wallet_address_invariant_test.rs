#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use litesvm_token::spl_token;
use solana_sdk::{
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig::actions::sign_v2::SignV2Args;
use swig_interface::{compact_instructions, AuthorityConfig, ClientAction, SignV2Instruction};
use swig_state::{
    action::{
        all::All, all_but_manage_authority::AllButManageAuthority, program::Program,
        program_all::ProgramAll, program_curated::ProgramCurated, sol_limit::SolLimit,
        token_limit::TokenLimit,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds},
    IntoBytes,
};

const WALLET_ADDRESS_INVARIANT_ERROR: u32 = 71;
solana_sdk::declare_id!("BXAu5ZWHnGun2XZjUZ9nqwiZ5dNVmofPGYdMC4rx4qLV");
const TEST_PROGRAM_ID: Pubkey = ID;
const TEST_PROGRAM_PATH: &str = "../target/deploy/test_program_authority.so";
const MUTATE_WALLET_ASSIGN: [u8; 8] = [10, 10, 10, 10, 10, 10, 10, 10];
const MUTATE_WALLET_ALLOCATE: [u8; 8] = [11, 11, 11, 11, 11, 11, 11, 11];

fn send_sign_v2(
    context: &mut SwigTestContext,
    swig: Pubkey,
    swig_wallet_address: Pubkey,
    authority: &Keypair,
    role_id: u32,
    inner: Instruction,
) -> Result<TransactionMetadata, FailedTransactionMetadata> {
    let sign_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        authority.pubkey(),
        inner,
        role_id,
    )
    .unwrap();
    let message = v0::Message::try_compile(
        &authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[authority]).unwrap();
    context.svm.send_transaction(tx)
}

fn send_sign_v2_many(
    context: &mut SwigTestContext,
    swig: Pubkey,
    swig_wallet_address: Pubkey,
    authority: &Keypair,
    role_id: u32,
    inner: Vec<Instruction>,
) -> Result<TransactionMetadata, FailedTransactionMetadata> {
    let accounts = vec![
        AccountMeta::new(swig, false),
        AccountMeta::new(swig_wallet_address, false),
        AccountMeta::new_readonly(authority.pubkey(), true),
    ];
    let (accounts, compact_ixs) = compact_instructions(swig, accounts, inner);
    let instruction_payload = compact_ixs.into_bytes();
    let args = SignV2Args::new(role_id, instruction_payload.len() as u16);
    let sign_ix = Instruction {
        program_id: program_id(),
        accounts,
        data: [args.into_bytes().unwrap(), &instruction_payload, &[2]].concat(),
    };
    let message = v0::Message::try_compile(
        &authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[authority]).unwrap();
    context.svm.send_transaction(tx)
}

fn assert_wallet_unmutated(
    context: &SwigTestContext,
    swig_wallet_address: &Pubkey,
    owner_before: Pubkey,
    data_len_before: usize,
    lamports_before: u64,
    result: Result<TransactionMetadata, FailedTransactionMetadata>,
) {
    let err = result.expect_err("wallet-address shape mutation must be rejected");
    assert_eq!(
        err.err,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(WALLET_ADDRESS_INVARIANT_ERROR),
        )
    );
    let wallet = context.svm.get_account(swig_wallet_address).unwrap();
    assert_eq!(wallet.owner, owner_before);
    assert_eq!(wallet.data.len(), data_len_before);
    assert_eq!(wallet.lamports, lamports_before);
}

fn setup_swig_with_role(
    context: &mut SwigTestContext,
    actions: Vec<ClientAction>,
) -> (Pubkey, Pubkey, Keypair, Keypair) {
    let root = Keypair::new();
    let role_authority = Keypair::new();
    context.svm.airdrop(&root.pubkey(), 10_000_000_000).unwrap();
    context
        .svm
        .airdrop(&role_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    create_swig_ed25519(context, &root, id).unwrap();
    add_authority_with_ed25519_root(
        context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: role_authority.pubkey().as_ref(),
        },
        actions,
    )
    .unwrap();
    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();
    context.svm.expire_blockhash();
    (swig, swig_wallet_address, root, role_authority)
}

fn program_system_actions() -> Vec<ClientAction> {
    vec![
        ClientAction::Program(Program {
            program_id: solana_system_interface::program::ID.to_bytes(),
        }),
        ClientAction::SolLimit(SolLimit {
            amount: 10_000_000_000,
        }),
    ]
}

fn program_curated_actions() -> Vec<ClientAction> {
    vec![
        ClientAction::ProgramCurated(ProgramCurated::new()),
        ClientAction::SolLimit(SolLimit {
            amount: 10_000_000_000,
        }),
    ]
}

fn program_all_actions() -> Vec<ClientAction> {
    vec![
        ClientAction::ProgramAll(ProgramAll {}),
        ClientAction::SolLimit(SolLimit {
            amount: 10_000_000_000,
        }),
    ]
}

#[test_log::test]
fn test_sign_v2_program_curated_assign_wallet_rolls_back() {
    let mut context = setup_test_context().unwrap();
    let (swig, swig_wallet_address, _, authority) =
        setup_swig_with_role(&mut context, program_curated_actions());
    let wallet_before = context.svm.get_account(&swig_wallet_address).unwrap();
    let new_owner = Pubkey::new_unique();
    let assign_ix = solana_system_interface::instruction::assign(&swig_wallet_address, &new_owner);
    let result = send_sign_v2(
        &mut context,
        swig,
        swig_wallet_address,
        &authority,
        1,
        assign_ix,
    );
    assert_wallet_unmutated(
        &context,
        &swig_wallet_address,
        wallet_before.owner,
        wallet_before.data.len(),
        wallet_before.lamports,
        result,
    );

    context.svm.expire_blockhash();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    let transfer_ix = solana_system_interface::instruction::transfer(
        &swig_wallet_address,
        &recipient.pubkey(),
        1_000_000,
    );
    send_sign_v2(
        &mut context,
        swig,
        swig_wallet_address,
        &authority,
        1,
        transfer_ix,
    )
    .expect("SignV2 transfer must still work after a rejected assign");
}

#[test_log::test]
fn test_sign_v2_program_curated_allocate_wallet_rolls_back() {
    let mut context = setup_test_context().unwrap();
    let (swig, swig_wallet_address, _, authority) =
        setup_swig_with_role(&mut context, program_curated_actions());
    let wallet_before = context.svm.get_account(&swig_wallet_address).unwrap();
    let allocate_ix = solana_system_interface::instruction::allocate(&swig_wallet_address, 80);
    let result = send_sign_v2(
        &mut context,
        swig,
        swig_wallet_address,
        &authority,
        1,
        allocate_ix,
    );
    assert_wallet_unmutated(
        &context,
        &swig_wallet_address,
        wallet_before.owner,
        wallet_before.data.len(),
        wallet_before.lamports,
        result,
    );
}

#[test_log::test]
fn test_sign_v2_program_system_assign_wallet_rolls_back() {
    let mut context = setup_test_context().unwrap();
    let (swig, swig_wallet_address, _, authority) =
        setup_swig_with_role(&mut context, program_system_actions());
    let wallet_before = context.svm.get_account(&swig_wallet_address).unwrap();
    let assign_ix =
        solana_system_interface::instruction::assign(&swig_wallet_address, &Pubkey::new_unique());
    let result = send_sign_v2(
        &mut context,
        swig,
        swig_wallet_address,
        &authority,
        1,
        assign_ix,
    );
    assert_wallet_unmutated(
        &context,
        &swig_wallet_address,
        wallet_before.owner,
        wallet_before.data.len(),
        wallet_before.lamports,
        result,
    );
}

#[test_log::test]
fn test_sign_v2_program_all_allocate_wallet_rolls_back() {
    let mut context = setup_test_context().unwrap();
    let (swig, swig_wallet_address, _, authority) =
        setup_swig_with_role(&mut context, program_all_actions());
    let wallet_before = context.svm.get_account(&swig_wallet_address).unwrap();
    let allocate_ix = solana_system_interface::instruction::allocate(&swig_wallet_address, 80);
    let result = send_sign_v2(
        &mut context,
        swig,
        swig_wallet_address,
        &authority,
        1,
        allocate_ix,
    );
    assert_wallet_unmutated(
        &context,
        &swig_wallet_address,
        wallet_before.owner,
        wallet_before.data.len(),
        wallet_before.lamports,
        result,
    );
}

#[test_log::test]
fn test_sign_v2_all_role_assign_wallet_rolls_back() {
    let mut context = setup_test_context().unwrap();
    let (swig, swig_wallet_address, _, authority) =
        setup_swig_with_role(&mut context, vec![ClientAction::All(All {})]);
    let wallet_before = context.svm.get_account(&swig_wallet_address).unwrap();
    let assign_ix =
        solana_system_interface::instruction::assign(&swig_wallet_address, &Pubkey::new_unique());
    let result = send_sign_v2(
        &mut context,
        swig,
        swig_wallet_address,
        &authority,
        1,
        assign_ix,
    );
    assert_wallet_unmutated(
        &context,
        &swig_wallet_address,
        wallet_before.owner,
        wallet_before.data.len(),
        wallet_before.lamports,
        result,
    );
}

#[test_log::test]
fn test_sign_v2_all_but_manage_authority_allocate_wallet_rolls_back() {
    let mut context = setup_test_context().unwrap();
    let (swig, swig_wallet_address, _, authority) = setup_swig_with_role(
        &mut context,
        vec![ClientAction::AllButManageAuthority(
            AllButManageAuthority {},
        )],
    );
    let wallet_before = context.svm.get_account(&swig_wallet_address).unwrap();
    let allocate_ix = solana_system_interface::instruction::allocate(&swig_wallet_address, 80);
    let result = send_sign_v2(
        &mut context,
        swig,
        swig_wallet_address,
        &authority,
        1,
        allocate_ix,
    );
    assert_wallet_unmutated(
        &context,
        &swig_wallet_address,
        wallet_before.owner,
        wallet_before.data.len(),
        wallet_before.lamports,
        result,
    );
}

#[test_log::test]
fn test_sign_v2_nonce_init_wallet_rolls_back() {
    let mut context = setup_test_context().unwrap();
    let (swig, swig_wallet_address, _, authority) =
        setup_swig_with_role(&mut context, program_curated_actions());
    let wallet_before = context.svm.get_account(&swig_wallet_address).unwrap();
    let allocate_ix = solana_system_interface::instruction::allocate(&swig_wallet_address, 80);
    let init_nonce_ix = solana_system_interface::instruction::create_nonce_account(
        &swig_wallet_address,
        &swig_wallet_address,
        &authority.pubkey(),
        1,
    )
    .into_iter()
    .nth(1)
    .unwrap();
    let result = send_sign_v2_many(
        &mut context,
        swig,
        swig_wallet_address,
        &authority,
        1,
        vec![allocate_ix, init_nonce_ix],
    );
    assert_wallet_unmutated(
        &context,
        &swig_wallet_address,
        wallet_before.owner,
        wallet_before.data.len(),
        wallet_before.lamports,
        result,
    );
}

#[test_log::test]
fn test_sign_v2_create_account_targeting_wallet_rolls_back() {
    let mut context = setup_test_context().unwrap();
    let (swig, swig_wallet_address, _, authority) =
        setup_swig_with_role(&mut context, program_system_actions());
    let wallet_before = context.svm.get_account(&swig_wallet_address).unwrap();
    let create_ix = solana_system_interface::instruction::create_account(
        &swig_wallet_address,
        &swig_wallet_address,
        1_000_000,
        80,
        &Pubkey::new_unique(),
    );
    let result = send_sign_v2(
        &mut context,
        swig,
        swig_wallet_address,
        &authority,
        1,
        create_ix,
    );
    assert_wallet_unmutated(
        &context,
        &swig_wallet_address,
        wallet_before.owner,
        wallet_before.data.len(),
        wallet_before.lamports,
        result,
    );
}

#[test_log::test]
fn test_sign_v2_indirect_cpi_assign_wallet_rolls_back() {
    let mut context = setup_test_context().unwrap();
    let program_data = std::fs::read(TEST_PROGRAM_PATH).expect("run cargo build-sbf first");
    let _ = context.svm.add_program(TEST_PROGRAM_ID, &program_data);

    let new_owner = Pubkey::new_unique();
    let (swig, swig_wallet_address, _, authority) = setup_swig_with_role(
        &mut context,
        vec![
            ClientAction::Program(Program {
                program_id: TEST_PROGRAM_ID.to_bytes(),
            }),
            ClientAction::SolLimit(SolLimit {
                amount: 10_000_000_000,
            }),
        ],
    );
    let wallet_before = context.svm.get_account(&swig_wallet_address).unwrap();
    let mut data = MUTATE_WALLET_ASSIGN.to_vec();
    data.extend_from_slice(new_owner.as_ref());
    let mutate_ix = Instruction {
        program_id: TEST_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(swig_wallet_address, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ],
        data,
    };
    let result = send_sign_v2(
        &mut context,
        swig,
        swig_wallet_address,
        &authority,
        1,
        mutate_ix,
    );
    assert_wallet_unmutated(
        &context,
        &swig_wallet_address,
        wallet_before.owner,
        wallet_before.data.len(),
        wallet_before.lamports,
        result,
    );
}

#[test_log::test]
fn test_sign_v2_indirect_cpi_allocate_wallet_rolls_back() {
    let mut context = setup_test_context().unwrap();
    let program_data = std::fs::read(TEST_PROGRAM_PATH).expect("run cargo build-sbf first");
    let _ = context.svm.add_program(TEST_PROGRAM_ID, &program_data);

    let (swig, swig_wallet_address, _, authority) = setup_swig_with_role(
        &mut context,
        vec![
            ClientAction::Program(Program {
                program_id: TEST_PROGRAM_ID.to_bytes(),
            }),
            ClientAction::SolLimit(SolLimit {
                amount: 10_000_000_000,
            }),
        ],
    );
    let wallet_before = context.svm.get_account(&swig_wallet_address).unwrap();
    let mut data = MUTATE_WALLET_ALLOCATE.to_vec();
    data.extend_from_slice(&80u64.to_le_bytes());
    let mutate_ix = Instruction {
        program_id: TEST_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(swig_wallet_address, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ],
        data,
    };
    let result = send_sign_v2(
        &mut context,
        swig,
        swig_wallet_address,
        &authority,
        1,
        mutate_ix,
    );
    assert_wallet_unmutated(
        &context,
        &swig_wallet_address,
        wallet_before.owner,
        wallet_before.data.len(),
        wallet_before.lamports,
        result,
    );
}

#[test_log::test]
fn test_sign_v2_program_curated_transfer_still_works() {
    let mut context = setup_test_context().unwrap();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    let (swig, swig_wallet_address, _, authority) =
        setup_swig_with_role(&mut context, program_curated_actions());
    let transfer_amount = 1_000_000;
    let transfer_ix = solana_system_interface::instruction::transfer(
        &swig_wallet_address,
        &recipient.pubkey(),
        transfer_amount,
    );
    let result = send_sign_v2(
        &mut context,
        swig,
        swig_wallet_address,
        &authority,
        1,
        transfer_ix,
    );
    assert!(
        result.is_ok(),
        "system transfer should still succeed: {:?}",
        result.err()
    );
    let wallet = context.svm.get_account(&swig_wallet_address).unwrap();
    assert_eq!(wallet.owner, solana_system_interface::program::ID);
    assert_eq!(wallet.data.len(), 0);
}

#[test_log::test]
fn test_sign_v2_all_role_create_account_other_still_works() {
    let mut context = setup_test_context().unwrap();
    let (swig, swig_wallet_address, _, authority) =
        setup_swig_with_role(&mut context, vec![ClientAction::All(All {})]);
    let new_account = Keypair::new();
    let rent = 1_000_000;
    let create_ix = solana_system_interface::instruction::create_account(
        &swig_wallet_address,
        &new_account.pubkey(),
        rent,
        0,
        &solana_system_interface::program::ID,
    );
    let sign_ix = SignV2Instruction::new_ed25519_with_signers(
        swig,
        swig_wallet_address,
        authority.pubkey(),
        create_ix,
        1,
        &[new_account.pubkey()],
    )
    .unwrap();
    let message = v0::Message::try_compile(
        &authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&authority, &new_account])
            .unwrap();
    context.svm.send_transaction(tx).unwrap();
    let created = context.svm.get_account(&new_account.pubkey()).unwrap();
    assert_eq!(created.lamports, rent);
    let wallet = context.svm.get_account(&swig_wallet_address).unwrap();
    assert_eq!(wallet.owner, solana_system_interface::program::ID);
    assert_eq!(wallet.data.len(), 0);
}

#[test_log::test]
fn test_sign_v2_program_curated_token_transfer_still_works() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&root.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    create_swig_ed25519(&mut context, &root, id).unwrap();

    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint,
        &context.default_payer,
        &swig_ata,
        1_000,
    )
    .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramCurated(ProgramCurated::new()),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint.to_bytes(),
                current_amount: 1_000,
            }),
        ],
    )
    .unwrap();

    context.svm.expire_blockhash();
    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig_wallet_address,
        &[],
        100,
    )
    .unwrap();
    send_sign_v2(
        &mut context,
        swig,
        swig_wallet_address,
        &authority,
        1,
        transfer_ix,
    )
    .unwrap();

    let wallet = context.svm.get_account(&swig_wallet_address).unwrap();
    assert_eq!(wallet.owner, solana_system_interface::program::ID);
    assert_eq!(wallet.data.len(), 0);
}
