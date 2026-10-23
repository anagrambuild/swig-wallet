#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ClientAction, SignV2Instruction};
use swig_state::{
    action::{program_all::ProgramAll, sol_limit::SolLimit},
    authority::{programexec::ProgramExecAuthority, AuthorityType},
    swig::{swig_account_seeds, swig_wallet_address_seeds},
    Transmutable,
};

/// Oracle instruction discriminator: "valtrade"
const ORACLE_DISCRIMINATOR: [u8; 8] = [0x76, 0x61, 0x6c, 0x74, 0x72, 0x61, 0x64, 0x65];

/// Oracle program binary path
const ORACLE_PROGRAM_PATH: &str = "../target/deploy/slippage_oracle.so";

/// Load the slippage oracle program into the test VM and return its program ID
fn load_oracle_program(context: &mut SwigTestContext) -> Pubkey {
    let program_id = Pubkey::from_str_const("EQ2rR75Y9nzQVSVBC4Fb8p7p8xVdRsaAxdNYBLiGTZjp");
    let elf = std::fs::read(ORACLE_PROGRAM_PATH)
        .expect("slippage_oracle.so not found -- run `cargo build-sbf` first");
    context.svm.add_program(program_id, &elf);
    program_id
}

/// Build a ValidateTrade oracle instruction
fn build_oracle_ix(
    oracle_program_id: Pubkey,
    swig_config: Pubkey,
    swig_wallet: Pubkey,
    input_amount: u64,
    min_output_amount: u64,
    min_bps: u16,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 18);
    data.extend_from_slice(&ORACLE_DISCRIMINATOR);
    data.extend_from_slice(&input_amount.to_le_bytes());
    data.extend_from_slice(&min_output_amount.to_le_bytes());
    data.extend_from_slice(&min_bps.to_le_bytes());

    Instruction {
        program_id: oracle_program_id,
        accounts: vec![
            AccountMeta::new_readonly(swig_config, false),
            AccountMeta::new_readonly(swig_wallet, false),
        ],
        data,
    }
}

/// Build ProgramExec authority data for the oracle program
fn create_program_exec_authority_data(program_id: Pubkey, instruction_prefix: &[u8]) -> Vec<u8> {
    const IX_PREFIX_OFFSET: usize = 32 + 1 + 7; // program_id + instruction_prefix_len + padding

    let mut data = vec![0u8; ProgramExecAuthority::LEN];
    // First 32 bytes: program_id
    data[..32].copy_from_slice(&program_id.to_bytes());
    // Byte 32: instruction_prefix_len
    data[32] = instruction_prefix.len() as u8;
    // Bytes 33-39: padding (already zeroed)
    // Bytes 40+: instruction_prefix
    data[IX_PREFIX_OFFSET..IX_PREFIX_OFFSET + instruction_prefix.len()]
        .copy_from_slice(instruction_prefix);
    data
}

/// Setup a swig with a ProgramExec authority bound to the oracle.
/// Returns (swig, swig_wallet, oracle_program_id, swig_authority).
fn setup_agent_swig(
    context: &mut SwigTestContext,
    sol_limit_lamports: u64,
) -> (Pubkey, Pubkey, Pubkey, Keypair) {
    let oracle_program_id = load_oracle_program(context);

    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    // Create swig with Ed25519 root authority
    create_swig_ed25519(context, &swig_authority, id).unwrap();

    // Fund the swig wallet
    context.svm.airdrop(&swig_wallet, 10_000_000_000).unwrap();

    // Build ProgramExec authority data bound to oracle discriminator
    let program_exec_data =
        create_program_exec_authority_data(oracle_program_id, &ORACLE_DISCRIMINATOR);

    // Add ProgramExec authority (role_id = 1) with ProgramAll + SolLimit
    add_authority_with_ed25519_root(
        context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::ProgramExec,
            authority: &program_exec_data,
        },
        vec![
            ClientAction::ProgramAll(ProgramAll),
            ClientAction::SolLimit(SolLimit {
                amount: sol_limit_lamports,
            }),
        ],
    )
    .unwrap();

    (swig, swig_wallet, oracle_program_id, swig_authority)
}

/// Test 1: Agent trade within spending limits succeeds.
///
/// The agent builds a valid oracle instruction (good slippage) and a transfer
/// of 0.5 SOL which is under the 1 SOL SolLimit. The transaction should
/// succeed and the recipient should receive the funds.
#[test_log::test]
fn test_agent_trade_within_limits_succeeds() {
    let mut context = setup_test_context().unwrap();

    let sol_limit = 1_000_000_000; // 1 SOL
    let (swig, swig_wallet, oracle_program_id, swig_authority) =
        setup_agent_swig(&mut context, sol_limit);

    let recipient = Pubkey::new_unique();
    let transfer_amount = 500_000_000; // 0.5 SOL

    // Oracle: 1000 input, 990 output, 9900 bps (99%) -> passes
    let oracle_ix = build_oracle_ix(oracle_program_id, swig, swig_wallet, 1000, 990, 9900);

    // Inner instruction: transfer from swig_wallet to recipient
    let inner_ix = system_instruction::transfer(&swig_wallet, &recipient, transfer_amount);

    context.svm.warp_to_slot(100);

    let instructions = SignV2Instruction::new_program_exec(
        swig,
        swig_wallet,
        swig_authority.pubkey(),
        oracle_ix,
        inner_ix,
        1, // ProgramExec role_id
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &instructions,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&swig_authority]).unwrap();

    let res = context.svm.send_transaction(tx);
    if res.is_err() {
        if let Some(logs) = res.as_ref().err().map(|e| &e.meta.logs) {
            for log in logs {
                println!("{}", log);
            }
        }
    }
    assert!(
        res.is_ok(),
        "Transaction should succeed: valid oracle + transfer within SolLimit"
    );

    // Verify recipient received the funds
    let recipient_balance = context.svm.get_balance(&recipient).unwrap();
    assert_eq!(
        recipient_balance, transfer_amount,
        "Recipient should have received the transferred lamports"
    );
}

/// Test 2: Agent trade exceeding SOL limit fails.
///
/// Same setup with SolLimit(1 SOL), but the agent tries to transfer 2 SOL
/// which exceeds the spending limit. The transaction should fail.
#[test_log::test]
fn test_agent_trade_exceeding_sol_limit_fails() {
    let mut context = setup_test_context().unwrap();

    let sol_limit = 1_000_000_000; // 1 SOL
    let (swig, swig_wallet, oracle_program_id, swig_authority) =
        setup_agent_swig(&mut context, sol_limit);

    let recipient = Pubkey::new_unique();
    let transfer_amount = 2_000_000_000; // 2 SOL -- exceeds the 1 SOL limit

    // Oracle: valid parameters (not the point of this test)
    let oracle_ix = build_oracle_ix(oracle_program_id, swig, swig_wallet, 1000, 990, 9900);

    let inner_ix = system_instruction::transfer(&swig_wallet, &recipient, transfer_amount);

    context.svm.warp_to_slot(100);

    let instructions = SignV2Instruction::new_program_exec(
        swig,
        swig_wallet,
        swig_authority.pubkey(),
        oracle_ix,
        inner_ix,
        1,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &instructions,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&swig_authority]).unwrap();

    let res = context.svm.send_transaction(tx);
    assert!(
        res.is_err(),
        "Transaction should fail: transfer amount exceeds SolLimit"
    );
}

/// Test 3: Bad slippage parameters are rejected by the oracle.
///
/// The agent passes bad slippage: 50% output with 99% min_bps. The oracle
/// instruction itself fails, which causes the whole transaction to fail.
#[test_log::test]
fn test_agent_bad_slippage_rejected_by_oracle() {
    let mut context = setup_test_context().unwrap();

    let sol_limit = 1_000_000_000; // 1 SOL
    let (swig, swig_wallet, oracle_program_id, swig_authority) =
        setup_agent_swig(&mut context, sol_limit);

    let recipient = Pubkey::new_unique();
    let transfer_amount = 500_000_000; // 0.5 SOL -- within limit

    // Oracle: 1000 input, 500 output (50%), 9900 bps (99%) -> fails because
    // required_min = 1000 * 9900 / 10000 = 990, but output is only 500
    let oracle_ix = build_oracle_ix(oracle_program_id, swig, swig_wallet, 1000, 500, 9900);

    let inner_ix = system_instruction::transfer(&swig_wallet, &recipient, transfer_amount);

    context.svm.warp_to_slot(100);

    let instructions = SignV2Instruction::new_program_exec(
        swig,
        swig_wallet,
        swig_authority.pubkey(),
        oracle_ix,
        inner_ix,
        1,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &instructions,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&swig_authority]).unwrap();

    let res = context.svm.send_transaction(tx);
    assert!(
        res.is_err(),
        "Transaction should fail: oracle rejects bad slippage parameters"
    );
}

/// Test 4: Without the oracle instruction, ProgramExec authentication fails.
///
/// The agent tries to send the SignV2 instruction without the preceding oracle
/// instruction. ProgramExec cannot authenticate because it requires a matching
/// preceding instruction from the bound program.
#[test_log::test]
fn test_agent_without_oracle_ix_cannot_authenticate() {
    let mut context = setup_test_context().unwrap();

    let sol_limit = 1_000_000_000; // 1 SOL
    let (swig, swig_wallet, oracle_program_id, swig_authority) =
        setup_agent_swig(&mut context, sol_limit);

    let recipient = Pubkey::new_unique();
    let transfer_amount = 500_000_000; // 0.5 SOL

    // Build the oracle and inner instructions via the normal path so we can
    // extract the sign instruction but omit the oracle instruction.
    let oracle_ix = build_oracle_ix(oracle_program_id, swig, swig_wallet, 1000, 990, 9900);
    let inner_ix = system_instruction::transfer(&swig_wallet, &recipient, transfer_amount);

    context.svm.warp_to_slot(100);

    let instructions = SignV2Instruction::new_program_exec(
        swig,
        swig_wallet,
        swig_authority.pubkey(),
        oracle_ix,
        inner_ix,
        1,
    )
    .unwrap();

    // Only send the second instruction (SignV2) without the first (oracle)
    let sign_ix_only = &instructions[1..];

    let message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        sign_ix_only,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&swig_authority]).unwrap();

    let res = context.svm.send_transaction(tx);
    assert!(
        res.is_err(),
        "Transaction should fail: no preceding oracle instruction for ProgramExec auth"
    );
}
