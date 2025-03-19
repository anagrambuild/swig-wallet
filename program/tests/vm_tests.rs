mod common;
use bytemuck::{Pod, Zeroable};
use common::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_program,
    transaction::VersionedTransaction,
};
use swig_state::{BytecodeAccount, ExecutionResultAccount, VMInstruction};

#[test_log::test]
fn test_initialize_bytecode() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let bytecode_account = Keypair::new();
    let result_account = Keypair::new();

    // Airdrop SOL to accounts
    context
        .svm
        .airdrop(&authority.pubkey(), 10_000_000_000)
        .unwrap();

    // NOTE commented these because these accounts need to be empty for the program
    // to initialize them context
    //     .svm
    //     .airdrop(&bytecode_account.pubkey(), 10_000_000_000)
    //     .unwrap();
    // context
    //     .svm
    //     .airdrop(&result_account.pubkey(), 10_000_000_000)
    //     .unwrap();

    // Define a simple program: push 5, push 3, add, return -> should return 8
    let instructions = vec![
        VMInstruction::PushValue { value: 5 },
        VMInstruction::PushValue { value: 3 },
        VMInstruction::Add,
        VMInstruction::Return,
    ];

    // Create instruction data
    let mut instruction_data = Vec::new();
    instruction_data.push(0); // InitializeBytecodeV1 instruction
    instruction_data.extend_from_slice(&[0; 5]); // padding
    instruction_data.extend_from_slice(&(instructions.len() as u16).to_le_bytes());

    // Create initialize bytecode instruction
    let swig_ix = swig_interface::InitializeBytecodeInstruction::new(
        bytecode_account.pubkey(),
        authority.pubkey(),
        system_program::ID,
        &instructions,
    );

    // NOTE commented this out because we actually want to use
    // `swig_interface::InitializeBytecodeInstruction::new` so our instruction is
    // matched properly in the program Serialize instructions

    // for instruction in &instructions {
    //     instruction.serialize(&mut instruction_data).unwrap();
    // }

    // Create accounts vector
    // let accounts = vec![
    //     AccountMeta::new(bytecode_account.pubkey(), true),
    //     AccountMeta::new(authority.pubkey(), true),
    //     AccountMeta::new_readonly(system_program::ID, false),
    // ];

    // // Create the instruction
    // let instruction = Instruction {
    //     program_id: program_id(),
    //     accounts,
    //     data: instruction_data,
    // };

    // Create and send transaction
    let message = v0::Message::try_compile(
        &authority.pubkey(),
        &[swig_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&authority, &bytecode_account],
    )
    .unwrap();

    let result = context.svm.send_transaction(transaction);
    assert!(
        result.is_ok(),
        "Failed to initialize bytecode: {:?}",
        result.err()
    );

    println!("initialize bytecode result: {:?}", result);

    // Verify the bytecode account
    let account = context.svm.get_account(&bytecode_account.pubkey()).unwrap();
    let bytecode: &BytecodeAccount = bytemuck::from_bytes(&account.data);
    println!("bytecode account: {:?}", bytecode);
    assert_eq!(bytecode.authority, authority.pubkey().to_bytes());
    assert_eq!(bytecode.instructions_len, 4);

    // Log the instructions for verification
    println!("Bytecode account instructions:");
    for (i, instr) in bytecode
        .instructions
        .iter()
        .take(bytecode.instructions_len as usize)
        .enumerate()
    {
        println!("  Instruction {}: {:?}", i, instr);
    }
}

#[test_log::test]
fn test_execute_bytecode() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let bytecode_account = Keypair::new();
    let result_account = Keypair::new();

    // Airdrop SOL to accounts
    context
        .svm
        .airdrop(&authority.pubkey(), 10_000_000_000)
        .unwrap();

    // First initialize the bytecode account with our test program
    let instructions = vec![
        VMInstruction::PushValue { value: 5 },
        VMInstruction::PushValue { value: 3 },
        VMInstruction::Add,
        VMInstruction::Return,
    ];

    // Create and send initialization transaction
    let init_ix = swig_interface::InitializeBytecodeInstruction::new(
        bytecode_account.pubkey(),
        authority.pubkey(),
        system_program::ID,
        &instructions,
    );

    let init_message = v0::Message::try_compile(
        &authority.pubkey(),
        &[init_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let init_transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(init_message),
        &[&authority, &bytecode_account],
    )
    .unwrap();

    let init_result = context.svm.send_transaction(init_transaction);
    assert!(
        init_result.is_ok(),
        "Failed to initialize bytecode: {:?}",
        init_result.err()
    );

    // Now execute the bytecode
    let execute_ix = swig_interface::ExecuteBytecodeInstruction::new(
        bytecode_account.pubkey(),
        result_account.pubkey(),
        authority.pubkey(),
        None, // No account indices needed for this simple test
    )
    .unwrap();

    let execute_message = v0::Message::try_compile(
        &authority.pubkey(),
        &[execute_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let execute_transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(execute_message),
        &[&authority, &result_account],
    )
    .unwrap();

    let execute_result = context.svm.send_transaction(execute_transaction);
    assert!(
        execute_result.is_ok(),
        "Failed to execute bytecode: {:?}",
        execute_result.err()
    );

    // Verify the result
    let result_account = context.svm.get_account(&result_account.pubkey()).unwrap();
    let result: &ExecutionResultAccount = bytemuck::from_bytes(&result_account.data);
    assert_eq!(result.result, 8); // 5 + 3 = 8
}
