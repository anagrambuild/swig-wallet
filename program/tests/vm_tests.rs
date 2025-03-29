// NOTE these tests existed to validate the VM functionality when the VM was
// standalone and was not a plugin. This is preserved as a record of how to use
// the SWIG VM in the event we want to revisit the standalone VM for any reason.

// mod common;
// use bytemuck::{Pod, Zeroable};
// use common::*;
// use solana_sdk::{
//     instruction::{AccountMeta, Instruction},
//     message::{v0, VersionedMessage},
//     pubkey::Pubkey,
//     rent::Rent,
//     signature::Keypair,
//     signer::Signer,
//     system_program,
//     transaction::VersionedTransaction,
// };
// use swig_state::{BytecodeAccount, VMInstruction};

// // This is a properly converted Pubkey
// fn program_id() -> Pubkey {
//     swig::ID.into()
// }

// #[test_log::test]
// fn test_initialize_bytecode() {
//     let mut context = setup_test_context().unwrap();
//     let authority = Keypair::new();
//     let bytecode_account = Keypair::new();
//     let result_account = Keypair::new();

//     // Airdrop SOL to accounts
//     context
//         .svm
//         .airdrop(&authority.pubkey(), 10_000_000_000)
//         .unwrap();

//     // NOTE commented these because these accounts need to be empty for the
// program     // to initialize them context
//     //     .svm
//     //     .airdrop(&bytecode_account.pubkey(), 10_000_000_000)
//     //     .unwrap();
//     // context
//     //     .svm
//     //     .airdrop(&result_account.pubkey(), 10_000_000_000)
//     //     .unwrap();

//     // Define a simple program: push 5, push 3, add, return -> should return
// 8     let instructions = vec![
//         VMInstruction::PushValue { value: 5 },
//         VMInstruction::PushValue { value: 3 },
//         VMInstruction::Add,
//         VMInstruction::Return,
//     ];

//     // Create the instruction data
//     let mut instruction_data = Vec::new();
//     instruction_data.push(0); // InitializeBytecodeV1 instruction
//     instruction_data.extend_from_slice(&[0; 5]); // padding
//     instruction_data.extend_from_slice(&(instructions.len() as
// u16).to_le_bytes());

//     // Create initialize bytecode instruction
//     let swig_ix = swig_interface::InitializeBytecodeInstruction::new(
//         bytecode_account.pubkey(),
//         authority.pubkey(),
//         system_program::ID,
//         &instructions,
//     );

//     // NOTE commented this out because we actually want to use
//     // `swig_interface::InitializeBytecodeInstruction::new` so our
// instruction is     // matched properly in the program Serialize instructions

//     // for instruction in &instructions {
//     //     instruction.serialize(&mut instruction_data).unwrap();
//     // }

//     // Create accounts vector
//     // let accounts = vec![
//     //     AccountMeta::new(bytecode_account.pubkey(), true),
//     //     AccountMeta::new(authority.pubkey(), true),
//     //     AccountMeta::new_readonly(system_program::ID, false),
//     // ];

//     // Create the instruction
//     // let ix = Instruction {
//     //     program_id: swig_id, // Use the imported swig_id
//     //     accounts,
//     //     data,
//     // };

//     // // Create the instruction
//     // let instruction = Instruction {
//     //     program_id: program_id(),
//     //     accounts,
//     //     data: instruction_data,
//     // };

//     // Create and send transaction
//     let message = v0::Message::try_compile(
//         &authority.pubkey(),
//         &[swig_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )
//     .unwrap();

//     let transaction = VersionedTransaction::try_new(
//         VersionedMessage::V0(message),
//         &[&authority, &bytecode_account],
//     )
//     .unwrap();

//     let result = context.svm.send_transaction(transaction);
//     assert!(
//         result.is_ok(),
//         "Failed to initialize bytecode: {:?}",
//         result.err()
//     );

//     println!("initialize bytecode result: {:?}", result);

//     // Verify the bytecode account
//     let account =
// context.svm.get_account(&bytecode_account.pubkey()).unwrap();
//     let bytecode: &BytecodeAccount = bytemuck::from_bytes(&account.data);
//     println!("bytecode account: {:?}", bytecode);
//     assert_eq!(bytecode.authority, authority.pubkey().to_bytes());
//     assert_eq!(bytecode.instructions_len, 4);

//     // Log the instructions for verification
//     println!("Bytecode account instructions:");
//     for (i, instr) in bytecode
//         .instructions
//         .iter()
//         .take(bytecode.instructions_len as usize)
//         .enumerate()
//     {
//         println!("  Instruction {}: {:?}", i, instr);
//     }
// }

// #[test_log::test]
// fn test_execute_bytecode() {
//     let mut context = setup_test_context().unwrap();
//     let authority = Keypair::new();
//     let bytecode_account = Keypair::new();

//     // Airdrop SOL to accounts
//     context
//         .svm
//         .airdrop(&authority.pubkey(), 10_000_000_000)
//         .unwrap();

//     // First initialize the bytecode account with our test program
//     let instructions = vec![
//         VMInstruction::PushValue { value: 5 },
//         VMInstruction::PushValue { value: 3 },
//         VMInstruction::Add,
//         VMInstruction::Return,
//     ];

//     // Create and send initialization transaction
//     let init_ix = swig_interface::InitializeBytecodeInstruction::new(
//         bytecode_account.pubkey(),
//         authority.pubkey(),
//         system_program::ID,
//         &instructions,
//     );

//     let init_message = v0::Message::try_compile(
//         &authority.pubkey(),
//         &[init_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )
//     .unwrap();

//     let init_transaction = VersionedTransaction::try_new(
//         VersionedMessage::V0(init_message),
//         &[&authority, &bytecode_account],
//     )
//     .unwrap();

//     let init_result = context.svm.send_transaction(init_transaction);
//     assert!(
//         init_result.is_ok(),
//         "Failed to initialize bytecode: {:?}",
//         init_result.err()
//     );

//     // Now execute the bytecode
//     let execute_ix = swig_interface::ExecuteBytecodeInstruction::new(
//         bytecode_account.pubkey(),
//         authority.pubkey(),
//         None, // No account indices needed for this simple test
//     )
//     .unwrap();

//     let execute_message = v0::Message::try_compile(
//         &authority.pubkey(),
//         &[execute_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )
//     .unwrap();

//     let execute_transaction =
//         VersionedTransaction::try_new(VersionedMessage::V0(execute_message),
// &[&authority])             .unwrap();

//     let execute_result = context.svm.send_transaction(execute_transaction);
//     println!("execute_result: {:?}", execute_result);
//     assert!(
//         execute_result.is_ok(),
//         "Failed to execute bytecode: {:?}",
//         execute_result.err()
//     );
// }

// #[test_log::test]
// fn test_token_account_owner_validation() {
//     let mut context = setup_test_context().unwrap();
//     let wallet = Keypair::new();
//     let recipient = Keypair::new();
//     let bytecode_account = Keypair::new();

//     // 1) Airdrop SOL to wallets
//     context
//         .svm
//         .airdrop(&wallet.pubkey(), 10_000_000_000)
//         .unwrap();
//     context
//         .svm
//         .airdrop(&recipient.pubkey(), 10_000_000_000)
//         .unwrap();

//     // 2) Create a new mint using the setup_mint utility
//     let mint_pubkey = setup_mint(&mut context.svm,
// &context.default_payer).unwrap();     println!("Mint created: {}",
// mint_pubkey);

//     // 3 & 4) Create recipient ATA
//     let recipient_ata = setup_ata(
//         &mut context.svm,
//         &mint_pubkey,
//         &recipient.pubkey(),
//         &context.default_payer,
//     )
//     .unwrap();
//     println!("Recipient ATA created: {}", recipient_ata);

//     // 5) Mint 1000 tokens to the recipient
//     mint_to(
//         &mut context.svm,
//         &mint_pubkey,
//         &context.default_payer,
//         &recipient_ata,
//         1000,
//     )
//     .unwrap();
//     println!("Minted 1000 tokens to recipient ATA");

//     // 6) Create VM instructions for pubkey comparison
//     // The ATA is owned by the recipient, so we need to verify this ownership
//     let recipient_pubkey = recipient.pubkey();
//     let pubkey_bytes = recipient_pubkey.to_bytes();

//     // Create VM instructions for bytecode
//     let mut comparison_instructions = Vec::new();

//     // Start with true (1)
//     comparison_instructions.push(VMInstruction::PushValue { value: 1 });

//     // In an ATA, the owner is at offset 32 in the token account data
//     // Each chunk is 8 bytes (i64 size)

//     // First chunk (bytes 0-8)
//     comparison_instructions.push(VMInstruction::LoadField {
//         account_index: 0, // Token account at index 0
//         field_offset: 32, // Owner field starts at offset 32
//         padding: [0; 4],
//     });

//     // Convert first 8 bytes to i64 and push expected value
//     let mut chunk_bytes = [0u8; 8];
//     chunk_bytes.copy_from_slice(&pubkey_bytes[0..8]);
//     let chunk_value = i64::from_le_bytes(chunk_bytes);
//     comparison_instructions.push(VMInstruction::PushValue { value:
// chunk_value });     comparison_instructions.push(VMInstruction::Equal);
//     comparison_instructions.push(VMInstruction::And); // AND with our initial
// 1

//     // Second chunk (bytes 8-16)
//     comparison_instructions.push(VMInstruction::LoadField {
//         account_index: 0,
//         field_offset: 40, // 32 + 8
//         padding: [0; 4],
//     });
//     chunk_bytes.copy_from_slice(&pubkey_bytes[8..16]);
//     let chunk_value = i64::from_le_bytes(chunk_bytes);
//     comparison_instructions.push(VMInstruction::PushValue { value:
// chunk_value });     comparison_instructions.push(VMInstruction::Equal);
//     comparison_instructions.push(VMInstruction::And);

//     // Third chunk (bytes 16-24)
//     comparison_instructions.push(VMInstruction::LoadField {
//         account_index: 0,
//         field_offset: 48, // 32 + 16
//         padding: [0; 4],
//     });
//     chunk_bytes.copy_from_slice(&pubkey_bytes[16..24]);
//     let chunk_value = i64::from_le_bytes(chunk_bytes);
//     comparison_instructions.push(VMInstruction::PushValue { value:
// chunk_value });     comparison_instructions.push(VMInstruction::Equal);
//     comparison_instructions.push(VMInstruction::And);

//     // Fourth chunk (bytes 24-32)
//     comparison_instructions.push(VMInstruction::LoadField {
//         account_index: 0,
//         field_offset: 56, // 32 + 24
//         padding: [0; 4],
//     });
//     chunk_bytes.copy_from_slice(&pubkey_bytes[24..32]);
//     let chunk_value = i64::from_le_bytes(chunk_bytes);
//     comparison_instructions.push(VMInstruction::PushValue { value:
// chunk_value });     comparison_instructions.push(VMInstruction::Equal);
//     comparison_instructions.push(VMInstruction::And);

//     // Add the final return instruction
//     comparison_instructions.push(VMInstruction::Return);

//     // Initialize bytecode account with our comparison instructions
//     let init_ix = swig_interface::InitializeBytecodeInstruction::new(
//         bytecode_account.pubkey(),
//         wallet.pubkey(),
//         system_program::ID,
//         &comparison_instructions,
//     );

//     let init_message = v0::Message::try_compile(
//         &wallet.pubkey(),
//         &[init_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )
//     .unwrap();

//     let init_transaction = VersionedTransaction::try_new(
//         VersionedMessage::V0(init_message),
//         &[&wallet, &bytecode_account],
//     )
//     .unwrap();

//     let init_result = context.svm.send_transaction(init_transaction);
//     assert!(
//         init_result.is_ok(),
//         "Failed to initialize comparison bytecode: {:?}",
//         init_result.err()
//     );
//     println!(
//         "Bytecode account initialized for token owner verification: {:?}",
//         init_result
//     );

//     // 7) Execute the bytecode with token_account as a remaining account
//     // Use the proper ExecuteBytecodeInstruction with Some account indices
//     let account_indices = Some(vec![0u8]);
//     let execute_ix = swig_interface::ExecuteBytecodeInstruction::new(
//         bytecode_account.pubkey(),
//         wallet.pubkey(),
//         account_indices,
//     )
//     .unwrap();

//     // Add the recipient_ata as the last account in the instruction accounts
// vector     let mut execute_ix_mut = execute_ix;
//     execute_ix_mut
//         .accounts
//         .push(AccountMeta::new_readonly(recipient_ata, false));

//     // Create the message without using the third parameter for lookup tables
//     let message = v0::Message::try_compile(
//         &wallet.pubkey(),
//         &[execute_ix_mut],
//         &[], // No lookup tables
//         context.svm.latest_blockhash(),
//     )
//     .unwrap();

//     let execute_transaction =
//         VersionedTransaction::try_new(VersionedMessage::V0(message),
// &[&wallet]).unwrap();

//     let execute_result = context.svm.send_transaction(execute_transaction);

//     println!(
//         "Token owner validation bytecode execution result: {:?}",
//         execute_result
//     );

//     // Should succeed because the recipient is the owner of the ATA
//     assert!(
//         execute_result.is_ok(),
//         "Token owner validation failed: {:?}",
//         execute_result.err()
//     );
//     println!("Token owner validation succeeded!");

//     // Optionally, try with an incorrect owner to ensure validation fails
//     let wrong_owner = Keypair::new();
//     println!("Now trying with incorrect owner: {}", wrong_owner.pubkey());

//     // Create new bytecode with wrong owner pubkey for comparison
//     let wrong_bytecode_account = Keypair::new();
//     let wrong_pubkey_bytes = wrong_owner.pubkey().to_bytes();
//     let mut wrong_comparison_instructions = Vec::new();

//     // Start with true (1)
//     wrong_comparison_instructions.push(VMInstruction::PushValue { value: 1
// });

//     // First chunk with wrong owner
//     wrong_comparison_instructions.push(VMInstruction::LoadField {
//         account_index: 0,
//         field_offset: 32,
//         padding: [0; 4],
//     });

//     chunk_bytes.copy_from_slice(&wrong_pubkey_bytes[0..8]);
//     let chunk_value = i64::from_le_bytes(chunk_bytes);
//     wrong_comparison_instructions.push(VMInstruction::PushValue { value:
// chunk_value });     wrong_comparison_instructions.push(VMInstruction::Equal);
//     wrong_comparison_instructions.push(VMInstruction::And);

//     // Second chunk with wrong owner
//     wrong_comparison_instructions.push(VMInstruction::LoadField {
//         account_index: 0,
//         field_offset: 40,
//         padding: [0; 4],
//     });
//     chunk_bytes.copy_from_slice(&wrong_pubkey_bytes[8..16]);
//     let chunk_value = i64::from_le_bytes(chunk_bytes);
//     wrong_comparison_instructions.push(VMInstruction::PushValue { value:
// chunk_value });     wrong_comparison_instructions.push(VMInstruction::Equal);
//     wrong_comparison_instructions.push(VMInstruction::And);

//     // Third chunk with wrong owner
//     wrong_comparison_instructions.push(VMInstruction::LoadField {
//         account_index: 0,
//         field_offset: 48,
//         padding: [0; 4],
//     });
//     chunk_bytes.copy_from_slice(&wrong_pubkey_bytes[16..24]);
//     let chunk_value = i64::from_le_bytes(chunk_bytes);
//     wrong_comparison_instructions.push(VMInstruction::PushValue { value:
// chunk_value });     wrong_comparison_instructions.push(VMInstruction::Equal);
//     wrong_comparison_instructions.push(VMInstruction::And);

//     // Fourth chunk with wrong owner
//     wrong_comparison_instructions.push(VMInstruction::LoadField {
//         account_index: 0,
//         field_offset: 56,
//         padding: [0; 4],
//     });
//     chunk_bytes.copy_from_slice(&wrong_pubkey_bytes[24..32]);
//     let chunk_value = i64::from_le_bytes(chunk_bytes);
//     wrong_comparison_instructions.push(VMInstruction::PushValue { value:
// chunk_value });     wrong_comparison_instructions.push(VMInstruction::Equal);
//     wrong_comparison_instructions.push(VMInstruction::And);

//     // Return the comparison result
//     wrong_comparison_instructions.push(VMInstruction::Return);

//     // Initialize bytecode account with wrong owner instructions
//     let wrong_init_ix = swig_interface::InitializeBytecodeInstruction::new(
//         wrong_bytecode_account.pubkey(),
//         wallet.pubkey(),
//         system_program::ID,
//         &wrong_comparison_instructions,
//     );

//     let wrong_init_message = v0::Message::try_compile(
//         &wallet.pubkey(),
//         &[wrong_init_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )
//     .unwrap();

//     let wrong_init_transaction = VersionedTransaction::try_new(
//         VersionedMessage::V0(wrong_init_message),
//         &[&wallet, &wrong_bytecode_account],
//     )
//     .unwrap();

//     let wrong_init_result =
// context.svm.send_transaction(wrong_init_transaction);     assert!(
//         wrong_init_result.is_ok(),
//         "Failed to initialize wrong owner bytecode: {:?}",
//         wrong_init_result.err()
//     );
//     println!("Wrong owner bytecode initialized: {:?}", wrong_init_result);

//     // Execute the bytecode with wrong owner validation
//     let wrong_execute_ix = swig_interface::ExecuteBytecodeInstruction::new(
//         wrong_bytecode_account.pubkey(),
//         wallet.pubkey(),
//         Some(vec![0u8]),
//     )
//     .unwrap();

//     // Add the recipient_ata as the last account in the instruction accounts
// vector     let mut wrong_execute_ix_mut = wrong_execute_ix;
//     wrong_execute_ix_mut
//         .accounts
//         .push(AccountMeta::new_readonly(recipient_ata, false));

//     // Create the message without using the third parameter for lookup tables
//     let wrong_message = v0::Message::try_compile(
//         &wallet.pubkey(),
//         &[wrong_execute_ix_mut],
//         &[], // No lookup tables
//         context.svm.latest_blockhash(),
//     )
//     .unwrap();

//     let wrong_execute_transaction =
//         VersionedTransaction::try_new(VersionedMessage::V0(wrong_message),
// &[&wallet]).unwrap();

//     let wrong_execute_result =
// context.svm.send_transaction(wrong_execute_transaction);     println!("Wrong
// owner validation result: {:?}", wrong_execute_result);

//     // The wrong owner validation should return 0 (false) because the
// comparison     // will fail Since we're using the wrong owner pubkey for
// comparison but the     // correct ATA
//     println!("Test completed for token owner validation via VM bytecode");
// }

// #[test_log::test]
// fn test_plugin_bytecode_token_validation() {
//     let mut context = setup_test_context().unwrap();
//     let wallet = Keypair::new();
//     let recipient = Keypair::new();

//     // Get the token program ID
//     let token_program_id = litesvm_token::spl_token::ID;

//     // Derive a PDA for the plugin bytecode account using "swig-pim" seed and
// token     // program id
//     let seeds = &[b"swig-pim", token_program_id.as_ref()];
//     let (plugin_bytecode_account, _) = Pubkey::find_program_address(seeds,
// &program_id());

//     println!("Plugin bytecode PDA: {}", plugin_bytecode_account);

//     // 1) Airdrop SOL to wallets
//     context
//         .svm
//         .airdrop(&wallet.pubkey(), 10_000_000_000)
//         .unwrap();
//     context
//         .svm
//         .airdrop(&recipient.pubkey(), 10_000_000_000)
//         .unwrap();

//     // 2) Create a new mint
//     let mint_pubkey = setup_mint(&mut context.svm,
// &context.default_payer).unwrap();     println!("Mint created: {}",
// mint_pubkey);

//     // 3) Create recipient ATA
//     let recipient_ata = setup_ata(
//         &mut context.svm,
//         &mint_pubkey,
//         &recipient.pubkey(),
//         &context.default_payer,
//     )
//     .unwrap();
//     println!("Recipient ATA created: {}", recipient_ata);

//     // 4) Mint 1000 tokens to the recipient
//     mint_to(
//         &mut context.svm,
//         &mint_pubkey,
//         &context.default_payer,
//         &recipient_ata,
//         1000,
//     )
//     .unwrap();
//     println!("Minted 1000 tokens to recipient ATA");

//     // 5) Create plugin VM instructions for pubkey comparison
//     // The ATA is owned by the recipient, so we need to verify this ownership
//     let recipient_pubkey = recipient.pubkey();
//     let pubkey_bytes = recipient_pubkey.to_bytes();

//     // Create VM instructions for plugin bytecode
//     let mut comparison_instructions = Vec::new();

//     // Start with true (1)
//     comparison_instructions.push(VMInstruction::PushValue { value: 1 });

//     // In an ATA, the owner is at offset 32 in the token account data
//     // Each chunk is 8 bytes (i64 size)

//     // First chunk (bytes 0-8)
//     comparison_instructions.push(VMInstruction::LoadField {
//         account_index: 0, // Token account at index 0
//         field_offset: 32, // Owner field starts at offset 32
//         padding: [0; 4],
//     });

//     // Convert first 8 bytes to i64 and push expected value
//     let mut chunk_bytes = [0u8; 8];
//     chunk_bytes.copy_from_slice(&pubkey_bytes[0..8]);
//     let chunk_value = i64::from_le_bytes(chunk_bytes);
//     comparison_instructions.push(VMInstruction::PushValue { value:
// chunk_value });     comparison_instructions.push(VMInstruction::Equal);
//     comparison_instructions.push(VMInstruction::And); // AND with our initial
// 1

//     // Second chunk (bytes 8-16)
//     comparison_instructions.push(VMInstruction::LoadField {
//         account_index: 0,
//         field_offset: 40, // 32 + 8
//         padding: [0; 4],
//     });
//     chunk_bytes.copy_from_slice(&pubkey_bytes[8..16]);
//     let chunk_value = i64::from_le_bytes(chunk_bytes);
//     comparison_instructions.push(VMInstruction::PushValue { value:
// chunk_value });     comparison_instructions.push(VMInstruction::Equal);
//     comparison_instructions.push(VMInstruction::And);

//     // Third chunk (bytes 16-24)
//     comparison_instructions.push(VMInstruction::LoadField {
//         account_index: 0,
//         field_offset: 48, // 32 + 16
//         padding: [0; 4],
//     });
//     chunk_bytes.copy_from_slice(&pubkey_bytes[16..24]);
//     let chunk_value = i64::from_le_bytes(chunk_bytes);
//     comparison_instructions.push(VMInstruction::PushValue { value:
// chunk_value });     comparison_instructions.push(VMInstruction::Equal);
//     comparison_instructions.push(VMInstruction::And);

//     // Fourth chunk (bytes 24-32)
//     comparison_instructions.push(VMInstruction::LoadField {
//         account_index: 0,
//         field_offset: 56, // 32 + 24
//         padding: [0; 4],
//     });
//     chunk_bytes.copy_from_slice(&pubkey_bytes[24..32]);
//     let chunk_value = i64::from_le_bytes(chunk_bytes);
//     comparison_instructions.push(VMInstruction::PushValue { value:
// chunk_value });     comparison_instructions.push(VMInstruction::Equal);
//     comparison_instructions.push(VMInstruction::And);

//     // Add the final return instruction
//     comparison_instructions.push(VMInstruction::Return);

//     // Initialize plugin bytecode account with our comparison instructions
//     let create_plugin_ix =
// swig_interface::CreatePluginBytecodeInstruction::new(
//         plugin_bytecode_account,
//         token_program_id,
//         token_program_id, // Using token_program_id as program_data for
// simplicity         wallet.pubkey(),
//         system_program::ID,
//         &comparison_instructions,
//     );

//     let create_plugin_message = v0::Message::try_compile(
//         &wallet.pubkey(),
//         &[create_plugin_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )
//     .unwrap();

//     let create_plugin_tx =
//         VersionedTransaction::try_new(VersionedMessage::V0(create_plugin_message), &[&wallet])
//             .unwrap();

//     let create_plugin_result =
// context.svm.send_transaction(create_plugin_tx);     assert!(
//         create_plugin_result.is_ok(),
//         "Failed to create plugin bytecode account: {:?}",
//         create_plugin_result.err()
//     );
//     println!(
//         "Plugin bytecode account created for token owner verification: {:?}",
//         create_plugin_result
//     );

//     // Execute the plugin bytecode with token_account as a remaining account
//     // Use the proper ExecutePluginBytecodeInstruction with Some account
// indices     let account_indices = Some(vec![0u8]);
//     let execute_plugin_ix =
// swig_interface::ExecutePluginBytecodeInstruction::new(
//         plugin_bytecode_account,
//         token_program_id,
//         wallet.pubkey(), // Use wallet as a temp placeholder for result
// account         wallet.pubkey(),
//         account_indices,
//     )
//     .unwrap();

//     // Add the recipient_ata as the remaining account in the instruction
// accounts     // vector
//     let mut execute_plugin_ix_mut = execute_plugin_ix;
//     execute_plugin_ix_mut
//         .accounts
//         .push(AccountMeta::new_readonly(recipient_ata, false));

//     let execute_plugin_message = v0::Message::try_compile(
//         &wallet.pubkey(),
//         &[execute_plugin_ix_mut],
//         &[],
//         context.svm.latest_blockhash(),
//     )
//     .unwrap();

//     let execute_plugin_tx =
//         VersionedTransaction::try_new(VersionedMessage::V0(execute_plugin_message), &[&wallet])
//             .unwrap();

//     let execute_plugin_result =
// context.svm.send_transaction(execute_plugin_tx);     println!(
//         "Plugin token owner validation execution result: {:?}",
//         execute_plugin_result
//     );

//     // Should succeed because the recipient is the owner of the ATA
//     assert!(
//         execute_plugin_result.is_ok(),
//         "Token owner validation failed: {:?}",
//         execute_plugin_result.err()
//     );
//     println!("Token owner validation via plugin succeeded!");
// }
