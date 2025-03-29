mod common;
use borsh::BorshDeserialize;
use common::*;
use litesvm_token::spl_token::{self, instruction::TokenInstruction};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_program,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_state::{swig_account_seeds, Swig, VMInstruction};

#[test_log::test]
fn test_create() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 13]>();
    let swig_created = create_swig_ed25519(&mut context, &authority, &id);
    assert!(swig_created.is_ok(), "{:?}", swig_created.err());
    let (swig_key, bench) = swig_created.unwrap();
    println!("Create CU {:?}", bench.compute_units_consumed);
    if let Some(account) = context.svm.get_account(&swig_key) {
        let swig = Swig::try_from_slice(&account.data).unwrap();
        let roles = swig.roles;
        assert_eq!(roles.len(), 1);
    }
}

#[test_log::test]
fn test_create_basic_token_transfer() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &recipient.pubkey(),
        &recipient,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, &id);
    assert!(swig_create_txn.is_ok());

    let ixd = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer { amount: 100 }.pack(),
    };

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        swig_authority.pubkey(),
        swig_authority.pubkey(),
        ixd,
        0,
    )
    .unwrap();
    let transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&swig_authority])
            .unwrap();
    let res = context.svm.send_transaction(transfer_tx);
    if res.is_err() {
        println!("{:?}", res.err());
    } else {
        println!("Sign Transfer CU {:?}", res.unwrap().compute_units_consumed);
    }
    let account = context.svm.get_account(&swig_ata).unwrap();
    let token_account = spl_token::state::Account::unpack(&account.data).unwrap();
    assert_eq!(token_account.amount, 900);
}

#[test_log::test]
fn test_plugin_in_sign_v1() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    // Airdrop SOL to accounts
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Get the token program ID
    let token_program_id = litesvm_token::spl_token::ID;

    // Derive a PDA for the plugin bytecode account using "swig-pim" seed and token
    // program id
    let seeds = &[b"swig-pim", token_program_id.as_ref()];
    let (plugin_bytecode_account, _) = Pubkey::find_program_address(seeds, &program_id());
    println!("Plugin bytecode PDA: {}", plugin_bytecode_account);

    // Create Swig wallet
    let id = rand::random::<[u8; 13]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, &id);
    assert!(swig_create_txn.is_ok());
    println!("Created Swig wallet: {}", swig);

    // Create a token mint and ATAs
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    println!("Created mint: {}", mint_pubkey);

    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();
    println!("Created Swig ATA: {}", swig_ata);

    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &recipient.pubkey(),
        &recipient,
    )
    .unwrap();
    println!("Created recipient ATA: {}", recipient_ata);

    // Mint tokens to the swig wallet
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();
    println!("Minted 1000 tokens to Swig ATA");

    // Create a plugin that validates token account ownership
    // This plugin will validate that the token account's owner matches the expected
    // account If it matches, it returns 0 (allow), otherwise returns 1 (deny)

    // For testing with sign_v1, we'll create a plugin that checks the recipient's
    // ATA to ensure it's owned by the recipient
    let recipient_pubkey = recipient.pubkey();
    let pubkey_bytes = recipient_pubkey.to_bytes();

    // Create VM instructions for plugin bytecode
    let mut comparison_instructions = Vec::new();

    // Start with true (1)
    comparison_instructions.push(VMInstruction::PushValue { value: 1 });

    // In an ATA, the owner is at offset 32 in the token account data
    // Each chunk is 8 bytes (i64 size)

    // First chunk (bytes 0-8)
    comparison_instructions.push(VMInstruction::LoadField {
        account_index: 0, // Token account at index 0
        field_offset: 32, // Owner field starts at offset 32
        padding: [0; 4],
    });

    // Convert first 8 bytes to i64 and push expected value
    let mut chunk_bytes = [0u8; 8];
    chunk_bytes.copy_from_slice(&pubkey_bytes[0..8]);
    let chunk_value = i64::from_le_bytes(chunk_bytes);
    comparison_instructions.push(VMInstruction::PushValue { value: chunk_value });
    comparison_instructions.push(VMInstruction::Equal);
    comparison_instructions.push(VMInstruction::And); // AND with our initial 1

    // Second chunk (bytes 8-16)
    comparison_instructions.push(VMInstruction::LoadField {
        account_index: 0,
        field_offset: 40, // 32 + 8
        padding: [0; 4],
    });
    chunk_bytes.copy_from_slice(&pubkey_bytes[8..16]);
    let chunk_value = i64::from_le_bytes(chunk_bytes);
    comparison_instructions.push(VMInstruction::PushValue { value: chunk_value });
    comparison_instructions.push(VMInstruction::Equal);
    comparison_instructions.push(VMInstruction::And);

    // Third chunk (bytes 16-24)
    comparison_instructions.push(VMInstruction::LoadField {
        account_index: 0,
        field_offset: 48, // 32 + 16
        padding: [0; 4],
    });
    chunk_bytes.copy_from_slice(&pubkey_bytes[16..24]);
    let chunk_value = i64::from_le_bytes(chunk_bytes);
    comparison_instructions.push(VMInstruction::PushValue { value: chunk_value });
    comparison_instructions.push(VMInstruction::Equal);
    comparison_instructions.push(VMInstruction::And);

    // Fourth chunk (bytes 24-32)
    comparison_instructions.push(VMInstruction::LoadField {
        account_index: 0,
        field_offset: 56, // 32 + 24
        padding: [0; 4],
    });
    chunk_bytes.copy_from_slice(&pubkey_bytes[24..32]);
    let chunk_value = i64::from_le_bytes(chunk_bytes);
    comparison_instructions.push(VMInstruction::PushValue { value: chunk_value });
    comparison_instructions.push(VMInstruction::Equal);
    comparison_instructions.push(VMInstruction::And);

    // Return the inverse of the comparison result (0 = success, non-zero = reject)
    // If owner matches recipient, result will be 1, so we use the Not instruction
    // to make it 0 (success)
    comparison_instructions.push(VMInstruction::Not);
    comparison_instructions.push(VMInstruction::Return);

    // Create a plugin bytecode account
    let create_plugin_ix = swig_interface::CreatePluginBytecodeInstruction::new(
        plugin_bytecode_account,
        token_program_id,
        token_program_id, // Using token_program_id as program_data for simplicity
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        context.swig_config,
        system_program::ID,
        &comparison_instructions,
    );

    let create_plugin_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[create_plugin_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let create_plugin_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(create_plugin_message),
        &[&swig_authority, &context.default_payer],
    )
    .unwrap();

    let create_plugin_result = context.svm.send_transaction(create_plugin_tx);
    assert!(
        create_plugin_result.is_ok(),
        "Failed to create plugin bytecode account: {:?}",
        create_plugin_result.err()
    );
    println!(
        "Created plugin bytecode account: {:?}",
        create_plugin_result
    );

    // Now create a token transfer instruction to be executed via sign_v1
    let transfer_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer { amount: 100 }.pack(),
    };

    // Create the sign_v1 instruction with the token transfer
    let sign_ix = swig_interface::SignInstruction::new_ed25519_with_plugin_targets(
        swig,
        swig_authority.pubkey(),
        swig_authority.pubkey(),
        transfer_ix,
        0,
        &[4], // Index of recipient_ata in the transaction
    )
    .unwrap();

    // Include the plugin bytecode account as an additional account
    let mut sign_ix_mut = sign_ix.clone();
    sign_ix_mut
        .accounts
        .push(AccountMeta::new_readonly(plugin_bytecode_account, false));

    // Create and send the transaction
    let transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_ix_mut],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&swig_authority])
            .unwrap();

    let transfer_result = context.svm.send_transaction(transfer_tx);
    println!("transfer_result: {:?}", transfer_result);
    assert!(
        transfer_result.is_ok(),
        "Token transfer with plugin validation failed: {:?}",
        transfer_result.err()
    );
    println!("Token transfer with plugin validation succeeded!");

    // Verify the token transfer was successful
    let account = context.svm.get_account(&swig_ata).unwrap();
    let token_account = spl_token::state::Account::unpack(&account.data).unwrap();
    assert_eq!(token_account.amount, 900);
}
