use solana_program::pubkey::Pubkey;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    signature::{Keypair, Signer},
    system_instruction,
    transaction::VersionedTransaction,
};
use swig_interface::program_id;
use swig_state::{
    authority::{programexec::ProgramExecAuthority, AuthorityType},
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
};

use super::*;
use crate::{client_role::ProgramExecClientRole, types::Permission, Ed25519ClientRole};

// Test program ID (same as used in program tests)
const TEST_PROGRAM_ID: Pubkey = solana_program::pubkey!("BXAu5ZWHnGun2XZjUZ9nqwiZ5dNVmofPGYdMC4rx4qLV");
const VALID_DISCRIMINATOR: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

#[test_log::test]
fn test_program_exec_sign_with_preceding_instruction() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [42u8; 32];
    let ed25519_authority = Keypair::new();
    let root_role_id = 0;

    // Create Swig wallet with Ed25519 root authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &ed25519_authority, swig_id).unwrap();

    let payer = context.default_payer.pubkey();

    // Get swig wallet address PDA
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    // Airdrop to swig wallet so it can execute transfers
    context.svm.airdrop(&swig_wallet_address, 10_000_000).unwrap();

    // Create ProgramExec authority
    let program_exec_role = ProgramExecClientRole::new(
        TEST_PROGRAM_ID,
        VALID_DISCRIMINATOR.to_vec(),
    );

    // Add ProgramExec authority using root authority
    let mut root_builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(ed25519_authority.pubkey())),
        payer,
        root_role_id,
    );

    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let permissions = vec![Permission::All];

    let add_auth_ix = root_builder
        .add_authority_instruction(
            AuthorityType::ProgramExec,
            &program_exec_role.authority_data(),
            permissions,
            Some(current_slot),
        )
        .unwrap();

    // Execute add authority instruction
    let msg = v0::Message::try_compile(
        &payer,
        &add_auth_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &ed25519_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to add ProgramExec authority: {:?}",
        result.err()
    );

    // Verify authority was added
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_data.state.roles, 2, "Should have 2 roles (root + program exec)");

    // Now use ProgramExec authority to sign a transfer
    let program_exec_role_id = 1; // The role ID of the ProgramExec authority we just added
    let recipient = Keypair::new();

    // Create the preceding instruction that the test program will execute
    // This instruction validates that it came from TEST_PROGRAM_ID with VALID_DISCRIMINATOR
    let preceding_instruction = Instruction {
        program_id: TEST_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(swig_key, false),           // config
            AccountMeta::new_readonly(swig_wallet_address, false), // wallet
        ],
        data: VALID_DISCRIMINATOR.to_vec(),
    };

    // Create the inner instruction that will be signed by the swig wallet
    let transfer_instruction = system_instruction::transfer(
        &swig_wallet_address,
        &recipient.pubkey(),
        1_000_000,
    );

    // Use ProgramExecClientRole to create both instructions
    let instructions = program_exec_role
        .sign_with_program_exec(
            swig_key,
            swig_wallet_address,
            payer,
            preceding_instruction,
            transfer_instruction,
            program_exec_role_id,
        )
        .unwrap();

    // The instructions vector contains [preceding_instruction, sign_instruction]
    assert_eq!(instructions.len(), 2, "Should have 2 instructions");

    // Note: This test would need the actual TEST_PROGRAM to be deployed to execute successfully.
    // For now, we're just testing that the instruction builder correctly creates the instructions.
    println!("✓ Successfully created ProgramExec sign instructions");
    println!("  - Preceding instruction program: {}", instructions[0].program_id);
    println!("  - Sign instruction program: {}", instructions[1].program_id);
    println!("  - Total instructions: {}", instructions.len());
}

#[test_log::test]
fn test_program_exec_authority_data_generation() {
    // Test that authority data is generated correctly
    let program_exec_role = ProgramExecClientRole::new(
        TEST_PROGRAM_ID,
        VALID_DISCRIMINATOR.to_vec(),
    );

    let authority_data = program_exec_role.authority_data();

    // Verify the authority data is not empty
    assert!(!authority_data.is_empty(), "Authority data should not be empty");

    // The authority data should contain the program ID and discriminator
    println!("✓ Authority data length: {} bytes", authority_data.len());

    // Verify the authority data contains the expected information
    // The format is: [program_id: 32 bytes][instruction_prefix_len: 1 byte][padding: 7 bytes][instruction_prefix: 40 bytes]
    assert_eq!(authority_data.len(), 80, "Authority data should be exactly 80 bytes");

    // Verify program ID (first 32 bytes)
    assert_eq!(
        &authority_data[0..32],
        &TEST_PROGRAM_ID.to_bytes(),
        "Program ID should match in authority data"
    );

    // Verify discriminator length (at offset 32)
    let prefix_len = authority_data[32] as usize;
    assert_eq!(prefix_len, VALID_DISCRIMINATOR.len(), "Prefix length should match");

    // Verify discriminator (starts at offset 40 after program_id + prefix_len + padding)
    const IX_PREFIX_OFFSET: usize = 40; // 32 + 1 + 7
    assert_eq!(
        &authority_data[IX_PREFIX_OFFSET..IX_PREFIX_OFFSET + prefix_len],
        &VALID_DISCRIMINATOR,
        "Discriminator should match in authority data"
    );
}

#[test_log::test]
fn test_program_exec_with_multiple_authorities() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [99u8; 32];
    let ed25519_authority = Keypair::new();

    // Create Swig wallet
    let (swig_key, _) = create_swig_ed25519(&mut context, &ed25519_authority, swig_id).unwrap();

    let payer = context.default_payer.pubkey();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    context.svm.airdrop(&swig_wallet_address, 10_000_000).unwrap();

    // Add multiple ProgramExec authorities with different discriminators
    let discriminator1 = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let discriminator2 = vec![9, 10, 11, 12, 13, 14, 15, 16];

    let program_exec_role1 = ProgramExecClientRole::new(
        TEST_PROGRAM_ID,
        discriminator1.clone(),
    );

    let program_exec_role2 = ProgramExecClientRole::new(
        TEST_PROGRAM_ID,
        discriminator2.clone(),
    );

    let mut root_builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(ed25519_authority.pubkey())),
        payer,
        0,
    );

    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    // Add first ProgramExec authority
    let add_auth_ix1 = root_builder
        .add_authority_instruction(
            AuthorityType::ProgramExec,
            &program_exec_role1.authority_data(),
            vec![Permission::All],
            Some(current_slot),
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &payer,
        &add_auth_ix1,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &ed25519_authority],
    )
    .unwrap();

    context.svm.send_transaction(tx).unwrap();

    // Add second ProgramExec authority
    let add_auth_ix2 = root_builder
        .add_authority_instruction(
            AuthorityType::ProgramExec,
            &program_exec_role2.authority_data(),
            vec![Permission::All],
            Some(current_slot),
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &payer,
        &add_auth_ix2,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &ed25519_authority],
    )
    .unwrap();

    context.svm.send_transaction(tx).unwrap();

    // Verify both authorities were added
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(
        swig_data.state.roles, 3,
        "Should have 3 roles (root + 2 program exec)"
    );

    println!("✓ Successfully added multiple ProgramExec authorities");
    println!("  - Total roles: {}", swig_data.state.roles);
}
