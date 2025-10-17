#![cfg(not(feature = "program_scope_test"))]

mod common;

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
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state::{
    action::{all::All, program::Program},
    authority::{programexec::ProgramExecAuthority, AuthorityType},
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
    IntoBytes, Transmutable,
};

// Test program ID - matches the declared ID in
// test-program-authority/src/lib.rs
solana_sdk::declare_id!("BXAu5ZWHnGun2XZjUZ9nqwiZ5dNVmofPGYdMC4rx4qLV");
const TEST_PROGRAM_ID: Pubkey = ID;

// Test program binary path
const TEST_PROGRAM_PATH: &str = "../target/deploy/test_program_authority.so";

// Test program instruction discriminators (must match
// test-program-authority/src/processor.rs)
const VALID_DISCRIMINATOR: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const INVALID_DISCRIMINATOR: [u8; 8] = [9, 9, 9, 9, 9, 9, 9, 9];

/// Helper function to deploy the test program
fn deploy_test_program(context: &mut SwigTestContext) -> anyhow::Result<()> {
    let program_data = std::fs::read(TEST_PROGRAM_PATH).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read test program: {}. Make sure to run `cargo build-sbf` first.",
            e
        )
    })?;

    context.svm.add_program(TEST_PROGRAM_ID, &program_data);
    Ok(())
}

/// Helper function to create or update the test program state account
fn set_test_program_state(
    context: &mut SwigTestContext,
    state_account: &Pubkey,
    should_fail: bool,
) -> anyhow::Result<()> {
    let state_data = vec![if should_fail { 1u8 } else { 0u8 }];

    // Create or update account
    let account = solana_sdk::account::Account {
        lamports: 1_000_000,
        data: state_data,
        owner: TEST_PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    };

    context.svm.set_account(*state_account, account)?;
    Ok(())
}

/// Helper function to create a ProgramExec authority
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

/// Test creating a swig with a ProgramExec authority
#[test_log::test]
fn test_create_program_exec_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create swig with root Ed25519 authority first
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Now add a ProgramExec authority
    let program_exec_data =
        create_program_exec_authority_data(TEST_PROGRAM_ID, &VALID_DISCRIMINATOR);

    let result = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::ProgramExec,
            authority: &program_exec_data,
        },
        vec![
            ClientAction::Program(Program {
                program_id: spl_token::ID.to_bytes(),
            }),
            ClientAction::All(All {}),
        ],
    );

    assert!(
        result.is_ok(),
        "Failed to add ProgramExec authority: {:?}",
        result.err()
    );

    // Verify the authority was added
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();

    assert_eq!(
        swig.state.roles, 2,
        "Should have 2 roles (root + program exec)"
    );

    // Verify the program exec authority
    let role_1 = swig.get_role(1).unwrap().unwrap();
    assert_eq!(
        role_1.position.authority_type().unwrap(),
        AuthorityType::ProgramExec,
        "Second authority should be ProgramExec"
    );
}

/// Test changing a ProgramExec authority's discriminator via remove + add
/// Note: UpdateAuthority only modifies permissions/actions, not authority data
/// itself, so to change the discriminator we need to remove and re-add the
/// authority.
#[test_log::test]
fn test_update_program_exec_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Add initial ProgramExec authority
    let initial_discriminator = [1, 2, 3, 4, 5, 6, 7, 8];
    let program_exec_data =
        create_program_exec_authority_data(TEST_PROGRAM_ID, &initial_discriminator);

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::ProgramExec,
            authority: &program_exec_data,
        },
        vec![ClientAction::All(All {})],
    )
    .unwrap();

    // Verify initial state
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(
        swig.state.roles, 2,
        "Should have 2 roles (root + program exec)"
    );

    // To "update" the discriminator, we need to remove the old authority and add a
    // new one because UpdateAuthority only modifies permissions/actions, not
    // authority data itself

    // Step 1: Remove the existing ProgramExec authority
    use swig_interface::RemoveAuthorityInstruction;

    let authority_to_remove_id = 1; // The ProgramExec authority we just added

    let remove_ix = RemoveAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        swig_authority.pubkey(),
        swig_authority.pubkey(),
        0, // acting_role_id (root authority)
        authority_to_remove_id,
    )
    .unwrap();

    // Execute remove instruction
    let msg = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[remove_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&swig_authority]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to remove ProgramExec authority: {:?}",
        result.err()
    );

    // Verify we're back to 1 role
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 1, "Should have 1 role after removal");

    // Step 2: Add a new ProgramExec authority with updated discriminator
    let new_discriminator = [9, 8, 7, 6, 5, 4, 3, 2];
    let updated_program_exec_data =
        create_program_exec_authority_data(TEST_PROGRAM_ID, &new_discriminator);

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::ProgramExec,
            authority: &updated_program_exec_data,
        },
        vec![ClientAction::All(All {})],
    )
    .unwrap();

    // Verify we have 2 roles again
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 2, "Should have 2 roles after re-adding");

    // Verify the new discriminator by checking the authority data
    // The new authority will have role_id = 2 (since role_id = 1 was removed)
    let new_role_id = 2;
    let role = swig.get_role(new_role_id).unwrap().unwrap();

    // The authority should be ProgramExec
    assert_eq!(
        role.authority.authority_type(),
        AuthorityType::ProgramExec,
        "Authority type should be ProgramExec"
    );

    // Downcast to ProgramExecAuthority to access the concrete type
    let program_exec_auth: &ProgramExecAuthority = role.authority.as_any().downcast_ref().unwrap();

    // Verify the program_id is correct
    assert_eq!(
        program_exec_auth.program_id,
        TEST_PROGRAM_ID.to_bytes(),
        "Program ID should match"
    );

    // Verify the discriminator was updated
    let stored_discriminator = &program_exec_auth.instruction_prefix[..new_discriminator.len()];
    assert_eq!(
        stored_discriminator, &new_discriminator,
        "Discriminator should be updated to new value"
    );
}

/// Helper to build program exec sign instructions using the ergonomic interface
/// This now uses SignV2Instruction::new_program_exec() which returns both the
/// preceding instruction and the sign instruction that must be executed
/// together.
///
/// authority_payload format: [instruction_sysvar_index: 1]
fn build_program_exec_sign_instructions(
    swig_account: Pubkey,
    swig_wallet_address: Pubkey,
    payer: Pubkey,
    preceding_instruction: Instruction,
    inner_instruction: Instruction,
    role_id: u32,
) -> anyhow::Result<Vec<Instruction>> {
    use swig_interface::SignV2Instruction;

    SignV2Instruction::new_program_exec(
        swig_account,
        swig_wallet_address,
        payer,
        preceding_instruction,
        inner_instruction,
        role_id,
    )
}

/// Test successful execution with valid program and state set to succeed
#[test_log::test]
fn test_program_exec_successful_execution() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let state_account = Keypair::new();

    // Deploy the test program
    deploy_test_program(&mut context).expect("Failed to deploy test program");

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    // Create swig with Ed25519 root
    create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Airdrop to swig and swig_wallet after creation so they can execute transfers
    context.svm.airdrop(&swig, 10_000_000).unwrap();
    context.svm.airdrop(&swig_wallet, 10_000_000).unwrap();

    // Add ProgramExec authority that expects test program calls
    let program_exec_data =
        create_program_exec_authority_data(TEST_PROGRAM_ID, &VALID_DISCRIMINATOR);

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::ProgramExec,
            authority: &program_exec_data,
        },
        vec![ClientAction::All(All {})],
    )
    .unwrap();

    // Set test program state to succeed (0)
    set_test_program_state(&mut context, &state_account.pubkey(), false).unwrap();

    context.svm.warp_to_slot(100);

    // Build test program instruction (with config and wallet as first two accounts)
    let test_program_ix = Instruction {
        program_id: TEST_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(swig, false), // config (swig account)
            AccountMeta::new_readonly(swig_wallet, false), // wallet (swig wallet address PDA)
            AccountMeta::new_readonly(state_account.pubkey(), false), // state account
            AccountMeta::new_readonly(program_id(), false), // swig program
        ],
        data: VALID_DISCRIMINATOR.to_vec(),
    };

    // Create a dummy inner instruction - swig will sign this transfer as a PDA
    // Transfer FROM swig wallet TO authority (swig wallet can sign as PDA)
    let inner_ix = system_instruction::transfer(&swig_wallet, &swig_authority.pubkey(), 1000);

    // Use the ergonomic interface to create both the preceding and sign
    // instructions
    let instructions = build_program_exec_sign_instructions(
        swig,
        swig_wallet,
        swig_authority.pubkey(),
        test_program_ix, // preceding instruction that validates the authority
        inner_ix,        // instruction to be signed by swig
        1,               // role_id for ProgramExec authority
    )
    .unwrap();

    // Build transaction with both instructions returned from the interface
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
        println!("Transaction failed: {:?}", res.as_ref().err());
        if let Some(logs) = res.as_ref().err().map(|e| &e.meta.logs) {
            for log in logs {
                println!("{}", log);
            }
        }
    }

    assert!(
        res.is_ok(),
        "Transaction should succeed with valid program execution and state=0"
    );
}

/// Test that execution fails when test program state is set to fail
#[test_log::test]
fn test_program_exec_fails_with_state_set_to_fail() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let state_account = Keypair::new();

    // Deploy the test program
    deploy_test_program(&mut context).expect("Failed to deploy test program");

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Airdrop to swig and swig_wallet after creation so they can execute transfers
    context.svm.airdrop(&swig, 10_000_000).unwrap();
    context.svm.airdrop(&swig_wallet, 10_000_000).unwrap();

    let program_exec_data =
        create_program_exec_authority_data(TEST_PROGRAM_ID, &VALID_DISCRIMINATOR);

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::ProgramExec,
            authority: &program_exec_data,
        },
        vec![ClientAction::All(All {})],
    )
    .unwrap();

    // Set test program state to FAIL (1)
    set_test_program_state(&mut context, &state_account.pubkey(), true).unwrap();

    context.svm.warp_to_slot(100);

    let test_program_ix = Instruction {
        program_id: TEST_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(swig, false),
            AccountMeta::new_readonly(swig_wallet, false),
            AccountMeta::new_readonly(state_account.pubkey(), false),
            AccountMeta::new_readonly(program_id(), false),
        ],
        data: VALID_DISCRIMINATOR.to_vec(),
    };

    // Create a dummy inner instruction - swig wallet will sign this transfer as a
    // PDA Transfer FROM swig wallet TO authority
    let inner_ix = system_instruction::transfer(&swig_wallet, &swig_authority.pubkey(), 1000);

    // Use the ergonomic interface to create both instructions
    let instructions = build_program_exec_sign_instructions(
        swig,
        swig_wallet,
        swig_authority.pubkey(),
        test_program_ix,
        inner_ix,
        1, // role_id
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

    // Should fail because test program state is set to 1
    assert!(res.is_err(), "Transaction should fail when state=1");

    if let Err(err) = res {
        println!("Got expected error: {:?}", err.err);
    }
}

/// Test failed token transfer with wrong program
#[test_log::test]
fn test_program_exec_wrong_program_fails() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Add ProgramExec authority expecting TEST_PROGRAM_ID
    let program_exec_data =
        create_program_exec_authority_data(TEST_PROGRAM_ID, &VALID_DISCRIMINATOR);

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::ProgramExec,
            authority: &program_exec_data,
        },
        vec![
            ClientAction::Program(Program {
                program_id: solana_sdk::system_program::ID.to_bytes(),
            }),
            ClientAction::All(All {}),
        ],
    )
    .unwrap();

    context.svm.warp_to_slot(100);
    context.svm.airdrop(&swig, 10_000_000_000).unwrap();
    context.svm.airdrop(&swig_wallet, 10_000_000_000).unwrap();

    // Try to use with system program instead (wrong program)
    // Mock instruction with system program, not TEST_PROGRAM_ID
    let mock_program_ix = Instruction {
        program_id: solana_sdk::system_program::ID,
        accounts: vec![
            AccountMeta::new_readonly(swig, false),
            AccountMeta::new_readonly(swig_wallet, false),
            AccountMeta::new(swig_authority.pubkey(), true),
        ],
        data: VALID_DISCRIMINATOR.to_vec(),
    };

    let transfer_ix = system_instruction::transfer(&swig_wallet, &recipient.pubkey(), 1000);

    // Use the ergonomic interface
    let instructions = build_program_exec_sign_instructions(
        swig,
        swig_wallet,
        swig_authority.pubkey(),
        mock_program_ix,
        transfer_ix,
        1, // role_id
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &instructions,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&swig_authority])
            .unwrap();

    let res = context.svm.send_transaction(transfer_tx);

    // Should fail because the preceding instruction is from system program, not
    // TEST_PROGRAM_ID
    assert!(res.is_err(), "Transaction should fail with wrong program");

    if let Err(err) = res {
        println!("Got expected error: {:?}", err.err);
    }
}

/// Test failed token transfer with invalid discriminator
#[test_log::test]
fn test_program_exec_invalid_discriminator_fails() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_wallet_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet,
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
        &swig_wallet_ata,
        1000,
    )
    .unwrap();

    create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Add ProgramExec authority expecting VALID_DISCRIMINATOR
    let program_exec_data = create_program_exec_authority_data(spl_token::ID, &VALID_DISCRIMINATOR);

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::ProgramExec,
            authority: &program_exec_data,
        },
        vec![
            ClientAction::Program(Program {
                program_id: spl_token::ID.to_bytes(),
            }),
            ClientAction::All(All {}),
        ],
    )
    .unwrap();

    context.svm.warp_to_slot(100);

    // Create mock program call with INVALID_DISCRIMINATOR
    let mut invalid_instruction_data = INVALID_DISCRIMINATOR.to_vec();
    invalid_instruction_data.extend_from_slice(&100u64.to_le_bytes()); // amount

    let mock_program_ix = Instruction {
        program_id: spl_token::ID,
        accounts: vec![
            AccountMeta::new_readonly(swig, false),
            AccountMeta::new_readonly(swig_wallet, false),
            AccountMeta::new(swig_wallet_ata, false),
        ],
        data: invalid_instruction_data,
    };

    let transfer_ix = Instruction {
        program_id: spl_token::ID,
        accounts: vec![
            AccountMeta::new(swig_wallet_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig_wallet, false),
        ],
        data: TokenInstruction::Transfer { amount: 100 }.pack(),
    };

    // Use the ergonomic interface
    let instructions = build_program_exec_sign_instructions(
        swig,
        swig_wallet,
        swig_authority.pubkey(),
        mock_program_ix,
        transfer_ix,
        1, // role_id
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &instructions,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&swig_authority])
            .unwrap();

    let res = context.svm.send_transaction(transfer_tx);

    // Should fail because the discriminator doesn't match
    assert!(
        res.is_err(),
        "Transaction should fail with invalid discriminator"
    );

    if let Err(err) = res {
        println!("Got expected error: {:?}", err.err);
    }
}

/// Test failed authentication with mismatched config account
#[test_log::test]
fn test_program_exec_mismatched_config_fails() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    let wrong_config = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&wrong_config.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_wallet_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet,
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
        &swig_wallet_ata,
        1000,
    )
    .unwrap();

    create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let program_exec_data = create_program_exec_authority_data(
        spl_token::ID,
        &[3, 0, 0, 0, 0, 0, 0, 0], // Transfer discriminator
    );

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::ProgramExec,
            authority: &program_exec_data,
        },
        vec![
            ClientAction::Program(Program {
                program_id: spl_token::ID.to_bytes(),
            }),
            ClientAction::All(All {}),
        ],
    )
    .unwrap();

    context.svm.warp_to_slot(100);

    // Create mock program call with WRONG config account (first account)
    let mock_program_ix = Instruction {
        program_id: spl_token::ID,
        accounts: vec![
            AccountMeta::new_readonly(wrong_config.pubkey(), false), // Wrong config!
            AccountMeta::new_readonly(swig_wallet, false),
            AccountMeta::new(swig_wallet_ata, false),
        ],
        data: TokenInstruction::Transfer { amount: 0 }.pack(),
    };

    let transfer_ix = Instruction {
        program_id: spl_token::ID,
        accounts: vec![
            AccountMeta::new(swig_wallet_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig_wallet, false),
        ],
        data: TokenInstruction::Transfer { amount: 100 }.pack(),
    };

    // Use the ergonomic interface
    let instructions = build_program_exec_sign_instructions(
        swig,
        swig_wallet,
        swig_authority.pubkey(),
        mock_program_ix,
        transfer_ix,
        1, // role_id
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &instructions,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&swig_authority])
            .unwrap();

    let res = context.svm.send_transaction(transfer_tx);

    // Should fail because config account doesn't match
    assert!(
        res.is_err(),
        "Transaction should fail with mismatched config account"
    );

    if let Err(err) = res {
        println!("Got expected error: {:?}", err.err);
    }
}

/// Test failed authentication with mismatched wallet account
#[test_log::test]
fn test_program_exec_mismatched_wallet_fails() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    let wrong_wallet = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&wrong_wallet.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_wallet_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet,
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
        &swig_wallet_ata,
        1000,
    )
    .unwrap();

    create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let program_exec_data = create_program_exec_authority_data(
        spl_token::ID,
        &[3, 0, 0, 0, 0, 0, 0, 0], // Transfer discriminator
    );

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::ProgramExec,
            authority: &program_exec_data,
        },
        vec![
            ClientAction::Program(Program {
                program_id: spl_token::ID.to_bytes(),
            }),
            ClientAction::All(All {}),
        ],
    )
    .unwrap();

    context.svm.warp_to_slot(100);

    // Create mock program call with WRONG wallet account (second account)
    let mock_program_ix = Instruction {
        program_id: spl_token::ID,
        accounts: vec![
            AccountMeta::new_readonly(swig, false),
            AccountMeta::new_readonly(wrong_wallet.pubkey(), false), // Wrong wallet!
            AccountMeta::new(swig_wallet_ata, false),
        ],
        data: TokenInstruction::Transfer { amount: 0 }.pack(),
    };

    let transfer_ix = Instruction {
        program_id: spl_token::ID,
        accounts: vec![
            AccountMeta::new(swig_wallet_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig_wallet, false),
        ],
        data: TokenInstruction::Transfer { amount: 100 }.pack(),
    };

    // Use the ergonomic interface
    let instructions = build_program_exec_sign_instructions(
        swig,
        swig_wallet,
        swig_authority.pubkey(),
        mock_program_ix,
        transfer_ix,
        1, // role_id
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &instructions,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&swig_authority])
            .unwrap();

    let res = context.svm.send_transaction(transfer_tx);

    // Should fail because wallet account doesn't match
    assert!(
        res.is_err(),
        "Transaction should fail with mismatched wallet account"
    );

    if let Err(err) = res {
        println!("Got expected error: {:?}", err.err);
    }
}
