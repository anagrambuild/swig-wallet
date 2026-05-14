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
