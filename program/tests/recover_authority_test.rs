#![cfg(not(feature = "program_scope_test"))]

mod common;

use alloy_signer_local::{LocalSigner, PrivateKeySigner};
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
    authority::{
        ed25519::ED25519Authority, programexec::ProgramExecAuthority,
        secp256k1::Secp256k1Authority, secp256r1::Secp256r1Authority, AuthorityType,
    },
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
};

solana_sdk::declare_id!("BXAu5ZWHnGun2XZjUZ9nqwiZ5dNVmofPGYdMC4rx4qLV");
const TEST_RECOVERY_PROGRAM_ID: Pubkey = ID;
const TEST_RECOVERY_PROGRAM_PATH: &str = "../target/deploy/test_program_authority.so";
const EXECUTE_RECOVERY_V1_DISCRIMINATOR: [u8; 8] = *b"execreV1";
const PENDING_RECOVERY_SEED: &[u8] = b"pending-recovery";
const PENDING_RECOVERY_V1_DISCRIMINATOR: [u8; 8] = *b"rpendV01";
const PENDING_RECOVERY_STATUS_EXECUTED: u8 = 2;
const PENDING_RECOVERY_V1_LEN: usize =
    8 + 32 + 32 + 4 + 32 + 32 + 32 + 8 + 8 + 1 + 1 + 2 + 2 + 2 + 2;

fn deploy_recovery_test_program(context: &mut SwigTestContext) -> anyhow::Result<Pubkey> {
    let program_data = std::fs::read(TEST_RECOVERY_PROGRAM_PATH).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read test recovery program: {}. Make sure to run `cargo build-sbf` first.",
            e
        )
    })?;
    context
        .svm
        .add_program(TEST_RECOVERY_PROGRAM_ID, &program_data)?;
    Ok(TEST_RECOVERY_PROGRAM_ID)
}

fn find_pending_recovery_address(
    recovery_program_id: &Pubkey,
    swig_wallet_address: &Pubkey,
    target_role_id: u32,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            PENDING_RECOVERY_SEED,
            swig_wallet_address.as_ref(),
            &target_role_id.to_le_bytes(),
        ],
        recovery_program_id,
    )
}

fn write_pubkey(data: &mut [u8], offset: usize, pubkey: &Pubkey) {
    data[offset..offset + 32].copy_from_slice(pubkey.as_ref());
}

fn write_hash(data: &mut [u8], offset: usize, value: &[u8; 32]) {
    data[offset..offset + 32].copy_from_slice(value);
}

fn hash_recovery_authority(authority_type: AuthorityType, authority: &[u8]) -> [u8; 32] {
    let _ = authority_type;
    solana_sdk::hash::hashv(&[authority]).to_bytes()
}

fn create_executed_pending_recovery(
    context: &mut SwigTestContext,
    recovery_program_id: Pubkey,
    swig_wallet_address: Pubkey,
    target_role_id: u32,
    guardian: Pubkey,
    old_authority_type: AuthorityType,
    new_authority_type: AuthorityType,
    old_authority: &[u8],
    new_authority: &[u8],
) -> Pubkey {
    let (pending, bump) =
        find_pending_recovery_address(&recovery_program_id, &swig_wallet_address, target_role_id);
    let mut data = vec![0u8; PENDING_RECOVERY_V1_LEN];
    data[0..8].copy_from_slice(&PENDING_RECOVERY_V1_DISCRIMINATOR);
    write_pubkey(&mut data, 8, &Pubkey::new_unique());
    write_pubkey(&mut data, 40, &swig_wallet_address);
    data[72..76].copy_from_slice(&target_role_id.to_le_bytes());
    write_pubkey(&mut data, 76, &guardian);
    write_hash(
        &mut data,
        108,
        &hash_recovery_authority(old_authority_type, old_authority),
    );
    write_hash(
        &mut data,
        140,
        &hash_recovery_authority(new_authority_type, new_authority),
    );
    data[172..180].copy_from_slice(&1u64.to_le_bytes());
    data[180..188].copy_from_slice(&1u64.to_le_bytes());
    data[188] = PENDING_RECOVERY_STATUS_EXECUTED;
    data[189] = bump;
    data[190..192].copy_from_slice(&(old_authority_type as u16).to_le_bytes());
    data[192..194].copy_from_slice(&(new_authority_type as u16).to_le_bytes());
    data[194..196].copy_from_slice(&(old_authority.len() as u16).to_le_bytes());
    data[196..198].copy_from_slice(&(new_authority.len() as u16).to_le_bytes());

    context
        .svm
        .set_account(
            pending,
            Account {
                lamports: 1_000_000,
                data,
                owner: recovery_program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    pending
}

fn execute_recovery_v1_instruction(
    recovery_program_id: Pubkey,
    swig: Pubkey,
    swig_wallet_address: Pubkey,
    target_role_id: u32,
    old_authority_type: u16,
    new_authority_type: u16,
    old_authority: &[u8],
    new_authority: &[u8],
) -> Instruction {
    let (pending, _) =
        find_pending_recovery_address(&recovery_program_id, &swig_wallet_address, target_role_id);
    let mut data =
        Vec::with_capacity(8 + 2 + 2 + 2 + 2 + old_authority.len() + new_authority.len());
    data.extend_from_slice(&EXECUTE_RECOVERY_V1_DISCRIMINATOR);
    data.extend_from_slice(&old_authority_type.to_le_bytes());
    data.extend_from_slice(&new_authority_type.to_le_bytes());
    data.extend_from_slice(&(old_authority.len() as u16).to_le_bytes());
    data.extend_from_slice(&(new_authority.len() as u16).to_le_bytes());
    data.extend_from_slice(old_authority);
    data.extend_from_slice(new_authority);

    Instruction {
        program_id: recovery_program_id,
        accounts: vec![
            AccountMeta::new_readonly(swig, false),
            AccountMeta::new_readonly(swig_wallet_address, false),
            AccountMeta::new(pending, false),
        ],
        data,
    }
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

fn compressed_evm_public_key(wallet: &PrivateKeySigner) -> Vec<u8> {
    wallet
        .credential()
        .verifying_key()
        .to_encoded_point(true)
        .to_bytes()
        .to_vec()
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

fn install_operator(
    _context: &mut SwigTestContext,
    _recovery_program_id: Pubkey,
    _admin: &Keypair,
    _operator: Pubkey,
) -> Pubkey {
    Pubkey::new_unique()
}

fn configure_recovery(
    _context: &mut SwigTestContext,
    _recovery_program_id: Pubkey,
    _operator: &Keypair,
    _swig_wallet_address: Pubkey,
    _target_role_id: u32,
    _guardian: Pubkey,
    _delay_slots: u64,
) {
}

fn start_recovery(
    context: &mut SwigTestContext,
    recovery_program_id: Pubkey,
    guardian: &Keypair,
    swig_wallet_address: Pubkey,
    target_role_id: u32,
    old_authority_type: AuthorityType,
    new_authority_type: AuthorityType,
    old_authority: &[u8],
    new_authority: &[u8],
) {
    create_executed_pending_recovery(
        context,
        recovery_program_id,
        swig_wallet_address,
        target_role_id,
        guardian.pubkey(),
        old_authority_type,
        new_authority_type,
        old_authority,
        new_authority,
    );
}

#[test_log::test]
fn test_program_exec_recovery_rotates_passkey_authority() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let admin = Keypair::new();
    let operator = Keypair::new();
    let guardian = Keypair::new();
    let recovery_program_id = deploy_recovery_test_program(&mut context).unwrap();

    install_operator(&mut context, recovery_program_id, &admin, operator.pubkey());
    context
        .svm
        .airdrop(&operator.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&guardian.pubkey(), 1_000_000_000)
        .unwrap();
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

    let recovery_program_id_bytes = recovery_program_id.to_bytes();
    let program_exec_data = ProgramExecAuthority::create_authority_data(
        &recovery_program_id_bytes,
        &EXECUTE_RECOVERY_V1_DISCRIMINATOR,
    );
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

    let delay_slots = 10;
    configure_recovery(
        &mut context,
        recovery_program_id,
        &operator,
        swig_wallet_address,
        1,
        guardian.pubkey(),
        delay_slots,
    );
    start_recovery(
        &mut context,
        recovery_program_id,
        &guardian,
        swig_wallet_address,
        1,
        AuthorityType::Secp256r1,
        AuthorityType::Secp256r1,
        &old_passkey,
        &new_passkey,
    );
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + delay_slots + 1);
    context.svm.expire_blockhash();

    let execute_ix = execute_recovery_v1_instruction(
        recovery_program_id,
        swig,
        swig_wallet_address,
        1,
        AuthorityType::Secp256r1 as u16,
        AuthorityType::Secp256r1 as u16,
        &old_passkey,
        &new_passkey,
    );
    let instructions = RecoverAuthorityInstruction::new_with_program_exec(
        swig,
        swig_wallet_address,
        execute_ix,
        2,
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
fn test_program_exec_recovery_rotates_passkey_to_ed25519_authority() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let new_authority = Keypair::new();
    let admin = Keypair::new();
    let operator = Keypair::new();
    let guardian = Keypair::new();
    let recovery_program_id = deploy_recovery_test_program(&mut context).unwrap();

    install_operator(&mut context, recovery_program_id, &admin, operator.pubkey());
    context
        .svm
        .airdrop(&operator.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&guardian.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let old_passkey = create_test_secp256r1_public_key();
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

    let recovery_program_id_bytes = recovery_program_id.to_bytes();
    let program_exec_data = ProgramExecAuthority::create_authority_data(
        &recovery_program_id_bytes,
        &EXECUTE_RECOVERY_V1_DISCRIMINATOR,
    );
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

    let delay_slots = 10;
    configure_recovery(
        &mut context,
        recovery_program_id,
        &operator,
        swig_wallet_address,
        1,
        guardian.pubkey(),
        delay_slots,
    );
    start_recovery(
        &mut context,
        recovery_program_id,
        &guardian,
        swig_wallet_address,
        1,
        AuthorityType::Secp256r1,
        AuthorityType::Ed25519,
        &old_passkey,
        new_authority.pubkey().as_ref(),
    );
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + delay_slots + 1);
    context.svm.expire_blockhash();

    let execute_ix = execute_recovery_v1_instruction(
        recovery_program_id,
        swig,
        swig_wallet_address,
        1,
        AuthorityType::Secp256r1 as u16,
        AuthorityType::Ed25519 as u16,
        &old_passkey,
        new_authority.pubkey().as_ref(),
    );
    let instructions = RecoverAuthorityInstruction::new_with_program_exec(
        swig,
        swig_wallet_address,
        execute_ix,
        2,
    )
    .unwrap();

    send_recovery_transaction(&mut context, &instructions).unwrap();

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let recovered_role = swig_state.get_role(1).unwrap().unwrap();
    let recovered_authority = recovered_role
        .authority
        .as_any()
        .downcast_ref::<ED25519Authority>()
        .unwrap();

    assert_eq!(
        recovered_authority.public_key,
        new_authority.pubkey().to_bytes()
    );
    assert!(recovered_role
        .get_action::<ManageAuthority>(&[])
        .unwrap()
        .is_some());
}

#[test_log::test]
fn test_program_exec_recovery_rotates_ed25519_authority() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let new_root_authority = Keypair::new();
    let admin = Keypair::new();
    let operator = Keypair::new();
    let guardian = Keypair::new();
    let recovery_program_id = deploy_recovery_test_program(&mut context).unwrap();

    install_operator(&mut context, recovery_program_id, &admin, operator.pubkey());
    context
        .svm
        .airdrop(&operator.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&guardian.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    let recovery_program_id_bytes = recovery_program_id.to_bytes();
    let program_exec_data = ProgramExecAuthority::create_authority_data(
        &recovery_program_id_bytes,
        &EXECUTE_RECOVERY_V1_DISCRIMINATOR,
    );
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

    let delay_slots = 10;
    configure_recovery(
        &mut context,
        recovery_program_id,
        &operator,
        swig_wallet_address,
        0,
        guardian.pubkey(),
        delay_slots,
    );
    start_recovery(
        &mut context,
        recovery_program_id,
        &guardian,
        swig_wallet_address,
        0,
        AuthorityType::Ed25519,
        AuthorityType::Ed25519,
        root_authority.pubkey().as_ref(),
        new_root_authority.pubkey().as_ref(),
    );
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + delay_slots + 1);
    context.svm.expire_blockhash();

    let execute_ix = execute_recovery_v1_instruction(
        recovery_program_id,
        swig,
        swig_wallet_address,
        0,
        AuthorityType::Ed25519 as u16,
        AuthorityType::Ed25519 as u16,
        root_authority.pubkey().as_ref(),
        new_root_authority.pubkey().as_ref(),
    );
    let instructions = RecoverAuthorityInstruction::new_with_program_exec(
        swig,
        swig_wallet_address,
        execute_ix,
        1,
    )
    .unwrap();

    send_recovery_transaction(&mut context, &instructions).unwrap();

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let recovered_role = swig_state.get_role(0).unwrap().unwrap();
    let recovered_authority = recovered_role
        .authority
        .as_any()
        .downcast_ref::<ED25519Authority>()
        .unwrap();

    assert_eq!(
        recovered_authority.public_key,
        new_root_authority.pubkey().to_bytes()
    );
}

#[test_log::test]
fn test_program_exec_recovery_rotates_ed25519_to_passkey_authority() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let admin = Keypair::new();
    let operator = Keypair::new();
    let guardian = Keypair::new();
    let recovery_program_id = deploy_recovery_test_program(&mut context).unwrap();

    install_operator(&mut context, recovery_program_id, &admin, operator.pubkey());
    context
        .svm
        .airdrop(&operator.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&guardian.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let new_passkey = create_test_secp256r1_public_key();
    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    let recovery_program_id_bytes = recovery_program_id.to_bytes();
    let program_exec_data = ProgramExecAuthority::create_authority_data(
        &recovery_program_id_bytes,
        &EXECUTE_RECOVERY_V1_DISCRIMINATOR,
    );
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

    let delay_slots = 10;
    configure_recovery(
        &mut context,
        recovery_program_id,
        &operator,
        swig_wallet_address,
        0,
        guardian.pubkey(),
        delay_slots,
    );
    start_recovery(
        &mut context,
        recovery_program_id,
        &guardian,
        swig_wallet_address,
        0,
        AuthorityType::Ed25519,
        AuthorityType::Secp256r1,
        root_authority.pubkey().as_ref(),
        &new_passkey,
    );
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + delay_slots + 1);
    context.svm.expire_blockhash();

    let execute_ix = execute_recovery_v1_instruction(
        recovery_program_id,
        swig,
        swig_wallet_address,
        0,
        AuthorityType::Ed25519 as u16,
        AuthorityType::Secp256r1 as u16,
        root_authority.pubkey().as_ref(),
        &new_passkey,
    );
    let instructions = RecoverAuthorityInstruction::new_with_program_exec_and_payer(
        swig,
        swig_wallet_address,
        execute_ix,
        1,
        context.default_payer.pubkey(),
    )
    .unwrap();

    send_recovery_transaction(&mut context, &instructions).unwrap();

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let recovered_role = swig_state.get_role(0).unwrap().unwrap();
    let recovered_authority = recovered_role
        .authority
        .as_any()
        .downcast_ref::<Secp256r1Authority>()
        .unwrap();

    assert_eq!(recovered_authority.public_key, new_passkey);
    assert_eq!(recovered_authority.signature_odometer, 0);
}

#[test_log::test]
fn test_program_exec_recovery_rotates_secp256k1_authority() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let old_wallet = LocalSigner::random();
    let new_wallet = LocalSigner::random();
    let old_authority = compressed_evm_public_key(&old_wallet);
    let new_authority = compressed_evm_public_key(&new_wallet);
    let admin = Keypair::new();
    let operator = Keypair::new();
    let guardian = Keypair::new();
    let recovery_program_id = deploy_recovery_test_program(&mut context).unwrap();

    install_operator(&mut context, recovery_program_id, &admin, operator.pubkey());
    context
        .svm
        .airdrop(&operator.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&guardian.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

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
            authority_type: AuthorityType::Secp256k1,
            authority: &old_authority,
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    let recovery_program_id_bytes = recovery_program_id.to_bytes();
    let program_exec_data = ProgramExecAuthority::create_authority_data(
        &recovery_program_id_bytes,
        &EXECUTE_RECOVERY_V1_DISCRIMINATOR,
    );
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

    let delay_slots = 10;
    configure_recovery(
        &mut context,
        recovery_program_id,
        &operator,
        swig_wallet_address,
        1,
        guardian.pubkey(),
        delay_slots,
    );
    start_recovery(
        &mut context,
        recovery_program_id,
        &guardian,
        swig_wallet_address,
        1,
        AuthorityType::Secp256k1,
        AuthorityType::Secp256k1,
        &old_authority,
        &new_authority,
    );
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + delay_slots + 1);
    context.svm.expire_blockhash();

    let execute_ix = execute_recovery_v1_instruction(
        recovery_program_id,
        swig,
        swig_wallet_address,
        1,
        AuthorityType::Secp256k1 as u16,
        AuthorityType::Secp256k1 as u16,
        &old_authority,
        &new_authority,
    );
    let instructions = RecoverAuthorityInstruction::new_with_program_exec(
        swig,
        swig_wallet_address,
        execute_ix,
        2,
    )
    .unwrap();

    send_recovery_transaction(&mut context, &instructions).unwrap();

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let recovered_role = swig_state.get_role(1).unwrap().unwrap();
    let recovered_authority = recovered_role
        .authority
        .as_any()
        .downcast_ref::<Secp256k1Authority>()
        .unwrap();

    assert_eq!(
        recovered_authority.public_key.as_ref(),
        new_authority.as_slice()
    );
    assert_eq!(recovered_authority.signature_odometer, 0);
}

#[test_log::test]
fn test_program_exec_recovery_requires_recovery_authority_permission() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let admin = Keypair::new();
    let operator = Keypair::new();
    let guardian = Keypair::new();
    let recovery_program_id = deploy_recovery_test_program(&mut context).unwrap();

    install_operator(&mut context, recovery_program_id, &admin, operator.pubkey());
    context
        .svm
        .airdrop(&operator.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&guardian.pubkey(), 1_000_000_000)
        .unwrap();
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

    let recovery_program_id_bytes = recovery_program_id.to_bytes();
    let program_exec_data = ProgramExecAuthority::create_authority_data(
        &recovery_program_id_bytes,
        &EXECUTE_RECOVERY_V1_DISCRIMINATOR,
    );
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

    let delay_slots = 10;
    configure_recovery(
        &mut context,
        recovery_program_id,
        &operator,
        swig_wallet_address,
        1,
        guardian.pubkey(),
        delay_slots,
    );
    start_recovery(
        &mut context,
        recovery_program_id,
        &guardian,
        swig_wallet_address,
        1,
        AuthorityType::Secp256r1,
        AuthorityType::Secp256r1,
        &old_passkey,
        &new_passkey,
    );
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + delay_slots + 1);
    context.svm.expire_blockhash();

    let execute_ix = execute_recovery_v1_instruction(
        recovery_program_id,
        swig,
        swig_wallet_address,
        1,
        AuthorityType::Secp256r1 as u16,
        AuthorityType::Secp256r1 as u16,
        &old_passkey,
        &new_passkey,
    );
    let instructions = RecoverAuthorityInstruction::new_with_program_exec(
        swig,
        swig_wallet_address,
        execute_ix,
        2,
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

#[test_log::test]
fn test_recovery_binding_rejects_pending_account_mismatch() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let admin = Keypair::new();
    let operator = Keypair::new();
    let guardian = Keypair::new();
    let recovery_program_id = deploy_recovery_test_program(&mut context).unwrap();

    install_operator(&mut context, recovery_program_id, &admin, operator.pubkey());
    context
        .svm
        .airdrop(&operator.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&guardian.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let primary_passkey = create_test_secp256r1_public_key();
    let secondary_passkey = create_test_secp256r1_public_key();
    let new_legit_passkey = create_test_secp256r1_public_key();
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
            authority: &primary_passkey,
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256r1,
            authority: &secondary_passkey,
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    let recovery_program_id_bytes = recovery_program_id.to_bytes();
    let program_exec_data = ProgramExecAuthority::create_authority_data(
        &recovery_program_id_bytes,
        &EXECUTE_RECOVERY_V1_DISCRIMINATOR,
    );
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

    let delay_slots = 10;
    configure_recovery(
        &mut context,
        recovery_program_id,
        &operator,
        swig_wallet_address,
        1,
        guardian.pubkey(),
        delay_slots,
    );
    start_recovery(
        &mut context,
        recovery_program_id,
        &guardian,
        swig_wallet_address,
        1,
        AuthorityType::Secp256r1,
        AuthorityType::Secp256r1,
        &primary_passkey,
        &new_legit_passkey,
    );
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + delay_slots + 1);
    context.svm.expire_blockhash();

    let execute_ix = execute_recovery_v1_instruction(
        recovery_program_id,
        swig,
        swig_wallet_address,
        1,
        AuthorityType::Secp256r1 as u16,
        AuthorityType::Secp256r1 as u16,
        &primary_passkey,
        &new_legit_passkey,
    );
    let mut instructions = RecoverAuthorityInstruction::new_with_program_exec(
        swig,
        swig_wallet_address,
        execute_ix,
        3,
    )
    .unwrap();
    let (wrong_pending, _) =
        find_pending_recovery_address(&recovery_program_id, &swig_wallet_address, 2);
    instructions[1].accounts[3].pubkey = wrong_pending;

    assert!(send_recovery_transaction(&mut context, &instructions).is_err());

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role_one = swig_state.get_role(1).unwrap().unwrap();
    let role_one_authority = role_one
        .authority
        .as_any()
        .downcast_ref::<Secp256r1Authority>()
        .unwrap();
    assert_eq!(role_one_authority.public_key, primary_passkey);

    let role_two = swig_state.get_role(2).unwrap().unwrap();
    let role_two_authority = role_two
        .authority
        .as_any()
        .downcast_ref::<Secp256r1Authority>()
        .unwrap();
    assert_eq!(role_two_authority.public_key, secondary_passkey);
}

#[test_log::test]
fn test_recovery_rejects_authority_type_mismatch() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let new_ed25519_authority = Keypair::new();
    let admin = Keypair::new();
    let operator = Keypair::new();
    let guardian = Keypair::new();
    let recovery_program_id = deploy_recovery_test_program(&mut context).unwrap();

    install_operator(&mut context, recovery_program_id, &admin, operator.pubkey());
    context
        .svm
        .airdrop(&operator.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&guardian.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let old_passkey = create_test_secp256r1_public_key();
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

    let recovery_program_id_bytes = recovery_program_id.to_bytes();
    let program_exec_data = ProgramExecAuthority::create_authority_data(
        &recovery_program_id_bytes,
        &EXECUTE_RECOVERY_V1_DISCRIMINATOR,
    );
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

    let delay_slots = 10;
    configure_recovery(
        &mut context,
        recovery_program_id,
        &operator,
        swig_wallet_address,
        1,
        guardian.pubkey(),
        delay_slots,
    );
    start_recovery(
        &mut context,
        recovery_program_id,
        &guardian,
        swig_wallet_address,
        1,
        AuthorityType::Ed25519,
        AuthorityType::Ed25519,
        root_authority.pubkey().as_ref(),
        new_ed25519_authority.pubkey().as_ref(),
    );
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + delay_slots + 1);
    context.svm.expire_blockhash();

    let execute_ix = execute_recovery_v1_instruction(
        recovery_program_id,
        swig,
        swig_wallet_address,
        1,
        AuthorityType::Ed25519 as u16,
        AuthorityType::Ed25519 as u16,
        root_authority.pubkey().as_ref(),
        new_ed25519_authority.pubkey().as_ref(),
    );
    let instructions = RecoverAuthorityInstruction::new_with_program_exec(
        swig,
        swig_wallet_address,
        execute_ix,
        2,
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
