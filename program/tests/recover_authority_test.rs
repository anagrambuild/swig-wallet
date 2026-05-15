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

mod upgradeable_loader {
    solana_sdk::declare_id!("BPFLoaderUpgradeab1e11111111111111111111111");
}

fn deploy_recovery_program(context: &mut SwigTestContext) -> anyhow::Result<Pubkey> {
    let recovery_program_id = Pubkey::new_from_array(swig_recovery::ID.to_bytes());
    let program_data = std::fs::read("../target/deploy/swig_recovery.so").map_err(|e| {
        anyhow::anyhow!(
            "Failed to read recovery program: {}. Make sure to run `cargo build-sbf` first.",
            e
        )
    })?;
    context
        .svm
        .add_program(recovery_program_id, &program_data)?;
    Ok(recovery_program_id)
}

fn set_recovery_program_upgrade_authority(
    context: &mut SwigTestContext,
    recovery_program_id: Pubkey,
    admin: Pubkey,
) -> anyhow::Result<Pubkey> {
    let (program_data, _) =
        Pubkey::find_program_address(&[recovery_program_id.as_ref()], &upgradeable_loader::ID);
    let mut data = vec![0u8; 45];
    data[0..4].copy_from_slice(&3u32.to_le_bytes());
    data[12] = 1;
    data[13..45].copy_from_slice(admin.as_ref());

    context.svm.set_account(
        program_data,
        Account {
            lamports: 1_000_000,
            data,
            owner: upgradeable_loader::ID,
            executable: false,
            rent_epoch: 0,
        },
    )?;
    Ok(program_data)
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

fn submit(
    context: &mut SwigTestContext,
    instructions: &[Instruction],
    extra_signers: &[&Keypair],
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
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
    context.svm.send_transaction(tx).map(|_| ())
}

fn install_operator(
    context: &mut SwigTestContext,
    recovery_program_id: Pubkey,
    admin: &Keypair,
    operator: Pubkey,
) -> Pubkey {
    let program_data =
        set_recovery_program_upgrade_authority(context, recovery_program_id, admin.pubkey())
            .unwrap();
    context.svm.airdrop(&admin.pubkey(), 1_000_000_000).unwrap();
    let ix = swig_recovery::instruction::set_operator_v1_instruction(
        recovery_program_id,
        context.default_payer.pubkey(),
        admin.pubkey(),
        program_data,
        operator,
    );
    submit(context, &[ix], &[admin]).unwrap();
    program_data
}

fn configure_recovery(
    context: &mut SwigTestContext,
    recovery_program_id: Pubkey,
    operator: &Keypair,
    swig_wallet_address: Pubkey,
    target_role_id: u32,
    guardian: Pubkey,
    delay_slots: u64,
) {
    let ix = swig_recovery::instruction::configure_recovery_v1_instruction(
        recovery_program_id,
        context.default_payer.pubkey(),
        operator.pubkey(),
        Pubkey::new_unique(),
        swig_wallet_address,
        target_role_id,
        guardian,
        delay_slots,
    );
    submit(context, &[ix], &[operator]).unwrap();
}

fn start_recovery(
    context: &mut SwigTestContext,
    recovery_program_id: Pubkey,
    guardian: &Keypair,
    swig_wallet_address: Pubkey,
    target_role_id: u32,
    authority_type: AuthorityType,
    old_authority: &[u8],
    new_authority: &[u8],
) {
    let ix = swig_recovery::instruction::start_recovery_v1_instruction(
        recovery_program_id,
        context.default_payer.pubkey(),
        guardian.pubkey(),
        swig_wallet_address,
        target_role_id,
        authority_type as u16,
        old_authority,
        new_authority,
    );
    submit(context, &[ix], &[guardian]).unwrap();
}

#[test_log::test]
fn test_program_exec_recovery_rotates_passkey_authority() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let admin = Keypair::new();
    let operator = Keypair::new();
    let guardian = Keypair::new();
    let recovery_program_id = deploy_recovery_program(&mut context).unwrap();

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
        &swig_recovery::instruction::EXECUTE_RECOVERY_V1_DISCRIMINATOR,
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
        &old_passkey,
        &new_passkey,
    );
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + delay_slots + 1);
    context.svm.expire_blockhash();

    let execute_ix = swig_recovery::instruction::execute_recovery_v1_instruction(
        recovery_program_id,
        swig,
        swig_wallet_address,
        1,
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
fn test_program_exec_recovery_rotates_ed25519_authority() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let new_root_authority = Keypair::new();
    let admin = Keypair::new();
    let operator = Keypair::new();
    let guardian = Keypair::new();
    let recovery_program_id = deploy_recovery_program(&mut context).unwrap();

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
        &swig_recovery::instruction::EXECUTE_RECOVERY_V1_DISCRIMINATOR,
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
        root_authority.pubkey().as_ref(),
        new_root_authority.pubkey().as_ref(),
    );
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + delay_slots + 1);
    context.svm.expire_blockhash();

    let execute_ix = swig_recovery::instruction::execute_recovery_v1_instruction(
        recovery_program_id,
        swig,
        swig_wallet_address,
        0,
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
    let recovery_program_id = deploy_recovery_program(&mut context).unwrap();

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
        &swig_recovery::instruction::EXECUTE_RECOVERY_V1_DISCRIMINATOR,
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
        &old_authority,
        &new_authority,
    );
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + delay_slots + 1);
    context.svm.expire_blockhash();

    let execute_ix = swig_recovery::instruction::execute_recovery_v1_instruction(
        recovery_program_id,
        swig,
        swig_wallet_address,
        1,
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
    let recovery_program_id = deploy_recovery_program(&mut context).unwrap();

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
        &swig_recovery::instruction::EXECUTE_RECOVERY_V1_DISCRIMINATOR,
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
        &old_passkey,
        &new_passkey,
    );
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + delay_slots + 1);
    context.svm.expire_blockhash();

    let execute_ix = swig_recovery::instruction::execute_recovery_v1_instruction(
        recovery_program_id,
        swig,
        swig_wallet_address,
        1,
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
    let recovery_program_id = deploy_recovery_program(&mut context).unwrap();

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
        &swig_recovery::instruction::EXECUTE_RECOVERY_V1_DISCRIMINATOR,
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
        &primary_passkey,
        &new_legit_passkey,
    );
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + delay_slots + 1);
    context.svm.expire_blockhash();

    let execute_ix = swig_recovery::instruction::execute_recovery_v1_instruction(
        recovery_program_id,
        swig,
        swig_wallet_address,
        1,
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
    let (wrong_pending, _) = swig_recovery::instruction::find_pending_recovery_address(
        &recovery_program_id,
        &swig_wallet_address,
        2,
    );
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
    let recovery_program_id = deploy_recovery_program(&mut context).unwrap();

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
        &swig_recovery::instruction::EXECUTE_RECOVERY_V1_DISCRIMINATOR,
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
        root_authority.pubkey().as_ref(),
        new_ed25519_authority.pubkey().as_ref(),
    );
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + delay_slots + 1);
    context.svm.expire_blockhash();

    let execute_ix = swig_recovery::instruction::execute_recovery_v1_instruction(
        recovery_program_id,
        swig,
        swig_wallet_address,
        1,
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

#[test_log::test]
fn test_operator_is_admin_installed_and_rotatable() {
    let mut context = setup_test_context().unwrap();
    let recovery_program_id = deploy_recovery_program(&mut context).unwrap();
    let admin = Keypair::new();
    let wrong_admin = Keypair::new();
    let operator_one = Keypair::new();
    let operator_two = Keypair::new();
    let guardian = Keypair::new();
    let swig_wallet_address = Pubkey::new_unique();
    let program_data =
        set_recovery_program_upgrade_authority(&mut context, recovery_program_id, admin.pubkey())
            .unwrap();

    for signer in [&admin, &wrong_admin, &operator_one, &operator_two] {
        context
            .svm
            .airdrop(&signer.pubkey(), 1_000_000_000)
            .unwrap();
    }

    let wrong_admin_ix = swig_recovery::instruction::set_operator_v1_instruction(
        recovery_program_id,
        context.default_payer.pubkey(),
        wrong_admin.pubkey(),
        program_data,
        operator_one.pubkey(),
    );
    assert!(submit(&mut context, &[wrong_admin_ix], &[&wrong_admin]).is_err());

    let install_ix = swig_recovery::instruction::set_operator_v1_instruction(
        recovery_program_id,
        context.default_payer.pubkey(),
        admin.pubkey(),
        program_data,
        operator_one.pubkey(),
    );
    submit(&mut context, &[install_ix], &[&admin]).unwrap();

    let configure_ix = swig_recovery::instruction::configure_recovery_v1_instruction(
        recovery_program_id,
        context.default_payer.pubkey(),
        operator_one.pubkey(),
        Pubkey::new_unique(),
        swig_wallet_address,
        1,
        guardian.pubkey(),
        10,
    );
    submit(&mut context, &[configure_ix], &[&operator_one]).unwrap();

    let rotate_ix = swig_recovery::instruction::set_operator_v1_instruction(
        recovery_program_id,
        context.default_payer.pubkey(),
        admin.pubkey(),
        program_data,
        operator_two.pubkey(),
    );
    submit(&mut context, &[rotate_ix], &[&admin]).unwrap();

    let stale_operator_ix = swig_recovery::instruction::configure_recovery_v1_instruction(
        recovery_program_id,
        context.default_payer.pubkey(),
        operator_one.pubkey(),
        Pubkey::new_unique(),
        swig_wallet_address,
        1,
        guardian.pubkey(),
        10,
    );
    assert!(submit(&mut context, &[stale_operator_ix], &[&operator_one]).is_err());

    let current_operator_ix = swig_recovery::instruction::configure_recovery_v1_instruction(
        recovery_program_id,
        context.default_payer.pubkey(),
        operator_two.pubkey(),
        Pubkey::new_unique(),
        swig_wallet_address,
        1,
        guardian.pubkey(),
        10,
    );
    submit(&mut context, &[current_operator_ix], &[&operator_two]).unwrap();
}
