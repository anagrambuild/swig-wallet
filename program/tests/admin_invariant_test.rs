#![cfg(not(feature = "program_scope_test"))]

mod common;

use anyhow::{anyhow, bail, Result};
use common::*;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use solana_sdk::{
    instruction::InstructionError,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig::error::SwigError;
use swig_interface::{
    AuthorityConfig, ClientAction, RemoveAuthorityInstruction, UpdateAuthorityData,
    UpdateAuthorityInstruction,
};
use swig_state::{
    action::{
        all::All, manage_authority::ManageAuthority, program::Program, sol_limit::SolLimit,
        Permission,
    },
    authority::AuthorityType,
    swig::SwigWithRoles,
};

fn send_update(
    context: &mut SwigTestContext,
    swig: Pubkey,
    authority: &Keypair,
    acting_role_id: u32,
    target_role_id: u32,
    update: UpdateAuthorityData,
) -> Result<Result<TransactionMetadata, FailedTransactionMetadata>> {
    context.svm.expire_blockhash();
    let payer = context.default_payer.pubkey();
    let instruction = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig,
        payer,
        authority.pubkey(),
        acting_role_id,
        target_role_id,
        update,
    )?;
    let message =
        v0::Message::try_compile(&payer, &[instruction], &[], context.svm.latest_blockhash())
            .map_err(|error| anyhow!("failed to compile update message: {error:?}"))?;
    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, authority],
    )
    .map_err(|error| anyhow!("failed to sign update transaction: {error:?}"))?;
    Ok(context.svm.send_transaction(transaction))
}

fn send_remove(
    context: &mut SwigTestContext,
    swig: Pubkey,
    authority: &Keypair,
    acting_role_id: u32,
    target_role_id: u32,
) -> Result<Result<TransactionMetadata, FailedTransactionMetadata>> {
    context.svm.expire_blockhash();
    let payer = context.default_payer.pubkey();
    let instruction = RemoveAuthorityInstruction::new_with_ed25519_authority(
        swig,
        payer,
        authority.pubkey(),
        acting_role_id,
        target_role_id,
    )?;
    let message =
        v0::Message::try_compile(&payer, &[instruction], &[], context.svm.latest_blockhash())
            .map_err(|error| anyhow!("failed to compile remove message: {error:?}"))?;
    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, authority],
    )
    .map_err(|error| anyhow!("failed to sign remove transaction: {error:?}"))?;
    Ok(context.svm.send_transaction(transaction))
}

fn require_success(
    result: Result<TransactionMetadata, FailedTransactionMetadata>,
    operation: &str,
) -> Result<()> {
    if let Err(failure) = result {
        bail!("{operation} failed unexpectedly: {:?}", failure.err);
    }
    Ok(())
}

fn assert_no_admin_error(
    result: Result<TransactionMetadata, FailedTransactionMetadata>,
) -> Result<()> {
    let failure = match result {
        Err(failure) => failure,
        Ok(_) => bail!("authority mutation unexpectedly removed the last admin"),
    };
    assert_eq!(
        failure.err,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(SwigError::NoAdminAuthorityWouldRemain as u32),
        )
    );
    Ok(())
}

fn setup_root() -> Result<(SwigTestContext, Pubkey, Keypair)> {
    let mut context = setup_test_context()?;
    let root = Keypair::new();
    context
        .svm
        .airdrop(&root.pubkey(), 10_000_000_000)
        .map_err(|error| anyhow!("failed to fund root: {error:?}"))?;
    let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random::<[u8; 32]>())?;
    Ok((context, swig, root))
}

fn add_ed25519_role(
    context: &mut SwigTestContext,
    swig: &Pubkey,
    root: &Keypair,
    authority: &Keypair,
    actions: Vec<ClientAction>,
) -> Result<()> {
    context
        .svm
        .airdrop(&authority.pubkey(), 10_000_000_000)
        .map_err(|error| anyhow!("failed to fund authority: {error:?}"))?;
    add_authority_with_ed25519_root(
        context,
        swig,
        root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority.pubkey().as_ref(),
        },
        actions,
    )?;
    Ok(())
}

#[test_log::test]
fn last_admin_action_removals_are_rejected_and_unchanged() -> Result<()> {
    let (mut context, swig, root) = setup_root()?;
    require_success(
        send_update(
            &mut context,
            swig,
            &root,
            0,
            0,
            UpdateAuthorityData::AddActions(vec![ClientAction::SolLimit(SolLimit { amount: 1 })]),
        )?,
        "add root spend action",
    )?;

    let destructive_updates = [
        // This replacement grows the account, proving a rejected post-state
        // also rolls back the preceding realloc and rent transfer.
        UpdateAuthorityData::ReplaceAll(vec![
            ClientAction::SolLimit(SolLimit { amount: 1 }),
            ClientAction::Program(Program {
                program_id: solana_system_interface::program::ID.to_bytes(),
            }),
        ]),
        UpdateAuthorityData::RemoveActionsByType(vec![Permission::All as u8]),
        UpdateAuthorityData::RemoveActionsByIndex(vec![0]),
    ];

    for update in destructive_updates {
        let before = context
            .svm
            .get_account(&swig)
            .ok_or_else(|| anyhow!("swig account missing before rejected update"))?;
        assert_no_admin_error(send_update(&mut context, swig, &root, 0, 0, update)?)?;
        let after = context
            .svm
            .get_account(&swig)
            .ok_or_else(|| anyhow!("swig account missing after rejected update"))?;
        assert_eq!(after.data, before.data);
        assert_eq!(after.lamports, before.lamports);
    }

    require_success(
        send_update(
            &mut context,
            swig,
            &root,
            0,
            0,
            UpdateAuthorityData::ReplaceAll(vec![
                ClientAction::ManageAuthority(ManageAuthority {}),
                ClientAction::SolLimit(SolLimit { amount: 1 }),
            ]),
        )?,
        "replace All with ManageAuthority",
    )?;

    let before = context
        .svm
        .get_account(&swig)
        .ok_or_else(|| anyhow!("swig account missing before rejected ManageAuthority removal"))?;
    assert_no_admin_error(send_update(
        &mut context,
        swig,
        &root,
        0,
        0,
        UpdateAuthorityData::RemoveActionsByType(vec![Permission::ManageAuthority as u8]),
    )?)?;
    let after = context
        .svm
        .get_account(&swig)
        .ok_or_else(|| anyhow!("swig account missing after rejected ManageAuthority removal"))?;
    assert_eq!(after.data, before.data);
    assert_eq!(after.lamports, before.lamports);
    Ok(())
}

#[test_log::test]
fn last_non_root_admin_cannot_self_remove() -> Result<()> {
    let (mut context, swig, root) = setup_root()?;
    let second_admin = Keypair::new();
    add_ed25519_role(
        &mut context,
        &swig,
        &root,
        &second_admin,
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )?;

    require_success(
        send_update(
            &mut context,
            swig,
            &root,
            0,
            0,
            UpdateAuthorityData::ReplaceAll(vec![ClientAction::SolLimit(SolLimit { amount: 1 })]),
        )?,
        "move admin permission from root to second role",
    )?;

    let before = context
        .svm
        .get_account(&swig)
        .ok_or_else(|| anyhow!("swig account missing before rejected removal"))?;
    assert_no_admin_error(send_remove(&mut context, swig, &second_admin, 1, 1)?)?;
    let after = context
        .svm
        .get_account(&swig)
        .ok_or_else(|| anyhow!("swig account missing after rejected removal"))?;
    assert_eq!(after.data, before.data);
    assert_eq!(after.lamports, before.lamports);

    let swig_state = SwigWithRoles::from_bytes(&after.data)
        .map_err(|error| anyhow!("failed to decode swig: {error:?}"))?;
    let root_role = swig_state
        .get_role(0)
        .map_err(|error| anyhow!("failed to load root role: {error:?}"))?
        .ok_or_else(|| anyhow!("root role missing"))?;
    let second_role = swig_state
        .get_role(1)
        .map_err(|error| anyhow!("failed to load second role: {error:?}"))?
        .ok_or_else(|| anyhow!("second role missing"))?;
    assert!(root_role
        .get_action::<All>(&[])
        .map_err(|error| anyhow!("failed to load root All action: {error:?}"))?
        .is_none());
    assert!(root_role
        .get_action::<ManageAuthority>(&[])
        .map_err(|error| anyhow!("failed to load root ManageAuthority action: {error:?}"))?
        .is_none());
    assert!(second_role
        .get_action::<ManageAuthority>(&[])
        .map_err(|error| anyhow!("failed to load second ManageAuthority action: {error:?}"))?
        .is_some());
    Ok(())
}

#[test_log::test]
fn non_admin_self_removal_still_succeeds_when_an_admin_remains() -> Result<()> {
    let (mut context, swig, root) = setup_root()?;
    let limited_authority = Keypair::new();
    add_ed25519_role(
        &mut context,
        &swig,
        &root,
        &limited_authority,
        vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
    )?;

    require_success(
        send_remove(&mut context, swig, &limited_authority, 1, 1)?,
        "non-admin self-removal",
    )?;

    let account = context
        .svm
        .get_account(&swig)
        .ok_or_else(|| anyhow!("swig account missing after self-removal"))?;
    let swig_state = SwigWithRoles::from_bytes(&account.data)
        .map_err(|error| anyhow!("failed to decode swig: {error:?}"))?;
    assert_eq!(swig_state.state.roles, 1);
    assert!(swig_state
        .get_role(0)
        .map_err(|error| anyhow!("failed to load root role: {error:?}"))?
        .ok_or_else(|| anyhow!("root role missing"))?
        .get_action::<All>(&[])
        .map_err(|error| anyhow!("failed to load root All action: {error:?}"))?
        .is_some());
    Ok(())
}
