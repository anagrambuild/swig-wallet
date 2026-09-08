#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use solana_sdk::{
    instruction::{Instruction, InstructionError},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{
    AddAuthorityInstruction, AuthorityConfig, ClientAction, CreateSessionInstruction,
    RemoveAuthorityInstruction, ReplaceAuthorityInstruction, UpdateAuthorityData,
    UpdateAuthorityInstruction,
};
use swig_state::{
    action::{
        all::All, manage_authority::ManageAuthority, replace_authority::ReplaceAuthority,
        sol_limit::SolLimit, Permission,
    },
    authority::{ed25519::CreateEd25519SessionAuthority, AuthorityType},
    swig::SwigWithRoles,
    IntoBytes, SwigAuthenticateError,
};

fn setup_manager(action: ClientAction) -> (SwigTestContext, Pubkey, Keypair, Keypair) {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let manager = Keypair::new();
    let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: manager.pubkey().as_ref(),
        },
        vec![action],
    )
    .unwrap();
    (context, swig, root, manager)
}

fn send(
    context: &mut SwigTestContext,
    signer: &Keypair,
    instruction: Instruction,
) -> Result<TransactionMetadata, Box<FailedTransactionMetadata>> {
    context.svm.expire_blockhash();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[instruction],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, signer],
    )
    .unwrap();
    context.svm.send_transaction(transaction).map_err(Box::new)
}

fn assert_rejected_unchanged(
    context: &mut SwigTestContext,
    swig: Pubkey,
    signer: &Keypair,
    instruction: Instruction,
    expected: SwigAuthenticateError,
) {
    let before = context.svm.get_account(&swig).unwrap();
    let error = send(context, signer, instruction).unwrap_err();
    assert_eq!(
        error.err,
        TransactionError::InstructionError(0, InstructionError::Custom(expected as u32)),
        "logs: {:?}",
        error.meta.logs,
    );
    assert_eq!(context.svm.get_account(&swig).unwrap(), before);
}

#[test]
fn delegated_managers_cannot_update_root_with_any_operation() {
    for action in [
        ClientAction::All(All {}),
        ClientAction::ManageAuthority(ManageAuthority {}),
    ] {
        let (mut context, swig, root, manager) = setup_manager(action);
        for operation in [
            UpdateAuthorityData::ReplaceAll(vec![ClientAction::SolLimit(SolLimit { amount: 1 })]),
            UpdateAuthorityData::AddActions(vec![ClientAction::SolLimit(SolLimit { amount: 1 })]),
            UpdateAuthorityData::RemoveActionsByType(vec![Permission::All as u8]),
            UpdateAuthorityData::RemoveActionsByIndex(vec![0]),
        ] {
            let instruction = UpdateAuthorityInstruction::new_with_ed25519_authority(
                swig,
                context.default_payer.pubkey(),
                manager.pubkey(),
                1,
                0,
                operation,
            )
            .unwrap();
            assert_rejected_unchanged(
                &mut context,
                swig,
                &manager,
                instruction,
                SwigAuthenticateError::PermissionDeniedCannotUpdateRootAuthority,
            );
        }

        // A rejected root mutation must leave the owner's revocation usable.
        let revoke = RemoveAuthorityInstruction::new_with_ed25519_authority(
            swig,
            context.default_payer.pubkey(),
            root.pubkey(),
            0,
            1,
        )
        .unwrap();
        send(&mut context, &root, revoke).unwrap();
        let account = context.svm.get_account(&swig).unwrap();
        let state = SwigWithRoles::from_bytes(&account.data).unwrap();
        assert!(state.get_role(1).unwrap().is_none());
        assert!(state
            .get_role(0)
            .unwrap()
            .unwrap()
            .get_action::<All>(&[])
            .unwrap()
            .is_some());
    }
}

#[test]
fn root_can_update_its_own_permissions_with_every_operation() {
    let (mut context, swig, root, _) = setup_manager(ClientAction::All(All {}));
    for operation in [
        UpdateAuthorityData::AddActions(vec![ClientAction::SolLimit(SolLimit { amount: 1 })]),
        UpdateAuthorityData::RemoveActionsByType(vec![Permission::SolLimit as u8]),
        UpdateAuthorityData::AddActions(vec![ClientAction::SolLimit(SolLimit { amount: 1 })]),
        UpdateAuthorityData::RemoveActionsByIndex(vec![1]),
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::ManageAuthority(ManageAuthority {})]),
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::All(All {})]),
    ] {
        let instruction = UpdateAuthorityInstruction::new_with_ed25519_authority(
            swig,
            context.default_payer.pubkey(),
            root.pubkey(),
            0,
            0,
            operation,
        )
        .unwrap();
        send(&mut context, &root, instruction).unwrap();
    }
    let account = context.svm.get_account(&swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let role = state.get_role(0).unwrap().unwrap();
    assert_eq!(role.position.num_actions(), 1);
    assert!(role.get_action::<All>(&[]).unwrap().is_some());
}

#[test]
fn delegated_managers_cannot_replace_root_without_an_explicit_scope() {
    for action in [
        ClientAction::All(All {}),
        ClientAction::ManageAuthority(ManageAuthority {}),
    ] {
        let (mut context, swig, _, manager) = setup_manager(action);
        let replacement = Keypair::new();
        let instruction = ReplaceAuthorityInstruction::new_with_ed25519_authority(
            swig,
            manager.pubkey(),
            1,
            0,
            replacement.pubkey().as_ref(),
        )
        .unwrap();
        assert_rejected_unchanged(
            &mut context,
            swig,
            &manager,
            instruction,
            SwigAuthenticateError::PermissionDeniedCannotUpdateRootAuthority,
        );
    }
}

#[test]
fn root_recovery_requires_the_matching_scope_and_preserves_permissions() {
    for target in [0, 1] {
        let (mut context, swig, _, recovery) = setup_manager(ClientAction::ReplaceAuthority(
            ReplaceAuthority::new(target),
        ));
        let replacement = Keypair::new();
        let instruction = ReplaceAuthorityInstruction::new_with_ed25519_authority(
            swig,
            recovery.pubkey(),
            1,
            0,
            replacement.pubkey().as_ref(),
        )
        .unwrap();
        if target != 0 {
            assert_rejected_unchanged(
                &mut context,
                swig,
                &recovery,
                instruction,
                SwigAuthenticateError::PermissionDeniedMissingPermission,
            );
            continue;
        }
        let before = context.svm.get_account(&swig).unwrap();
        let before_state = SwigWithRoles::from_bytes(&before.data).unwrap();
        let before_actions = before_state.get_role(0).unwrap().unwrap().actions.to_vec();
        send(&mut context, &recovery, instruction).unwrap();
        let account = context.svm.get_account(&swig).unwrap();
        let state = SwigWithRoles::from_bytes(&account.data).unwrap();
        let role = state.get_role(0).unwrap().unwrap();
        assert_eq!(
            role.authority.identity().unwrap(),
            replacement.pubkey().as_ref()
        );
        assert_eq!(role.actions, before_actions);

        let revoke = RemoveAuthorityInstruction::new_with_ed25519_authority(
            swig,
            context.default_payer.pubkey(),
            replacement.pubkey(),
            0,
            1,
        )
        .unwrap();
        send(&mut context, &replacement, revoke).unwrap();
    }
}

#[test]
fn root_can_rotate_its_own_signer() {
    let (mut context, swig, root, _) = setup_manager(ClientAction::All(All {}));
    let replacement = Keypair::new();
    let instruction = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig,
        root.pubkey(),
        0,
        0,
        replacement.pubkey().as_ref(),
    )
    .unwrap();
    send(&mut context, &root, instruction).unwrap();
    let account = context.svm.get_account(&swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let role = state.get_role(0).unwrap().unwrap();
    assert_eq!(
        role.authority.identity().unwrap(),
        replacement.pubkey().as_ref()
    );
    assert!(role.get_action::<All>(&[]).unwrap().is_some());
}

#[test]
fn delegated_managers_can_still_update_and_replace_ordinary_roles() {
    for action in [
        ClientAction::All(All {}),
        ClientAction::ManageAuthority(ManageAuthority {}),
    ] {
        let (mut context, swig, _, manager) = setup_manager(action);
        let target = Keypair::new();
        add_authority_with_ed25519_root(
            &mut context,
            &swig,
            &manager,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: target.pubkey().as_ref(),
            },
            vec![ClientAction::All(All {})],
        )
        .unwrap();
        let update = UpdateAuthorityInstruction::new_with_ed25519_authority(
            swig,
            context.default_payer.pubkey(),
            manager.pubkey(),
            1,
            2,
            UpdateAuthorityData::ReplaceAll(vec![ClientAction::ManageAuthority(
                ManageAuthority {},
            )]),
        )
        .unwrap();
        send(&mut context, &manager, update).unwrap();
        let replacement = Keypair::new();
        let replace = ReplaceAuthorityInstruction::new_with_ed25519_authority(
            swig,
            manager.pubkey(),
            1,
            2,
            replacement.pubkey().as_ref(),
        )
        .unwrap();
        send(&mut context, &manager, replace).unwrap();
        let account = context.svm.get_account(&swig).unwrap();
        let state = SwigWithRoles::from_bytes(&account.data).unwrap();
        let role = state.get_role(2).unwrap().unwrap();
        assert_eq!(
            role.authority.identity().unwrap(),
            replacement.pubkey().as_ref()
        );
        assert!(role.get_action::<ManageAuthority>(&[]).unwrap().is_some());
    }
}

#[test]
fn only_root_can_grant_replacement_scopes_through_add_or_update() {
    for action in [
        ClientAction::All(All {}),
        ClientAction::ManageAuthority(ManageAuthority {}),
    ] {
        let (mut context, swig, root, manager) = setup_manager(action);
        // Protect every scope, including permission to replace a recovery
        // delegate rather than root directly.
        for scope in [0, 1] {
            let new_authority = Keypair::new();
            let add = AddAuthorityInstruction::new_with_ed25519_authority(
                swig,
                context.default_payer.pubkey(),
                manager.pubkey(),
                1,
                AuthorityConfig {
                    authority_type: AuthorityType::Ed25519,
                    authority: new_authority.pubkey().as_ref(),
                },
                vec![
                    ClientAction::All(All {}),
                    ClientAction::ReplaceAuthority(ReplaceAuthority::new(scope)),
                ],
            )
            .unwrap();
            assert_rejected_unchanged(
                &mut context,
                swig,
                &manager,
                add,
                SwigAuthenticateError::PermissionDeniedToManageAuthority,
            );
            for operation in [
                UpdateAuthorityData::AddActions(vec![ClientAction::ReplaceAuthority(
                    ReplaceAuthority::new(scope),
                )]),
                UpdateAuthorityData::ReplaceAll(vec![
                    ClientAction::All(All {}),
                    ClientAction::ReplaceAuthority(ReplaceAuthority::new(scope)),
                ]),
            ] {
                let update = UpdateAuthorityInstruction::new_with_ed25519_authority(
                    swig,
                    context.default_payer.pubkey(),
                    manager.pubkey(),
                    1,
                    1,
                    operation,
                )
                .unwrap();
                assert_rejected_unchanged(
                    &mut context,
                    swig,
                    &manager,
                    update,
                    SwigAuthenticateError::PermissionDeniedToManageAuthority,
                );
            }
        }

        // Root may grant and subsequently revise recovery permissions through
        // both update encodings; a manager with an explicit scope can use it.
        for operation in [
            UpdateAuthorityData::AddActions(vec![ClientAction::ReplaceAuthority(
                ReplaceAuthority::new(0),
            )]),
            UpdateAuthorityData::ReplaceAll(vec![
                ClientAction::All(All {}),
                ClientAction::ReplaceAuthority(ReplaceAuthority::new(0)),
            ]),
        ] {
            let update = UpdateAuthorityInstruction::new_with_ed25519_authority(
                swig,
                context.default_payer.pubkey(),
                root.pubkey(),
                0,
                1,
                operation,
            )
            .unwrap();
            send(&mut context, &root, update).unwrap();
        }
        let replacement = Keypair::new();
        let replace = ReplaceAuthorityInstruction::new_with_ed25519_authority(
            swig,
            manager.pubkey(),
            1,
            0,
            replacement.pubkey().as_ref(),
        )
        .unwrap();
        send(&mut context, &manager, replace).unwrap();
    }
}

#[test]
fn managers_cannot_rewrite_or_take_over_existing_recovery_roles() {
    for action in [
        ClientAction::All(All {}),
        ClientAction::ManageAuthority(ManageAuthority {}),
    ] {
        let (mut context, swig, root, manager) = setup_manager(action);
        for scope in [0, 1] {
            let recovery = Keypair::new();
            add_authority_with_ed25519_root(
                &mut context,
                &swig,
                &root,
                AuthorityConfig {
                    authority_type: AuthorityType::Ed25519,
                    authority: recovery.pubkey().as_ref(),
                },
                vec![
                    ClientAction::All(All {}),
                    ClientAction::ReplaceAuthority(ReplaceAuthority::new(scope)),
                ],
            )
            .unwrap();
            let account = context.svm.get_account(&swig).unwrap();
            let state = SwigWithRoles::from_bytes(&account.data).unwrap();
            let target_role = state
                .lookup_role_id(recovery.pubkey().as_ref())
                .unwrap()
                .unwrap();
            for operation in [
                UpdateAuthorityData::ReplaceAll(vec![ClientAction::All(All {})]),
                UpdateAuthorityData::AddActions(vec![ClientAction::SolLimit(SolLimit {
                    amount: 1,
                })]),
                UpdateAuthorityData::RemoveActionsByType(vec![Permission::ReplaceAuthority as u8]),
                UpdateAuthorityData::RemoveActionsByIndex(vec![1]),
            ] {
                let update = UpdateAuthorityInstruction::new_with_ed25519_authority(
                    swig,
                    context.default_payer.pubkey(),
                    manager.pubkey(),
                    1,
                    target_role,
                    operation,
                )
                .unwrap();
                assert_rejected_unchanged(
                    &mut context,
                    swig,
                    &manager,
                    update,
                    SwigAuthenticateError::PermissionDeniedToManageAuthority,
                );
            }
            let replace = ReplaceAuthorityInstruction::new_with_ed25519_authority(
                swig,
                manager.pubkey(),
                1,
                target_role,
                manager.pubkey().as_ref(),
            )
            .unwrap();
            assert_rejected_unchanged(
                &mut context,
                swig,
                &manager,
                replace,
                SwigAuthenticateError::PermissionDeniedToManageAuthority,
            );

            // Possessing recovery and All does not permit editing one's own
            // root-controlled action set, but existing self-rotation remains.
            let update = UpdateAuthorityInstruction::new_with_ed25519_authority(
                swig,
                context.default_payer.pubkey(),
                recovery.pubkey(),
                target_role,
                target_role,
                UpdateAuthorityData::ReplaceAll(vec![ClientAction::All(All {})]),
            )
            .unwrap();
            assert_rejected_unchanged(
                &mut context,
                swig,
                &recovery,
                update,
                SwigAuthenticateError::PermissionDeniedToManageAuthority,
            );
            let new_recovery = Keypair::new();
            let replace = ReplaceAuthorityInstruction::new_with_ed25519_authority(
                swig,
                recovery.pubkey(),
                target_role,
                target_role,
                new_recovery.pubkey().as_ref(),
            )
            .unwrap();
            send(&mut context, &recovery, replace).unwrap();

            // Root can explicitly grant another role permission to rotate this
            // recovery signer; a generic manager alone cannot do so.
            let scoped = Keypair::new();
            add_authority_with_ed25519_root(
                &mut context,
                &swig,
                &root,
                AuthorityConfig {
                    authority_type: AuthorityType::Ed25519,
                    authority: scoped.pubkey().as_ref(),
                },
                vec![ClientAction::ReplaceAuthority(ReplaceAuthority::new(
                    target_role,
                ))],
            )
            .unwrap();
            let account = context.svm.get_account(&swig).unwrap();
            let state = SwigWithRoles::from_bytes(&account.data).unwrap();
            let scoped_role = state
                .lookup_role_id(scoped.pubkey().as_ref())
                .unwrap()
                .unwrap();
            let replace = ReplaceAuthorityInstruction::new_with_ed25519_authority(
                swig,
                scoped.pubkey(),
                scoped_role,
                target_role,
                recovery.pubkey().as_ref(),
            )
            .unwrap();
            send(&mut context, &scoped, replace).unwrap();
        }
    }
}

#[test]
fn active_administrative_sessions_cannot_update_or_replace_root() {
    for action in [
        ClientAction::All(All {}),
        ClientAction::ManageAuthority(ManageAuthority {}),
    ] {
        let mut context = setup_test_context().unwrap();
        let root = Keypair::new();
        let owner = Keypair::new();
        let session_key = Keypair::new();
        let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
        let authority = CreateEd25519SessionAuthority::new(owner.pubkey().to_bytes(), [0; 32], 100);
        add_authority_with_ed25519_root(
            &mut context,
            &swig,
            &root,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519Session,
                authority: authority.into_bytes().unwrap(),
            },
            vec![action],
        )
        .unwrap();
        context.svm.warp_to_slot(1);
        let create_session = CreateSessionInstruction::new_with_ed25519_authority(
            swig,
            context.default_payer.pubkey(),
            owner.pubkey(),
            1,
            session_key.pubkey(),
            50,
        )
        .unwrap();
        send(&mut context, &owner, create_session).unwrap();
        let update = UpdateAuthorityInstruction::new_with_ed25519_authority(
            swig,
            context.default_payer.pubkey(),
            session_key.pubkey(),
            1,
            0,
            UpdateAuthorityData::ReplaceAll(vec![ClientAction::SolLimit(SolLimit { amount: 1 })]),
        )
        .unwrap();
        let replace = ReplaceAuthorityInstruction::new_with_ed25519_authority(
            swig,
            session_key.pubkey(),
            1,
            0,
            owner.pubkey().as_ref(),
        )
        .unwrap();
        for instruction in [update, replace] {
            assert_rejected_unchanged(
                &mut context,
                swig,
                &session_key,
                instruction,
                SwigAuthenticateError::PermissionDeniedCannotUpdateRootAuthority,
            );
        }
    }
}
