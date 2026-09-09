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
use swig::actions::{
    add_authority_v1::AddAuthorityV1Args, update_authority_v1::UpdateAuthorityV1Args,
};
use swig_interface::{
    AddAuthorityInstruction, AuthorityConfig, ClientAction, CreateSessionInstruction,
    RemoveAuthorityInstruction, ReplaceAuthorityInstruction, UpdateAuthorityData,
    UpdateAuthorityInstruction,
};
use swig_state::{
    action::{
        all::All, manage_authority::ManageAuthority, replace_authority::ReplaceAuthority,
        sol_limit::SolLimit, Action, Permission,
    },
    authority::{ed25519::CreateEd25519SessionAuthority, AuthorityType},
    swig::SwigWithRoles,
    IntoBytes, SwigAuthenticateError, Transmutable,
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
fn only_root_can_grant_recovery_for_root_through_add_or_update() {
    for manage_only in [false, true] {
        for scope in [0, 1] {
            for normalized_boundaries in [false, true] {
                let manager_action = if manage_only {
                    ClientAction::ManageAuthority(ManageAuthority {})
                } else {
                    ClientAction::All(All {})
                };
                let (mut context, swig, root, manager) = setup_manager(manager_action);
                let recovery = Keypair::new();
                // Put root's scope after a non-root scope to check every grant.
                let actions = || {
                    vec![
                        ClientAction::ReplaceAuthority(ReplaceAuthority::new(1)),
                        ClientAction::ReplaceAuthority(ReplaceAuthority::new(scope)),
                    ]
                };
                for acting_root in [false, true] {
                    let (signer, acting_role_id) = if acting_root {
                        (&root, 0)
                    } else {
                        (&manager, 1)
                    };
                    let mut add = AddAuthorityInstruction::new_with_ed25519_authority(
                        swig,
                        context.default_payer.pubkey(),
                        signer.pubkey(),
                        acting_role_id,
                        AuthorityConfig {
                            authority_type: AuthorityType::Ed25519,
                            authority: recovery.pubkey().as_ref(),
                        },
                        actions(),
                    )
                    .unwrap();
                    if normalized_boundaries {
                        clear_instruction_action_boundaries(&mut add, AddAuthorityV1Args::LEN + 32);
                    }
                    if scope == 0 && !acting_root {
                        assert_rejected_unchanged(
                            &mut context,
                            swig,
                            signer,
                            add,
                            SwigAuthenticateError::PermissionDeniedToManageAuthority,
                        );
                    } else {
                        send(&mut context, signer, add).unwrap();
                        break;
                    }
                }
                for acting_root in [false, true] {
                    let (signer, acting_role_id) = if acting_root {
                        (&root, 0)
                    } else {
                        (&manager, 1)
                    };
                    for operation in [
                        UpdateAuthorityData::AddActions(actions()),
                        UpdateAuthorityData::ReplaceAll(actions()),
                    ] {
                        let mut update = UpdateAuthorityInstruction::new_with_ed25519_authority(
                            swig,
                            context.default_payer.pubkey(),
                            signer.pubkey(),
                            acting_role_id,
                            2,
                            operation,
                        )
                        .unwrap();
                        if normalized_boundaries {
                            clear_instruction_action_boundaries(
                                &mut update,
                                UpdateAuthorityV1Args::LEN + 1,
                            );
                        }
                        if scope == 0 && !acting_root {
                            assert_rejected_unchanged(
                                &mut context,
                                swig,
                                signer,
                                update,
                                SwigAuthenticateError::PermissionDeniedToManageAuthority,
                            );
                        } else {
                            send(&mut context, signer, update).unwrap();
                        }
                    }
                }
                let account = context.svm.get_account(&swig).unwrap();
                let state = SwigWithRoles::from_bytes(&account.data).unwrap();
                let role = state.get_role(2).unwrap().unwrap();
                assert_eq!(role.position.num_actions(), 2);
                assert!(role
                    .get_action::<ReplaceAuthority>(&scope.to_le_bytes())
                    .unwrap()
                    .is_some());
            }
        }
    }
}

#[test]
fn managers_retain_existing_management_of_recovery_roles() {
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
            let before_actions = state
                .get_role(target_role)
                .unwrap()
                .unwrap()
                .actions
                .to_vec();
            let replacement = Keypair::new();
            let replace = ReplaceAuthorityInstruction::new_with_ed25519_authority(
                swig,
                manager.pubkey(),
                1,
                target_role,
                replacement.pubkey().as_ref(),
            )
            .unwrap();
            send(&mut context, &manager, replace).unwrap();
            let account = context.svm.get_account(&swig).unwrap();
            let state = SwigWithRoles::from_bytes(&account.data).unwrap();
            let role = state.get_role(target_role).unwrap().unwrap();
            assert_eq!(
                role.authority.identity().unwrap(),
                replacement.pubkey().as_ref()
            );
            assert_eq!(role.actions, before_actions);

            for operation in [
                UpdateAuthorityData::AddActions(vec![ClientAction::SolLimit(SolLimit {
                    amount: 1,
                })]),
                UpdateAuthorityData::RemoveActionsByIndex(vec![2]),
                UpdateAuthorityData::RemoveActionsByType(vec![Permission::ReplaceAuthority as u8]),
                UpdateAuthorityData::ReplaceAll(vec![ClientAction::All(All {})]),
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
                send(&mut context, &manager, update).unwrap();
            }
            let account = context.svm.get_account(&swig).unwrap();
            let state = SwigWithRoles::from_bytes(&account.data).unwrap();
            let role = state.get_role(target_role).unwrap().unwrap();
            assert_eq!(role.position.num_actions(), 1);
            assert!(role.get_action::<All>(&[]).unwrap().is_some());
        }
    }
}

#[test]
fn active_administrative_sessions_cannot_update_root_or_grant_its_recovery() {
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
        for (target, operation, error) in [
            (
                0,
                UpdateAuthorityData::ReplaceAll(vec![ClientAction::All(All {})]),
                SwigAuthenticateError::PermissionDeniedCannotUpdateRootAuthority,
            ),
            (
                1,
                UpdateAuthorityData::AddActions(vec![ClientAction::ReplaceAuthority(
                    ReplaceAuthority::new(0),
                )]),
                SwigAuthenticateError::PermissionDeniedToManageAuthority,
            ),
        ] {
            let update = UpdateAuthorityInstruction::new_with_ed25519_authority(
                swig,
                context.default_payer.pubkey(),
                session_key.pubkey(),
                1,
                target,
                operation,
            )
            .unwrap();
            assert_rejected_unchanged(&mut context, swig, &session_key, update, error);
        }
    }
}

// Change only the boundary fields in a production Ed25519 builder's payload.
// Its final byte selects the authority account and is not part of the actions.
fn clear_instruction_action_boundaries(instruction: &mut Instruction, mut cursor: usize) {
    let actions_end = instruction.data.len() - 1;
    while cursor < actions_end {
        let action_len =
            u16::from_le_bytes(instruction.data[cursor + 2..cursor + 4].try_into().unwrap())
                as usize;
        instruction.data[cursor + 4..cursor + 8].fill(0);
        cursor += Action::LEN + action_len;
    }
    assert_eq!(cursor, actions_end);
}
