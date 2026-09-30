use pinocchio::program_error::ProgramError;
use swig_state::{
    action::{
        all::All,
        all_but_manage_authority::AllButManageAuthority,
        close_swig_authority::CloseSwigAuthority,
        manage_authority::ManageAuthority,
        program::Program,
        program_all::ProgramAll,
        program_curated::ProgramCurated,
        program_scope::ProgramScope,
        replace_authority::ReplaceAuthority,
        sol_destination_limit::SolDestinationLimit,
        sol_limit::SolLimit,
        sol_recurring_destination_limit::SolRecurringDestinationLimit,
        sol_recurring_limit::SolRecurringLimit,
        stake_all::StakeAll,
        stake_limit::StakeLimit,
        stake_recurring_limit::StakeRecurringLimit,
        sub_account::SubAccount,
        sub_account_v2::{SubAccountV2All, SubAccountV2Create},
        token_destination_limit::TokenDestinationLimit,
        token_limit::TokenLimit,
        token_recurring_destination_limit::TokenRecurringDestinationLimit,
        token_recurring_limit::TokenRecurringLimit,
        Action, ActionLoader, Permission,
    },
    IntoBytes, SwigStateError, Transmutable,
};

fn action_bytes(permission: Permission, data_len: usize) -> Vec<u8> {
    let mut bytes = Action::new(permission, data_len as u16, (Action::LEN + data_len) as u32)
        .into_bytes()
        .unwrap()
        .to_vec();
    bytes.resize(bytes.len() + data_len, 0);
    bytes
}

#[test]
fn every_nonrepeatable_permission_type_is_rejected_twice_in_one_role() {
    let permissions = [
        (Permission::SolLimit, SolLimit::LEN),
        (Permission::SolRecurringLimit, SolRecurringLimit::LEN),
        (Permission::All, All::LEN),
        (Permission::ManageAuthority, ManageAuthority::LEN),
        (Permission::StakeLimit, StakeLimit::LEN),
        (Permission::StakeRecurringLimit, StakeRecurringLimit::LEN),
        (Permission::StakeAll, StakeAll::LEN),
        (Permission::ProgramAll, ProgramAll::LEN),
        (Permission::ProgramCurated, ProgramCurated::LEN),
        (
            Permission::AllButManageAuthority,
            AllButManageAuthority::LEN,
        ),
        (Permission::CloseSwigAuthority, CloseSwigAuthority::LEN),
    ];

    for (permission, data_len) in permissions {
        let mut actions = action_bytes(permission, data_len);
        actions.extend(action_bytes(permission, data_len));
        assert_eq!(
            ActionLoader::validate_v2_actions(&actions, 0),
            Err(ProgramError::Custom(
                SwigStateError::DuplicateNonRepeatableAction as u32,
            )),
            "duplicate {permission:?} should be rejected",
        );
    }
}

#[test]
fn repeatable_permissions_remain_repeatable_in_one_role() {
    let permissions = [
        (Permission::Program, Program::LEN),
        (Permission::ProgramScope, ProgramScope::LEN),
        (Permission::TokenLimit, TokenLimit::LEN),
        (Permission::TokenRecurringLimit, TokenRecurringLimit::LEN),
        (Permission::SubAccount, SubAccount::LEN),
        (Permission::SolDestinationLimit, SolDestinationLimit::LEN),
        (
            Permission::SolRecurringDestinationLimit,
            SolRecurringDestinationLimit::LEN,
        ),
        (
            Permission::TokenDestinationLimit,
            TokenDestinationLimit::LEN,
        ),
        (
            Permission::TokenRecurringDestinationLimit,
            TokenRecurringDestinationLimit::LEN,
        ),
        (Permission::ReplaceAuthority, ReplaceAuthority::LEN),
    ];

    for (permission, data_len) in permissions {
        let mut actions = action_bytes(permission, data_len);
        actions.extend(action_bytes(permission, data_len));
        assert_eq!(
            ActionLoader::validate_v2_actions(&actions, 0),
            Ok(()),
            "repeatable {permission:?} should remain allowed",
        );
    }

    let mut scoped = action_bytes(Permission::SubAccountV2All, SubAccountV2All::LEN);
    let mut second_scope = action_bytes(Permission::SubAccountV2All, SubAccountV2All::LEN);
    second_scope[Action::LEN..Action::LEN + size_of::<u32>()].copy_from_slice(&1u32.to_le_bytes());
    scoped.extend(second_scope);
    assert_eq!(ActionLoader::validate_v2_actions(&scoped, 2), Ok(()));
}

#[test]
fn duplicate_v2_create_keeps_the_existing_specific_error() {
    let mut actions = action_bytes(Permission::SubAccountV2Create, SubAccountV2Create::LEN);
    actions.extend(action_bytes(
        Permission::SubAccountV2Create,
        SubAccountV2Create::LEN,
    ));

    assert_eq!(
        ActionLoader::validate_v2_actions(&actions, 0),
        Err(ProgramError::Custom(
            SwigStateError::DuplicateV2SubAccountAction as u32,
        )),
    );
}

#[test]
fn distinct_nonrepeatable_permission_types_can_coexist() {
    let mut actions = action_bytes(Permission::SolLimit, SolLimit::LEN);
    actions.extend(action_bytes(
        Permission::SolRecurringLimit,
        SolRecurringLimit::LEN,
    ));

    assert_eq!(ActionLoader::validate_v2_actions(&actions, 0), Ok(()));
}
