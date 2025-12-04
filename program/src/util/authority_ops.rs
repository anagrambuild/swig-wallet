use pinocchio::{msg, program_error::ProgramError};
use swig_state::{
    action::{authlock::AuthorizationLock, Action, Actionable, Permission, IX_SPECIFIC_ACTIONS},
    SwigStateError, Transmutable,
};

pub fn check_new_actions_validity(new_actions: &[u8]) -> Result<(), ProgramError> {
    let mut cursor = 0;
    while cursor < new_actions.len() {
        if cursor + Action::LEN > new_actions.len() {
            break;
        }
        let action = unsafe { Action::load_unchecked(&new_actions[cursor..cursor + Action::LEN])? };
        if IX_SPECIFIC_ACTIONS.contains(&action.permission()?) {
            return Err(SwigStateError::InvalidPermissionForRole.into());
        }
        cursor = action.boundary() as usize;
    }
    Ok(())
}

pub fn check_remove_actions_validity_by_index(
    existing_actions: &[u8],
    remove_indexes: &[u16],
    authlock_exists: bool,
) -> Result<(), ProgramError> {
    let mut cursor = 0;
    let mut index = 0;
    while cursor < existing_actions.len() {
        if cursor + Action::LEN > existing_actions.len() {
            break;
        }
        let action =
            unsafe { Action::load_unchecked(&existing_actions[cursor..cursor + Action::LEN])? };
        // Cannot remove ix specific actions
        if remove_indexes.contains(&index) && IX_SPECIFIC_ACTIONS.contains(&action.permission()?) {
            return Err(SwigStateError::InvalidPermissionForRole.into());
        }
        // Cannot remove manage authlocks if authlock exists
        if authlock_exists
            && remove_indexes.contains(&index)
            && action.permission()? == Permission::ManageAuthorizationLocks
        {
            return Err(SwigStateError::InvalidPermissionForRole.into());
        }
        cursor = action.boundary() as usize;
        index += 1;
    }
    Ok(())
}

pub fn check_remove_actions_validity_by_type(remove_types: &[u8]) -> Result<(), ProgramError> {
    for permission in IX_SPECIFIC_ACTIONS {
        if remove_types.contains(&(permission as u8)) {
            return Err(SwigStateError::InvalidPermissionForRole.into());
        }
    }
    Ok(())
}

pub fn get_all_actions_of_type<'a, A: Actionable<'a>>(
    actions_bytes: &'a [u8],
) -> Result<Vec<&'a A>, ProgramError> {
    let mut matched_actions: Vec<&'a A> = Vec::new();
    let mut cursor = 0;
    if actions_bytes.len() < Action::LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    while cursor < actions_bytes.len() {
        let action = unsafe {
            Action::load_unchecked(actions_bytes.get_unchecked(cursor..cursor + Action::LEN))?
        };
        cursor += Action::LEN;
        if action.permission()? == A::TYPE {
            let action_obj =
                unsafe { A::load_unchecked(actions_bytes.get_unchecked(cursor..cursor + A::LEN))? };
            matched_actions.push(action_obj);
        }
        cursor = action.boundary() as usize;
    }
    Ok(matched_actions)
}
