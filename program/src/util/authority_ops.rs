use pinocchio::program_error::ProgramError;
use swig_state::{
    action::{Action, Permission, IX_SPECIFIC_ACTIONS},
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
) -> Result<(), ProgramError> {
    let mut cursor = 0;
    let mut index = 0;
    while cursor < existing_actions.len() {
        if cursor + Action::LEN > existing_actions.len() {
            break;
        }
        let action =
            unsafe { Action::load_unchecked(&existing_actions[cursor..cursor + Action::LEN])? };
        if remove_indexes.contains(&index) && IX_SPECIFIC_ACTIONS.contains(&action.permission()?) {
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
