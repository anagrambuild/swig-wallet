use pinocchio::{msg, program_error::ProgramError};
use swig_state::{
    action::{authlock::AuthorizationLock, Action, Actionable, Permission, IX_SPECIFIC_ACTIONS},
    role::Position,
    SwigStateError, Transmutable,
};

use crate::actions::manage_auth_lock_v1::find_auth_lock_for_mint;

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

/// Recomputes the aggregated authorization lock for a specific mint from all
/// active roles.
///
/// This function iterates through all roles (except the global role ID 0) and
/// aggregates the authorization locks for the specified mint. Only non-expired
/// locks are included.
///
/// # Arguments
/// * `roles` - Raw bytes containing all role data
/// * `mint` - The mint to compute the lock for
/// * `current_slot` - Current slot number to check expiry
///
/// # Returns
/// * `Result<AuthorizationLock, ProgramError>` - The aggregated lock
pub fn recompute_auth_lock_for_mint(
    roles: &[u8],
    mint: &[u8; 32],
    current_slot: u64,
) -> Result<Option<AuthorizationLock>, ProgramError> {
    let mut total_amount = 0u64;
    let mut earliest_expiry = u64::MAX;

    // Iterate all roles (except ID 0 which is the global cache role)
    let mut cursor = 0;
    while cursor < roles.len() {
        if cursor + Position::LEN > roles.len() {
            break;
        }

        let position = unsafe { Position::load_unchecked(&roles[cursor..cursor + Position::LEN])? };

        // Skip global cache role
        if position.id() == 0 {
            cursor = position.boundary() as usize;
            continue;
        }

        // Calculate actions data range
        let actions_start = cursor + Position::LEN + position.authority_length() as usize;
        let actions_end = position.boundary() as usize;

        if actions_start < actions_end && actions_end <= roles.len() {
            let actions_data = unsafe { roles.get_unchecked(actions_start..actions_end) };

            // Check for AuthorizationLock with this mint
            if let Some(lock) = find_auth_lock_for_mint(actions_data, mint)? {
                // Only include non-expired locks
                if !lock.is_expired(current_slot) {
                    total_amount = total_amount.saturating_add(lock.amount);
                    earliest_expiry = earliest_expiry.min(lock.expires_at);
                }
            }
        }

        cursor = position.boundary() as usize;
    }

    if total_amount == 0 {
        return Ok(None);
    }

    Ok(Some(AuthorizationLock::new(
        *mint,
        total_amount,
        earliest_expiry,
    )))
}
