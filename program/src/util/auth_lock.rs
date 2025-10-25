use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use swig_assertions::{check_bytes_match, check_self_owned};
use swig_state::{
    action::{
        all::All, authorization_lock::AuthorizationLock,
        manage_auth_lock::ManageAuthorizationLocks, manage_authority::ManageAuthority, Action,
        Actionable, Permission,
    },
    authority::{authority_type_to_length, AuthorityType},
    role::{Position, Role, RoleMut},
    swig::{Swig, SwigBuilder},
    Discriminator, IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, ManageAuthorizationLocksV1Accounts, UpdateAuthorityV1Accounts},
        SwigInstruction,
    },
};

/// Gets the authlocks by mints from the swig roles.
/// If the mint is found in the global role, it will be added to the to_be_updated list.
/// Otherwise, it will be added to the to_be_removed list.
pub fn get_authlock_by_mints(
    swig: &Swig,
    swig_roles: &mut [u8],
    mints: Vec<[u8; 32]>,
) -> Result<(Vec<AuthorizationLock>, Vec<AuthorizationLock>), ProgramError> {
    let mut cursor = 0;
    let mut roles = Vec::new();
    let mut to_be_updated: Vec<AuthorizationLock> = Vec::new();
    let mut to_be_removed: Vec<AuthorizationLock> = Vec::new();

    while cursor < swig_roles.len() {
        let position =
            unsafe { Position::load_unchecked(&swig_roles[cursor..cursor + Position::LEN])? };

        // Skip the global role
        if position.id() != 0 {
            roles.push(position.id());
        }
        cursor = position.boundary() as usize;
    }

    for (index, mint) in mints.iter().enumerate() {
        let mut mint_found = false;
        let mut new_auth_lock = AuthorizationLock {
            mint: mint.clone(),
            amount: 0,
            expires_at: u64::MAX,
        };

        for role_id in &roles {
            let role = Swig::get_mut_role(*role_id, swig_roles)?.unwrap();

            let auth_lock = role.get_action::<AuthorizationLock>(mint);
            if auth_lock.is_ok() {
                let auth_lock = auth_lock.unwrap();

                if auth_lock.is_some() {
                    mint_found = true;
                    new_auth_lock.update_for_global(auth_lock.unwrap());
                }
            }
        }

        if !mint_found {
            to_be_removed.push(new_auth_lock);
        } else {
            to_be_updated.push(new_auth_lock);
        }
    }

    Ok((to_be_updated, to_be_removed))
}

pub fn get_affected_auth_lock_from_role(
    swig_roles: &[u8],
    authority_to_update_id: u32,
) -> Result<(bool, Vec<AuthorizationLock>, Vec<u16>, Option<u16>), ProgramError> {
    let mut cursor = 0;
    let mut authlocks = Vec::new();
    let mut can_manage_auth_lock = false;
    let mut indices = Vec::new();
    let mut auth_lock_index = None;
    while cursor < swig_roles.len() {
        if cursor + Position::LEN > swig_roles.len() {
            break;
        }
        let position =
            unsafe { Position::load_unchecked(&swig_roles[cursor..cursor + Position::LEN])? };
        cursor += Position::LEN;

        if position.id() == authority_to_update_id {
            let actions_data = &swig_roles
                [cursor + position.authority_length() as usize..position.boundary() as usize];

            let mut action_cursor = 0;
            let mut action_index = 0u16;

            while action_cursor + Action::LEN <= actions_data.len() {
                let action = unsafe {
                    Action::load_unchecked(
                        &actions_data[action_cursor..action_cursor + Action::LEN],
                    )?
                };

                if action.permission()? == Permission::AuthorizationLock {
                    // Check if we have enough data to read the AuthorizationLock
                    let auth_lock_start = action_cursor + Action::LEN;
                    let auth_lock_end = auth_lock_start + AuthorizationLock::LEN;

                    if auth_lock_end <= actions_data.len() {
                        let auth_lock = unsafe {
                            AuthorizationLock::load_unchecked(
                                &actions_data[auth_lock_start..auth_lock_end],
                            )
                            .map_err(|_| ProgramError::InvalidInstructionData)?
                        };
                        authlocks.push(AuthorizationLock {
                            mint: auth_lock.mint,
                            amount: auth_lock.amount,
                            expires_at: auth_lock.expires_at,
                        });
                        indices.push(action_index);
                    }
                }

                if action.permission()? == Permission::ManageAuthorizationLocks {
                    can_manage_auth_lock = true;
                    auth_lock_index = Some(action_index);
                }

                action_index += 1;
                // Advance to the next action by skipping the current action's data
                action_cursor += Action::LEN + action.length() as usize;
            }
        }
        cursor = position.boundary() as usize;
    }
    Ok((can_manage_auth_lock, authlocks, indices, auth_lock_index))
}

pub fn get_matching_args_action_by_mint(
    authlocks: &mut Vec<AuthorizationLock>,
    mint: [u8; 32],
) -> Option<AuthorizationLock> {
    let mut found_index = None;
    for (index, authlock) in authlocks.iter().enumerate() {
        if authlock.mint == mint {
            found_index = Some(index);
            break;
        }
    }
    if found_index.is_none() {
        return None;
    }
    let index = found_index.unwrap();
    Some(authlocks.remove(index))
}

pub fn modify_global_auth_locks(
    swig_account_data: &mut [u8],
    mints: Vec<[u8; 32]>,
) -> Result<i64, ProgramError> {
    // Get fresh references to the swig account data after reallocation
    let swig_data_len = swig_account_data.len();
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };

    let (mut to_be_updated, mut to_be_removed) = get_authlock_by_mints(swig, swig_roles, mints)?;

    let target_role_id = 0;
    let mut size_diff = 0;
    let (current_actions_size, authority_offset, actions_offset) = {
        let mut cursor = 0;
        let mut found = false;
        let mut auth_offset = 0;
        let mut act_offset = 0;
        let mut current_size = 0;

        for _i in 0..swig.roles {
            let position =
                unsafe { Position::load_unchecked(&swig_roles[cursor..cursor + Position::LEN])? };
            if position.id() == target_role_id {
                found = true;
                auth_offset = cursor;
                act_offset = cursor + Position::LEN + position.authority_length() as usize;
                current_size = position.boundary() as usize - act_offset;

                break;
            }
            cursor = position.boundary() as usize;
        }

        if !found {
            return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
        }

        (current_size, auth_offset, act_offset)
    };

    if !to_be_updated.is_empty() {
        perform_modify_authlock_operation(
            swig_roles,
            swig_data_len,
            authority_offset,
            actions_offset,
            current_actions_size,
            &mut to_be_updated,
            target_role_id,
            true,
        )?;
    }

    if !to_be_removed.is_empty() {
        size_diff = perform_modify_authlock_operation(
            swig_roles,
            swig_data_len,
            authority_offset,
            actions_offset,
            current_actions_size,
            &mut to_be_removed,
            target_role_id,
            false,
        )?;
    }

    Ok(size_diff)
}

/// Performs a replace-all operation on an authority's actions.
pub fn perform_replace_all_operation(
    swig_roles: &mut [u8],
    swig_data_len: usize,
    authority_offset: usize,
    actions_offset: usize,
    current_actions_size: usize,
    new_actions: &[u8],
    authority_to_update_id: u32,
) -> Result<i64, ProgramError> {
    let new_actions_size = new_actions.len();
    let size_diff = new_actions_size as i64 - current_actions_size as i64;

    if size_diff != 0 {
        // Need to shift data if size changed
        let role_end = actions_offset + current_actions_size;
        let original_data_len = (swig_data_len as i64 - Swig::LEN as i64) as usize;
        let remaining_data_len = original_data_len - role_end;

        if size_diff > 0 {
            // Growing: shift data to the right
            if remaining_data_len > 0 {
                let new_role_end = (role_end as i64 + size_diff) as usize;
                if new_role_end + remaining_data_len <= swig_roles.len() {
                    swig_roles.copy_within(role_end..role_end + remaining_data_len, new_role_end);
                } else {
                    return Err(SwigError::StateError.into());
                }
            }
        } else {
            // Shrinking: shift data to the left
            if remaining_data_len > 0 {
                let new_role_end = (role_end as i64 + size_diff) as usize;
                swig_roles.copy_within(role_end..role_end + remaining_data_len, new_role_end);
            }
        }

        // Update boundaries of all roles after this one
        let mut cursor = 0;
        for _i in 0..swig_roles.len() / Position::LEN {
            if cursor + Position::LEN > swig_roles.len() {
                break;
            }
            let position = unsafe {
                Position::load_mut_unchecked(&mut swig_roles[cursor..cursor + Position::LEN])?
            };

            if position.boundary() as usize > role_end {
                position.boundary = (position.boundary() as i64 + size_diff) as u32;
            }

            // Update the position for the role we're updating
            if position.id() == authority_to_update_id {
                position.boundary = (position.boundary() as i64 + size_diff) as u32;
                position.num_actions = if authority_to_update_id == 0 {
                    calculate_num_actions(new_actions).unwrap_or(0) as u16
                } else {
                    calculate_num_actions(new_actions)? as u16
                };
            }

            cursor = position.boundary() as usize;
        }
    } else {
        // Same size: just update the position's num_actions
        let position = unsafe {
            Position::load_mut_unchecked(
                &mut swig_roles[authority_offset..authority_offset + Position::LEN],
            )?
        };
        position.num_actions = if authority_to_update_id == 0 {
            calculate_num_actions(new_actions).unwrap_or(0) as u16
        } else {
            calculate_num_actions(new_actions)? as u16
        };
    }

    if actions_offset + new_actions_size > swig_roles.len() {
        return Err(SwigError::StateError.into());
    }

    // Copy actions data and recalculate boundaries
    let mut cursor = actions_offset;
    let mut action_cursor = 0;

    while action_cursor < new_actions.len() {
        if action_cursor + Action::LEN > new_actions.len() {
            break;
        }

        let action_header = unsafe {
            Action::load_unchecked(&new_actions[action_cursor..action_cursor + Action::LEN])?
        };
        let action_len = action_header.length() as usize;
        let total_action_size = Action::LEN + action_len;

        if action_cursor + total_action_size > new_actions.len() && authority_to_update_id != 0 {
            return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
        }

        // Copy action header and update boundary
        swig_roles[cursor..cursor + Action::LEN]
            .copy_from_slice(&new_actions[action_cursor..action_cursor + Action::LEN]);
        let next_boundary = (cursor - actions_offset + total_action_size) as u32;
        swig_roles[cursor + 4..cursor + 8].copy_from_slice(&next_boundary.to_le_bytes());

        // Copy action data
        swig_roles[cursor + Action::LEN..cursor + total_action_size].copy_from_slice(
            &new_actions[action_cursor + Action::LEN..action_cursor + total_action_size],
        );

        cursor += total_action_size;
        action_cursor += total_action_size;
    }

    Ok(size_diff)
}

/// Performs an add-actions operation on an authority.
pub fn perform_add_actions_operation(
    swig_roles: &mut [u8],
    swig_data_len: usize,
    authority_offset: usize,
    actions_offset: usize,
    current_actions_size: usize,
    new_actions: &[u8],
    authority_to_update_id: u32,
) -> Result<i64, ProgramError> {
    // For add operation, we need to append new actions to existing ones
    let mut combined_actions = Vec::new();

    // Copy existing actions
    combined_actions
        .extend_from_slice(&swig_roles[actions_offset..actions_offset + current_actions_size]);

    // Add new actions
    combined_actions.extend_from_slice(new_actions);

    // Use replace_all logic with combined actions
    perform_replace_all_operation(
        swig_roles,
        swig_data_len,
        authority_offset,
        actions_offset,
        current_actions_size,
        &combined_actions,
        authority_to_update_id,
    )
}

/// Performs a remove-actions-by-type operation on an authority.
pub fn perform_modify_authlock_operation(
    swig_roles: &mut [u8],
    swig_data_len: usize,
    authority_offset: usize,
    actions_offset: usize,
    current_actions_size: usize,
    authlocks: &mut Vec<AuthorizationLock>,
    authority_to_update_id: u32,
    update_op: bool,
) -> Result<i64, ProgramError> {
    let mut filtered_actions = Vec::new();

    let mut cursor = 0;
    let current_actions = &swig_roles[actions_offset..actions_offset + current_actions_size];

    // Parse existing actions and filter out the ones to remove
    while cursor < current_actions.len() {
        if cursor + Action::LEN > current_actions.len() {
            break;
        }

        let action_header =
            unsafe { Action::load_unchecked(&current_actions[cursor..cursor + Action::LEN])? };
        let action_len = action_header.length() as usize;
        let total_action_size = Action::LEN + action_len;

        if cursor + total_action_size > current_actions.len() && authority_to_update_id != 0 {
            return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
        }

        // Check if this action type should be removed
        let permission = action_header.permission()?;
        let action_discriminator = permission as u8;
        if action_discriminator == Permission::AuthorizationLock as u8 {
            let authorization_lock = unsafe {
                AuthorizationLock::load_unchecked(
                    &current_actions[cursor + Action::LEN..cursor + total_action_size],
                )?
            };

            let authlock_action =
                get_matching_args_action_by_mint(authlocks, authorization_lock.mint);
            if authlock_action.is_some() {
                // For update operation, we need to update the authlock data with the new data,
                // otherwise, we need to keep the existing authlock data for removal operation.
                if update_op {
                    let authlock = authlock_action.unwrap();

                    let action_data = Action::new(
                        Permission::AuthorizationLock,
                        authlock.into_bytes()?.len() as u16,
                        (cursor + Action::LEN + actions_offset + total_action_size) as u32,
                    );

                    filtered_actions.extend_from_slice(&action_data.into_bytes()?);
                    filtered_actions.extend_from_slice(&authlock.into_bytes()?);
                }
            } else {
                filtered_actions
                    .extend_from_slice(&current_actions[cursor..cursor + total_action_size]);
            }
        } else {
            filtered_actions
                .extend_from_slice(&current_actions[cursor..cursor + total_action_size]);
        }

        cursor += total_action_size;
    }

    // Ensure we don't remove all actions
    if filtered_actions.is_empty() && authority_to_update_id != 0 {
        return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
    }

    // Check if all the arg mints are updated or removed
    if !authlocks.is_empty() {
        return Err(SwigError::AuthLockNotExists.into());
    }

    // Use replace_all logic with filtered actions
    let size_diff = perform_replace_all_operation(
        swig_roles,
        swig_data_len,
        authority_offset,
        actions_offset,
        current_actions_size,
        &filtered_actions,
        authority_to_update_id,
    )?;
    Ok(size_diff)
}

/// Calculates the actual number of actions in the provided actions data.
///
/// This function iterates through the actions data and counts the number of
/// valid actions by parsing action headers and their boundaries.
///
/// # Arguments
/// * `actions_data` - Raw bytes containing action data
///
/// # Returns
/// * `Result<u8, ProgramError>` - The number of actions found, or error if
///   invalid data
pub fn calculate_num_actions(actions_data: &[u8]) -> Result<u8, ProgramError> {
    let mut cursor = 0;
    let mut count = 0u8;

    while cursor < actions_data.len() {
        if cursor + Action::LEN > actions_data.len() {
            break;
        }

        let action_header =
            unsafe { Action::load_unchecked(&actions_data[cursor..cursor + Action::LEN])? };
        cursor += Action::LEN;

        let action_len = action_header.length() as usize;
        if cursor + action_len > actions_data.len() {
            return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
        }

        cursor += action_len;
        count += 1;

        // Prevent overflow
        if count == u8::MAX {
            return Err(ProgramError::InvalidInstructionData);
        }
    }

    if count == 0 {
        return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
    }

    Ok(count)
}
