/// Module for updating existing authorities in a Swig wallet.
/// This module implements functionality to update authority roles by adding
/// or removing specific permissions while maintaining proper authentication.
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
        all::All, authlock::AuthorizationLock, manage_authlock::ManageAuthorizationLocks,
        manage_authority::ManageAuthority, Action, Permission,
    },
    authority::{authority_type_to_length, AuthorityType},
    role::{Position, Role, RoleMut},
    swig::{Swig, SwigBuilder},
    Discriminator, IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, ManageAuthLockV1Accounts},
        SwigInstruction,
    },
    util::authority_ops::*,
};

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
fn calculate_num_actions(actions_data: &[u8]) -> Result<u8, ProgramError> {
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

/// Struct representing the complete update authority instruction data.
///
/// # Fields
/// * `args` - The update authority arguments
/// * `data_payload` - Raw data payload
/// * `authority_payload` - Authority-specific payload data
/// * `operation_data` - Operation-specific data (actions, indices, etc.)
pub struct ManageAuthLockV1<'a> {
    pub args: &'a ManageAuthLockV1Args,
    data_payload: &'a [u8],
    authority_payload: &'a [u8],
    operation_data: &'a [u8],
}

/// Operation types for updating authorities.
///
/// Defines the different ways an authority can be updated:
/// - ReplaceAll: Replace all actions with new set (original behavior)
/// - AddActions: Add new actions to existing set
/// - RemoveActionsByType: Remove actions by their discriminator/type
/// - RemoveActionsByIndex: Remove actions by their position index
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ManageAuthLockOperation {
    AddAuthorizationLocks = 0,
    RemoveAuthorizationLocks = 1,
    ModifyAuthorizationLock = 2,
}

impl ManageAuthLockOperation {
    pub fn from_u8(value: u8) -> Result<Self, ProgramError> {
        match value {
            0 => Ok(Self::AddAuthorizationLocks),
            1 => Ok(Self::RemoveAuthorizationLocks),
            2 => Ok(Self::ModifyAuthorizationLock),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

/// Arguments for updating an existing authority in a Swig wallet.
///
/// # Fields
/// * `instruction` - The instruction type identifier
/// * `actions_data_len` - Length of the actions data
/// * `num_actions` - Number of actions for the authority update
/// * `_padding` - Padding bytes for alignment
/// * `acting_role_id` - ID of the role performing the update
/// * `authority_to_update_id` - ID of the authority to update
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct ManageAuthLockV1Args {
    pub instruction: SwigInstruction,
    pub actions_data_len: u16,
    pub num_actions: u8,
    pub operation: ManageAuthLockOperation,
    _padding: [u8; 2],
    pub acting_role_id: u32,
    pub authority_to_update_id: u32,
}

impl Transmutable for ManageAuthLockV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl ManageAuthLockV1Args {
    /// Creates a new instance of ManageAuthLockV1Args.
    ///
    /// # Arguments
    /// * `acting_role_id` - ID of the role performing the update
    /// * `authority_to_update_id` - ID of the authority to update
    /// * `num_actions` - Number of actions for the authority update
    pub fn new(
        acting_role_id: u32,
        authority_to_update_id: u32,
        actions_data_len: u16,
        num_actions: u8,
        operation: ManageAuthLockOperation,
    ) -> Self {
        Self {
            instruction: SwigInstruction::ManageAuthLockV1,
            actions_data_len,
            acting_role_id,
            authority_to_update_id,
            num_actions,
            operation,
            _padding: [0; 2],
        }
    }
}

impl IntoBytes for ManageAuthLockV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> ManageAuthLockV1<'a> {
    /// Parses the instruction data bytes into an ManageAuthLockV1 instance.
    ///
    /// # Arguments
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < ManageAuthLockV1Args::LEN {
            return Err(SwigError::InvalidSwigUpdateAuthorityInstructionDataTooShort.into());
        }

        let (inst, rest) = data.split_at(ManageAuthLockV1Args::LEN);
        let args = unsafe { ManageAuthLockV1Args::load_unchecked(inst)? };
        let (actions_payload, authority_payload) = rest.split_at(args.actions_data_len as usize);
        Ok(Self {
            args,
            operation_data: actions_payload,
            authority_payload,
            data_payload: &data[..ManageAuthLockV1Args::LEN + args.actions_data_len as usize],
        })
    }

    /// Gets the operation type for this instruction.
    pub fn get_operation(&self) -> Result<ManageAuthLockOperation, ProgramError> {
        Ok(self.args.operation)
    }

    /// Gets the operation data as actions for ReplaceAll and AddActions
    /// operations.
    pub fn get_actions_data(&self) -> Result<&[u8], ProgramError> {
        match self.get_operation()? {
            // All variants currently encode the operation in the first byte of
            // `operation_data`, followed by the raw action bytes. The args
            // struct also carries the operation enum, so we intentionally skip
            // the first byte here.
            ManageAuthLockOperation::AddAuthorizationLocks
            | ManageAuthLockOperation::RemoveAuthorizationLocks
            | ManageAuthLockOperation::ModifyAuthorizationLock => {
                if self.operation_data.is_empty() {
                    return Err(ProgramError::InvalidInstructionData);
                }
                Ok(&self.operation_data[1..])
            },
        }
    }

    /// Gets the operation data as action type discriminators for
    /// RemoveActionsByType.
    pub fn get_remove_mints(&self) -> Result<Vec<[u8; 32]>, ProgramError> {
        match self.get_operation()? {
            ManageAuthLockOperation::RemoveAuthorizationLocks => {
                if self.operation_data.len() <= 1 {
                    return Err(ProgramError::InvalidInstructionData);
                }

                // Skip the leading operation byte – the remaining bytes are a
                // contiguous list of 32-byte mints.
                let data = &self.operation_data[1..];
                let mut mints: Vec<[u8; 32]> = Vec::new();
                for chunk in data.chunks_exact(32) {
                    let mint = chunk
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?;
                    mints.push(mint);
                }
                Ok(mints)
            },
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }

    /// Get the changed mints from the operation data
    pub fn get_changed_mints(&self) -> Result<Vec<[u8; 32]>, ProgramError> {
        match self.get_operation()? {
            ManageAuthLockOperation::ModifyAuthorizationLock
            | ManageAuthLockOperation::AddAuthorizationLocks => {
                let auth_locks = self.get_auth_locks()?;
                let mints = auth_locks
                    .iter()
                    .map(|lock| lock.mint)
                    .collect::<Vec<[u8; 32]>>();
                Ok(mints)
            },
            ManageAuthLockOperation::RemoveAuthorizationLocks => {
                let remove_mints = self.get_remove_mints()?;
                Ok(remove_mints)
            },
        }
    }

    /// Gets the operation data as action indices for RemoveActionsByIndex.
    pub fn get_auth_locks(&self) -> Result<Vec<&AuthorizationLock>, ProgramError> {
        match self.get_operation()? {
            ManageAuthLockOperation::ModifyAuthorizationLock
            | ManageAuthLockOperation::AddAuthorizationLocks => {
                if self.operation_data.len() <= 1 {
                    return Err(ProgramError::InvalidInstructionData);
                }

                // Skip the leading operation byte – the remaining bytes are a
                // packed list of `AuthorizationLock` action payloads.
                let data = &self.operation_data[1..];
                let mut cursor = 0;
                let mut auth_locks: Vec<&AuthorizationLock> = Vec::new();

                while cursor < data.len() {
                    if cursor + Action::LEN > data.len() {
                        break;
                    }

                    let action_header =
                        unsafe { Action::load_unchecked(&data[cursor..cursor + Action::LEN])? };
                    let action_len = action_header.length() as usize;
                    let total_action_size = Action::LEN + action_len;

                    if action_header.permission()? == Permission::AuthorizationLock {
                        let auth_lock = unsafe {
                            AuthorizationLock::load_unchecked(
                                &data[cursor + Action::LEN
                                    ..cursor + Action::LEN + AuthorizationLock::LEN],
                            )?
                        };
                        auth_locks.push(auth_lock);
                    } else {
                        return Err(SwigError::ContainsNonAuthorizationLockAction.into());
                    }

                    cursor += total_action_size;
                }
                Ok(auth_locks)
            },
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

fn get_remove_indices_by_mints(
    mints: &Vec<[u8; 32]>,
    actions_data: &[u8],
) -> Result<Vec<u16>, ProgramError> {
    let mut remove_indices: Vec<u16> = Vec::new();

    let mut cursor = 0;
    Ok(remove_indices)
}

/// Performs a replace-all operation on an authority's actions.
fn perform_replace_all_operation(
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
                // Also add a condition in unwrap that will return 0 if authority_to_update_id is 0 and error is returned
                let num_actions = if authority_to_update_id == 0 {
                    calculate_num_actions(new_actions).unwrap_or(0) as u16
                } else {
                    calculate_num_actions(new_actions)? as u16
                };
                position.num_actions = num_actions;
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
        let num_actions = if authority_to_update_id == 0 {
            calculate_num_actions(new_actions).unwrap_or(0) as u16
        } else {
            calculate_num_actions(new_actions)? as u16
        };
        position.num_actions = num_actions;
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

        if action_cursor + total_action_size > new_actions.len() {
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
fn perform_add_actions_operation(
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
fn perform_remove_by_type_operation(
    swig_roles: &mut [u8],
    swig_data_len: usize,
    authority_offset: usize,
    actions_offset: usize,
    current_actions_size: usize,
    remove_types: &[u8],
    authority_to_update_id: u32,
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
        if !remove_types.contains(&action_discriminator) {
            // Keep this action
            filtered_actions
                .extend_from_slice(&current_actions[cursor..cursor + total_action_size]);
        }

        cursor += total_action_size;
    }

    // Ensure we don't remove all actions
    if filtered_actions.is_empty() && authority_to_update_id != 0 {
        return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
    }

    // Use replace_all logic with filtered actions
    perform_replace_all_operation(
        swig_roles,
        swig_data_len,
        authority_offset,
        actions_offset,
        current_actions_size,
        &filtered_actions,
        authority_to_update_id,
    )
}

/// Performs a remove-actions-by-index operation on an authority.
fn perform_remove_by_mints_operation(
    swig_roles: &mut [u8],
    swig_data_len: usize,
    authority_offset: usize,
    actions_offset: usize,
    current_actions_size: usize,
    remove_mints: &Vec<[u8; 32]>,
    authority_to_update_id: u32,
) -> Result<i64, ProgramError> {
    let mut filtered_actions = Vec::new();
    let mut cursor = 0;
    let mut action_index = 0u16;
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

        if action_header.permission()? == Permission::AuthorizationLock {
            let auth_lock = unsafe {
                AuthorizationLock::load_unchecked(
                    &current_actions
                        [cursor + Action::LEN..cursor + Action::LEN + AuthorizationLock::LEN],
                )?
            };

            // Check if this auth lock should be removed
            if !remove_mints.contains(&auth_lock.mint) {
                // Keep this action
                filtered_actions
                    .extend_from_slice(&current_actions[cursor..cursor + total_action_size]);
            } else {
            }
        } else {
            filtered_actions
                .extend_from_slice(&current_actions[cursor..cursor + total_action_size]);
        }

        cursor += total_action_size;
        action_index += 1;
    }

    // Ensure we don't remove all actions
    if filtered_actions.is_empty() && authority_to_update_id != 0 {
        return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
    }

    // Use replace_all logic with filtered actions
    perform_replace_all_operation(
        swig_roles,
        swig_data_len,
        authority_offset,
        actions_offset,
        current_actions_size,
        &filtered_actions,
        authority_to_update_id,
    )
}

/// Updates an existing authority in a Swig wallet.
///
/// This function handles the complete flow of updating an authority:
/// 1. Validates the acting role's permissions
/// 2. Authenticates the request
/// 3. Verifies the authority exists and can be updated
/// 4. Updates the authority's actions/permissions
/// 5. Handles account reallocation if needed
///
/// # Arguments
/// * `ctx` - The account context for updating authority
/// * `update` - Raw update authority instruction data
/// * `all_accounts` - All accounts involved in the operation
///
/// # Returns
/// * `ProgramResult` - Success or error status
pub fn manage_auth_lock_v1(
    ctx: Context<ManageAuthLockV1Accounts>,
    update: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_bytes_match(
        ctx.accounts.system_program.key(),
        &pinocchio_system::ID,
        32,
        SwigError::InvalidSystemProgram,
    )?;

    let update_authority_v1 = ManageAuthLockV1::from_instruction_bytes(update)
        .map_err(|e| ProgramError::InvalidInstructionData)?;

    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let swig_data_len = swig_account_data.len();

    if swig_account_data[0] != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };

    // Get and validate acting role
    let acting_role = Swig::get_mut_role(update_authority_v1.args.acting_role_id, swig_roles)?;
    if acting_role.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let acting_role = acting_role.unwrap();

    // Authenticate the caller
    let clock = Clock::get()?;
    let slot = clock.slot;

    if acting_role.authority.session_based() {
        acting_role.authority.authenticate_session(
            all_accounts,
            update_authority_v1.authority_payload,
            update_authority_v1.data_payload,
            slot,
        )?;
    } else {
        acting_role.authority.authenticate(
            all_accounts,
            update_authority_v1.authority_payload,
            update_authority_v1.data_payload,
            slot,
        )?;
    }

    // Check permissions - same as add/remove authority
    let all = acting_role.get_action::<All>(&[])?;
    let manage_authority = acting_role.get_action::<ManageAuthority>(&[])?;

    if all.is_none() && manage_authority.is_none() {
        return Err(SwigAuthenticateError::PermissionDeniedToManageAuthority.into());
    }

    // Verify the authority to update exists and calculate size difference
    let existing_authlocks: Option<Vec<AuthorizationLock>> = None;
    let (current_actions_size, authority_offset, actions_offset) = {
        let mut cursor = 0;
        let mut found = false;
        let mut auth_offset = 0;
        let mut act_offset = 0;
        let mut current_size = 0;

        for _i in 0..swig.roles {
            let position =
                unsafe { Position::load_unchecked(&swig_roles[cursor..cursor + Position::LEN])? };

            if position.id() == update_authority_v1.args.authority_to_update_id {
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

    let current_actions = &swig_roles[actions_offset..actions_offset + current_actions_size];

    let existing_authlocks = get_all_actions_of_type::<AuthorizationLock>(current_actions)?;

    let existing_manage_authlocks =
        get_all_actions_of_type::<ManageAuthorizationLocks>(current_actions)?;

    // Calculate size difference first
    let operation = update_authority_v1.get_operation()?;
    let size_diff = match operation {
        ManageAuthLockOperation::AddAuthorizationLocks => {
            // For add, we append new actions after the existing ones. The
            // on-chain layout stores only the raw action bytes (without the
            // leading operation discriminator), so size_diff should be computed
            // using the decoded actions slice.
            let new_actions = update_authority_v1.get_actions_data()?;
            new_actions.len() as i64 // Adding to existing, so just the new size
        },
        ManageAuthLockOperation::RemoveAuthorizationLocks => {
            // For remove operations, we need to calculate how much will be removed
            // This is complex, so for now we'll calculate it in the operation function
            0 // Will be calculated in the operation
        },
        ManageAuthLockOperation::ModifyAuthorizationLock => {
            // For remove operations, we need to calculate how much will be removed
            // This is complex, so for now we'll calculate it in the operation function
            0 // Will be calculated in the operation
        },
    };

    // Handle account reallocation if size changed (before operations)
    let new_reserved_lamports = if size_diff != 0 {
        let new_size = (swig_data_len as i64 + size_diff) as usize;
        let aligned_size =
            core::alloc::Layout::from_size_align(new_size, core::mem::size_of::<u64>())
                .map_err(|_| SwigError::InvalidAlignment)?
                .pad_to_align()
                .size();

        ctx.accounts.swig.realloc(aligned_size, false)?;

        let cost = Rent::get()?.minimum_balance(aligned_size);
        let current_lamports = unsafe { *ctx.accounts.swig.borrow_lamports_unchecked() };

        let additional_cost = cost.saturating_sub(current_lamports);

        if additional_cost > 0 {
            Transfer {
                from: ctx.accounts.payer,
                to: ctx.accounts.swig,
                lamports: additional_cost,
            }
            .invoke()?;
        }

        cost
    } else {
        // No size change, so no need to transfer additional funds
        0
    };

    // Get fresh references to the swig account data after reallocation
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let _swig = unsafe { Swig::load_mut_unchecked(swig_header)? };

    let mut size_diff = 0;
    // Now perform the operation with the reallocated account
    match operation {
        ManageAuthLockOperation::AddAuthorizationLocks => {
            let new_actions = update_authority_v1.get_actions_data()?;

            perform_add_actions_operation(
                swig_roles,
                swig_data_len,
                authority_offset,
                actions_offset,
                current_actions_size,
                new_actions,
                update_authority_v1.args.authority_to_update_id,
            )?;
        },
        ManageAuthLockOperation::RemoveAuthorizationLocks => {
            // exclude the existing auth locks from the new actions and pass it to the replace all operation
            let remove_mints = update_authority_v1.get_remove_mints()?;

            size_diff = perform_remove_by_mints_operation(
                swig_roles,
                swig_data_len,
                authority_offset,
                actions_offset,
                current_actions_size,
                &remove_mints,
                update_authority_v1.args.authority_to_update_id,
            )?;

            if size_diff != 0 {
                msg!("size_diff: {:?}", size_diff);
                let existing_swig_size = ctx.accounts.swig.data_len();
                let new_swig_size = existing_swig_size as i64 + size_diff as i64;
                let aligned_size = core::alloc::Layout::from_size_align(
                    new_swig_size as usize,
                    core::mem::size_of::<u64>(),
                )
                .map_err(|_| SwigError::InvalidAlignment)?
                .pad_to_align()
                .size();

                ctx.accounts.swig.resize(aligned_size)?;

                let cost = Rent::get()?.minimum_balance(aligned_size);
                let current_lamports = unsafe { *ctx.accounts.swig.borrow_lamports_unchecked() };

                let additional_cost = current_lamports.saturating_sub(cost);

                if additional_cost > 0 {
                    unsafe {
                        *ctx.accounts.swig.borrow_mut_lamports_unchecked() -= additional_cost;
                        *ctx.accounts.payer.borrow_mut_lamports_unchecked() += additional_cost;
                    }
                }
            }
        },
        ManageAuthLockOperation::ModifyAuthorizationLock => {
            let modify_auth_locks = update_authority_v1.get_auth_locks()?;

            let mut modify_role =
                Swig::get_mut_role(update_authority_v1.args.authority_to_update_id, swig_roles)?;
            if modify_role.is_none() {
                return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
            }
            let modify_role = modify_role.unwrap();
            let mut actions = modify_role.actions;

            for auth_lock in modify_auth_locks {
                if let Some(action) =
                    RoleMut::get_action_mut::<AuthorizationLock>(actions, &auth_lock.mint)?
                {
                    action.update(auth_lock.amount, auth_lock.expires_at);
                } else {
                    return Err(SwigError::InvalidAuthorizationLockNotFound.into());
                }
            }
        },
    }

    /// CACHE UPDATE AND EXPIRED AUTH HANDLING MODULE
    {
        let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
        let (swig_header, swig_roles) =
            unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };

        let current_slot = Clock::get()?.slot;
        let (cache_auth_locks, expired_auth_locks) = get_cache_data(
            swig_roles,
            update_authority_v1.get_changed_mints()?,
            current_slot,
        )?;
        msg!("expired_auth_locks: {:?}", expired_auth_locks);
        msg!("cache_auth_locks: {:?}", cache_auth_locks);

        // collect all the mints that are expired for each position
        let mut cache_role = Swig::get_mut_role(0, swig_roles)?;
        if cache_role.is_none() {
            return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
        }
        let cache_role = cache_role.unwrap();
        let mut actions = cache_role.actions;

        for (position_id, expired_mints) in expired_auth_locks {
            // Remove the actions for the expired mints for each Role
            todo!("Remove actions logic here");
        }

        for auth_lock in cache_auth_locks {
            if let Some(action) =
                RoleMut::get_action_mut::<AuthorizationLock>(actions, &auth_lock.mint)?
            {
                // Update the cache lock with new cache_auth_locks
                action.update(auth_lock.amount, auth_lock.expires_at);
            } else {
                todo!("Add logic here");
            }
        }
    }
    Ok(())
}

pub fn get_cache_data(
    roles: &[u8],
    mints: Vec<[u8; 32]>,
    current_slot: u64,
) -> Result<(Vec<AuthorizationLock>, Vec<(u32, Vec<[u8; 32]>)>), ProgramError> {
    // create a authlock vector that corresponds to the mints
    let mut cache_auth_locks = Vec::new();
    for mint in mints {
        let auth_lock = AuthorizationLock::new(mint, 0, u64::MAX);
        cache_auth_locks.push(auth_lock);
    }
    let mut expired_auth_locks = Vec::new();

    // Iterate through the role_data and update the auth lock for each which is there in the mint.
    let mut cursor = 0;

    while cursor < roles.len() {
        if cursor + Position::LEN > roles.len() {
            break;
        }

        let position = unsafe {
            Position::load_unchecked(roles.get_unchecked(cursor..cursor + Position::LEN))?
        };

        let mut actions_offset = cursor + Position::LEN + position.authority_length() as usize;

        let actions_data = unsafe {
            roles.get_unchecked(
                actions_offset..actions_offset + position.num_actions as usize * Action::LEN,
            )
        };
        msg!("position: {:?}", position);

        let mut expired_mints = Vec::new();
        let mut actions_cursor = 0;
        for _i in 0..position.num_actions as usize {
            let action = unsafe {
                Action::load_unchecked(
                    actions_data.get_unchecked(actions_cursor..actions_cursor + Action::LEN),
                )?
            };
            if action.permission()? == Permission::AuthorizationLock {
                let auth_lock = unsafe {
                    AuthorizationLock::load_unchecked(actions_data.get_unchecked(
                        actions_cursor + Action::LEN
                            ..actions_cursor + Action::LEN + AuthorizationLock::LEN,
                    ))?
                };
                // call the auth_lock.update_cache with the corresponding cache_auth_locks where the mint is the auth_lock.mint
                if let Some(cache_lock) = cache_auth_locks
                    .iter_mut()
                    .find(|lock| lock.mint == auth_lock.mint)
                {
                    if !auth_lock.update_cache(cache_lock, current_slot) {
                        expired_mints.push(auth_lock.mint);
                    }
                }
            }
            actions_cursor = action.boundary() as usize;
        }

        if !expired_mints.is_empty() {
            expired_auth_locks.push((position.id(), expired_mints));
        }

        cursor = position.boundary() as usize;
    }

    Ok((cache_auth_locks, expired_auth_locks))
}
