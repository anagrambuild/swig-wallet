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
    action::{all::All, manage_authority::ManageAuthority, Action, ActionLoader},
    authority::{authority_type_to_length, AuthorityType},
    role::Position,
    swig::Swig,
    tail::SavedTail,
    Discriminator, IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, UpdateAuthorityV1Accounts},
        SwigInstruction,
    },
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
            return Err(ProgramError::InvalidInstructionData);
        }

        let action_header =
            unsafe { Action::load_unchecked(&actions_data[cursor..cursor + Action::LEN])? };
        cursor += Action::LEN;

        let action_len = action_header.length() as usize;
        if cursor + action_len > actions_data.len() {
            return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
        }

        let action_data = &actions_data[cursor..cursor + action_len];
        if !ActionLoader::validate_layout(action_header.permission()?, action_data)? {
            return Err(ProgramError::InvalidInstructionData);
        }

        cursor += action_len;
        count = count
            .checked_add(1)
            .ok_or(ProgramError::InvalidInstructionData)?;
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
pub struct UpdateAuthorityV1<'a> {
    pub args: &'a UpdateAuthorityV1Args,
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
pub enum AuthorityUpdateOperation {
    ReplaceAll = 0,
    AddActions = 1,
    RemoveActionsByType = 2,
    RemoveActionsByIndex = 3,
}

impl AuthorityUpdateOperation {
    pub fn from_u8(value: u8) -> Result<Self, ProgramError> {
        match value {
            0 => Ok(Self::ReplaceAll),
            1 => Ok(Self::AddActions),
            2 => Ok(Self::RemoveActionsByType),
            3 => Ok(Self::RemoveActionsByIndex),
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
pub struct UpdateAuthorityV1Args {
    pub instruction: SwigInstruction,
    pub actions_data_len: u16,
    pub num_actions: u8,
    _padding: [u8; 3],
    pub acting_role_id: u32,
    pub authority_to_update_id: u32,
}

impl Transmutable for UpdateAuthorityV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl UpdateAuthorityV1Args {
    /// Creates a new instance of UpdateAuthorityV1Args.
    ///
    /// # Arguments
    /// * `acting_role_id` - ID of the role performing the update
    /// * `authority_to_update_id` - ID of the authority to update
    /// * `actions_data_len` - Length of the actions data
    /// * `num_actions` - Number of actions for the authority update
    pub fn new(
        acting_role_id: u32,
        authority_to_update_id: u32,
        actions_data_len: u16,
        num_actions: u8,
    ) -> Self {
        Self {
            instruction: SwigInstruction::UpdateAuthorityV1,
            acting_role_id,
            authority_to_update_id,
            actions_data_len,
            num_actions,
            _padding: [0; 3],
        }
    }
}

impl IntoBytes for UpdateAuthorityV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> UpdateAuthorityV1<'a> {
    /// Parses the instruction data bytes into an UpdateAuthorityV1 instance.
    ///
    /// # Arguments
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < UpdateAuthorityV1Args::LEN {
            return Err(SwigError::InvalidSwigUpdateAuthorityInstructionDataTooShort.into());
        }

        let (inst, rest) = data.split_at(UpdateAuthorityV1Args::LEN);
        let args = unsafe { UpdateAuthorityV1Args::load_unchecked(inst)? };
        let actions_data_len = args.actions_data_len as usize;
        let data_payload_len = UpdateAuthorityV1Args::LEN
            .checked_add(actions_data_len)
            .ok_or(SwigError::InvalidSwigUpdateAuthorityInstructionDataTooShort)?;
        if actions_data_len > rest.len() {
            return Err(SwigError::InvalidSwigUpdateAuthorityInstructionDataTooShort.into());
        }

        let (actions_payload, authority_payload) = rest.split_at(actions_data_len);

        Ok(Self {
            args,
            operation_data: actions_payload,
            authority_payload,
            data_payload: &data[..data_payload_len],
        })
    }

    /// Detects if this is a new format instruction (with operation type
    /// encoded).
    pub fn is_new_format(&self) -> bool {
        // New format has num_actions = 0 and first byte is operation type
        self.args.num_actions == 0 && !self.operation_data.is_empty()
    }

    /// Gets the operation type for this instruction.
    pub fn get_operation(&self) -> Result<AuthorityUpdateOperation, ProgramError> {
        if self.is_new_format() {
            // New format: operation type is encoded in first byte
            if self.operation_data.is_empty() {
                return Err(ProgramError::InvalidInstructionData);
            }
            AuthorityUpdateOperation::from_u8(self.operation_data[0])
        } else {
            // Old format: always ReplaceAll
            Ok(AuthorityUpdateOperation::ReplaceAll)
        }
    }

    /// Gets the operation data as actions for ReplaceAll and AddActions
    /// operations.
    pub fn get_actions_data(&self) -> Result<&[u8], ProgramError> {
        match self.get_operation()? {
            AuthorityUpdateOperation::ReplaceAll => {
                if self.is_new_format() {
                    // New format: skip first byte (operation type)
                    Ok(&self.operation_data[1..])
                } else {
                    // Old format: all data is actions
                    Ok(self.operation_data)
                }
            },
            AuthorityUpdateOperation::AddActions => {
                // New format only: skip first byte (operation type)
                Ok(&self.operation_data[1..])
            },
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }

    /// Gets the operation data as action type discriminators for
    /// RemoveActionsByType.
    pub fn get_remove_types(&self) -> Result<&[u8], ProgramError> {
        match self.get_operation()? {
            AuthorityUpdateOperation::RemoveActionsByType => {
                // New format only: skip first byte (operation type)
                Ok(&self.operation_data[1..])
            },
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }

    /// Gets the operation data as action indices for RemoveActionsByIndex.
    pub fn get_remove_indices(&self) -> Result<Vec<u16>, ProgramError> {
        match self.get_operation()? {
            AuthorityUpdateOperation::RemoveActionsByIndex => {
                // New format only: skip first byte (operation type)
                let data = &self.operation_data[1..];
                if data.len() % 2 != 0 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let mut indices = Vec::new();
                for chunk in data.chunks_exact(2) {
                    let index = u16::from_le_bytes([chunk[0], chunk[1]]);
                    indices.push(index);
                }
                Ok(indices)
            },
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

/// Performs a replace-all operation on an authority's actions.
fn perform_replace_all_operation(
    swig_roles: &mut [u8],
    current_roles_len: usize,
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
        let remaining_data_len = current_roles_len - role_end;

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
        let new_roles_len = (current_roles_len as i64 + size_diff) as usize;
        while cursor < new_roles_len {
            if cursor + Position::LEN > new_roles_len {
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
                position.num_actions = calculate_num_actions(new_actions)? as u16;
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
        position.num_actions = calculate_num_actions(new_actions)? as u16;
    }

    let final_roles_len = (current_roles_len as i64 + size_diff) as usize;
    if actions_offset + new_actions_size > final_roles_len {
        return Err(SwigError::StateError.into());
    }

    // Copy actions data and recalculate boundaries
    let mut cursor = actions_offset;
    let mut action_cursor = 0;

    while action_cursor < new_actions.len() {
        if action_cursor + Action::LEN > new_actions.len() {
            return Err(ProgramError::InvalidInstructionData);
        }

        let action_header = unsafe {
            Action::load_unchecked(&new_actions[action_cursor..action_cursor + Action::LEN])?
        };
        let action_len = action_header.length() as usize;
        let total_action_size = Action::LEN + action_len;

        if action_cursor + total_action_size > new_actions.len() {
            return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
        }

        let permission = action_header.permission()?;
        let action_data =
            &new_actions[action_cursor + Action::LEN..action_cursor + total_action_size];
        if !ActionLoader::validate_layout(permission, action_data)? {
            return Err(ProgramError::InvalidInstructionData);
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
    current_roles_len: usize,
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
        current_roles_len,
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
    current_roles_len: usize,
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
            return Err(ProgramError::InvalidInstructionData);
        }

        let action_header =
            unsafe { Action::load_unchecked(&current_actions[cursor..cursor + Action::LEN])? };
        let action_len = action_header.length() as usize;
        let total_action_size = Action::LEN + action_len;

        if cursor + total_action_size > current_actions.len() {
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
    if filtered_actions.is_empty() {
        return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
    }

    // Use replace_all logic with filtered actions
    perform_replace_all_operation(
        swig_roles,
        current_roles_len,
        authority_offset,
        actions_offset,
        current_actions_size,
        &filtered_actions,
        authority_to_update_id,
    )
}

/// Performs a remove-actions-by-index operation on an authority.
fn perform_remove_by_index_operation(
    swig_roles: &mut [u8],
    current_roles_len: usize,
    authority_offset: usize,
    actions_offset: usize,
    current_actions_size: usize,
    remove_indices: &[u16],
    authority_to_update_id: u32,
) -> Result<i64, ProgramError> {
    let mut filtered_actions = Vec::new();
    let mut cursor = 0;
    let mut action_index = 0u16;
    let current_actions = &swig_roles[actions_offset..actions_offset + current_actions_size];

    // Parse existing actions and filter out the ones to remove
    while cursor < current_actions.len() {
        if cursor + Action::LEN > current_actions.len() {
            return Err(ProgramError::InvalidInstructionData);
        }

        let action_header =
            unsafe { Action::load_unchecked(&current_actions[cursor..cursor + Action::LEN])? };
        let action_len = action_header.length() as usize;
        let total_action_size = Action::LEN + action_len;

        if cursor + total_action_size > current_actions.len() {
            return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
        }

        // Check if this action index should be removed
        if !remove_indices.contains(&action_index) {
            // Keep this action
            filtered_actions
                .extend_from_slice(&current_actions[cursor..cursor + total_action_size]);
        }

        cursor += total_action_size;
        action_index += 1;
    }

    // Ensure we don't remove all actions
    if filtered_actions.is_empty() {
        return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
    }

    // Use replace_all logic with filtered actions
    perform_replace_all_operation(
        swig_roles,
        current_roles_len,
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
pub fn update_authority_v1(
    ctx: Context<UpdateAuthorityV1Accounts>,
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

    let update_authority_v1 = UpdateAuthorityV1::from_instruction_bytes(update).map_err(|e| {
        msg!("UpdateAuthorityV1 Args Error: {:?}", e);
        ProgramError::InvalidInstructionData
    })?;

    let operation = update_authority_v1.get_operation()?;
    let mut account_len: usize;
    let (
        saved_tail,
        current_roles_len,
        current_actions_size,
        authority_offset,
        actions_offset,
        prealloc_size_diff,
    ) = {
        let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
        account_len = swig_account_data.len();
        if swig_account_data[0] != Discriminator::SwigConfigAccount as u8 {
            return Err(SwigError::InvalidSwigAccountDiscriminator.into());
        }

        let parts = Swig::split_parts_mut(swig_account_data)?;
        let saved_tail = SavedTail::take(parts.tail)?;
        let swig = parts.state;
        let swig_roles = parts.roles;
        let roles_len = swig_roles.len();

        // Get and validate acting role.
        let acting_role = Swig::get_mut_role(update_authority_v1.args.acting_role_id, swig_roles)?;
        if acting_role.is_none() {
            return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
        }
        let acting_role = acting_role.unwrap();

        // Authenticate the caller.
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

        // Check permissions - same as add/remove authority.
        let all = acting_role.get_action::<All>(&[])?;
        let manage_authority = acting_role.get_action::<ManageAuthority>(&[])?;
        if all.is_none() && manage_authority.is_none() {
            return Err(SwigAuthenticateError::PermissionDeniedToManageAuthority.into());
        }

        // Verify the authority to update exists and calculate offsets.
        let (current_actions_size, authority_offset, actions_offset) = {
            let mut cursor = 0usize;
            let mut found = false;
            let mut auth_offset = 0usize;
            let mut act_offset = 0usize;
            let mut current_size = 0usize;

            for _ in 0..swig.roles {
                if cursor + Position::LEN > roles_len {
                    return Err(ProgramError::InvalidAccountData);
                }
                let position = unsafe {
                    Position::load_unchecked(&swig_roles[cursor..cursor + Position::LEN])?
                };
                let boundary = position.boundary() as usize;
                if boundary < cursor + Position::LEN || boundary > roles_len {
                    return Err(ProgramError::InvalidAccountData);
                }

                if position.id() == update_authority_v1.args.authority_to_update_id {
                    found = true;
                    auth_offset = cursor;
                    act_offset = cursor + Position::LEN + position.authority_length() as usize;
                    current_size = boundary - act_offset;
                    break;
                }
                cursor = boundary;
            }

            if !found {
                return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
            }
            (current_size, auth_offset, act_offset)
        };

        let prealloc_size_diff = match operation {
            AuthorityUpdateOperation::ReplaceAll => {
                let new_actions = update_authority_v1.get_actions_data()?;
                new_actions.len() as i64 - current_actions_size as i64
            },
            AuthorityUpdateOperation::AddActions => {
                let new_actions = update_authority_v1.get_actions_data()?;
                new_actions.len() as i64 // Adding to existing, so just the new size
            },
            AuthorityUpdateOperation::RemoveActionsByType => {
                // For remove operations, we need to calculate how much will be removed
                // This is complex, so for now we'll calculate it in the operation function
                0 // Will be calculated in the operation
            },
            AuthorityUpdateOperation::RemoveActionsByIndex => {
                // For remove operations, we need to calculate how much will be removed
                // This is complex, so for now we'll calculate it in the operation function
                0 // Will be calculated in the operation
            },
        };

        (
            saved_tail,
            roles_len,
            current_actions_size,
            authority_offset,
            actions_offset,
            prealloc_size_diff,
        )
    };

    // Handle account reallocation if size changed (before operations)
    if prealloc_size_diff > 0 {
        let new_size = (account_len as i64 + prealloc_size_diff) as usize;
        let aligned_size =
            core::alloc::Layout::from_size_align(new_size, core::mem::size_of::<u64>())
                .map_err(|_| SwigError::InvalidAlignment)?
                .pad_to_align()
                .size();

        ctx.accounts.swig.realloc(aligned_size, false)?;
        account_len = aligned_size;

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
    }

    // Get fresh references to the swig account data after reallocation
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    saved_tail.restore(swig_account_data)?;
    let (_, swig_roles_and_tail) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let roles_capacity_len = swig_roles_and_tail
        .len()
        .checked_sub(saved_tail.len())
        .ok_or(ProgramError::InvalidAccountData)?;
    let (swig_roles, _) = unsafe { swig_roles_and_tail.split_at_mut_unchecked(roles_capacity_len) };

    // Now perform the operation with the reallocated account
    let size_diff = match operation {
        AuthorityUpdateOperation::ReplaceAll => {
            let new_actions = update_authority_v1.get_actions_data()?;
            perform_replace_all_operation(
                swig_roles,
                current_roles_len,
                authority_offset,
                actions_offset,
                current_actions_size,
                new_actions,
                update_authority_v1.args.authority_to_update_id,
            )?
        },
        AuthorityUpdateOperation::AddActions => {
            let new_actions = update_authority_v1.get_actions_data()?;
            perform_add_actions_operation(
                swig_roles,
                current_roles_len,
                authority_offset,
                actions_offset,
                current_actions_size,
                new_actions,
                update_authority_v1.args.authority_to_update_id,
            )?
        },
        AuthorityUpdateOperation::RemoveActionsByType => {
            let remove_types = update_authority_v1.get_remove_types()?;
            perform_remove_by_type_operation(
                swig_roles,
                current_roles_len,
                authority_offset,
                actions_offset,
                current_actions_size,
                remove_types,
                update_authority_v1.args.authority_to_update_id,
            )?
        },
        AuthorityUpdateOperation::RemoveActionsByIndex => {
            let remove_indices = update_authority_v1.get_remove_indices()?;
            perform_remove_by_index_operation(
                swig_roles,
                current_roles_len,
                authority_offset,
                actions_offset,
                current_actions_size,
                &remove_indices,
                update_authority_v1.args.authority_to_update_id,
            )?
        },
    };

    if size_diff < 0 {
        let new_size = (account_len as i64 + size_diff) as usize;
        let aligned_size =
            core::alloc::Layout::from_size_align(new_size, core::mem::size_of::<u64>())
                .map_err(|_| SwigError::InvalidAlignment)?
                .pad_to_align()
                .size();

        ctx.accounts.swig.resize(aligned_size)?;

        let cost = Rent::get()?.minimum_balance(aligned_size);
        let current_lamports = unsafe { *ctx.accounts.swig.borrow_lamports_unchecked() };

        let additional_cost = current_lamports.saturating_sub(cost);

        if additional_cost > 0 {
            unsafe {
                *ctx.accounts.swig.borrow_mut_lamports_unchecked() =
                    current_lamports - additional_cost;
                *ctx.accounts.payer.borrow_mut_lamports_unchecked() =
                    ctx.accounts.payer.lamports() + additional_cost;
            };
        }
    }
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let roles_end = Swig::roles_end_offset(swig_account_data)?;
    swig_account_data[roles_end..].fill(0);
    saved_tail.restore_at(swig_account_data, roles_end)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use swig_state::{
        action::{all::All, manage_authority::ManageAuthority, Action, Actionable},
        authority::{ed25519::ED25519Authority, AuthorityType},
        swig::{Swig, SwigBuilder},
        tail::{rent_claimer, SavedTail},
        IntoBytes, TransmutableMut,
    };

    #[test]
    fn from_instruction_bytes_rejects_short_actions_payload() {
        let args = UpdateAuthorityV1Args::new(0, 1, 8, 0);
        let mut data = args.into_bytes().unwrap().to_vec();
        data.extend_from_slice(&[1, 2]);

        assert!(matches!(
            UpdateAuthorityV1::from_instruction_bytes(&data),
            Err(ProgramError::Custom(code))
                if code == SwigError::InvalidSwigUpdateAuthorityInstructionDataTooShort as u32
        ));
    }

    #[test]
    fn perform_replace_all_growth_preserves_tail_region() -> Result<(), ProgramError> {
        let mut account_buffer = vec![0u8; Swig::LEN + 256];
        let swig = Swig::new([1u8; 32], 255, 0);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig)?;

        let authority = ED25519Authority {
            public_key: [2u8; 32],
        };
        let all_data = All {}.into_bytes()?;
        let all_header = Action::new(
            All::TYPE,
            all_data.len() as u16,
            Action::LEN as u32 + all_data.len() as u32,
        );
        let all_actions = [all_header.into_bytes()?, all_data].concat();
        builder.add_role(
            AuthorityType::Ed25519,
            authority.into_bytes()?,
            &all_actions,
        )?;
        drop(builder);

        let roles_end = Swig::roles_end_offset(&account_buffer)?;
        account_buffer.truncate(roles_end);
        let tail = rent_claimer::entry(&[77u8; 32]);
        account_buffer.extend_from_slice(&tail);
        let expected_tail = tail.to_vec();

        let saved_tail = {
            let (_, tail_slice) = Swig::split_roles_and_tail_mut(&mut account_buffer)?;
            SavedTail::take(tail_slice)?
        };

        let ma_data = ManageAuthority {}.into_bytes()?;
        let ma_header = Action::new(
            ManageAuthority::TYPE,
            ma_data.len() as u16,
            Action::LEN as u32 + ma_data.len() as u32,
        );
        let grown_actions = [all_actions.as_slice(), ma_header.into_bytes()?, ma_data].concat();
        let expected_diff = grown_actions.len() as i64 - all_actions.len() as i64;

        account_buffer.resize((account_buffer.len() as i64 + expected_diff) as usize, 0);
        saved_tail.restore(&mut account_buffer)?;

        let (roles_len, authority_offset, actions_offset, current_actions_size) = {
            let (roles, _) = Swig::split_roles_and_tail(&account_buffer)?;
            let position = unsafe { Position::load_unchecked(&roles[..Position::LEN])? };
            let authority_offset = 0usize;
            let actions_offset = Position::LEN + position.authority_length() as usize;
            let current_actions_size = position.boundary() as usize - actions_offset;
            (
                roles.len(),
                authority_offset,
                actions_offset,
                current_actions_size,
            )
        };

        {
            let (swig_header, roles_and_tail) = account_buffer.split_at_mut(Swig::LEN);
            let _swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
            let roles_capacity_len = roles_and_tail.len() - saved_tail.len();
            let (roles_capacity, _) = roles_and_tail.split_at_mut(roles_capacity_len);
            let applied = perform_replace_all_operation(
                roles_capacity,
                roles_len,
                authority_offset,
                actions_offset,
                current_actions_size,
                &grown_actions,
                0,
            )?;
            assert_eq!(applied, expected_diff);
        }

        saved_tail.restore(&mut account_buffer)?;
        let (_, tail_after) = Swig::split_roles_and_tail(&account_buffer)?;
        assert_eq!(tail_after, expected_tail.as_slice());
        Ok(())
    }
}
