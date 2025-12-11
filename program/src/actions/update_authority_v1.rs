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
    action::{all::All, manage_authority::ManageAuthority, Action},
    authority::{authority_type_to_length, AuthorityType},
    role::Position,
    swig::{Swig, SwigBuilder},
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

/// Validates that there are no duplicate SubAccount indices in the actions
/// data.
///
/// This prevents security issues where multiple actions could point to the same
/// sub-account index. Only performs validation if SubAccount actions are
/// present.
///
/// # Arguments
/// * `actions_data` - Raw bytes containing action data
///
/// # Returns
/// * `Result<(), ProgramError>` - Ok if no duplicates, error otherwise
fn validate_no_duplicate_sub_account_indices(actions_data: &[u8]) -> Result<(), ProgramError> {
    use swig_state::action::{sub_account::SubAccount, Permission};

    let mut cursor = 0;
    let mut seen_indices = Vec::new();
    let mut has_sub_account_actions = false;

    while cursor < actions_data.len() {
        if cursor + Action::LEN > actions_data.len() {
            break;
        }

        let action_header =
            unsafe { Action::load_unchecked(&actions_data[cursor..cursor + Action::LEN])? };
        cursor += Action::LEN;

        let action_len = action_header.length() as usize;
        if cursor + action_len > actions_data.len() {
            break;
        }

        // Check for duplicate SubAccount indices only if we have SubAccount actions
        if action_header.permission()? == Permission::SubAccount {
            has_sub_account_actions = true;
            if action_len == SubAccount::LEN {
                let sub_account_action = unsafe {
                    SubAccount::load_unchecked(&actions_data[cursor..cursor + action_len])?
                };
                let index = sub_account_action.sub_account_index;

                if seen_indices.contains(&index) {
                    return Err(SwigStateError::InvalidAuthorityData.into());
                }
                seen_indices.push(index);
            }
        }

        cursor += action_len;
    }

    Ok(())
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
        let (actions_payload, authority_payload) = rest.split_at(args.actions_data_len as usize);

        Ok(Self {
            args,
            operation_data: actions_payload,
            authority_payload,
            data_payload: &data[..UpdateAuthorityV1Args::LEN + args.actions_data_len as usize],
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
    swig_data_len: usize,
    authority_offset: usize,
    actions_offset: usize,
    current_actions_size: usize,
    new_actions: &[u8],
    authority_to_update_id: u32,
) -> Result<i64, ProgramError> {
    // Validate no duplicate SubAccount indices before processing
    validate_no_duplicate_sub_account_indices(new_actions)?;

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
        while cursor < (swig_roles.len() + size_diff as usize) {
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

    // Validate the combined actions for duplicate SubAccount indices
    // Note: perform_replace_all_operation will also validate, but we do it here
    // explicitly to catch issues with the combination of existing + new actions
    validate_no_duplicate_sub_account_indices(&combined_actions)?;

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
        swig_data_len,
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
    swig_data_len: usize,
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
            break;
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

    // Calculate size difference first
    let operation = update_authority_v1.get_operation()?;
    let size_diff = match operation {
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

    // Now perform the operation with the reallocated account
    match operation {
        AuthorityUpdateOperation::ReplaceAll => {
            let new_actions = update_authority_v1.get_actions_data()?;
            perform_replace_all_operation(
                swig_roles,
                swig_data_len,
                authority_offset,
                actions_offset,
                current_actions_size,
                new_actions,
                update_authority_v1.args.authority_to_update_id,
            )?;
        },
        AuthorityUpdateOperation::AddActions => {
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
        AuthorityUpdateOperation::RemoveActionsByType => {
            let remove_types = update_authority_v1.get_remove_types()?;
            perform_remove_by_type_operation(
                swig_roles,
                swig_data_len,
                authority_offset,
                actions_offset,
                current_actions_size,
                remove_types,
                update_authority_v1.args.authority_to_update_id,
            )?;
        },
        AuthorityUpdateOperation::RemoveActionsByIndex => {
            let remove_indices = update_authority_v1.get_remove_indices()?;
            perform_remove_by_index_operation(
                swig_roles,
                swig_data_len,
                authority_offset,
                actions_offset,
                current_actions_size,
                &remove_indices,
                update_authority_v1.args.authority_to_update_id,
            )?;
        },
    }

    Ok(())
}
