/// Module for removing actions from an existing role in a Swig wallet.
/// This module implements the functionality to remove specific actions from
/// a role's action set by their indices.
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use swig_assertions::{check_bytes_match, check_self_owned};
use swig_state_x::{
    action::{all::All, manage_authority::ManageAuthority, Action},
    role::Position,
    swig::{Swig, SwigBuilder},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, RemoveActionsFromRoleV1Accounts},
        SwigInstruction,
    },
};

/// Struct representing the complete remove actions from role instruction data.
///
/// # Fields
/// * `args` - The remove actions from role arguments
/// * `data_payload` - Raw data payload
/// * `authority_payload` - Authority-specific payload data
/// * `action_indices` - Indices of actions to remove
pub struct RemoveActionsFromRoleV1<'a> {
    pub args: &'a RemoveActionsFromRoleV1Args,
    data_payload: &'a [u8],
    authority_payload: &'a [u8],
    action_indices: &'a [u8],
}

/// Arguments for removing actions from an existing role in a Swig wallet.
///
/// # Fields
/// * `instruction` - The instruction type identifier
/// * `indices_count` - Number of indices to remove
/// * `_padding` - Padding bytes for alignment
/// * `target_role_id` - ID of the role to remove actions from
/// * `acting_role_id` - ID of the role performing the removal
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct RemoveActionsFromRoleV1Args {
    pub instruction: SwigInstruction,
    pub indices_count: u16,
    _padding: [u8; 4],
    pub target_role_id: u32,
    pub acting_role_id: u32,
}

impl Transmutable for RemoveActionsFromRoleV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl RemoveActionsFromRoleV1Args {
    /// Creates a new instance of RemoveActionsFromRoleV1Args.
    ///
    /// # Arguments
    /// * `acting_role_id` - ID of the role performing the removal
    /// * `target_role_id` - ID of the role to remove actions from
    /// * `indices_count` - Number of indices to remove
    pub fn new(acting_role_id: u32, target_role_id: u32, indices_count: u16) -> Self {
        Self {
            instruction: SwigInstruction::RemoveActionsFromRoleV1,
            indices_count,
            _padding: [0; 4],
            target_role_id,
            acting_role_id,
        }
    }
}

impl IntoBytes for RemoveActionsFromRoleV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> RemoveActionsFromRoleV1<'a> {
    /// Parses the instruction data bytes into a RemoveActionsFromRoleV1
    /// instance.
    ///
    /// # Arguments
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < RemoveActionsFromRoleV1Args::LEN {
            return Err(SwigError::InvalidSwigRemoveActionsFromRoleInstructionDataTooShort.into());
        }

        let (inst, rest) = data.split_at(RemoveActionsFromRoleV1Args::LEN);
        let args = unsafe { RemoveActionsFromRoleV1Args::load_unchecked(inst)? };

        // Each index is a u16, so we need indices_count * 2 bytes
        let indices_len = args.indices_count as usize * 2;
        if rest.len() < indices_len {
            return Err(SwigError::InvalidSwigRemoveActionsFromRoleInstructionDataTooShort.into());
        }

        let (action_indices, authority_payload) = rest.split_at(indices_len);

        Ok(Self {
            args,
            authority_payload,
            action_indices,
            data_payload: &data[..RemoveActionsFromRoleV1Args::LEN + indices_len],
        })
    }

    /// Extracts the action indices from the raw bytes.
    ///
    /// # Returns
    /// * `Vec<u16>` - Vector of action indices
    pub fn get_indices(&self) -> Vec<u16> {
        let mut indices = Vec::with_capacity(self.args.indices_count as usize);
        for i in 0..self.args.indices_count as usize {
            let start = i * 2;
            let bytes = [self.action_indices[start], self.action_indices[start + 1]];
            indices.push(u16::from_le_bytes(bytes));
        }
        indices
    }
}

/// Removes actions from an existing role in a Swig wallet.
///
/// This function handles the complete flow of removing actions from a role:
/// 1. Validates the acting role's permissions
/// 2. Authenticates the request
/// 3. Finds the target role
/// 4. Validates the action indices
/// 5. Removes the specified actions
/// 6. Updates role boundaries and shrinks the account
///
/// # Arguments
/// * `ctx` - The account context for removing actions from role
/// * `remove` - Raw remove actions from role instruction data
/// * `all_accounts` - All accounts involved in the operation
///
/// # Returns
/// * `ProgramResult` - Success or error status
pub fn remove_actions_from_role_v1(
    ctx: Context<RemoveActionsFromRoleV1Accounts>,
    remove: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_bytes_match(
        ctx.accounts.system_program.key(),
        &pinocchio_system::ID,
        32,
        SwigError::InvalidSystemProgram,
    )?;

    let remove_actions_from_role_v1 = RemoveActionsFromRoleV1::from_instruction_bytes(remove)
        .map_err(|e| {
            msg!("RemoveActionsFromRoleV1 Args Error: {:?}", e);
            ProgramError::InvalidInstructionData
        })?;

    if remove_actions_from_role_v1.args.indices_count == 0 {
        return Err(SwigError::InvalidActionIndicesEmpty.into());
    }

    let mut indices = remove_actions_from_role_v1.get_indices();
    // Sort indices in descending order to avoid shifting issues when removing
    indices.sort_by(|a, b| b.cmp(a));

    // Check for duplicates
    for i in 1..indices.len() {
        if indices[i] == indices[i - 1] {
            return Err(SwigError::InvalidActionIndicesDuplicate.into());
        }
    }

    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let swig_data_len = swig_account_data.len();

    // Find and validate the target role
    let (target_role_offset, target_role_boundary, total_removal_size) = {
        if swig_account_data[0] != Discriminator::SwigAccount as u8 {
            return Err(SwigError::InvalidSwigAccountDiscriminator.into());
        }

        let (swig_header, swig_roles) =
            unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
        let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };

        // Find the acting role
        let acting_role =
            Swig::get_mut_role(remove_actions_from_role_v1.args.acting_role_id, swig_roles)?;
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
                remove_actions_from_role_v1.authority_payload,
                remove_actions_from_role_v1.data_payload,
                slot,
            )?;
        } else {
            acting_role.authority.authenticate(
                all_accounts,
                remove_actions_from_role_v1.authority_payload,
                remove_actions_from_role_v1.data_payload,
                slot,
            )?;
        }

        // Check permissions
        let all = acting_role.get_action::<All>(&[])?;
        let manage_authority = acting_role.get_action::<ManageAuthority>(&[])?;

        if all.is_none() && manage_authority.is_none() {
            return Err(SwigAuthenticateError::PermissionDeniedToManageAuthority.into());
        }

        // Find the target role
        let mut cursor = 0;
        let mut target_found = false;
        let mut target_role_offset = 0;
        let mut target_role_boundary = 0;

        for _i in 0..swig.roles {
            let position =
                unsafe { Position::load_unchecked(&swig_roles[cursor..cursor + Position::LEN])? };

            if position.id() == remove_actions_from_role_v1.args.target_role_id {
                target_found = true;
                target_role_offset = cursor;
                target_role_boundary = position.boundary() as usize;
                break;
            }

            cursor = position.boundary() as usize;
        }

        if !target_found {
            return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
        }

        // Get the target role to validate indices and calculate removal size
        let target_position = unsafe {
            Position::load_unchecked(
                &swig_roles[target_role_offset..target_role_offset + Position::LEN],
            )?
        };

        // Validate we're not removing all actions
        if indices.len() >= target_position.num_actions() as usize {
            return Err(SwigError::InvalidAuthorityMustHaveAtLeastOneAction.into());
        }

        // Parse actions to validate indices and calculate removal sizes
        let actions_start =
            target_role_offset + Position::LEN + target_position.authority_length() as usize;
        let actions_data = &swig_roles[actions_start..target_role_boundary];

        let mut action_cursor = 0;
        let mut action_index = 0;
        let mut total_removal_size = 0;

        while action_cursor < actions_data.len() {
            let action = unsafe {
                Action::load_unchecked(&actions_data[action_cursor..action_cursor + Action::LEN])?
            };

            // Check if this action index is in our removal list
            if indices.contains(&action_index) {
                let action_total_size = action.boundary() as usize - action_cursor;
                total_removal_size += action_total_size;
            }

            action_cursor = action.boundary() as usize;
            action_index += 1;
        }

        // Validate all indices were valid
        if indices.iter().any(|&idx| idx >= action_index) {
            return Err(SwigError::InvalidActionIndexOutOfBounds.into());
        }

        (target_role_offset, target_role_boundary, total_removal_size)
    };

    // Now modify the account data
    #[cfg(test)]
    println!("Starting account data modification phase");
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let mut swig_builder = SwigBuilder::new_from_bytes(swig_account_data)?;

    // Get the target position and actions data
    let (actions_start, actions_end, authority_length) = {
        let target_position = unsafe {
            Position::load_unchecked(
                &swig_builder.role_buffer[target_role_offset..target_role_offset + Position::LEN],
            )?
        };
        let actions_start =
            target_role_offset + Position::LEN + target_position.authority_length() as usize;
        let actions_end = target_position.boundary() as usize;
        let authority_length = target_position.authority_length() as usize;
        (actions_start, actions_end, authority_length)
    };

    // Parse all existing actions and keep only those NOT in the removal indices
    let mut kept_actions = Vec::new();
    let mut action_cursor = 0; // Relative to actions_start
    let mut action_index = 0;

    while actions_start + action_cursor < actions_end {
        let action = unsafe {
            Action::load_unchecked(
                &swig_builder.role_buffer
                    [actions_start + action_cursor..actions_start + action_cursor + Action::LEN],
            )?
        };

        let next_action_start = action.boundary() as usize;
        let action_size = next_action_start - action_cursor;

        // If this action should be kept (not removed)
        if !indices.contains(&action_index) {
            // Copy the complete action data (header + data)
            let action_data = swig_builder.role_buffer
                [actions_start + action_cursor..actions_start + action_cursor + action_size]
                .to_vec();
            kept_actions.push(action_data);
        }

        action_cursor = next_action_start;
        action_index += 1;
    }

    // Now rebuild the actions section from scratch
    let mut write_cursor = actions_start;
    let mut actions_size = 0;

    for (i, action_data) in kept_actions.iter().enumerate() {
        // Copy the action data
        let action_len = action_data.len();
        swig_builder.role_buffer[write_cursor..write_cursor + action_len]
            .copy_from_slice(action_data);

        // Update the boundary in the action header to be correct
        // Boundary is relative to actions_start
        let next_pos = write_cursor + action_len - actions_start;
        swig_builder.role_buffer[write_cursor + 4..write_cursor + 8]
            .copy_from_slice(&(next_pos as u32).to_le_bytes());

        write_cursor += action_len;
        actions_size += action_len;
    }

    // Update role position
    let position = unsafe {
        Position::load_mut_unchecked(
            &mut swig_builder.role_buffer[target_role_offset..target_role_offset + Position::LEN],
        )?
    };
    position.num_actions = kept_actions.len() as u16;
    position.boundary =
        (target_role_offset + Position::LEN + authority_length + actions_size) as u32;

    // Shift data after the role
    let old_actions_end = actions_end;
    let new_actions_end = actions_start + actions_size;
    let bytes_after = swig_builder.role_buffer.len() - old_actions_end;

    if bytes_after > 0 {
        swig_builder.role_buffer.copy_within(
            old_actions_end..old_actions_end + bytes_after,
            new_actions_end,
        );
    }

    // Update boundaries of roles that come after
    let shrinkage = old_actions_end - new_actions_end;
    let mut cursor = new_actions_end;
    while cursor < swig_builder.role_buffer.len() - shrinkage {
        if cursor + Position::LEN > swig_builder.role_buffer.len() - shrinkage {
            break;
        }

        let pos = unsafe {
            Position::load_mut_unchecked(
                &mut swig_builder.role_buffer[cursor..cursor + Position::LEN],
            )?
        };

        if cursor > target_role_offset {
            pos.boundary -= shrinkage as u32;
        }

        cursor = pos.boundary() as usize;
    }

    // Clear unused bytes
    let new_data_end = swig_builder.role_buffer.len() - shrinkage;
    swig_builder.role_buffer[new_data_end..].fill(0);

    // Use the total_removal_size calculated during validation
    let total_removed_bytes = total_removal_size;

    // Shrink the account
    let new_account_size = core::alloc::Layout::from_size_align(
        swig_data_len - total_removed_bytes,
        core::mem::size_of::<u64>(),
    )
    .map_err(|_| SwigError::InvalidAlignment)?
    .pad_to_align()
    .size();

    ctx.accounts.swig.realloc(new_account_size, false)?;

    // Update reserved lamports
    let new_reserved_lamports = Rent::get()?.minimum_balance(new_account_size);
    swig_builder.swig.reserved_lamports = new_reserved_lamports;

    Ok(())
}
