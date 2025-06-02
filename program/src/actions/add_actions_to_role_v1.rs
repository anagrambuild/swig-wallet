/// Module for adding actions to an existing role in a Swig wallet.
/// This module implements the functionality to append additional actions to
/// a role's existing action set.
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
use swig_state_x::{
    action::{
        all::All, manage_authority::ManageAuthority,
        manage_authorization_lock::ManageAuthorizationLock, Action, ActionLoader, Permission,
    },
    role::Position,
    swig::{Swig, SwigBuilder},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{AddActionsToRoleV1Accounts, Context},
        SwigInstruction,
    },
};

/// Struct representing the complete add actions to role instruction data.
///
/// # Fields
/// * `args` - The add actions to role arguments
/// * `data_payload` - Raw data payload
/// * `authority_payload` - Authority-specific payload data
/// * `actions` - Actions data to be added
pub struct AddActionsToRoleV1<'a> {
    pub args: &'a AddActionsToRoleV1Args,
    data_payload: &'a [u8],
    authority_payload: &'a [u8],
    actions: &'a [u8],
}

/// Arguments for adding actions to an existing role in a Swig wallet.
///
/// # Fields
/// * `instruction` - The instruction type identifier
/// * `actions_data_len` - Length of the actions data
/// * `num_actions` - Number of actions to add
/// * `_padding` - Padding bytes for alignment
/// * `target_role_id` - ID of the role to add actions to
/// * `acting_role_id` - ID of the role performing the addition
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct AddActionsToRoleV1Args {
    pub instruction: SwigInstruction,
    pub actions_data_len: u16,
    pub num_actions: u8,
    _padding: [u8; 3],
    pub target_role_id: u32,
    pub acting_role_id: u32,
}

impl Transmutable for AddActionsToRoleV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl AddActionsToRoleV1Args {
    /// Creates a new instance of AddActionsToRoleV1Args.
    ///
    /// # Arguments
    /// * `acting_role_id` - ID of the role performing the addition
    /// * `target_role_id` - ID of the role to add actions to
    /// * `actions_data_len` - Length of the actions data
    /// * `num_actions` - Number of actions to add
    pub fn new(
        acting_role_id: u32,
        target_role_id: u32,
        actions_data_len: u16,
        num_actions: u8,
    ) -> Self {
        Self {
            instruction: SwigInstruction::AddActionsToRoleV1,
            actions_data_len,
            num_actions,
            _padding: [0; 3],
            target_role_id,
            acting_role_id,
        }
    }
}

impl IntoBytes for AddActionsToRoleV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> AddActionsToRoleV1<'a> {
    /// Parses the instruction data bytes into an AddActionsToRoleV1 instance.
    ///
    /// # Arguments
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < AddActionsToRoleV1Args::LEN {
            return Err(SwigError::InvalidSwigAddActionsToRoleInstructionDataTooShort.into());
        }

        let (inst, rest) = data.split_at(AddActionsToRoleV1Args::LEN);
        let args = unsafe { AddActionsToRoleV1Args::load_unchecked(inst)? };
        let (actions_payload, authority_payload) = rest.split_at(args.actions_data_len as usize);

        Ok(Self {
            args,
            authority_payload,
            actions: actions_payload,
            data_payload: &data[..AddActionsToRoleV1Args::LEN + args.actions_data_len as usize],
        })
    }
}

/// Adds actions to an existing role in a Swig wallet.
///
/// This function handles the complete flow of adding actions to a role:
/// 1. Validates the acting role's permissions
/// 2. Authenticates the request
/// 3. Finds the target role
/// 4. Allocates space for the new actions
/// 5. Appends the actions to the role's existing action set
///
/// # Arguments
/// * `ctx` - The account context for adding actions to role
/// * `add` - Raw add actions to role instruction data
/// * `all_accounts` - All accounts involved in the operation
///
/// # Returns
/// * `ProgramResult` - Success or error status
pub fn add_actions_to_role_v1(
    ctx: Context<AddActionsToRoleV1Accounts>,
    add: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_bytes_match(
        ctx.accounts.system_program.key(),
        &pinocchio_system::ID,
        32,
        SwigError::InvalidSystemProgram,
    )?;

    let add_actions_to_role_v1 = AddActionsToRoleV1::from_instruction_bytes(add).map_err(|e| {
        msg!("AddActionsToRoleV1 Args Error: {:?}", e);
        ProgramError::InvalidInstructionData
    })?;

    if add_actions_to_role_v1.args.num_actions == 0 {
        return Err(SwigError::InvalidAuthorityMustHaveAtLeastOneAction.into());
    }

    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let swig_data_len = swig_account_data.len();

    // Find and validate the target role, calculate space needed
    let (new_reserved_lamports, target_role_boundary, target_role_offset) = {
        if swig_account_data[0] != Discriminator::SwigAccount as u8 {
            return Err(SwigError::InvalidSwigAccountDiscriminator.into());
        }

        let (swig_header, swig_roles) =
            unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
        let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };

        // Find the acting role
        let acting_role =
            Swig::get_mut_role(add_actions_to_role_v1.args.acting_role_id, swig_roles)?;
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
                add_actions_to_role_v1.authority_payload,
                add_actions_to_role_v1.data_payload,
                slot,
            )?;
        } else {
            acting_role.authority.authenticate(
                all_accounts,
                add_actions_to_role_v1.authority_payload,
                add_actions_to_role_v1.data_payload,
                slot,
            )?;
        }

        // Check permissions
        let all = acting_role.get_action::<All>(&[])?;
        let manage_authority = acting_role.get_action::<ManageAuthority>(&[])?;

        if all.is_none() && manage_authority.is_none() {
            return Err(SwigAuthenticateError::PermissionDeniedToManageAuthority.into());
        }

        // Check if any actions being added are AuthorizationLock and verify permission
        let mut action_cursor = 0;
        for _i in 0..add_actions_to_role_v1.args.num_actions {
            let header =
                &add_actions_to_role_v1.actions[action_cursor..action_cursor + Action::LEN];
            let action_header = unsafe { Action::load_unchecked(header)? };

            if action_header.permission()? == Permission::AuthorizationLock {
                let manage_auth_lock = acting_role.get_action::<ManageAuthorizationLock>(&[])?;
                if all.is_none() && manage_auth_lock.is_none() {
                    return Err(SwigAuthenticateError::PermissionDeniedToManageAuthority.into());
                }
            }

            action_cursor += Action::LEN + action_header.length() as usize;
        }

        // Find the target role
        let mut cursor = 0;
        let mut target_found = false;
        let mut target_role_offset = 0;
        let mut target_role_boundary = 0;

        for _i in 0..swig.roles {
            let position =
                unsafe { Position::load_unchecked(&swig_roles[cursor..cursor + Position::LEN])? };

            if position.id() == add_actions_to_role_v1.args.target_role_id {
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

        // Calculate new account size
        let additional_size = add_actions_to_role_v1.actions.len();
        let account_size = core::alloc::Layout::from_size_align(
            swig_data_len + additional_size,
            core::mem::size_of::<u64>(),
        )
        .map_err(|_| SwigError::InvalidAlignment)?
        .pad_to_align()
        .size();

        ctx.accounts.swig.realloc(account_size, false)?;

        let cost = Rent::get()?
            .minimum_balance(account_size)
            .checked_sub(swig.reserved_lamports)
            .unwrap_or_default();

        if cost > 0 {
            Transfer {
                from: ctx.accounts.payer,
                to: ctx.accounts.swig,
                lamports: cost,
            }
            .invoke()?;
        }

        (
            swig.reserved_lamports + cost,
            target_role_boundary,
            target_role_offset,
        )
    };

    // Now modify the account data
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let mut swig_builder = SwigBuilder::new_from_bytes(swig_account_data)?;
    swig_builder.swig.reserved_lamports = new_reserved_lamports;

    // Calculate the new data size and shift existing data
    let additional_size = add_actions_to_role_v1.actions.len();
    let shift_from = target_role_boundary;
    let shift_to = target_role_boundary + additional_size;

    // Calculate how much data we have after the target role
    let old_role_buffer_len = swig_data_len - Swig::LEN;
    let data_to_shift = old_role_buffer_len.saturating_sub(shift_from);

    if data_to_shift > 0 && shift_from < old_role_buffer_len {
        // Shift data to make room for new actions
        swig_builder
            .role_buffer
            .copy_within(shift_from..shift_from + data_to_shift, shift_to);
    }

    // Update all role boundaries that come after the target role
    let mut cursor = 0;
    for i in 0..swig_builder.swig.roles {
        let position = unsafe {
            Position::load_mut_unchecked(
                &mut swig_builder.role_buffer[cursor..cursor + Position::LEN],
            )?
        };

        let old_boundary = position.boundary as usize;

        if cursor == target_role_offset {
            // This is the target role, update its num_actions and boundary
            position.num_actions += add_actions_to_role_v1.args.num_actions as u16;
            position.boundary += additional_size as u32;
        } else if cursor > target_role_offset {
            // This role comes after the target, update its boundary
            position.boundary += additional_size as u32;
        }

        // Move to next role using the original boundary
        cursor = if old_boundary <= target_role_boundary {
            old_boundary
        } else {
            old_boundary + additional_size
        };
    }

    // Add the new actions to the target role
    let mut action_cursor = 0;
    let mut insert_cursor = target_role_boundary;

    for _i in 0..add_actions_to_role_v1.args.num_actions {
        let header = &add_actions_to_role_v1.actions[action_cursor..action_cursor + Action::LEN];
        let action_header = unsafe { Action::load_unchecked(header)? };
        action_cursor += Action::LEN;

        let action_slice = &add_actions_to_role_v1.actions
            [action_cursor..action_cursor + action_header.length() as usize];
        action_cursor += action_header.length() as usize;

        if ActionLoader::validate_layout(action_header.permission()?, action_slice)? {
            // Copy action header
            swig_builder.role_buffer[insert_cursor..insert_cursor + Action::LEN]
                .copy_from_slice(header);

            // Fix boundary: position where next action starts within actions buffer
            // This should match the pattern used in add_role method
            let actions_start = target_role_offset
                + Position::LEN
                + unsafe {
                    Position::load_unchecked(
                        &swig_builder.role_buffer
                            [target_role_offset..target_role_offset + Position::LEN],
                    )?
                    .authority_length() as usize
                };
            let current_action_pos_in_actions = insert_cursor - actions_start;
            let next_action_pos_in_actions =
                current_action_pos_in_actions + Action::LEN + action_header.length() as usize;
            swig_builder.role_buffer[insert_cursor + 4..insert_cursor + 8]
                .copy_from_slice(&(next_action_pos_in_actions as u32).to_le_bytes());

            insert_cursor += Action::LEN;

            // Copy action data
            swig_builder.role_buffer
                [insert_cursor..insert_cursor + action_header.length() as usize]
                .copy_from_slice(action_slice);
            insert_cursor += action_header.length() as usize;
        } else {
            return Err(ProgramError::InvalidAccountData);
        }
    }

    Ok(())
}
