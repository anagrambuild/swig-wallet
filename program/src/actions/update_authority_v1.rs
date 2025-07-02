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

/// Struct representing the complete update authority instruction data.
///
/// # Fields
/// * `args` - The update authority arguments
/// * `data_payload` - Raw data payload
/// * `authority_payload` - Authority-specific payload data
/// * `actions` - Actions data for the authority update
pub struct UpdateAuthorityV1<'a> {
    pub args: &'a UpdateAuthorityV1Args,
    data_payload: &'a [u8],
    authority_payload: &'a [u8],
    actions: &'a [u8],
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
            actions: actions_payload,
            authority_payload,
            data_payload: &data[..UpdateAuthorityV1Args::LEN + args.actions_data_len as usize],
        })
    }
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

    // Cannot update root authority (ID 0)
    if update_authority_v1.args.authority_to_update_id == 0 {
        return Err(SwigAuthenticateError::PermissionDeniedCannotUpdateRootAuthority.into());
    }

    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let swig_data_len = swig_account_data.len();

    if swig_account_data[0] != Discriminator::SwigAccount as u8 {
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

    let new_actions_size = update_authority_v1.actions.len();
    let size_diff = new_actions_size as i64 - current_actions_size as i64;

    let new_reserved_lamports = if size_diff != 0 {
        let new_size = (swig_data_len as i64 + size_diff) as usize;
        let aligned_size =
            core::alloc::Layout::from_size_align(new_size, core::mem::size_of::<u64>())
                .map_err(|_| SwigError::InvalidAlignment)?
                .pad_to_align()
                .size();

        ctx.accounts.swig.realloc(aligned_size, false)?;

        let cost = Rent::get()?
            .minimum_balance(aligned_size)
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

        swig.reserved_lamports + cost
    } else {
        swig.reserved_lamports
    };

    // Update the authority with new actions in place
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
    swig.reserved_lamports = new_reserved_lamports;

    // Update the role's actions in place
    if size_diff != 0 {
        // Need to shift data if size changed
        let role_end = actions_offset + current_actions_size;
        // Calculate remaining data based on original data size, not new buffer size
        let original_data_len = (swig_data_len as i64 - Swig::LEN as i64) as usize;
        let remaining_data_len = original_data_len - role_end;

        if size_diff > 0 {
            // Growing: shift data to the right
            if remaining_data_len > 0 {
                let new_role_end = (role_end as i64 + size_diff) as usize;
                // Ensure we don't exceed buffer bounds
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
        for _i in 0..swig.roles {
            let position = unsafe {
                Position::load_mut_unchecked(&mut swig_roles[cursor..cursor + Position::LEN])?
            };

            if position.boundary() as usize > role_end {
                position.boundary = (position.boundary() as i64 + size_diff) as u32;
            }

            // Update the position for the role we're updating
            if position.id() == update_authority_v1.args.authority_to_update_id {
                position.boundary = (position.boundary() as i64 + size_diff) as u32;
                position.num_actions = calculate_num_actions(update_authority_v1.actions)? as u16;
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
        position.num_actions = calculate_num_actions(update_authority_v1.actions)? as u16;
    }

    // Copy the new actions data
    swig_roles[actions_offset..actions_offset + new_actions_size]
        .copy_from_slice(update_authority_v1.actions);

    Ok(())
}
