/// Module for enabling and disabling sub-accounts in a Swig wallet.
/// This module implements functionality to toggle the active state of
/// sub-accounts, allowing authorized roles to control sub-account access.
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_assertions::*;
use swig_state::{
    action::{all::All, sub_account::SubAccount, ActionLoader, Actionable},
    authority::AuthorityType,
    role::RoleMut,
    swig::Swig,
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, ToggleSubAccountV1Accounts},
        SwigInstruction,
    },
};

/// Arguments for toggling a sub-account's enabled state.
///
/// # Fields
/// * `discriminator` - The instruction type identifier
/// * `_padding` - Padding byte for alignment
/// * `enabled` - The desired enabled state (true/false)
/// * `role_id` - ID of the role performing the toggle
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct ToggleSubAccountV1Args {
    discriminator: SwigInstruction,
    _padding: u8,
    pub enabled: bool,
    pub role_id: u32,
}

impl ToggleSubAccountV1Args {
    /// Creates a new instance of ToggleSubAccountV1Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the role performing the toggle
    /// * `enabled` - The desired enabled state
    pub fn new(role_id: u32, enabled: bool) -> Self {
        Self {
            discriminator: SwigInstruction::ToggleSubAccountV1,
            _padding: 0,
            role_id,
            enabled,
        }
    }
}

impl Transmutable for ToggleSubAccountV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for ToggleSubAccountV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Struct representing the complete toggle sub-account instruction data.
///
/// # Fields
/// * `args` - The toggle arguments
/// * `authority_payload` - Authority-specific payload data
/// * `data_payload` - Raw instruction data payload
pub struct ToggleSubAccountV1<'a> {
    pub args: &'a ToggleSubAccountV1Args,
    pub authority_payload: &'a [u8],
    pub data_payload: &'a [u8],
}

impl<'a> ToggleSubAccountV1<'a> {
    /// Parses the instruction data bytes into a ToggleSubAccountV1 instance.
    ///
    /// # Arguments
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < ToggleSubAccountV1Args::LEN {
            return Err(SwigError::InvalidInstructionDataTooShort.into());
        }

        // Split the data into args and the rest (authority payload)
        let (args_data, authority_payload) = data.split_at(ToggleSubAccountV1Args::LEN);

        let args = unsafe { ToggleSubAccountV1Args::load_unchecked(args_data)? };

        Ok(Self {
            args,
            authority_payload,
            data_payload: args_data,
        })
    }
}

/// Enables or disables a sub-account in a Swig wallet.
///
/// This function handles the complete flow of toggling a sub-account:
/// 1. Validates the parent wallet and sub-account relationship
/// 2. Authenticates the authority
/// 3. Verifies proper permissions (All or ManageAuthority)
/// 4. Updates the sub-account's enabled state
///
/// # Arguments
/// * `ctx` - The account context for toggling
/// * `data` - Raw toggle instruction data
/// * `all_accounts` - All accounts involved in the operation
///
/// # Returns
/// * `ProgramResult` - Success or error status
#[inline(always)]
pub fn toggle_sub_account_v1(
    ctx: Context<ToggleSubAccountV1Accounts>,
    data: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    msg!("toggle_sub_account_v1 called");
    // Check that the swig account is owned by our program
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    // Check that the sub_account is system owned (it holds assets)
    check_system_owner(ctx.accounts.sub_account, SwigError::OwnerMismatchSubAccount)?;
    // Parse the instruction data
    let toggle_sub_account = ToggleSubAccountV1::from_instruction_bytes(data)?;

    // Verify the swig account data
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    // Split the swig account data to get the header and roles
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_unchecked(swig_header)? };

    // Get the role using the role_id from the instruction
    let role_opt = Swig::get_mut_role(toggle_sub_account.args.role_id, swig_roles)?;
    if role_opt.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let role = role_opt.unwrap();

    // Authenticate the authority
    let clock = Clock::get()?;
    let slot = clock.slot;

    // Authenticate based on authority type (session-based or not)
    if role.authority.session_based() {
        role.authority.authenticate_session(
            all_accounts,
            toggle_sub_account.authority_payload,
            toggle_sub_account.data_payload,
            slot,
        )?;
    } else {
        role.authority.authenticate(
            all_accounts,
            toggle_sub_account.authority_payload,
            toggle_sub_account.data_payload,
            slot,
        )?;
    }

    // Get mutable reference to the SubAccount action to check permissions and update state
    let sub_account_action_mut = RoleMut::get_action_mut::<SubAccount>(
        role.actions,
        ctx.accounts.sub_account.key().as_ref(),
    )?;

    if let Some(action) = sub_account_action_mut {
        // Check that the provided sub-account matches the one stored in the action
        if action.sub_account != ctx.accounts.sub_account.key().as_ref() {
            return Err(SwigError::InvalidSwigSubAccountSwigIdMismatch.into());
        }

        msg!(
            "Sub-account matches, updating enabled state from {} to: {}",
            action.enabled,
            toggle_sub_account.args.enabled
        );
        // Update the enabled state
        action.enabled = toggle_sub_account.args.enabled;
        msg!("Updated enabled state to: {}", action.enabled);
    } else {
        // Check if has All permission as fallback
        let has_all_permission = role.get_action::<All>(&[])?.is_some();
        if !has_all_permission {
            return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
        }
        // If has All permission but no SubAccount action, this is an error for toggle operation
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    }

    msg!("toggle_sub_account_v1 completed successfully");
    Ok(())
}
