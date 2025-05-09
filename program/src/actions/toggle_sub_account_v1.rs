use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_assertions::*;
use swig_state_x::{
    action::{all::All, manage_authority::ManageAuthority, ActionLoader, Actionable},
    authority::AuthorityType,
    role::RoleMut,
    swig::{Swig, SwigSubAccount},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, ToggleSubAccountV1Accounts},
        SwigInstruction,
    },
};

/// Arguments for the ToggleSubAccountV1 instruction
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct ToggleSubAccountV1Args {
    discriminator: SwigInstruction,
    _padding: u8,
    pub enabled: bool,
    pub role_id: u32,
}

impl ToggleSubAccountV1Args {
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

/// Struct for parsing the ToggleSubAccountV1 instruction data
pub struct ToggleSubAccountV1<'a> {
    pub args: &'a ToggleSubAccountV1Args,
    pub authority_payload: &'a [u8],
    pub data_payload: &'a [u8],
}

impl<'a> ToggleSubAccountV1<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < ToggleSubAccountV1Args::LEN {
            return Err(SwigError::InvalidInstructionDataTooShort.into());
        }

        // Split the data into args and the rest (authority payload)
        let (args_data, rest) = data.split_at(ToggleSubAccountV1Args::LEN);

        let args = unsafe { ToggleSubAccountV1Args::load_unchecked(args_data)? };

        Ok(Self {
            args,
            authority_payload: rest,
            data_payload: args_data,
        })
    }
}

/// Implementation of the ToggleSubAccountV1 instruction handler
#[inline(always)]
pub fn toggle_sub_account_v1(
    ctx: Context<ToggleSubAccountV1Accounts>,
    data: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    // Check that the accounts are owned by our program
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_self_owned(ctx.accounts.sub_account, SwigError::OwnerMismatchSubAccount)?;

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

    // Check if the role has the required permissions
    let manage_authority_action = role.get_action::<ManageAuthority>(&[])?;
    let all_action = role.get_action::<All>(&[])?;

    if manage_authority_action.is_none() && all_action.is_none() {
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    }

    // Verify the sub-account data
    let sub_account_data = unsafe { ctx.accounts.sub_account.borrow_mut_data_unchecked() };
    if unsafe { *sub_account_data.get_unchecked(0) } != Discriminator::SwigSubAccount as u8 {
        return Err(SwigError::InvalidSwigSubAccountDiscriminator.into());
    }

    // Load the sub-account
    let mut sub_account = unsafe { SwigSubAccount::load_mut_unchecked(sub_account_data)? };

    // Check that the sub-account belongs to this swig account
    if sub_account.swig_id != swig.id {
        return Err(SwigError::InvalidSwigSubAccountSwigIdMismatch.into());
    }

    // Toggle the enabled state
    sub_account.enabled = toggle_sub_account.args.enabled;

    Ok(())
}
