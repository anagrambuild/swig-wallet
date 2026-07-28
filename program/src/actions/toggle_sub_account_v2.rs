//! Module for toggling the enabled kill-switch on a V2 sub-account.
//!
//! Unlike V1 — where the enabled flag lives inside a role's `SubAccount` action
//! — a V2 sub-account's enabled flag lives on its program-owned state account.
//! Authorization is default-deny: the acting role must hold a scoped
//! `SubAccountV2Toggle { subacc_id }` or `SubAccountV2All { subacc_id }` action.
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_assertions::*;
use swig_state::{
    action::Permission,
    sub_account_v2::SubAccountV2,
    swig::{sub_account_v2_state_seeds_with_bump, Swig},
    Discriminator, IntoBytes, Transmutable, TransmutableMut,
};

use crate::{
    actions::sub_account_sign_v2::authorize_scoped_v2,
    error::SwigError,
    instruction::{
        accounts::{Context, ToggleSubAccountV2Accounts},
        SwigInstruction,
    },
};

/// Arguments for toggling a V2 sub-account.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct ToggleSubAccountV2Args {
    discriminator: SwigInstruction,
    /// Desired enabled state
    pub enabled: u8,
    _padding: u8,
    /// Role performing the toggle
    pub auth_role_id: u32,
    /// Sub-account being toggled
    pub subacc_id: u32,
    _padding2: u32,
}

impl ToggleSubAccountV2Args {
    pub fn new(auth_role_id: u32, subacc_id: u32, enabled: bool) -> Self {
        Self {
            discriminator: SwigInstruction::ToggleSubAccountV2,
            enabled: u8::from(enabled),
            _padding: 0,
            auth_role_id,
            subacc_id,
            _padding2: 0,
        }
    }
}

impl Transmutable for ToggleSubAccountV2Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for ToggleSubAccountV2Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Parsed toggle instruction.
pub struct ToggleSubAccountV2<'a> {
    pub args: &'a ToggleSubAccountV2Args,
    pub authority_payload: &'a [u8],
    pub data_payload: &'a [u8],
}

impl<'a> ToggleSubAccountV2<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < ToggleSubAccountV2Args::LEN {
            return Err(SwigError::InvalidInstructionDataTooShort.into());
        }
        let (args_data, authority_payload) = data.split_at(ToggleSubAccountV2Args::LEN);
        let args = unsafe { ToggleSubAccountV2Args::load_unchecked(args_data)? };
        if args.enabled > 1 {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(Self {
            args,
            authority_payload,
            data_payload: args_data,
        })
    }
}

/// Flips the enabled kill-switch on a V2 sub-account.
#[inline(always)]
pub fn toggle_sub_account_v2(
    ctx: Context<ToggleSubAccountV2Accounts>,
    data: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    // The V2 state account is program-owned.
    check_self_owned(
        ctx.accounts.sub_account_state,
        SwigError::OwnerMismatchSubAccountV2State,
    )?;

    let toggle = ToggleSubAccountV2::from_instruction_bytes(data)?;

    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }
    let parts = Swig::split_parts_mut(swig_account_data)?;
    let swig = parts.state;
    let swig_roles = parts.roles;

    // V2 requires the wallet-address (migrated) Swig generation.
    if swig.wallet_bump == 0 {
        return Err(SwigError::SignV2CannotBeUsedWithSwigV1.into());
    }
    let swig_id = swig.id;

    // Authenticate the acting role and require a scoped toggle permission.
    let role_opt = Swig::get_mut_role(toggle.args.auth_role_id, swig_roles)?;
    if role_opt.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let mut role = role_opt.unwrap();
    let clock = pinocchio::sysvars::clock::Clock::get()?;
    if role.authority.session_based() {
        role.authority.authenticate_session(
            all_accounts,
            toggle.authority_payload,
            toggle.data_payload,
            clock.slot,
        )?;
    } else {
        role.authority.authenticate(
            all_accounts,
            toggle.authority_payload,
            toggle.data_payload,
            clock.slot,
        )?;
    }

    // Scoped auth: SubAccountV2Toggle { id } or SubAccountV2All { id }.
    authorize_scoped_v2(&role, Permission::SubAccountV2Toggle, toggle.args.subacc_id)?;

    // Load and bind the state account, then flip enabled.
    let state_data = unsafe { ctx.accounts.sub_account_state.borrow_mut_data_unchecked() };
    let state = unsafe { SubAccountV2::load_mut_unchecked(state_data)? };
    state.check_discriminator()?;
    state.is_enabled()?;
    if state.swig_id != swig_id {
        return Err(SwigError::InvalidSwigSubAccountV2SwigIdMismatch.into());
    }
    if state.subacc_id != toggle.args.subacc_id {
        return Err(SwigError::InvalidSwigSubAccountV2IdMismatch.into());
    }
    // Bind the account to its canonical PDA address using the stored bump.
    let id_le = toggle.args.subacc_id.to_le_bytes();
    let bump = [state.bump];
    let seeds = sub_account_v2_state_seeds_with_bump(&swig_id, &id_le, &bump);
    check_self_pda(
        &seeds,
        ctx.accounts.sub_account_state.key(),
        SwigError::InvalidSeedSubAccountV2,
    )?;

    state.set_enabled(toggle.args.enabled == 1);
    Ok(())
}
