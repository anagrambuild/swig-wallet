//! Module for signing transactions as a V2 sub-account asset account.
//!
//! Authorization is default-deny and scoped: the acting role must hold a
//! `SubAccountV2Sign { subacc_id }` or `SubAccountV2All { subacc_id }` action.
//! Wallet-level `All` / `ManageAuthority` grant nothing here.
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_assertions::*;
use swig_compact_instructions::InstructionIterator;
use swig_state::{
    action::{Action, Permission},
    role::RoleMut,
    sub_account_v2::SubAccountV2,
    swig::{sub_account_v2_asset_signer, sub_account_v2_state_seeds_with_bump, Swig},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, SubAccountSignV2Accounts},
        SwigInstruction,
    },
    AccountClassification,
};

/// Authorizes a scoped V2 sub-account runtime operation.
///
/// Returns `Ok(())` if `role` holds a matching `specific` action for `subacc_id`
/// or a `SubAccountV2All` action for `subacc_id`. Wallet-level overrides are
/// intentionally not consulted — access is default-denied.
///
/// `specific` must be one of the scoped V2 runtime permissions
/// (`SubAccountV2Sign`/`Withdraw`/`Toggle`). All scoped V2 bodies carry
/// `subacc_id` as their first four little-endian bytes.
pub(crate) fn authorize_scoped_v2(
    role: &RoleMut<'_>,
    specific: Permission,
    subacc_id: u32,
) -> ProgramResult {
    let id_le = subacc_id.to_le_bytes();
    let actions = &*role.actions;
    let mut cursor = 0usize;
    while cursor + Action::LEN <= actions.len() {
        let header = unsafe { Action::load_unchecked(&actions[cursor..cursor + Action::LEN])? };
        let data_start = cursor + Action::LEN;
        let data_end = data_start
            .checked_add(header.length() as usize)
            .ok_or(SwigError::StateError)?;
        if data_end > actions.len() {
            return Err(SwigError::StateError.into());
        }
        let permission = header.permission()?;
        if (permission == specific || permission == Permission::SubAccountV2All)
            && header.length() as usize >= 4
            && actions[data_start..data_start + 4] == id_le
        {
            return Ok(());
        }
        cursor = data_end;
    }
    Err(SwigError::PermissionDeniedMissingSubAccountV2Permission.into())
}

/// Loads and validates a V2 sub-account state account against the parent swig
/// and the requested `subacc_id`, returning the cached `asset_bump`.
///
/// Verifies the account is the canonical state PDA (via the stored bump), has
/// the right discriminator, belongs to this swig, matches the id, is enabled,
/// and that `asset_account` is the state's recorded asset PDA.
pub(crate) fn validate_v2_state(
    state_account: &AccountInfo,
    asset_account: &AccountInfo,
    swig_id: &[u8; 32],
    subacc_id: u32,
) -> Result<u8, ProgramError> {
    check_self_owned(state_account, SwigError::OwnerMismatchSubAccountV2State)?;
    let state_data = unsafe { state_account.borrow_data_unchecked() };
    let state = unsafe { SubAccountV2::load_unchecked(state_data)? };
    state.check_discriminator()?;
    if &state.swig_id != swig_id {
        return Err(SwigError::InvalidSwigSubAccountV2SwigIdMismatch.into());
    }
    if state.subacc_id != subacc_id {
        return Err(SwigError::InvalidSwigSubAccountV2IdMismatch.into());
    }
    if !state.enabled {
        return Err(SwigError::InvalidSwigSubAccountV2Disabled.into());
    }
    // Bind the state account to its canonical PDA address.
    let id_le = subacc_id.to_le_bytes();
    let bump = [state.bump];
    let seeds = sub_account_v2_state_seeds_with_bump(swig_id, &id_le, &bump);
    check_self_pda(
        &seeds,
        state_account.key(),
        SwigError::InvalidSeedSubAccountV2,
    )?;
    // Bind the asset account to the state's recorded asset PDA.
    if &state.sub_account != asset_account.key().as_ref() {
        return Err(SwigError::InvalidSeedSubAccountV2.into());
    }
    Ok(state.asset_bump)
}

/// Arguments for signing a transaction with a V2 sub-account.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct SubAccountSignV2Args {
    instruction: SwigInstruction,
    pub instruction_payload_len: u16,
    pub role_id: u32,
    pub subacc_id: u32,
    _padding: [u8; 4],
}

impl SubAccountSignV2Args {
    pub fn new(role_id: u32, subacc_id: u32, instruction_payload_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::SubAccountSignV2,
            instruction_payload_len,
            role_id,
            subacc_id,
            _padding: [0; 4],
        }
    }
}

impl Transmutable for SubAccountSignV2Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for SubAccountSignV2Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Parsed sign instruction.
pub struct SubAccountSignV2<'a> {
    pub args: &'a SubAccountSignV2Args,
    authority_payload: &'a [u8],
    instruction_payload: &'a [u8],
}

impl<'a> SubAccountSignV2<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < SubAccountSignV2Args::LEN {
            return Err(SwigError::InvalidSwigSignInstructionDataTooShort.into());
        }
        let (inst, rest) = unsafe { data.split_at_unchecked(SubAccountSignV2Args::LEN) };
        let args = unsafe { SubAccountSignV2Args::load_unchecked(inst)? };
        let instruction_payload_len = args.instruction_payload_len as usize;
        if instruction_payload_len > rest.len() {
            return Err(SwigError::InvalidSwigSignInstructionDataTooShort.into());
        }
        let (instruction_payload, authority_payload) =
            unsafe { rest.split_at_unchecked(instruction_payload_len) };
        Ok(Self {
            args,
            authority_payload,
            instruction_payload,
        })
    }
}

/// Signs and executes a transaction as a V2 sub-account asset account.
#[inline(always)]
pub fn sub_account_sign_v2(
    ctx: Context<SubAccountSignV2Accounts>,
    all_accounts: &[AccountInfo],
    data: &[u8],
    _account_classifiers: &[AccountClassification],
) -> ProgramResult {
    check_stack_height(1, SwigError::Cpi)?;
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_system_owner(ctx.accounts.sub_account, SwigError::OwnerMismatchSubAccount)?;

    let sign = SubAccountSignV2::from_instruction_bytes(data)?;

    let swig_id = {
        let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
        if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigConfigAccount as u8
        {
            return Err(SwigError::InvalidSwigAccountDiscriminator.into());
        }
        let parts = Swig::split_parts_mut(swig_account_data)?;
        let swig = parts.state;
        let swig_roles = parts.roles;
        if swig.wallet_bump == 0 {
            return Err(SwigError::SignV2CannotBeUsedWithSwigV1.into());
        }
        let swig_id = swig.id;

        let role_opt = Swig::get_mut_role(sign.args.role_id, swig_roles)?;
        if role_opt.is_none() {
            return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
        }
        let role = role_opt.unwrap();
        let clock = Clock::get()?;
        if role.authority.session_based() {
            role.authority.authenticate_session(
                all_accounts,
                sign.authority_payload,
                sign.instruction_payload,
                clock.slot,
            )?;
        } else {
            role.authority.authenticate(
                all_accounts,
                sign.authority_payload,
                sign.instruction_payload,
                clock.slot,
            )?;
        }
        authorize_scoped_v2(&role, Permission::SubAccountV2Sign, sign.args.subacc_id)?;
        swig_id
    };

    // Validate the state account and obtain the asset bump for signing.
    let asset_bump = validate_v2_state(
        ctx.accounts.sub_account_state,
        ctx.accounts.sub_account,
        &swig_id,
        sign.args.subacc_id,
    )?;

    // Execute the inner instructions signed by the asset PDA.
    let rkeys: &[&Pubkey] = &[];
    let ix_iter = InstructionIterator::new(
        all_accounts,
        sign.instruction_payload,
        ctx.accounts.sub_account.key(),
        rkeys,
    )?;
    let id_le = sign.args.subacc_id.to_le_bytes();
    let bump_byte = [asset_bump];
    let seeds = sub_account_v2_asset_signer(&swig_id, &id_le, &bump_byte);
    let signer = seeds.as_slice();
    for ix in ix_iter {
        if let Ok(instruction) = ix {
            instruction.execute(
                all_accounts,
                ctx.accounts.sub_account.key(),
                &[signer.into()],
            )?;
        } else {
            return Err(SwigError::InstructionExecutionError.into());
        }
    }

    // Ensure the asset account remains rent-exempt.
    let account_data = unsafe { ctx.accounts.sub_account.borrow_data_unchecked() };
    let rent_exempt_minimum =
        pinocchio::sysvars::rent::Rent::get()?.minimum_balance(account_data.len());
    let current_lamports = unsafe { *ctx.accounts.sub_account.borrow_lamports_unchecked() };
    if current_lamports < rent_exempt_minimum {
        return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
    }
    Ok(())
}
