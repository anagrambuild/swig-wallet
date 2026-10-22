//! Module for closing token accounts owned by a Swig wallet.
//!
//! This module implements closing of SPL token accounts,
//! returning rent to a specified destination. Supports closing
//! multiple token accounts in a single transaction.

use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    memory::sol_memcmp,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use pinocchio_pubkey::from_str;
use swig_assertions::check_self_owned;
use swig_state::{
    action::{
        all::All, all_but_manage_authority::AllButManageAuthority,
        close_swig_authority::CloseSwigAuthority, manage_authority::ManageAuthority,
        token_destination_limit::TokenDestinationLimit, token_limit::TokenLimit,
        token_recurring_destination_limit::TokenRecurringDestinationLimit,
        token_recurring_limit::TokenRecurringLimit,
    },
    role::RoleMut,
    swig::{swig_account_signer, swig_wallet_address_seeds, swig_wallet_address_signer, Swig},
    tail::rent_claimer,
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable,
};

use crate::{
    actions::sign_v2::{
        has_token_destination_limits, read_wsol_reserve, wsol_accounted_balance,
        TOKEN_ACCOUNT_BASE_DATA_LEN, TOKEN_ACCOUNT_INITIALIZED_STATE, TOKEN_NATIVE_RESERVE_RANGE,
        TOKEN_STATE_INDEX, WSOL_MINT,
    },
    error::SwigError,
    instruction::{
        accounts::{CloseTokenAccountV1Accounts, Context},
        SwigInstruction,
    },
    is_swig_v2,
    util::TokenClose,
    SPL_TOKEN_2022_ID, SPL_TOKEN_ID,
};

/// Arguments for closing a token account.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct CloseTokenAccountV1Args {
    pub discriminator: SwigInstruction,
    pub token_account_offset: u16,
    pub role_id: u32,
}

impl CloseTokenAccountV1Args {
    pub fn new(role_id: u32, token_account_offset: u16) -> Self {
        Self {
            discriminator: SwigInstruction::CloseTokenAccountV1,
            token_account_offset,
            role_id,
        }
    }
}

impl Transmutable for CloseTokenAccountV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for CloseTokenAccountV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

pub struct CloseTokenAccountV1<'a> {
    pub args: &'a CloseTokenAccountV1Args,
    pub authority_payload: &'a [u8],
}

impl<'a> CloseTokenAccountV1<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < CloseTokenAccountV1Args::LEN {
            return Err(SwigError::InvalidInstructionDataTooShort.into());
        }

        let (args_data, authority_payload) = data.split_at(CloseTokenAccountV1Args::LEN);
        let args = unsafe { CloseTokenAccountV1Args::load_unchecked(args_data)? };

        Ok(Self {
            args,
            authority_payload,
        })
    }
}

/// Token-2022's wrapped-native-SOL mint.
///
/// Token-2022 represents wrapped native SOL under its own native mint, which
/// is distinct from the legacy SPL Token program's native mint (`WSOL_MINT`
/// in `sign_v2`). Both must receive identical spend accounting.
const TOKEN_2022_NATIVE_MINT: Pubkey = from_str("9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP");

/// Resolves the wrapped-native mint for the (already validated) token
/// program handling this close.
fn native_wsol_mint(token_program_id: &Pubkey) -> Pubkey {
    if token_program_id == &SPL_TOKEN_ID {
        WSOL_MINT
    } else {
        TOKEN_2022_NATIVE_MINT
    }
}

/// Reads the native reserve of a Token-2022 native token account.
///
/// Token-2022 keeps the legacy SPL token account base layout — the wrapped
/// native reserve sits behind the `is_native` COption tag at bytes 109..121 —
/// but real accounts may carry trailing extension data, so only the base
/// prefix is validated here (unlike `read_wsol_reserve`, which requires the
/// exact legacy 165-byte layout).
fn read_token_2022_native_reserve(data: &[u8]) -> Result<u64, ProgramError> {
    if data.len() < TOKEN_ACCOUNT_BASE_DATA_LEN
        || data[TOKEN_STATE_INDEX] != TOKEN_ACCOUNT_INITIALIZED_STATE
        || data[109..113] != [1, 0, 0, 0]
    {
        return Err(SwigError::AccountDataModifiedUnexpectedly.into());
    }
    Ok(u64::from_le_bytes(
        data[TOKEN_NATIVE_RESERVE_RANGE]
            .try_into()
            .map_err(|_| SwigError::AccountDataModifiedUnexpectedly)?,
    ))
}

/// Closes one or more token accounts owned by the Swig wallet.
///
/// All token accounts must belong to the same token program (SPL Token or
/// Token-2022). Token accounts are passed as remaining accounts starting at
/// `token_account_offset`.
pub fn close_token_account_v1(
    ctx: Context<CloseTokenAccountV1Accounts>,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    // Verify the swig account is owned by this program
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;

    let close_ix = CloseTokenAccountV1::from_instruction_bytes(data)?;

    // Load and validate swig account
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_data_unchecked() };
    let swig = unsafe { Swig::load_unchecked(&swig_account_data[..Swig::LEN])? };

    // Verify discriminator
    if swig_account_data[0] != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    // Verify swig_wallet_address is the correct PDA (always, regardless of V1/V2)
    let (expected_wallet_address, wallet_bump) = pinocchio::pubkey::find_program_address(
        &swig_wallet_address_seeds(ctx.accounts.swig.key().as_ref()),
        &crate::ID,
    );
    if ctx.accounts.swig_wallet_address.key() != &expected_wallet_address {
        return Err(SwigError::InvalidSeedSwigAccount.into());
    }

    // Get and authenticate role
    let swig_roles = Swig::split_parts(swig_account_data)?.roles;
    let role_opt = unsafe {
        let roles_ptr = swig_roles.as_ptr() as *mut u8;
        let roles_mut = core::slice::from_raw_parts_mut(roles_ptr, swig_roles.len());
        Swig::get_mut_role(close_ix.args.role_id, roles_mut)?
    };

    if role_opt.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let role = role_opt.unwrap();

    // Authenticate
    let current_slot = Clock::get()?.slot;
    if role.authority.session_based() {
        role.authority.authenticate_session(
            accounts,
            close_ix.authority_payload,
            close_ix.args.into_bytes()?,
            current_slot,
        )?;
    } else {
        role.authority.authenticate(
            accounts,
            close_ix.authority_payload,
            close_ix.args.into_bytes()?,
            current_slot,
        )?;
    }

    // Unrestricted asset permissions also authorize closing token accounts.
    let has_all = RoleMut::get_action_mut::<All>(role.actions, &[])?.is_some();
    let has_all_but_manage =
        RoleMut::get_action_mut::<AllButManageAuthority>(role.actions, &[])?.is_some();
    let has_manage = RoleMut::get_action_mut::<ManageAuthority>(role.actions, &[])?.is_some();
    let has_close = RoleMut::get_action_mut::<CloseSwigAuthority>(role.actions, &[])?.is_some();
    if !has_all && !has_all_but_manage && !has_manage && !has_close {
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    }
    if let Some(claimer) = rent_claimer::read_strict(Swig::split_parts(swig_account_data)?.tail)? {
        if ctx.accounts.destination.key().as_ref() != claimer.as_ref() {
            return Err(SwigError::InvalidRentClaimerDestination.into());
        }
    }

    // Use is_swig_v2 to determine expected authority
    let is_v2 = unsafe { is_swig_v2(swig_account_data) };

    // Extract swig values we need before releasing the borrow
    let swig_id = swig.id;
    let swig_bump = swig.bump;

    // Verify the token program is valid
    let token_program_id = ctx.accounts.token_program.key();
    if token_program_id != &SPL_TOKEN_ID && token_program_id != &SPL_TOKEN_2022_ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    // Get the token accounts from remaining accounts
    let token_account_offset = close_ix.args.token_account_offset as usize;
    if token_account_offset >= accounts.len() {
        return Err(SwigError::InvalidInstructionDataTooShort.into());
    }

    // Determine expected authority based on V1/V2
    // V2: expect swig_wallet_address as authority
    // V1: expect swig as authority
    // Fallback: check the other in case of unmigrated token accounts
    let (expected_authority, fallback_authority) = if is_v2 {
        (
            ctx.accounts.swig_wallet_address.key(),
            ctx.accounts.swig.key(),
        )
    } else {
        (
            ctx.accounts.swig.key(),
            ctx.accounts.swig_wallet_address.key(),
        )
    };

    // Pre-compute signers for both cases
    let wallet_bump_bytes = [wallet_bump];
    let wallet_seeds =
        swig_wallet_address_signer(ctx.accounts.swig.key().as_ref(), &wallet_bump_bytes);
    let swig_bump_bytes = [swig_bump];
    let swig_seeds = swig_account_signer(&swig_id, &swig_bump_bytes);

    let unrestricted_spend = has_all || has_all_but_manage;
    // Validate every source and consume bounded WSOL spend before the first CPI.
    // A later error rolls back authentication and every permission update.
    for token_account in &accounts[token_account_offset..] {
        // Verify token account is owned by the token program
        let token_account_owner = token_account.owner();
        if token_account_owner != token_program_id {
            return Err(SwigError::OwnerMismatchTokenAccount.into());
        }

        // Read token account data using unchecked borrow (no runtime borrow tracking)
        let token_data = unsafe { token_account.borrow_data_unchecked() };
        if token_data.len() < 72 {
            return Err(ProgramError::InvalidAccountData);
        }

        // Token account authority is at bytes 32-64
        let token_authority = &token_data[32..64];

        // First check the expected authority
        let use_expected =
            unsafe { sol_memcmp(token_authority, expected_authority.as_ref(), 32) == 0 };
        // Only check fallback if expected didn't match (handles unmigrated token
        // accounts)
        let use_fallback = !use_expected
            && unsafe { sol_memcmp(token_authority, fallback_authority.as_ref(), 32) == 0 };

        if !use_expected && !use_fallback {
            return Err(SwigError::InvalidSwigTokenAccountOwner.into());
        }

        // Wrapped-native value exists under both supported token programs.
        // Enforce identical allowance and destination accounting against the
        // handling program's own native mint before any CPI so a closer
        // cannot withdraw wrapped SOL outside its delegated budget.
        let native_mint = native_wsol_mint(token_program_id);
        if token_data.get(..32) == Some(native_mint.as_slice()) {
            let reserve = if token_program_id == &SPL_TOKEN_ID {
                read_wsol_reserve(token_program_id, token_data)?
            } else {
                read_token_2022_native_reserve(token_data)?
            };
            let amount = u64::from_le_bytes(token_data[64..72].try_into().unwrap());
            let spent = wsol_accounted_balance(amount, reserve, token_account.lamports())?;
            if !unrestricted_spend {
                let general_limit = if let Some(limit) =
                    RoleMut::get_action_mut::<TokenLimit>(role.actions, &native_mint)?
                {
                    limit.run(spent)?;
                    true
                } else if let Some(limit) =
                    RoleMut::get_action_mut::<TokenRecurringLimit>(role.actions, &native_mint)?
                {
                    limit.run(spent, current_slot)?;
                    true
                } else {
                    false
                };
                let destination_limit = has_token_destination_limits(role.actions, &native_mint)?;
                if destination_limit {
                    let mut key = [0u8; 64];
                    key[..32].copy_from_slice(&native_mint);
                    key[32..].copy_from_slice(ctx.accounts.destination.key());
                    if let Some(limit) = RoleMut::get_action_mut::<TokenRecurringDestinationLimit>(
                        role.actions,
                        &key,
                    )? {
                        limit.run(spent, current_slot)?;
                    } else if let Some(limit) =
                        RoleMut::get_action_mut::<TokenDestinationLimit>(role.actions, &key)?
                    {
                        limit.run(spent)?;
                    } else {
                        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                    }
                }
                if !general_limit && !destination_limit {
                    return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                }
            }
        }
    }

    for token_account in &accounts[token_account_offset..] {
        let token_data = unsafe { token_account.borrow_data_unchecked() };
        let token_authority = token_data
            .get(32..64)
            .ok_or(ProgramError::InvalidAccountData)?;
        let use_wallet_as_signer = token_authority == ctx.accounts.swig_wallet_address.key();

        // Close the token account via CPI using TokenClose utility
        let token_close = TokenClose {
            token_program: token_program_id,
            account: token_account,
            destination: ctx.accounts.destination,
            authority: if use_wallet_as_signer {
                ctx.accounts.swig_wallet_address
            } else {
                ctx.accounts.swig
            },
        };

        // Invoke with appropriate signer
        if use_wallet_as_signer {
            token_close.invoke_signed(&[wallet_seeds.as_slice().into()])?;
        } else {
            token_close.invoke_signed(&[swig_seeds.as_slice().into()])?;
        }
    }

    Ok(())
}
