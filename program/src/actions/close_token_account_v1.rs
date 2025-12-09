//! Module for closing a single token account owned by a Swig wallet.
//!
//! This module implements closing of an SPL token account,
//! returning rent to a specified destination.

use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    memory::sol_memcmp,
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_assertions::check_self_owned;
use swig_state::{
    action::{all::All, manage_authority::ManageAuthority},
    swig::{swig_account_signer, swig_wallet_address_seeds, swig_wallet_address_signer, Swig},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable,
};

use crate::{
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
    pub _padding: [u8; 2],
    pub role_id: u32,
}

impl CloseTokenAccountV1Args {
    pub fn new(role_id: u32) -> Self {
        Self {
            discriminator: SwigInstruction::CloseTokenAccountV1,
            _padding: [0; 2],
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

/// Closes a single token account owned by the Swig wallet.
///
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
    let swig_roles = &swig_account_data[Swig::LEN..];
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

    // Check permissions: must have All or ManageAuthority
    let has_all = role.get_action::<All>(&[])?.is_some();
    let has_manage = role.get_action::<ManageAuthority>(&[])?.is_some();
    if !has_all && !has_manage {
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    }

    // Use is_swig_v2 to determine expected authority
    let is_v2 = unsafe { is_swig_v2(swig_account_data) };

    // Extract swig values we need before releasing the borrow
    let swig_id = swig.id;
    let swig_bump = swig.bump;

    // Verify the token account is owned by a token program
    let token_program_id = ctx.accounts.token_program.key();
    if token_program_id != &SPL_TOKEN_ID && token_program_id != &SPL_TOKEN_2022_ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    let token_account_owner = ctx.accounts.token_account.owner();
    if token_account_owner != token_program_id {
        return Err(SwigError::OwnerMismatchTokenAccount.into());
    }

    // Read token account data using unchecked borrow (no runtime borrow tracking)
    let token_data = unsafe { ctx.accounts.token_account.borrow_data_unchecked() };
    if token_data.len() < 72 {
        return Err(ProgramError::InvalidAccountData);
    }

    // Token account authority is at bytes 32-64
    let token_authority = &token_data[32..64];

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

    // First check the expected authority
    let use_expected = unsafe { sol_memcmp(token_authority, expected_authority.as_ref(), 32) == 0 };
    // Only check fallback if expected didn't match (handles unmigrated token accounts)
    let use_fallback = !use_expected
        && unsafe { sol_memcmp(token_authority, fallback_authority.as_ref(), 32) == 0 };

    if !use_expected && !use_fallback {
        return Err(SwigError::InvalidSwigTokenAccountOwner.into());
    }

    // Determine which authority to use for signing
    let use_wallet_as_signer = (is_v2 && use_expected) || (!is_v2 && use_fallback);

    // Close the token account via CPI using TokenClose utility
    let token_close = TokenClose {
        token_program: token_program_id,
        account: ctx.accounts.token_account,
        destination: ctx.accounts.destination,
        authority: if use_wallet_as_signer {
            ctx.accounts.swig_wallet_address
        } else {
            ctx.accounts.swig
        },
    };

    // Invoke with appropriate signer
    if use_wallet_as_signer {
        let bump = [wallet_bump];
        let seeds = swig_wallet_address_signer(ctx.accounts.swig.key().as_ref(), &bump);
        token_close.invoke_signed(&[seeds.as_slice().into()])?;
    } else {
        let bump = [swig_bump];
        let seeds = swig_account_signer(&swig_id, &bump);
        token_close.invoke_signed(&[seeds.as_slice().into()])?;
    }

    Ok(())
}
