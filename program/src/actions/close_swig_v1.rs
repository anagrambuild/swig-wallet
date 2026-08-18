//! Module for closing a Swig wallet account.
//!
//! This module implements the final closing of a Swig account,
//! transferring all lamports (SOL + rent) to destination.

use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    memory::sol_memset,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use swig_assertions::{check_bytes_match, check_self_owned};
use swig_state::{
    action::{
        all::All, close_swig_authority::CloseSwigAuthority, manage_authority::ManageAuthority,
    },
    swig::{swig_wallet_address_seeds, swig_wallet_address_signer, Swig},
    tail::rent_claimer,
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable,
};

use crate::{
    actions::sub_account_lifecycle::active_count_for_close,
    error::SwigError,
    instruction::{
        accounts::{CloseSwigV1Accounts, Context},
        SwigInstruction,
    },
};

/// Arguments for closing a Swig account.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct CloseSwigV1Args {
    pub discriminator: SwigInstruction,
    pub _padding: [u8; 2],
    pub role_id: u32,
}

impl CloseSwigV1Args {
    pub fn new(role_id: u32) -> Self {
        Self {
            discriminator: SwigInstruction::CloseSwigV1,
            _padding: [0; 2],
            role_id,
        }
    }
}

impl Transmutable for CloseSwigV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for CloseSwigV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

pub struct CloseSwigV1<'a> {
    pub args: &'a CloseSwigV1Args,
    pub authority_payload: &'a [u8],
}

impl<'a> CloseSwigV1<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < CloseSwigV1Args::LEN {
            return Err(SwigError::InvalidInstructionDataTooShort.into());
        }

        let (args_data, authority_payload) = data.split_at(CloseSwigV1Args::LEN);
        let args = unsafe { CloseSwigV1Args::load_unchecked(args_data)? };

        Ok(Self {
            args,
            authority_payload,
        })
    }
}

/// Validates that close proceeds cannot be routed to an unrecoverable or
/// Swig-owned destination. A configured rent claimer additionally pins the
/// only permitted destination.
fn validate_close_destination(
    destination: &Pubkey,
    destination_is_writable: bool,
    swig: &Pubkey,
    swig_wallet_address: &Pubkey,
    configured_rent_claimer: Option<&[u8; 32]>,
) -> ProgramResult {
    if !destination_is_writable
        || destination == &[0u8; 32]
        || destination == swig
        || destination == swig_wallet_address
    {
        return Err(SwigError::InvalidRentClaimerDestination.into());
    }

    if let Some(claimer) = configured_rent_claimer {
        if destination != claimer {
            return Err(SwigError::InvalidRentClaimerDestination.into());
        }
    }

    Ok(())
}

/// Closes the Swig account and returns all lamports to destination.
pub fn close_swig_v1(
    ctx: Context<CloseSwigV1Accounts>,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    // Verify swig account ownership
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_bytes_match(
        ctx.accounts.system_program.key(),
        &pinocchio_system::ID,
        32,
        SwigError::InvalidSystemProgram,
    )?;

    let close_ix = CloseSwigV1::from_instruction_bytes(data)?;

    // Load swig account
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };

    if swig_account_data[0] != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    // The active-child close guard applies only to migrated V2 Swigs. V1
    // parents retain their legacy close behavior and are not parsed here.
    if active_count_for_close(swig_account_data)? != 0 {
        return Err(SwigError::ActiveSubAccountsRemain.into());
    }

    let parts = Swig::split_parts_mut(swig_account_data)?;
    let swig = parts.state;
    let swig_roles = parts.roles;
    let configured_rent_claimer = rent_claimer::read_strict(parts.tail)?;

    // Verify swig_wallet_address is the correct PDA
    let (expected_wallet_address, _wallet_bump) = pinocchio::pubkey::find_program_address(
        &swig_wallet_address_seeds(ctx.accounts.swig.key().as_ref()),
        &crate::ID,
    );
    if ctx.accounts.swig_wallet_address.key() != &expected_wallet_address {
        return Err(SwigError::InvalidSeedSwigAccount.into());
    }

    // Get and authenticate role
    let role_opt = Swig::get_mut_role(close_ix.args.role_id, swig_roles)?;
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

    // Check permissions: must have All, ManageAuthority, or CloseSwigAuthority
    let has_all = role.get_action::<All>(&[])?.is_some();
    let has_manage = role.get_action::<ManageAuthority>(&[])?.is_some();
    let has_close = role.get_action::<CloseSwigAuthority>(&[])?.is_some();
    if !has_all && !has_manage && !has_close {
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    }
    validate_close_destination(
        ctx.accounts.destination.key(),
        ctx.accounts.destination.is_writable(),
        ctx.accounts.swig.key(),
        ctx.accounts.swig_wallet_address.key(),
        configured_rent_claimer,
    )?;

    // Store swig values before dropping borrow
    let wallet_bump = swig.wallet_bump;
    let swig_data_len = swig_account_data.len();

    // Check that swig account only has rent-exempt minimum (no excess SOL balance)
    let rent = Rent::get()?;
    let swig_rent_exempt = rent.minimum_balance(swig_data_len);
    let swig_lamports = ctx.accounts.swig.lamports();
    if swig_lamports > swig_rent_exempt {
        return Err(SwigError::WalletNotEmpty.into());
    }

    // Check that swig_wallet_address only has rent-exempt minimum (no excess SOL
    // balance) swig_wallet_address is a 0-size system account, so rent exempt
    // is for 0 bytes
    let wallet_rent_exempt = rent.minimum_balance(0);
    let wallet_lamports = ctx.accounts.swig_wallet_address.lamports();
    if wallet_lamports > wallet_rent_exempt {
        return Err(SwigError::WalletNotEmpty.into());
    }

    // Transfer lamports from swig_wallet_address to destination (if any)
    if wallet_lamports > 0 {
        let bump = [wallet_bump];
        let seeds = swig_wallet_address_signer(ctx.accounts.swig.key().as_ref(), &bump);
        pinocchio_system::instructions::Transfer {
            from: ctx.accounts.swig_wallet_address,
            to: ctx.accounts.destination,
            lamports: wallet_lamports,
        }
        .invoke_signed(&[seeds.as_slice().into()])?;
    }

    // Calculate rent for closed account (1 byte for discriminator)
    let closed_account_rent = rent.minimum_balance(1);

    // Transfer excess lamports to destination, keeping rent for 1 byte
    let lamports_to_transfer = swig_lamports.saturating_sub(closed_account_rent);

    unsafe {
        *ctx.accounts.swig.borrow_mut_lamports_unchecked() = closed_account_rent;
        *ctx.accounts.destination.borrow_mut_lamports_unchecked() += lamports_to_transfer;
    }

    // Resize account to 1 byte
    ctx.accounts.swig.resize(1)?;

    // Set discriminator to ClosedSwigAccount (255) to mark as permanently closed
    unsafe {
        let swig_data = ctx.accounts.swig.borrow_mut_data_unchecked();
        swig_data[0] = Discriminator::ClosedSwigAccount as u8;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_invalid_destination(
        destination: &Pubkey,
        swig: &Pubkey,
        swig_wallet_address: &Pubkey,
    ) {
        assert!(matches!(
            validate_close_destination(destination, true, swig, swig_wallet_address, None),
            Err(ProgramError::Custom(code))
                if code == SwigError::InvalidRentClaimerDestination as u32
        ));
    }

    #[test]
    fn close_destination_rejects_zero_pubkey_without_configured_claimer() {
        assert_invalid_destination(&[0u8; 32], &[1u8; 32], &[2u8; 32]);
    }

    #[test]
    fn close_destination_rejects_swig_without_configured_claimer() {
        let swig = [1u8; 32];
        assert_invalid_destination(&swig, &swig, &[2u8; 32]);
    }

    #[test]
    fn close_destination_rejects_wallet_address_without_configured_claimer() {
        let wallet = [2u8; 32];
        assert_invalid_destination(&wallet, &[1u8; 32], &wallet);
    }

    #[test]
    fn close_destination_allows_safe_external_destination_without_configured_claimer() {
        assert!(validate_close_destination(&[3u8; 32], true, &[1u8; 32], &[2u8; 32], None).is_ok());
    }

    #[test]
    fn close_destination_rejects_readonly_account() {
        assert!(matches!(
            validate_close_destination(&[3u8; 32], false, &[1u8; 32], &[2u8; 32], None),
            Err(ProgramError::Custom(code))
                if code == SwigError::InvalidRentClaimerDestination as u32
        ));
    }
}
