/// Module for creating sub-accounts within a Swig wallet.
/// This module implements functionality to create and initialize sub-accounts
/// that operate under the authority of a main wallet account with specific
/// permissions and constraints.
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use swig_assertions::*;
use swig_state::{
    action::{
        all::All, manage_authority::ManageAuthority, sub_account::SubAccount, ActionLoader,
        Actionable,
    },
    authority::AuthorityType,
    role::RoleMut,
    swig::{
        sub_account_seeds_with_bump, sub_account_signer, swig_account_seeds_with_bump,
        swig_account_signer, Swig,
    },
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, CreateSubAccountV1Accounts},
        SwigInstruction,
    },
};

/// Arguments for creating a new sub-account in a Swig wallet.
///
/// # Fields
/// * `discriminator` - The instruction type identifier
/// * `_padding1` - Padding bytes for alignment
/// * `role_id` - ID of the role creating the sub-account
/// * `sub_account_bump` - Bump seed for sub-account PDA derivation
/// * `_padding2` - Additional padding bytes for alignment
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct CreateSubAccountV1Args {
    discriminator: SwigInstruction,
    _padding1: u16,
    pub role_id: u32,
    pub sub_account_bump: u8,
    _padding2: [u8; 7],
}

impl CreateSubAccountV1Args {
    /// Creates a new instance of CreateSubAccountV1Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the role creating the sub-account
    /// * `sub_account_bump` - Bump seed for sub-account PDA derivation
    pub fn new(role_id: u32, sub_account_bump: u8) -> Self {
        Self {
            discriminator: SwigInstruction::CreateSubAccountV1,
            _padding1: 0,
            role_id,
            sub_account_bump,
            _padding2: [0; 7],
        }
    }
}

impl Transmutable for CreateSubAccountV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for CreateSubAccountV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Struct representing the complete create sub-account instruction data.
///
/// # Fields
/// * `args` - The sub-account creation arguments
/// * `authority_payload` - Authority-specific payload data
/// * `data_payload` - Raw instruction data payload
pub struct CreateSubAccountV1<'a> {
    pub args: &'a CreateSubAccountV1Args,
    pub authority_payload: &'a [u8],
    pub data_payload: &'a [u8],
}

impl<'a> CreateSubAccountV1<'a> {
    /// Parses the instruction data bytes into a CreateSubAccountV1 instance.
    ///
    /// # Arguments
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < CreateSubAccountV1Args::LEN {
            return Err(SwigError::InvalidSwigCreateInstructionDataTooShort.into());
        }

        // Split the data into args and the rest (authority payload)
        let (args_data, authority_payload) = data.split_at(CreateSubAccountV1Args::LEN);

        let args = unsafe { CreateSubAccountV1Args::load_unchecked(args_data)? };

        Ok(Self {
            args,
            authority_payload,
            data_payload: args_data,
        })
    }
}

/// Creates a new sub-account under a Swig wallet.
///
/// This function handles the complete flow of sub-account creation:
/// 1. Validates the parent wallet and authority
/// 2. Verifies the role has sub-account creation permission
/// 3. Derives and validates the sub-account address
/// 4. Creates and initializes the sub-account with proper settings
///
/// # Arguments
/// * `ctx` - The account context for sub-account creation
/// * `data` - Raw sub-account creation instruction data
/// * `all_accounts` - All accounts involved in the operation
///
/// # Returns
/// * `ProgramResult` - Success or error status
#[inline(always)]
pub fn create_sub_account_v1(
    ctx: Context<CreateSubAccountV1Accounts>,
    data: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    // Check that the swig account is owned by our program
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    // Check that the sub_account is system owned (will hold assets)
    check_system_owner(ctx.accounts.sub_account, SwigError::OwnerMismatchSubAccount)?;

    // Parse the instruction data
    let create_sub_account = CreateSubAccountV1::from_instruction_bytes(data)?;

    // Verify the swig account data
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    // Split the swig account data to get the header and roles
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_unchecked(swig_header)? };

    let (swig_roles, _) =
        unsafe { swig_roles.split_at_mut_unchecked(swig.roles_boundary as usize) };
    // Get the role using the role_id from the instruction
    let role_opt = Swig::get_mut_role(create_sub_account.args.role_id, swig_roles)?;
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
            &all_accounts,
            create_sub_account.authority_payload,
            create_sub_account.data_payload,
            slot,
        )?;
    } else {
        role.authority.authenticate(
            &all_accounts,
            create_sub_account.authority_payload,
            create_sub_account.data_payload,
            slot,
        )?;
    }
    // Check if the role has the required permissions (All or SubAccount)
    let has_all_permission = {
        let all_action = RoleMut::get_action_mut::<All>(role.actions, &[])?;
        all_action.is_some()
    };

    let has_sub_account_permission = {
        let sub_account_action = RoleMut::get_action_mut::<SubAccount>(role.actions, &[])?;
        sub_account_action.is_some()
    };

    if !has_all_permission && !has_sub_account_permission {
        return Err(SwigError::AuthorityCannotCreateSubAccount.into());
    }
    // Derive the sub-account address using the authority index as seed (keeping PDA
    // for deterministic addressing)
    let role_id_bytes = create_sub_account.args.role_id.to_le_bytes();
    let bump_byte = [create_sub_account.args.sub_account_bump];
    let sub_account_seeds = sub_account_seeds_with_bump(&swig.id, &role_id_bytes, &bump_byte);
    // Check that sub_account passed in matches derived address
    let bump = check_self_pda(
        &sub_account_seeds,
        ctx.accounts.sub_account.key(),
        SwigError::InvalidSeedSwigAccount,
    )?;

    // Transfer lamports to the sub_account to make it system-owned and rent-exempt
    // This follows the same pattern as swig_wallet_address creation in create_v1.rs
    let sub_account_rent_exemption = Rent::get()?.minimum_balance(0); // 0 space for system account

    // Get current lamports in sub-account
    let current_sub_account_lamports =
        unsafe { *ctx.accounts.sub_account.borrow_lamports_unchecked() };

    // Only transfer if the account needs more lamports for rent exemption
    let sub_account_lamports_to_transfer =
        if current_sub_account_lamports >= sub_account_rent_exemption {
            0
        } else {
            sub_account_rent_exemption - current_sub_account_lamports
        };

    if sub_account_lamports_to_transfer > 0 {
        // Use CPI to system program for clean lamport transfer
        pinocchio_system::instructions::Transfer {
            from: ctx.accounts.payer,
            to: ctx.accounts.sub_account,
            lamports: sub_account_lamports_to_transfer,
        }
        .invoke()?;
    }

    // Update the SubAccount action to store all sub-account metadata
    if let Some(sub_account_action_mut) = RoleMut::get_action_mut::<SubAccount>(role.actions, &[])?
    {
        sub_account_action_mut
            .sub_account
            .copy_from_slice(ctx.accounts.sub_account.key().as_ref());
        sub_account_action_mut.bump = create_sub_account.args.sub_account_bump;
        sub_account_action_mut.enabled = true; // Default to enabled
        sub_account_action_mut.role_id = create_sub_account.args.role_id;
        sub_account_action_mut.swig_id = swig.id;
    }

    Ok(())
}
