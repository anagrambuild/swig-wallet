/// Module for handling SOL transfers with destination-specific limits.
/// This module implements the logic for transferring SOL with both general
/// and destination-specific limits applied.
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_state::{
    action::{
        sol_destination_limit::SolDestinationLimit, sol_limit::SolLimit,
        sol_recurring_limit::SolRecurringLimit,
    },
    authority::AuthorityType,
    role::RoleMut,
    swig::{swig_account_signer, Swig},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, SignV1Accounts},
        SwigInstruction,
    },
};

/// Arguments for transferring SOL with destination limits.
///
/// # Fields
/// * `instruction` - The instruction type identifier
/// * `role_id` - ID of the role attempting the transfer
/// * `destination` - The destination pubkey to transfer SOL to
/// * `amount` - Amount of lamports to transfer
#[derive(Debug)]
#[repr(C, align(8))]
pub struct SolDestinationLimitV1Args {
    instruction: SwigInstruction,
    pub role_id: u32,
    pub destination: Pubkey,
    pub amount: u64,
}

impl SolDestinationLimitV1Args {
    /// Creates a new instance of SolDestinationLimitV1Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the signing role
    /// * `destination` - The destination pubkey
    /// * `amount` - Amount of lamports to transfer
    pub fn new(role_id: u32, destination: Pubkey, amount: u64) -> Self {
        Self {
            instruction: SwigInstruction::SolDestinationLimitV1,
            role_id,
            destination,
            amount,
        }
    }
}

impl Transmutable for SolDestinationLimitV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for SolDestinationLimitV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Struct representing the complete SOL destination limit transfer instruction
/// data.
///
/// # Fields
/// * `args` - The transfer arguments
/// * `authority_payload` - Authority-specific payload data
pub struct SolDestinationLimitV1<'a> {
    pub args: &'a SolDestinationLimitV1Args,
    authority_payload: &'a [u8],
}

impl<'a> SolDestinationLimitV1<'a> {
    /// Parses the instruction data bytes into a SolDestinationLimitV1 instance.
    ///
    /// # Arguments
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < SolDestinationLimitV1Args::LEN {
            return Err(SwigError::InvalidSwigSignInstructionDataTooShort.into());
        }
        let (inst, authority_payload) =
            unsafe { data.split_at_unchecked(SolDestinationLimitV1Args::LEN) };
        let args = unsafe { SolDestinationLimitV1Args::load_unchecked(inst)? };

        Ok(Self {
            args,
            authority_payload,
        })
    }
}

/// Transfers SOL with destination-specific limits applied.
///
/// This function handles SOL transfers with both general SOL limits and
/// destination-specific limits. It ensures that:
/// 1. The authority is valid and authenticated
/// 2. General SOL limits are respected (if they exist)
/// 3. Destination-specific limits are respected (if they exist)
/// 4. The transfer is executed
///
/// # Arguments
/// * `ctx` - The account context for the transfer
/// * `all_accounts` - All accounts involved in the transaction
/// * `data` - Raw transfer instruction data
///
/// # Returns
/// * `ProgramResult` - Success or error status
#[inline(always)]
pub fn sol_destination_limit_v1(
    ctx: Context<SignV1Accounts>,
    all_accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let transfer_instruction = SolDestinationLimitV1::from_instruction_bytes(data)?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };

    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
    let role = Swig::get_mut_role(transfer_instruction.args.role_id, swig_roles)?;

    if role.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let role = role.unwrap();

    let clock = Clock::get()?;
    let slot = clock.slot;

    // Authenticate the authority
    if role.authority.session_based() {
        role.authority.authenticate_session(
            all_accounts,
            transfer_instruction.authority_payload,
            &[], // No instruction payload for simple transfers
            slot,
        )?;
    } else {
        role.authority.authenticate(
            all_accounts,
            transfer_instruction.authority_payload,
            &[], // No instruction payload for simple transfers
            slot,
        )?;
    }

    let amount = transfer_instruction.args.amount;
    let destination_pubkey = transfer_instruction.args.destination.as_ref();
    let actions = role.actions;

    // Check destination-specific limit first
    let mut destination_limit_checked = false;
    if let Some(dest_action) =
        RoleMut::get_action_mut::<SolDestinationLimit>(actions, &destination_pubkey)?
    {
        dest_action.run(amount)?;
        destination_limit_checked = true;
    }

    // Check general SOL limits (these should be combined with destination limits)
    let mut general_limit_checked = false;
    if let Some(action) = RoleMut::get_action_mut::<SolLimit>(actions, &[])? {
        action.run(amount)?;
        general_limit_checked = true;
    } else if let Some(action) = RoleMut::get_action_mut::<SolRecurringLimit>(actions, &[])? {
        action.run(amount, slot)?;
        general_limit_checked = true;
    }

    // At least one limit must be present (either destination-specific or general)
    if !destination_limit_checked && !general_limit_checked {
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    }

    // Check that the Swig account has sufficient balance
    let current_lamports = ctx.accounts.swig.lamports();
    if current_lamports < swig.reserved_lamports + amount {
        return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
    }

    // Find the destination account
    let destination_account = all_accounts
        .iter()
        .find(|account| account.key() == &transfer_instruction.args.destination)
        .ok_or(SwigError::InvalidAccountsLength)?;

    // Perform the SOL transfer
    unsafe {
        *ctx.accounts.swig.borrow_mut_lamports_unchecked() -= amount;
        *destination_account.borrow_mut_lamports_unchecked() += amount;
    }

    Ok(())
}
