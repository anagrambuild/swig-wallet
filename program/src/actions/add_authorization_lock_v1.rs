/// Module for adding authorization locks to Swig accounts.
/// Authorization locks pre-authorize token spending up to a specific amount
/// and expiry slot, providing a mechanism for payment preauthorizations.

use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use swig_assertions::*;
use swig_state_x::{
    role::Position,
    swig::{AuthorizationLock, Swig, SwigBuilder},
    Discriminator, IntoBytes, SwigStateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{AddAuthorizationLockV1Accounts, Context},
        SwigInstruction,
    },
};

/// Arguments for adding an authorization lock to a Swig wallet.
///
/// # Fields
/// * `instruction` - The instruction type identifier
/// * `token_mint` - The mint of the token to lock
/// * `amount` - The maximum amount that can be spent
/// * `expiry_slot` - The slot when this lock expires
#[derive(Debug, NoPadding)]
#[repr(C, align(8))]
pub struct AddAuthorizationLockV1Args {
    instruction: SwigInstruction,
    _padding: [u8; 6], // Add padding to align to 8 bytes
    pub token_mint: [u8; 32],
    pub amount: u64,
    pub expiry_slot: u64,
}

impl AddAuthorizationLockV1Args {
    /// Creates a new instance of AddAuthorizationLockV1Args.
    ///
    /// # Arguments
    /// * `token_mint` - The mint of the token to lock
    /// * `amount` - The maximum amount that can be spent
    /// * `expiry_slot` - The slot when this lock expires
    pub fn new(token_mint: [u8; 32], amount: u64, expiry_slot: u64) -> Self {
        Self {
            instruction: SwigInstruction::AddAuthorizationLockV1,
            _padding: [0; 6],
            token_mint,
            amount,
            expiry_slot,
        }
    }
}

impl Transmutable for AddAuthorizationLockV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for AddAuthorizationLockV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Adds an authorization lock to a Swig wallet.
///
/// This function:
/// 1. Validates the Swig account
/// 2. Checks that the lock hasn't already expired
/// 3. Reallocates the account to accommodate the new lock
/// 4. Adds the authorization lock to the end of the account data
///
/// # Arguments
/// * `ctx` - The account context for the operation
/// * `data` - Raw instruction data bytes
///
/// # Returns
/// * `ProgramResult` - Success or error status
#[inline(always)]
pub fn add_authorization_lock_v1(
    ctx: Context<AddAuthorizationLockV1Accounts>,
    data: &[u8],
) -> ProgramResult {
    check_stack_height(1, SwigError::Cpi)?;
    
    if data.len() < AddAuthorizationLockV1Args::LEN {
        return Err(SwigError::InvalidSwigSignInstructionDataTooShort.into());
    }

    let args = unsafe { AddAuthorizationLockV1Args::load_unchecked(data)? };

    // Get current slot to validate expiry
    let clock = Clock::get()?;
    if args.expiry_slot <= clock.slot {
        return Err(SwigError::InvalidAuthorizationLockExpiry.into());
    }

    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    // Calculate current data layout sizes
    let (swig_header, remaining_data) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };

    // Find the end of roles data to determine where authorization locks start
    let mut roles_end = 0;
    let mut cursor = 0;
    for _i in 0..swig.roles {
        if cursor + Position::LEN > remaining_data.len() {
            return Err(SwigStateError::InvalidRoleData.into());
        }
        let position = unsafe {
            Position::load_unchecked(&remaining_data[cursor..cursor + Position::LEN])?
        };
        cursor = position.boundary() as usize;
        roles_end = cursor;
    }

    // Calculate required space for new authorization lock
    let new_lock_size = AuthorizationLock::LEN;
    let current_auth_locks_size = swig.authorization_locks as usize * AuthorizationLock::LEN;
    let required_total_size = Swig::LEN + roles_end + current_auth_locks_size + new_lock_size;

    // Check if we need to reallocate
    let current_size = ctx.accounts.swig.data_len();
    if required_total_size > current_size {
        // Reallocate account
        ctx.accounts.swig.realloc(required_total_size, false)?;
        let rent = Rent::get()?;
        let rent_required = rent.minimum_balance(required_total_size);
        let current_lamports = ctx.accounts.swig.lamports();
        if rent_required > current_lamports {
            let additional_rent = rent_required - current_lamports;
            Transfer {
                from: ctx.accounts.payer,
                to: ctx.accounts.swig,
                lamports: additional_rent,
            }
            .invoke()?;
        }
    }

    // Re-borrow data after potential reallocation
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    
    // Create the new authorization lock
    let new_lock = AuthorizationLock {
        token_mint: args.token_mint,
        amount: args.amount,
        expiry_slot: args.expiry_slot,
    };

    // Write the new lock at the end of the authorization locks section
    let auth_locks_start = Swig::LEN + roles_end;
    let new_lock_offset = auth_locks_start + current_auth_locks_size;
    
    let lock_bytes = new_lock.into_bytes()?;
    swig_account_data[new_lock_offset..new_lock_offset + new_lock_size]
        .copy_from_slice(lock_bytes);

    // Update the authorization locks count in the header
    let (swig_header, _) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
    swig.authorization_locks += 1;

    msg!(
        "Added authorization lock for mint {:?}, amount: {}, expiry_slot: {}",
        args.token_mint,
        args.amount,
        args.expiry_slot
    );

    Ok(())
}