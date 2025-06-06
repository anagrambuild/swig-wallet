/// Module for removing authorization locks from Swig accounts.
/// Authorization locks can be removed by authorities with proper permissions,
/// which helps manage payment preauthorizations by revoking them when needed.

use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_assertions::*;
use swig_state_x::{
    action::{all::All, manage_authorization_locks::ManageAuthorizationLocks},
    role::Position,
    swig::{AuthorizationLock, Swig, SwigBuilder},
    Discriminator, IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{RemoveAuthorizationLockV1Accounts, Context},
        SwigInstruction,
    },
};

/// Arguments for removing an authorization lock from a Swig wallet.
///
/// # Fields
/// * `instruction` - The instruction type identifier
/// * `acting_role_id` - ID of the role performing the operation
/// * `lock_index` - Index of the authorization lock to remove
#[derive(Debug, NoPadding)]
#[repr(C, align(8))]
pub struct RemoveAuthorizationLockV1Args {
    instruction: SwigInstruction,
    _padding: [u8; 6], // Adjusted padding for proper alignment
    pub acting_role_id: u32,
    pub lock_index: u32,
}

impl RemoveAuthorizationLockV1Args {
    /// Creates a new instance of RemoveAuthorizationLockV1Args.
    ///
    /// # Arguments
    /// * `acting_role_id` - ID of the role performing the operation
    /// * `lock_index` - Index of the authorization lock to remove
    pub fn new(acting_role_id: u32, lock_index: u32) -> Self {
        Self {
            instruction: SwigInstruction::RemoveAuthorizationLockV1,
            _padding: [0; 6],
            acting_role_id,
            lock_index,
        }
    }
}

impl Transmutable for RemoveAuthorizationLockV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for RemoveAuthorizationLockV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Structured data for the remove authorization lock instruction.
pub struct RemoveAuthorizationLockV1<'a> {
    pub args: &'a RemoveAuthorizationLockV1Args,
    data_payload: &'a [u8],
    authority_payload: &'a [u8],
}

impl<'a> RemoveAuthorizationLockV1<'a> {
    /// Parses the instruction data bytes into a RemoveAuthorizationLockV1 instance.
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < RemoveAuthorizationLockV1Args::LEN {
            return Err(SwigError::InvalidSwigSignInstructionDataTooShort.into());
        }

        let (inst, authority_payload) = data.split_at(RemoveAuthorizationLockV1Args::LEN);
        let args = unsafe { RemoveAuthorizationLockV1Args::load_unchecked(inst)? };

        Ok(Self {
            args,
            data_payload: inst,
            authority_payload,
        })
    }
}

/// Removes an authorization lock from a Swig wallet.
///
/// This function:
/// 1. Validates the acting role's permissions (All or ManageAuthorizationLocks)
/// 2. Authenticates the request
/// 3. Validates the Swig account and lock index
/// 4. Removes the authorization lock by shifting remaining locks down
/// 5. Updates the authorization lock count
///
/// # Arguments
/// * `ctx` - The account context for the operation
/// * `data` - Raw instruction data bytes
/// * `all_accounts` - All accounts involved in the operation
///
/// # Returns
/// * `ProgramResult` - Success or error status
#[inline(always)]
pub fn remove_authorization_lock_v1(
    ctx: Context<RemoveAuthorizationLockV1Accounts>,
    data: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    check_stack_height(1, SwigError::Cpi)?;
    
    let remove_lock = RemoveAuthorizationLockV1::from_instruction_bytes(data)?;

    // Get current slot for authentication
    let clock = Clock::get()?;

    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    // Authentication and permission checking
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
    let acting_role = Swig::get_mut_role(remove_lock.args.acting_role_id, swig_roles)?;
    if acting_role.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let acting_role = acting_role.unwrap();

    // Authenticate the caller
    let slot = clock.slot;
    if acting_role.authority.session_based() {
        acting_role.authority.authenticate_session(
            all_accounts,
            remove_lock.authority_payload,
            remove_lock.data_payload,
            slot,
        )?;
    } else {
        acting_role.authority.authenticate(
            all_accounts,
            remove_lock.authority_payload,
            remove_lock.data_payload,
            slot,
        )?;
    }

    // Check permissions: must have All or ManageAuthorizationLocks
    let all = acting_role.get_action::<All>(&[])?;
    let manage_auth_locks = acting_role.get_action::<ManageAuthorizationLocks>(&[])?;

    if all.is_none() && manage_auth_locks.is_none() {
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    }

    // Re-borrow data after authentication
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (swig_header, remaining_data) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };

    // Validate that we have authorization locks to remove
    if swig.authorization_locks == 0 {
        return Err(SwigError::InvalidAuthorizationLockIndex.into());
    }

    // Validate lock index
    if remove_lock.args.lock_index >= swig.authorization_locks as u32 {
        return Err(SwigError::InvalidAuthorizationLockIndex.into());
    }

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

    let auth_locks_start = roles_end;
    let lock_size = AuthorizationLock::LEN;
    let total_locks = swig.authorization_locks as usize;
    let lock_index = remove_lock.args.lock_index as usize;

    // Calculate positions
    let lock_to_remove_start = auth_locks_start + (lock_index * lock_size);
    let lock_to_remove_end = lock_to_remove_start + lock_size;
    let locks_after_start = lock_to_remove_end;
    let locks_after_end = auth_locks_start + (total_locks * lock_size);

    // Log the lock being removed for debugging
    if lock_to_remove_start + lock_size <= remaining_data.len() {
        let lock_data = &remaining_data[lock_to_remove_start..lock_to_remove_end];
        if let Ok(lock) = unsafe { AuthorizationLock::load_unchecked(lock_data) } {
            msg!(
                "Removing authorization lock {} for mint {:?}, amount: {}, expiry_slot: {}",
                lock_index,
                lock.token_mint,
                lock.amount,
                lock.expiry_slot
            );
        }
    }

    // Shift all locks after the removed lock down by one position
    if lock_index < total_locks - 1 {
        let locks_after_count = total_locks - lock_index - 1;
        let move_size = locks_after_count * lock_size;
        
        // Safety check: ensure we don't go out of bounds
        if locks_after_end <= remaining_data.len() && 
           lock_to_remove_start + move_size <= remaining_data.len() {
            // Use copy_within to safely move the data
            let source_start = locks_after_start;
            let source_end = locks_after_end;
            let dest_start = lock_to_remove_start;
            
            remaining_data.copy_within(source_start..source_end, dest_start);
        } else {
            return Err(SwigError::InvalidAuthorizationLockIndex.into());
        }
    }

    // Update the authorization locks count in the header
    let (swig_header, _) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
    swig.authorization_locks -= 1;

    msg!(
        "Removed authorization lock at index {}, {} locks remaining",
        lock_index,
        swig.authorization_locks
    );

    Ok(())
}