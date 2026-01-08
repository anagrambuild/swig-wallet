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
use swig_state::{
    action::{all::All, manage_authorization_locks::ManageAuthorizationLocks},
    role::Position,
    swig::{AuthorizationLock, Swig, SwigBuilder},
    Discriminator, IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, RemoveAuthorizationLockV1Accounts},
        SwigInstruction,
    },
};

/// Number of slots after expiry before an authorization lock can be removed by any
/// authority with All or ManageAuthority permissions (not just the creator).
/// Set to 5 Solana epochs (~2,160,000 slots = ~10 days at 400ms/slot)
pub const EXPIRED_LOCK_CLEANUP_THRESHOLD_SLOTS: u64 = 5 * 432_000;

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
    /// Parses the instruction data bytes into a RemoveAuthorizationLockV1
    /// instance.
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
/// 3. Validates role ownership (both All and ManageAuthorizationLocks can only
///    remove own locks)
/// 4. Validates the Swig account and lock index
/// 5. Removes the authorization lock by shifting remaining locks down
/// 6. Updates the authorization lock count
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
    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigConfigAccount as u8 {
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
    let has_all_permission = acting_role.get_action::<All>(&[])?.is_some();
    let has_manage_auth_locks_permission = acting_role
        .get_action::<ManageAuthorizationLocks>(&[])?
        .is_some();

    if !has_all_permission && !has_manage_auth_locks_permission {
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    }

    // Re-borrow data after authentication
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (swig_header, remaining_data) =
        unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
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
        let position =
            unsafe { Position::load_unchecked(&remaining_data[cursor..cursor + Position::LEN])? };
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

    // Validate role ownership with expired lock cleanup exception
    // Rules:
    // 1. Role can always remove its own authorization locks
    // 2. If lock is expired beyond cleanup threshold, any role with All or
    //    ManageAuthority can remove it (proactive cleanup)
    if lock_to_remove_start + lock_size <= remaining_data.len() {
        // Zero-copy: cast the raw bytes directly to a reference
        let lock = unsafe {
            &*(remaining_data[lock_to_remove_start..lock_to_remove_end].as_ptr()
                as *const AuthorizationLock)
        };

        // Check if this is the lock creator or if cleanup is allowed
        let is_lock_creator = lock.role_id == remove_lock.args.acting_role_id;
        let is_expired_beyond_threshold =
            lock.expiry_slot + EXPIRED_LOCK_CLEANUP_THRESHOLD_SLOTS < slot;
        let can_cleanup = has_all_permission; // Only All permission can cleanup others' locks

        if !is_lock_creator && !(is_expired_beyond_threshold && can_cleanup) {
            msg!(
                "Permission denied: Role {} cannot remove authorization lock created by role {} \
                 (lock not expired beyond cleanup threshold or missing All permission)",
                remove_lock.args.acting_role_id,
                lock.role_id
            );
            return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
        }

        if is_expired_beyond_threshold && !is_lock_creator {
            msg!(
                "Cleaning up expired authorization lock: created by role {}, expired at slot {}, \
                 current slot {}, cleanup performed by role {}",
                lock.role_id,
                lock.expiry_slot,
                slot,
                remove_lock.args.acting_role_id
            );
        }
    }

    // Log the lock being removed for debugging
    if lock_to_remove_start + lock_size <= remaining_data.len() {
        // Zero-copy: cast the raw bytes directly to a reference
        let lock = unsafe {
            &*(remaining_data[lock_to_remove_start..lock_to_remove_end].as_ptr()
                as *const AuthorizationLock)
        };
    }

    // Shift all locks after the removed lock down by one position
    if lock_index < total_locks - 1 {
        let locks_after_count = total_locks - lock_index - 1;
        let move_size = locks_after_count * lock_size;

        // Safety check: ensure we don't go out of bounds
        if locks_after_end <= remaining_data.len()
            && lock_to_remove_start + move_size <= remaining_data.len()
        {
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

    Ok(())
}

/// Proactively removes expired authorization locks that are beyond the cleanup threshold.
/// This function can be called during SignV2 execution to reclaim space.
///
/// # Arguments
/// * `swig_account_data` - Mutable reference to the swig account data
/// * `current_slot` - Current slot number
/// * `max_removals` - Maximum number of expired locks to remove in one call (to limit compute)
///
/// # Returns
/// * `Result<usize, ProgramError>` - Number of locks removed, or error
pub fn cleanup_expired_authorization_locks(
    swig_account_data: &mut [u8],
    current_slot: u64,
    max_removals: usize,
) -> Result<usize, ProgramError> {
    if swig_account_data.len() < Swig::LEN {
        return Ok(0);
    }

    let (swig_header, remaining_data) = swig_account_data.split_at_mut(Swig::LEN);
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };

    if swig.authorization_locks == 0 {
        return Ok(0);
    }

    // Find the end of roles data to determine where authorization locks start
    let mut roles_end = 0;
    let mut cursor = 0;
    for _i in 0..swig.roles {
        if cursor + Position::LEN > remaining_data.len() {
            return Err(SwigStateError::InvalidRoleData.into());
        }
        let position =
            unsafe { Position::load_unchecked(&remaining_data[cursor..cursor + Position::LEN])? };
        cursor = position.boundary() as usize;
        roles_end = cursor;
    }

    let auth_locks_start = roles_end;
    let lock_size = AuthorizationLock::LEN;
    let mut total_locks = swig.authorization_locks as usize;
    let mut removals = 0;
    let cleanup_threshold = current_slot.saturating_sub(EXPIRED_LOCK_CLEANUP_THRESHOLD_SLOTS);

    // Iterate backwards through locks to remove expired ones
    // Going backwards makes removal easier as we don't need to adjust index
    let mut lock_index = total_locks;
    while lock_index > 0 && removals < max_removals {
        lock_index -= 1;

        let lock_start = auth_locks_start + (lock_index * lock_size);
        let lock_end = lock_start + lock_size;

        if lock_end > remaining_data.len() {
            break;
        }

        // Check if this lock is expired beyond threshold
        let lock = unsafe {
            &*(remaining_data[lock_start..lock_end].as_ptr() as *const AuthorizationLock)
        };

        if lock.expiry_slot < cleanup_threshold {
            // Remove this expired lock by shifting all locks after it down
            if lock_index < total_locks - 1 {
                let locks_after_count = total_locks - lock_index - 1;
                let move_size = locks_after_count * lock_size;
                let source_start = lock_end;
                let source_end = auth_locks_start + (total_locks * lock_size);

                if source_end <= remaining_data.len()
                    && lock_start + move_size <= remaining_data.len()
                {
                    remaining_data.copy_within(source_start..source_end, lock_start);
                }
            }

            total_locks -= 1;
            removals += 1;

            msg!(
                "Proactively cleaned up expired authorization lock: role_id={}, expired at slot {}, current slot {}",
                lock.role_id,
                lock.expiry_slot,
                current_slot
            );
        }
    }

    // Update the authorization locks count
    if removals > 0 {
        let (swig_header, _) = swig_account_data.split_at_mut(Swig::LEN);
        let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
        swig.authorization_locks = total_locks as u16;
    }

    Ok(removals)
}
