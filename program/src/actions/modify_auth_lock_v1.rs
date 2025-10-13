/// Module for modifying authorization locks for an existing authority.
extern crate alloc;
/// This module implements the functionality to add, remove, or update authorization locks
/// for authorities that have the ManageAuthorizationLocks permission.
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use swig_assertions::{check_bytes_match, check_self_owned};
use swig_state::{
    action::{
        all::All,
        authorization_lock::{AuthorizationLock, AuthorizationLockCache},
        manage_auth_lock::ManageAuthorizationLocks,
        manage_authority::ManageAuthority,
        Action, Actionable, Permission,
    },
    role::{Position, Role},
    swig::Swig,
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, ModifyAuthLockV1Accounts},
        SwigInstruction,
    },
};

/// Enum representing different modification operations for authorization locks.
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum AuthLockOperation {
    /// Add a new authorization lock
    Add {
        mint: [u8; 32],
        amount: u64,
        expires_at: u64,
    } = 0,
    /// Remove an existing authorization lock by index
    Remove { mint: [u8; 32] } = 1,
    /// Update an existing authorization lock by index
    Update {
        mint: [u8; 32],
        new_amount: u64,
        new_expires_at: u64,
    } = 2,
}

impl AuthLockOperation {
    /// Creates an AuthLockOperation from the operation byte and associated data.
    ///
    /// # Arguments
    /// * `operation_byte` - The operation type (0=Add, 1=Remove, 2=Update)
    /// * `data` - The data payload containing the associated data for Remove/Update operations
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - The parsed operation or error
    pub fn from_operation_and_data(operation_byte: u8, data: &[u8]) -> Result<Self, ProgramError> {
        match operation_byte {
            0 => {
                if data.len() < 32 + 8 + 8 {
                    return Err(SwigError::InvalidAuthorizationLockDataLength.into());
                }
                let mut mint = [0u8; 32];
                mint.copy_from_slice(&data[..32]);
                let amount = u64::from_le_bytes(data[32..40].try_into().unwrap());
                let expires_at = u64::from_le_bytes(data[40..48].try_into().unwrap());
                Ok(AuthLockOperation::Add {
                    mint,
                    amount,
                    expires_at,
                })
            },
            1 => {
                if data.len() < 32 {
                    return Err(SwigError::InvalidAuthorizationLockDataLength.into());
                }
                let mut mint = [0u8; 32];
                mint.copy_from_slice(&data[..32]);
                Ok(AuthLockOperation::Remove { mint })
            },
            2 => {
                if data.len() < 32 + 8 + 8 {
                    return Err(SwigError::InvalidAuthorizationLockDataLength.into());
                }
                let mut mint = [0u8; 32];
                mint.copy_from_slice(&data[..32]);
                let new_amount = u64::from_le_bytes(data[32..40].try_into().unwrap());
                let new_expires_at = u64::from_le_bytes(data[40..48].try_into().unwrap());
                Ok(AuthLockOperation::Update {
                    mint,
                    new_amount,
                    new_expires_at,
                })
            },
            _ => Err(SwigError::InvalidOperation.into()),
        }
    }
}

/// Arguments for modifying authorization locks for an authority.
///
/// # Fields
/// * `instruction` - The instruction type identifier
/// * `operation` - The operation to perform (0=Add, 1=Remove, 2=Update)
/// * `_padding` - Padding bytes for alignment
/// * `role_id` - ID of the role modifying the locks
#[repr(C, align(8))]
#[derive(Debug)]
pub struct ModifyAuthLockV1Args {
    pub instruction: SwigInstruction,
    pub operation: u8,
    _padding: [u8; 3],
    pub role_id: u32,
}

impl Transmutable for ModifyAuthLockV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl ModifyAuthLockV1Args {
    /// Creates a new instance of ModifyAuthLockV1Args for adding a lock.
    ///
    /// # Arguments
    /// * `role_id` - ID of the role adding the lock
    pub fn new_add(role_id: u32) -> Self {
        Self {
            instruction: SwigInstruction::ModifyAuthLockV1,
            operation: 0, // AuthLockOperation::Add
            _padding: [0; 3],
            role_id,
        }
    }

    /// Creates a new instance of ModifyAuthLockV1Args for removing a lock.
    ///
    /// # Arguments
    /// * `role_id` - ID of the role removing the lock
    pub fn new_remove(role_id: u32) -> Self {
        Self {
            instruction: SwigInstruction::ModifyAuthLockV1,
            operation: 1, // AuthLockOperation::Remove
            _padding: [0; 3],
            role_id,
        }
    }

    /// Creates a new instance of ModifyAuthLockV1Args for updating a lock.
    ///
    /// # Arguments
    /// * `role_id` - ID of the role updating the lock
    pub fn new_update(role_id: u32) -> Self {
        Self {
            instruction: SwigInstruction::ModifyAuthLockV1,
            operation: 2, // AuthLockOperation::Update
            _padding: [0; 3],
            role_id,
        }
    }
}

impl IntoBytes for ModifyAuthLockV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Struct representing the complete modify auth lock instruction data.
///
/// # Fields
/// * `args` - The modify auth lock arguments
/// * `operation` - The parsed operation with associated data
/// * `data_payload` - Raw data payload
/// * `authority_payload` - Authority-specific payload data
/// * `lock_data` - Authorization lock data (for Add/Update operations)
pub struct ModifyAuthLockV1<'a> {
    pub args: &'a ModifyAuthLockV1Args,
    pub operation: AuthLockOperation,
    data_payload: &'a [u8],
    authority_payload: &'a [u8],
    lock_data: &'a [u8],
}

impl<'a> ModifyAuthLockV1<'a> {
    /// Parses the instruction data bytes into a ModifyAuthLockV1 instance.
    ///
    /// # Arguments
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < ModifyAuthLockV1Args::LEN {
            return Err(SwigError::InvalidInstructionDataTooShort.into());
        }

        let (inst, rest) = data.split_at(ModifyAuthLockV1Args::LEN);
        let args = unsafe { ModifyAuthLockV1Args::load_unchecked(inst)? };

        // Parse the operation with its associated data
        let operation = match args.operation {
            0 => {
                // For Add operation, extract mint, amount, and expires_at
                if rest.len() < 32 + 8 + 8 {
                    return Err(SwigError::InvalidAuthorizationLockDataLength.into());
                }
                let mut mint = [0u8; 32];
                mint.copy_from_slice(&rest[..32]);
                let amount = u64::from_le_bytes(rest[32..40].try_into().unwrap());
                let expires_at = u64::from_le_bytes(rest[40..48].try_into().unwrap());
                AuthLockOperation::Add {
                    mint,
                    amount,
                    expires_at,
                }
            },
            1 => {
                // For Remove operation, extract mint
                if rest.len() < 32 {
                    return Err(SwigError::InvalidAuthorizationLockDataLength.into());
                }
                let mut mint = [0u8; 32];
                mint.copy_from_slice(&rest[..32]);
                AuthLockOperation::Remove { mint }
            },
            2 => {
                // For Update operation, extract mint, new_amount, and new_expires_at
                if rest.len() < 32 + 8 + 8 {
                    return Err(SwigError::InvalidAuthorizationLockDataLength.into());
                }
                let mut mint = [0u8; 32];
                mint.copy_from_slice(&rest[..32]);
                let new_amount = u64::from_le_bytes(rest[32..40].try_into().unwrap());
                let new_expires_at = u64::from_le_bytes(rest[40..48].try_into().unwrap());
                AuthLockOperation::Update {
                    mint,
                    new_amount,
                    new_expires_at,
                }
            },
            _ => return Err(SwigError::InvalidOperation.into()),
        };

        let (lock_payload, authority_payload) = match operation {
            AuthLockOperation::Add { .. } => {
                // For Add, the mint, amount, and expires_at data is already consumed
                let remaining = &rest[48..];
                (remaining, remaining)
            },
            AuthLockOperation::Remove { .. } => {
                // For Remove, the mint data is already consumed
                let remaining = &rest[32..];
                (remaining, remaining)
            },
            AuthLockOperation::Update { .. } => {
                // For Update, the mint, amount, and expires_at data is already consumed
                let remaining = &rest[48..];
                (remaining, remaining)
            },
        };

        // Calculate the actual data payload size based on operation
        let data_payload_size = ModifyAuthLockV1Args::LEN
            + match operation {
                AuthLockOperation::Add { .. } => 48,
                AuthLockOperation::Remove { .. } => 32,
                AuthLockOperation::Update { .. } => 48,
            };

        Ok(Self {
            args,
            operation,
            lock_data: lock_payload,
            authority_payload,
            data_payload: &data[..data_payload_size.min(data.len())],
        })
    }
}

/// Modifies authorization locks for an existing authority.
///
/// This function handles the complete flow of modifying authorization locks:
/// 1. Validates the acting role's permissions (must have All or ManageAuthorizationLocks)
/// 2. Authenticates the request
/// 3. Verifies the target authority exists and has ManageAuthorizationLocks permission
/// 4. Performs the requested operation (Add/Remove/Update) on AuthorizationLock actions
/// 5. Handles account reallocation if needed
///
/// # Arguments
/// * `ctx` - The account context for modifying auth locks
/// * `modify_lock` - Raw modify auth lock instruction data
/// * `all_accounts` - All accounts involved in the operation
///
/// # Returns
/// * `ProgramResult` - Success or error status
pub fn modify_auth_lock_v1(
    ctx: Context<ModifyAuthLockV1Accounts>,
    modify_lock: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_bytes_match(
        ctx.accounts.system_program.key(),
        &pinocchio_system::ID,
        32,
        SwigError::InvalidSystemProgram,
    )?;

    let modify_auth_lock_v1 =
        ModifyAuthLockV1::from_instruction_bytes(modify_lock).map_err(|e| {
            msg!("ModifyAuthLockV1 Args Error: {:?}", e);
            ProgramError::InvalidInstructionData
        })?;

    let operation = modify_auth_lock_v1.operation;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let swig_data_len = swig_account_data.len();

    if swig_account_data[0] != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };

    let (swig_roles, _) =
        unsafe { swig_roles.split_at_mut_unchecked(swig.roles_boundary as usize) };

    // Get and validate acting role
    let acting_role = Swig::get_mut_role(modify_auth_lock_v1.args.role_id, swig_roles)?;
    if acting_role.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let acting_role = acting_role.unwrap();

    // Authenticate the caller
    let clock = Clock::get()?;
    let slot = clock.slot;

    if acting_role.authority.session_based() {
        acting_role.authority.authenticate_session(
            all_accounts,
            modify_auth_lock_v1.authority_payload,
            modify_auth_lock_v1.data_payload,
            slot,
        )?;
    } else {
        acting_role.authority.authenticate(
            all_accounts,
            modify_auth_lock_v1.authority_payload,
            modify_auth_lock_v1.data_payload,
            slot,
        )?;
    }

    // Check permissions - must have All or ManageAuthorizationLocks permission
    let all = acting_role.get_action::<All>(&[])?;
    let manage_auth_lock = acting_role.get_action::<ManageAuthorizationLocks>(&[])?;

    if all.is_none() && manage_auth_lock.is_none() {
        return Err(SwigAuthenticateError::PermissionDeniedToManageAuthorizationLocks.into());
    }

    // Verify the target role has ManageAuthorizationLocks permission
    let target_role = Swig::get_mut_role(modify_auth_lock_v1.args.role_id, swig_roles)?;
    if target_role.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let target_role = target_role.unwrap();

    let target_all = target_role.get_action::<All>(&[])?;
    let target_manage_auth_lock = target_role.get_action::<ManageAuthorizationLocks>(&[])?;

    if target_all.is_none() && target_manage_auth_lock.is_none() {
        return Err(SwigError::TargetAuthorityDoesNotHaveManageAuthorizationLocksPermission.into());
    }

    // Find the role's actions offset and size
    let (actions_offset, current_actions_size) = {
        let mut cursor = 0;
        let mut found = false;
        let mut act_offset = 0;
        let mut current_size = 0;

        for _i in 0..swig.roles {
            let position =
                unsafe { Position::load_unchecked(&swig_roles[cursor..cursor + Position::LEN])? };

            if position.id() == modify_auth_lock_v1.args.role_id {
                found = true;
                act_offset = cursor + Position::LEN + position.authority_length() as usize;
                current_size = position.boundary() as usize - act_offset;
                break;
            }
            cursor = position.boundary() as usize;
        }

        if !found {
            return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
        }

        (act_offset, current_size)
    };

    // Find whether an AuthorizationLock for the given mint exists in this role (store in Option)
    let existing_lock_info = match operation {
        AuthLockOperation::Add { mint, .. } => {
            find_auth_lock_in_role(swig_roles, actions_offset, current_actions_size, &mint)?
        },
        AuthLockOperation::Remove { mint } => {
            find_auth_lock_in_role(swig_roles, actions_offset, current_actions_size, &mint)?
        },
        AuthLockOperation::Update { mint, .. } => {
            find_auth_lock_in_role(swig_roles, actions_offset, current_actions_size, &mint)?
        },
    };

    // Perform the requested operation
    match operation {
        AuthLockOperation::Add {
            mint,
            amount,
            expires_at,
        } => {
            if existing_lock_info.is_some() {
                return Err(SwigError::AuthorizationLockAlreadyExists.into());
            }

            // Grow and add new action; this helper handles resize, rent, boundaries, and write
            add_authorization_lock_action(
                &ctx,
                modify_auth_lock_v1,
                swig_roles,
                actions_offset,
                current_actions_size,
                swig_data_len,
                mint,
                amount,
                expires_at,
            )?;
            // Update cache incrementally
            add_to_cache(&ctx, mint)?;
        },
        AuthLockOperation::Remove { mint } => {
            let (target_offset, target_size) = match existing_lock_info {
                Some(v) => v,
                None => return Err(SwigError::AuthorizationLockNotFound.into()),
            };

            remove_authorization_lock_action_swap(
                &ctx,
                modify_auth_lock_v1,
                swig_roles,
                actions_offset,
                current_actions_size,
                swig_data_len,
                target_offset,
                target_size,
            )?;

            let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
            let (swig_header, swig_roles) =
                unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
            let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
            let (swig_roles, auth_lock_cache) =
                unsafe { swig_roles.split_at_mut_unchecked(swig.roles_boundary as usize) };
            msg!("auth_lock_cache: {:?}", auth_lock_cache.len());

            // Rebuild cache to ensure count and entries align after shrink
            rebuild_authorization_lock_cache(&ctx)?;

            // As an additional safeguard, recompute count from tail zeros
            // to ensure header reflects actual number of populated cache entries.
            let (swig2, _roles2, tail2) = get_roles_and_tail(&ctx)?;
            let entry_size = 32 + 8 + 8;
            let mut actual = 0usize;
            // Scan contiguous populated entries (non-all-zero 48-byte blocks)
            while (actual + 1) * entry_size <= tail2.len() {
                let base = actual * entry_size;
                let block = &tail2[base..base + entry_size];
                if block.iter().all(|b| *b == 0) {
                    break;
                }
                actual += 1;
            }
            swig2.auth_lock_count = actual as u32;

            let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
            let (swig_header, swig_roles) =
                unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
            let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
            let (swig_roles, auth_lock_cache) =
                unsafe { swig_roles.split_at_mut_unchecked(swig.roles_boundary as usize) };
            msg!("auth_lock_cache: {:?}", auth_lock_cache.len());
        },
        AuthLockOperation::Update {
            mint,
            new_amount,
            new_expires_at,
        } => {
            if existing_lock_info.is_none() {
                return Err(SwigError::AuthorizationLockNotFound.into());
            }

            update_authorization_lock_action(
                modify_auth_lock_v1,
                swig_roles,
                actions_offset,
                current_actions_size,
                mint,
                new_amount,
                new_expires_at,
            )?;
            // Update cache incrementally
            update_cache(&ctx, mint)?;
        },
    }

    Ok(())
}

/// Rebuilds the AuthorizationLockCache section after roles in the Swig account.
/// Layout: [Swig header][roles (roles_boundary)][auth lock cache...]
fn rebuild_authorization_lock_cache(ctx: &Context<ModifyAuthLockV1Accounts>) -> ProgramResult {
    // Gather fresh views
    let (swig, roles_bytes, tail) = get_roles_and_tail(ctx)?;

    // Walk roles and aggregate by mint: (total_amount, earliest_expires_at)
    let mut aggregates: alloc::vec::Vec<([u8; 32], u64, u64)> = alloc::vec::Vec::new();

    let mut cursor_roles: usize = 0;
    while cursor_roles < roles_bytes.len() {
        if cursor_roles + Position::LEN > roles_bytes.len() {
            break;
        }
        let pos = unsafe {
            Position::load_unchecked(&roles_bytes[cursor_roles..cursor_roles + Position::LEN])?
        };
        let auth_len = pos.authority_length() as usize;
        let start = cursor_roles + Position::LEN + auth_len;
        let end = pos.boundary() as usize;

        let mut c = start;
        while c < end {
            if c + Action::LEN > end {
                break;
            }
            let hdr = unsafe { Action::load_unchecked(&roles_bytes[c..c + Action::LEN])? };
            let len = hdr.length() as usize;
            let cont_start = c + Action::LEN;
            let cont_end = cont_start + len;
            if cont_end > end {
                break;
            }

            if hdr.permission()? == Permission::AuthorizationLock && len >= AuthorizationLock::LEN {
                let lock = unsafe {
                    AuthorizationLock::load_unchecked(
                        &roles_bytes[cont_start..cont_start + AuthorizationLock::LEN],
                    )?
                };
                // Merge into aggregates
                if let Some(entry) = aggregates.iter_mut().find(|e| e.0 == lock.mint) {
                    // total
                    entry.1 = entry.1.saturating_add(lock.amount);
                    // earliest
                    if lock.expires_at < entry.2 {
                        entry.2 = lock.expires_at;
                    }
                } else {
                    aggregates.push((lock.mint, lock.amount, lock.expires_at));
                }
            }

            c = cont_end;
        }

        cursor_roles = pos.boundary() as usize;
    }

    // Write aggregates to tail
    let entry_size = 32 + 8 + 8;
    let needed = aggregates.len();
    if needed > 0 {
        ensure_tail_capacity(ctx, needed)?;
        // Re-borrow in case of resize
        let (_swig2, _roles2, tail2) = get_roles_and_tail(ctx)?;
        // Write entries
        for (i, (mint, total, earliest)) in aggregates.iter().enumerate() {
            let base = i * entry_size;
            tail2[base..base + 32].copy_from_slice(mint);
            tail2[base + 32..base + 40].copy_from_slice(&total.to_le_bytes());
            tail2[base + 40..base + 48].copy_from_slice(&earliest.to_le_bytes());
        }
        // Zero out any leftover old cache bytes beyond new count
        let zero_start = needed * entry_size;
        if zero_start < tail2.len() {
            tail2[zero_start..].fill(0);
        }
        swig.auth_lock_count = needed as u32;
    } else {
        // No entries remain; zero out existing tail and set count to 0
        tail.fill(0);
        swig.auth_lock_count = 0;
    }

    Ok(())
}

// --- Cache helpers (zero-copy, append/update/remove with capacity checks)

fn get_roles_and_tail<'a>(
    ctx: &'a Context<ModifyAuthLockV1Accounts>,
) -> Result<(&'a mut Swig, &'a mut [u8], &'a mut [u8]), ProgramError> {
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (swig_header, rest) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
    let (roles_bytes, tail) = unsafe { rest.split_at_mut_unchecked(swig.roles_boundary as usize) };
    Ok((swig, roles_bytes, tail))
}

fn ensure_tail_capacity(
    ctx: &Context<ModifyAuthLockV1Accounts>,
    needed_entries: usize,
) -> ProgramResult {
    let current_total = unsafe { ctx.accounts.swig.borrow_data_unchecked().len() };
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (swig_header, rest) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
    let (_roles, _tail) = unsafe { rest.split_at_mut_unchecked(swig.roles_boundary as usize) };
    let needed_total = Swig::LEN + swig.roles_boundary as usize + needed_entries * (32 + 8 + 8);
    if needed_total > current_total {
        let aligned_size =
            core::alloc::Layout::from_size_align(needed_total, core::mem::size_of::<u64>())
                .map_err(|_| SwigError::InvalidAlignment)?
                .pad_to_align()
                .size();
        let cost = Rent::get()?.minimum_balance(aligned_size);
        let current_lamports = unsafe { *ctx.accounts.swig.borrow_lamports_unchecked() };
        let additional_cost = cost.saturating_sub(current_lamports);
        if additional_cost > 0 {
            Transfer {
                from: ctx.accounts.payer,
                to: ctx.accounts.swig,
                lamports: additional_cost,
            }
            .invoke()?;
        }
        ctx.accounts.swig.resize(aligned_size)?;
    }
    Ok(())
}

fn compute_sum_and_earliest_for_mint(roles_bytes: &[u8], mint: &[u8; 32]) -> (u64, u64, bool) {
    let mut cursor_roles: usize = 0;
    let mut sum: u64 = 0;
    let mut earliest: u64 = u64::MAX;
    let mut found = false;
    while cursor_roles < roles_bytes.len() {
        if cursor_roles + Position::LEN > roles_bytes.len() {
            break;
        }
        let pos = unsafe {
            Position::load_unchecked(&roles_bytes[cursor_roles..cursor_roles + Position::LEN])
                .unwrap()
        };
        let auth_len = pos.authority_length() as usize;
        let start = cursor_roles + Position::LEN + auth_len;
        let end = pos.boundary() as usize;
        let mut c = start;
        while c < end {
            if c + Action::LEN > end {
                break;
            }
            let hdr = unsafe { Action::load_unchecked(&roles_bytes[c..c + Action::LEN]).unwrap() };
            let len = hdr.length() as usize;
            let cont_start = c + Action::LEN;
            let cont_end = cont_start + len;
            if cont_end > end {
                break;
            }
            if hdr.permission().unwrap() == Permission::AuthorizationLock
                && len >= AuthorizationLock::LEN
            {
                let lock = unsafe {
                    AuthorizationLock::load_unchecked(
                        &roles_bytes[cont_start..cont_start + AuthorizationLock::LEN],
                    )
                    .unwrap()
                };
                if &lock.mint == mint {
                    sum = sum.saturating_add(lock.amount);
                    if lock.expires_at < earliest {
                        earliest = lock.expires_at;
                    }
                    found = true;
                }
            }
            c = cont_end;
        }
        cursor_roles = pos.boundary() as usize;
    }
    (sum, earliest, found)
}

fn find_cache_entry_index(tail: &[u8], count: usize, mint: &[u8; 32]) -> Option<usize> {
    let mut i = 0usize;
    while i < count {
        let base = i * (32 + 8 + 8);
        if &tail[base..base + 32] == mint {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn add_to_cache(ctx: &Context<ModifyAuthLockV1Accounts>, mint: [u8; 32]) -> ProgramResult {
    let (swig, roles_bytes, tail) = get_roles_and_tail(ctx)?;
    let (sum, earliest, found_in_roles) = compute_sum_and_earliest_for_mint(roles_bytes, &mint);
    if !found_in_roles {
        return Ok(());
    }
    let count = swig.auth_lock_count as usize;
    if let Some(idx) = find_cache_entry_index(tail, count, &mint) {
        let base = idx * (32 + 8 + 8);
        tail[base + 32..base + 40].copy_from_slice(&sum.to_le_bytes());
        tail[base + 40..base + 48].copy_from_slice(&earliest.to_le_bytes());
    } else {
        ensure_tail_capacity(ctx, count + 1)?;
        // re-borrow after potential resize
        let (swig, _roles2, tail2) = get_roles_and_tail(ctx)?;
        let base = count * (32 + 8 + 8);
        tail2[base..base + 32].copy_from_slice(&mint);
        tail2[base + 32..base + 40].copy_from_slice(&sum.to_le_bytes());
        tail2[base + 40..base + 48].copy_from_slice(&earliest.to_le_bytes());
        swig.auth_lock_count = (count + 1) as u32;
    }
    Ok(())
}

fn remove_from_cache(ctx: &Context<ModifyAuthLockV1Accounts>, mint: [u8; 32]) -> ProgramResult {
    let (swig, roles_bytes, tail) = get_roles_and_tail(ctx)?;
    let (sum, earliest, found_in_roles) = compute_sum_and_earliest_for_mint(roles_bytes, &mint);
    msg!(
        "sum: {:?}, earliest: {:?}, found_in_roles: {:?}",
        sum,
        earliest,
        found_in_roles
    );
    let count = swig.auth_lock_count as usize;
    if let Some(idx) = find_cache_entry_index(tail, count, &mint) {
        msg!("idx: {:?}", idx);
        if !found_in_roles || sum == 0 {
            // remove entry by swapping with last
            if count > 0 && idx != count - 1 {
                msg!("count: {:?}, idx: {:?}", count, idx);
                let dst = idx * (32 + 8 + 8);
                let src = (count - 1) * (32 + 8 + 8);
                let len = 32 + 8 + 8;
                tail.copy_within(src..src + len, dst);
            }
            // zero last (optional)
            msg!("count: {:?}", count);
            let base_last = (count - 1) * (32 + 8 + 8);
            tail[base_last..base_last + 32 + 8 + 8].fill(0);
            swig.auth_lock_count = (count - 1) as u32;
        } else {
            // update totals
            msg!("idx: {:?}", idx);
            let base = idx * (32 + 8 + 8);
            tail[base + 32..base + 40].copy_from_slice(&sum.to_le_bytes());
            tail[base + 40..base + 48].copy_from_slice(&earliest.to_le_bytes());
        }
    }
    Ok(())
}

fn update_cache(ctx: &Context<ModifyAuthLockV1Accounts>, mint: [u8; 32]) -> ProgramResult {
    let (swig, roles_bytes, tail) = get_roles_and_tail(ctx)?;
    let (sum, earliest, found_in_roles) = compute_sum_and_earliest_for_mint(roles_bytes, &mint);
    let count = swig.auth_lock_count as usize;
    if let Some(idx) = find_cache_entry_index(tail, count, &mint) {
        if !found_in_roles || sum == 0 {
            // remove entry
            if count > 0 && idx != count - 1 {
                let dst = idx * (32 + 8 + 8);
                let src = (count - 1) * (32 + 8 + 8);
                let len = 32 + 8 + 8;
                tail.copy_within(src..src + len, dst);
            }
            let base_last = (count - 1) * (32 + 8 + 8);
            tail[base_last..base_last + 32 + 8 + 8].fill(0);
            swig.auth_lock_count = (count - 1) as u32;
        } else {
            // update existing
            let base = idx * (32 + 8 + 8);
            tail[base + 32..base + 40].copy_from_slice(&sum.to_le_bytes());
            tail[base + 40..base + 48].copy_from_slice(&earliest.to_le_bytes());
        }
    } else if found_in_roles && sum > 0 {
        // append new entry
        ensure_tail_capacity(ctx, count + 1)?;
        let (swig2, _roles2, tail2) = get_roles_and_tail(ctx)?;
        let base = count * (32 + 8 + 8);
        tail2[base..base + 32].copy_from_slice(&mint);
        tail2[base + 32..base + 40].copy_from_slice(&sum.to_le_bytes());
        tail2[base + 40..base + 48].copy_from_slice(&earliest.to_le_bytes());
        swig2.auth_lock_count = (count + 1) as u32;
    }
    Ok(())
}

/// Returns the offset and total size of the AuthorizationLock action for `mint` within
/// the role's actions, if present.
fn find_auth_lock_in_role(
    swig_roles: &[u8],
    actions_offset: usize,
    current_actions_size: usize,
    mint: &[u8; 32],
) -> Result<Option<(usize, usize)>, ProgramError> {
    let mut cursor = actions_offset;
    while cursor < actions_offset + current_actions_size {
        if cursor + Action::LEN > actions_offset + current_actions_size {
            break;
        }

        let action_header =
            unsafe { Action::load_unchecked(&swig_roles[cursor..cursor + Action::LEN])? };
        let action_len = action_header.length() as usize;
        let total_action_size = Action::LEN + action_len;

        if cursor + total_action_size > actions_offset + current_actions_size {
            break;
        }

        if action_header.permission()? == Permission::AuthorizationLock {
            let lock_data = &swig_roles[cursor + Action::LEN..cursor + total_action_size];
            if lock_data.len() >= AuthorizationLock::LEN {
                let existing_lock = unsafe {
                    AuthorizationLock::load_unchecked(&lock_data[..AuthorizationLock::LEN])?
                };
                if &existing_lock.mint == mint {
                    return Ok(Some((cursor, total_action_size)));
                }
            }
        }

        cursor += total_action_size;
    }
    Ok(None)
}

/// Removes an AuthorizationLock action by swapping the target with the last action within
/// the role's actions, then shrinking the account and updating boundaries.
fn remove_authorization_lock_action_swap(
    ctx: &Context<ModifyAuthLockV1Accounts>,
    modify_auth_lock_v1: ModifyAuthLockV1,
    swig_roles: &mut [u8],
    actions_offset: usize,
    current_actions_size: usize,
    swig_data_len: usize,
    target_offset: usize,
    target_size: usize,
) -> ProgramResult {
    // Find the last action in this role's action list
    let mut cursor = actions_offset;
    let mut last_offset = actions_offset;
    let mut last_size = 0usize;
    while cursor < actions_offset + current_actions_size {
        if cursor + Action::LEN > actions_offset + current_actions_size {
            break;
        }
        let action_header =
            unsafe { Action::load_unchecked(&swig_roles[cursor..cursor + Action::LEN])? };
        let action_len = action_header.length() as usize;
        let total_action_size = Action::LEN + action_len;
        if cursor + total_action_size > actions_offset + current_actions_size {
            break;
        }
        last_offset = cursor;
        last_size = total_action_size;
        cursor += total_action_size;
    }

    if last_size == 0 {
        return Err(SwigError::AuthorizationLockNotFound.into());
    }

    // If the target is not the last action, swap by copying last over target
    if target_offset != last_offset {
        // Copy last action bytes over the target slot
        let src = last_offset;
        let dst = target_offset;
        // Ensure sizes match when overwriting; if not, only safe when equal sizes.
        // AuthorizationLock actions share the same length, so this is safe here.
        if last_size != target_size {
            return Err(SwigError::StateError.into());
        }
        swig_roles.copy_within(src..src + last_size, dst);

        // Fix the moved action's boundary header to reflect its new position
        let new_boundary = (dst - actions_offset + last_size) as u32;
        swig_roles[dst + 4..dst + 8].copy_from_slice(&new_boundary.to_le_bytes());
    }

    // Now remove the tail (the last action) by shifting anything after it left by last_size
    let remaining_start = last_offset + last_size;
    let remaining_end = actions_offset + current_actions_size;
    if remaining_start < remaining_end {
        let shift_size = remaining_end - remaining_start;
        // Shift down to overwrite last action region
        for i in 0..shift_size {
            swig_roles[last_offset + i] = swig_roles[remaining_start + i];
        }
    }

    // Shrink account and update boundaries
    let new_size = swig_data_len - last_size;
    let aligned_size = core::alloc::Layout::from_size_align(new_size, core::mem::size_of::<u64>())
        .map_err(|_| SwigError::InvalidAlignment)?
        .pad_to_align()
        .size();

    ctx.accounts.swig.resize(aligned_size)?;

    // Re-borrow and update positions' boundaries
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
    // Recompute roles_end from positions to avoid stale boundary and then subtract removed size
    let mut roles_end: usize = 0;
    let mut r_cursor: usize = 0;
    for _i in 0..swig.roles {
        if r_cursor + Position::LEN > swig_roles.len() {
            return Err(SwigError::StateError.into());
        }
        let position =
            unsafe { Position::load_unchecked(&swig_roles[r_cursor..r_cursor + Position::LEN])? };
        r_cursor = position.boundary() as usize;
        roles_end = r_cursor;
    }
    let new_roles_end = roles_end.saturating_sub(last_size);
    // Shift the authorization lock cache left by last_size to keep it immediately after roles
    // Cache layout starts at roles_end and contains auth_lock_count entries of 48 bytes each
    let cache_entry_size = 32 + 8 + 8;
    let cache_len_bytes = (swig.auth_lock_count as usize) * cache_entry_size;
    if roles_end + cache_len_bytes <= swig_roles.len()
        && new_roles_end + cache_len_bytes <= swig_roles.len()
    {
        // Move the whole cache block left by last_size bytes
        swig_roles.copy_within(roles_end..roles_end + cache_len_bytes, new_roles_end);
        // Optionally zero the trailing bytes that are now unused (not strictly necessary)
        let trailing_start = new_roles_end + cache_len_bytes;
        let trailing_end = core::cmp::min(roles_end + cache_len_bytes, swig_roles.len());
        if trailing_start < trailing_end {
            swig_roles[trailing_start..trailing_end].fill(0);
        }
    }
    // Update roles boundary after moving cache
    swig.roles_boundary = new_roles_end as u32;
    let (swig_roles, _) = unsafe { swig_roles.split_at_mut_unchecked(new_roles_end) };

    let mut update_cursor = 0;
    for _i in 0..swig.roles {
        if update_cursor + Position::LEN > swig_roles.len() {
            break;
        }
        let position = unsafe {
            Position::load_mut_unchecked(
                &mut swig_roles[update_cursor..update_cursor + Position::LEN],
            )?
        };

        // For roles after the modified region, reduce their boundary
        if position.boundary() as usize > actions_offset + current_actions_size {
            position.boundary = (position.boundary() as u32 - last_size as u32) as u32;
        }

        // Update the boundary for the role we're modifying
        if position.id() == modify_auth_lock_v1.args.role_id {
            position.boundary = (position.boundary() as u32 - last_size as u32) as u32;
        }

        update_cursor = position.boundary() as usize;
    }

    Ok(())
}

/// Handles adding a new AuthorizationLock action to the role.
fn add_authorization_lock_action(
    ctx: &Context<ModifyAuthLockV1Accounts>,
    modify_auth_lock_v1: ModifyAuthLockV1,
    swig_roles: &mut [u8],
    actions_offset: usize,
    current_actions_size: usize,
    swig_data_len: usize,
    mint: [u8; 32],
    amount: u64,
    expires_at: u64,
) -> ProgramResult {
    // Create the new AuthorizationLock action
    let new_lock = AuthorizationLock {
        mint,
        amount,
        expires_at,
    };

    // Check if a lock already exists for the same mint
    let mut cursor = actions_offset;
    while cursor < actions_offset + current_actions_size {
        if cursor + Action::LEN > actions_offset + current_actions_size {
            break;
        }

        let action_header =
            unsafe { Action::load_unchecked(&swig_roles[cursor..cursor + Action::LEN])? };
        let action_len = action_header.length() as usize;
        let total_action_size = Action::LEN + action_len;

        if cursor + total_action_size > actions_offset + current_actions_size {
            break;
        }

        // Check if this is an AuthorizationLock action
        if action_header.permission()? == Permission::AuthorizationLock {
            let lock_data = &swig_roles[cursor + Action::LEN..cursor + total_action_size];
            if lock_data.len() >= AuthorizationLock::LEN {
                let existing_lock = unsafe {
                    AuthorizationLock::load_unchecked(&lock_data[..AuthorizationLock::LEN])?
                };

                // Check if the mint matches
                if existing_lock.mint == new_lock.mint {
                    return Err(SwigError::AuthorizationLockAlreadyExists.into());
                }
            }
        }

        cursor += total_action_size;
    }

    // Create action header - we'll set the boundary later
    let action_header = Action::new(
        Permission::AuthorizationLock,
        AuthorizationLock::LEN as u16,
        0, // Will be set correctly later
    );

    let new_action_size = Action::LEN + AuthorizationLock::LEN;
    let size_diff = new_action_size as i64;

    // Handle account reallocation: pre-fund, then resize
    let new_size = (swig_data_len as i64 + size_diff) as usize;
    let aligned_size = core::alloc::Layout::from_size_align(new_size, core::mem::size_of::<u64>())
        .map_err(|_| SwigError::InvalidAlignment)?
        .pad_to_align()
        .size();

    let cost = Rent::get()?.minimum_balance(aligned_size);
    let current_lamports = unsafe { *ctx.accounts.swig.borrow_lamports_unchecked() };
    let additional_cost = cost.saturating_sub(current_lamports);
    if additional_cost > 0 {
        Transfer {
            from: ctx.accounts.payer,
            to: ctx.accounts.swig,
            lamports: additional_cost,
        }
        .invoke()?;
    }
    ctx.accounts.swig.resize(aligned_size)?;

    // Get fresh references to the swig account data after reallocation
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };

    // Recompute roles_end from positions to avoid relying on a stale boundary
    let mut roles_end: usize = 0;
    let mut r_cursor: usize = 0;
    for _i in 0..swig.roles {
        if r_cursor + Position::LEN > swig_roles.len() {
            return Err(SwigError::StateError.into());
        }
        let position =
            unsafe { Position::load_unchecked(&swig_roles[r_cursor..r_cursor + Position::LEN])? };
        r_cursor = position.boundary() as usize;
        roles_end = r_cursor;
    }
    swig.roles_boundary = roles_end as u32;

    // Shift existing data to make room for the new action
    let role_end = roles_end;
    let original_data_len = (swig_data_len as i64 - Swig::LEN as i64) as usize;
    let remaining_data_len = original_data_len - role_end;

    if remaining_data_len > 0 {
        let new_role_end = (role_end as i64 + size_diff) as usize;
        if new_role_end + remaining_data_len <= swig_roles.len() {
            swig_roles.copy_within(role_end..role_end + remaining_data_len, new_role_end);
        } else {
            return Err(SwigError::StateError.into());
        }
    }

    // Update boundaries of all roles after this one
    let mut update_cursor = 0;
    for _i in 0..swig.roles {
        if update_cursor + Position::LEN > swig_roles.len() {
            break;
        }
        let position = unsafe {
            Position::load_mut_unchecked(
                &mut swig_roles[update_cursor..update_cursor + Position::LEN],
            )?
        };

        if position.boundary() as usize > role_end {
            position.boundary = (position.boundary() as i64 + size_diff) as u32;
        }

        // Update the boundary for the role we're modifying
        if position.id() == modify_auth_lock_v1.args.role_id {
            position.boundary = (position.boundary() as i64 + size_diff) as u32;
        }

        update_cursor = position.boundary() as usize;
    }

    // Write the new action at the end of current actions
    let new_action_offset = actions_offset + current_actions_size;
    // Write header then lock data directly
    swig_roles[new_action_offset..new_action_offset + Action::LEN]
        .copy_from_slice(action_header.into_bytes()?);
    swig_roles[new_action_offset + Action::LEN..new_action_offset + new_action_size]
        .copy_from_slice(new_lock.into_bytes()?);

    // Update the action boundary to point to the end of this action
    let next_boundary = (new_action_offset - actions_offset + new_action_size) as u32;
    swig_roles[new_action_offset + 4..new_action_offset + 8]
        .copy_from_slice(&next_boundary.to_le_bytes());

    // Finally, update the global roles boundary to include the newly appended bytes
    swig.roles_boundary = (swig.roles_boundary as i64 + size_diff) as u32;

    Ok(())
}

/// Handles removing an AuthorizationLock action from the role by mint.
fn remove_authorization_lock_action(
    ctx: Context<ModifyAuthLockV1Accounts>,
    modify_auth_lock_v1: ModifyAuthLockV1,
    swig_roles: &mut [u8],
    actions_offset: usize,
    current_actions_size: usize,
    swig_data_len: usize,
    mint: [u8; 32],
) -> ProgramResult {
    // Find the AuthorizationLock action to remove by mint
    let mut cursor = actions_offset;
    let mut action_to_remove_offset = None;
    let mut action_size = 0;

    while cursor < actions_offset + current_actions_size {
        if cursor + Action::LEN > actions_offset + current_actions_size {
            break;
        }

        let action_header =
            unsafe { Action::load_unchecked(&swig_roles[cursor..cursor + Action::LEN])? };
        let action_len = action_header.length() as usize;
        let total_action_size = Action::LEN + action_len;

        if cursor + total_action_size > actions_offset + current_actions_size {
            break;
        }

        // Check if this is an AuthorizationLock action
        if action_header.permission()? == Permission::AuthorizationLock {
            let lock_data = &swig_roles[cursor + Action::LEN..cursor + total_action_size];
            if lock_data.len() >= AuthorizationLock::LEN {
                let existing_lock = unsafe {
                    AuthorizationLock::load_unchecked(&lock_data[..AuthorizationLock::LEN])?
                };

                // Check if the mint matches
                if existing_lock.mint == mint {
                    action_to_remove_offset = Some(cursor);
                    action_size = total_action_size;
                    break;
                }
            }
        }

        cursor += total_action_size;
    }

    let action_offset = match action_to_remove_offset {
        Some(offset) => offset,
        None => return Err(SwigError::AuthorizationLockNotFound.into()),
    };

    // Shift remaining actions to the left to fill the gap
    let remaining_start = action_offset + action_size;
    let remaining_end = actions_offset + current_actions_size;

    if remaining_start < remaining_end {
        let shift_amount = action_size;
        let shift_size = remaining_end - remaining_start;

        // Shift data to the left to fill the gap
        for i in 0..shift_size {
            if i + shift_amount < swig_roles.len()
                && remaining_start + i + shift_amount < swig_roles.len()
            {
                swig_roles[remaining_start + i] = swig_roles[remaining_start + i + shift_amount];
            }
        }
    }

    // Handle account reallocation to free up space
    let new_size = swig_data_len - action_size;
    let aligned_size = core::alloc::Layout::from_size_align(new_size, core::mem::size_of::<u64>())
        .map_err(|_| SwigError::InvalidAlignment)?
        .pad_to_align()
        .size();

    ctx.accounts.swig.resize(aligned_size)?;

    // Get fresh references to the swig account data after reallocation
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };

    let (swig_roles, _) =
        unsafe { swig_roles.split_at_mut_unchecked(swig.roles_boundary as usize) };
    // Update role boundaries
    let mut update_cursor = 0;
    for _i in 0..swig.roles {
        if update_cursor + Position::LEN > swig_roles.len() {
            break;
        }
        let position = unsafe {
            Position::load_mut_unchecked(
                &mut swig_roles[update_cursor..update_cursor + Position::LEN],
            )?
        };

        // Update boundaries for roles that come after the modified role
        if position.boundary() as usize > actions_offset + current_actions_size {
            position.boundary = (position.boundary() as u32 - action_size as u32) as u32;
        }

        // Update the boundary for the role we're modifying
        if position.id() == modify_auth_lock_v1.args.role_id {
            position.boundary = (position.boundary() as u32 - action_size as u32) as u32;
        }

        update_cursor = position.boundary() as usize;
    }

    Ok(())
}

/// Handles updating an existing AuthorizationLock action with new values.
fn update_authorization_lock_action(
    modify_auth_lock_v1: ModifyAuthLockV1,
    swig_roles: &mut [u8],
    actions_offset: usize,
    current_actions_size: usize,
    mint: [u8; 32],
    new_amount: u64,
    new_expires_at: u64,
) -> ProgramResult {
    // Find the AuthorizationLock action to update by mint
    let mut cursor = actions_offset;
    let mut action_to_update_offset = None;

    while cursor < actions_offset + current_actions_size {
        if cursor + Action::LEN > actions_offset + current_actions_size {
            break;
        }

        let action_header =
            unsafe { Action::load_unchecked(&swig_roles[cursor..cursor + Action::LEN])? };
        let action_len = action_header.length() as usize;
        let total_action_size = Action::LEN + action_len;

        if cursor + total_action_size > actions_offset + current_actions_size {
            break;
        }

        // Check if this is an AuthorizationLock action
        if action_header.permission()? == Permission::AuthorizationLock {
            let lock_data = &swig_roles[cursor + Action::LEN..cursor + total_action_size];
            if lock_data.len() >= AuthorizationLock::LEN {
                let existing_lock = unsafe {
                    AuthorizationLock::load_unchecked(&lock_data[..AuthorizationLock::LEN])?
                };

                // Check if the mint matches
                if existing_lock.mint == mint {
                    action_to_update_offset = Some(cursor);
                    break;
                }
            }
        }

        cursor += total_action_size;
    }

    let action_offset = match action_to_update_offset {
        Some(offset) => offset,
        None => return Err(SwigError::AuthorizationLockNotFound.into()),
    };

    // Create the updated lock with the provided data
    let updated_lock = AuthorizationLock {
        mint,
        amount: new_amount,
        expires_at: new_expires_at,
    };

    // Write the updated lock data
    let lock_data_offset = action_offset + Action::LEN;
    swig_roles[lock_data_offset..lock_data_offset + AuthorizationLock::LEN]
        .copy_from_slice(updated_lock.into_bytes()?);

    Ok(())
}
