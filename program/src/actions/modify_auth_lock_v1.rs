/// Module for modifying authorization locks for an existing authority.
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
        all::All, authorization_lock::AuthorizationLock,
        manage_auth_lock::ManageAuthorizationLocks, manage_authority::ManageAuthority, Action,
        Actionable, Permission,
    },
    role::Position,
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

    // Perform the requested operation
    match operation {
        AuthLockOperation::Add {
            mint,
            amount,
            expires_at,
        } => {
            add_authorization_lock_action(
                ctx,
                modify_auth_lock_v1,
                swig_roles,
                actions_offset,
                current_actions_size,
                swig_data_len,
                mint,
                amount,
                expires_at,
            )?;
        },
        AuthLockOperation::Remove { mint } => {
            remove_authorization_lock_action(
                ctx,
                modify_auth_lock_v1,
                swig_roles,
                actions_offset,
                current_actions_size,
                swig_data_len,
                mint,
            )?;
        },
        AuthLockOperation::Update {
            mint,
            new_amount,
            new_expires_at,
        } => {
            update_authorization_lock_action(
                modify_auth_lock_v1,
                swig_roles,
                actions_offset,
                current_actions_size,
                mint,
                new_amount,
                new_expires_at,
            )?;
        },
    }

    Ok(())
}

/// Handles adding a new AuthorizationLock action to the role.
fn add_authorization_lock_action(
    ctx: Context<ModifyAuthLockV1Accounts>,
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

    // Create the new action data
    let mut new_action_data = Vec::new();

    // Create action header - we'll set the boundary later
    let action_header = Action::new(
        Permission::AuthorizationLock,
        AuthorizationLock::LEN as u16,
        0, // Will be set correctly later
    );

    new_action_data.extend_from_slice(action_header.into_bytes()?);
    new_action_data.extend_from_slice(new_lock.into_bytes()?);

    let new_action_size = new_action_data.len();
    let size_diff = new_action_size as i64;

    // Handle account reallocation first
    let new_size = (swig_data_len as i64 + size_diff) as usize;
    let aligned_size = core::alloc::Layout::from_size_align(new_size, core::mem::size_of::<u64>())
        .map_err(|_| SwigError::InvalidAlignment)?
        .pad_to_align()
        .size();

    ctx.accounts.swig.resize(aligned_size)?;

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

    // Get fresh references to the swig account data after reallocation
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };

    // Shift existing data to make room for the new action
    let role_end = actions_offset + current_actions_size;
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
    swig_roles[new_action_offset..new_action_offset + new_action_size]
        .copy_from_slice(&new_action_data);

    // Update the action boundary to point to the end of this action
    let next_boundary = (new_action_offset - actions_offset + new_action_size) as u32;
    swig_roles[new_action_offset + 4..new_action_offset + 8]
        .copy_from_slice(&next_boundary.to_le_bytes());

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
