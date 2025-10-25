/// Module for updating existing authorities in a Swig wallet.
/// This module implements functionality to update authority roles by adding
/// or removing specific permissions while maintaining proper authentication.
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
    authority::{authority_type_to_length, AuthorityType},
    role::{Position, Role, RoleMut},
    swig::{Swig, SwigBuilder},
    Discriminator, IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, ManageAuthorizationLocksV1Accounts, UpdateAuthorityV1Accounts},
        SwigInstruction,
    },
    util::auth_lock::{
        get_authlock_by_mints, get_matching_args_action_by_mint, modify_global_auth_locks,
        perform_add_actions_operation, perform_modify_authlock_operation,
    },
};

/// Struct representing the complete update authority instruction data.
///
/// # Fields
/// * `args` - The update authority arguments
/// * `data_payload` - Raw data payload
/// * `authority_payload` - Authority-specific payload data
/// * `operation_data` - Operation-specific data (actions, indices, etc.)
pub struct ManageAuthorizationLocksV1<'a> {
    pub args: &'a ManageAuthorizationLocksV1Args,
    data_payload: &'a [u8],
    authority_payload: &'a [u8],
    operation_data: &'a [u8],
}

/// Operation types for updating authorities.
///
/// Defines the different ways an authority can be updated:
/// - ReplaceAll: Replace all actions with new set (original behavior)
/// - AddActions: Add new actions to existing set
/// - RemoveActionsByType: Remove actions by their discriminator/type
/// - RemoveActionsByIndex: Remove actions by their position index
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ManageAuthorizationLocksOperation {
    AddLock = 0,
    RemoveLock = 1,
    UpdateLock = 2,
}

impl ManageAuthorizationLocksOperation {
    pub fn from_u8(value: u8) -> Result<Self, ProgramError> {
        match value {
            0 => Ok(Self::AddLock),
            1 => Ok(Self::RemoveLock),
            2 => Ok(Self::UpdateLock),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

/// Arguments for updating an existing authority in a Swig wallet.
///
/// # Fields
/// * `instruction` - The instruction type identifier
/// * `actions_data_len` - Length of the actions data
/// * `num_actions` - Number of actions for the authority update
/// * `_padding` - Padding bytes for alignment
/// * `acting_role_id` - ID of the role performing the update
/// * `authority_to_update_id` - ID of the authority to update
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct ManageAuthorizationLocksV1Args {
    pub instruction: SwigInstruction,
    pub actions_data_len: u16,
    pub acting_role_id: u32,
    pub authority_to_update_id: u32,
    _padding: [u8; 4],
}

impl Transmutable for ManageAuthorizationLocksV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl ManageAuthorizationLocksV1Args {
    /// Creates a new instance of UpdateAuthorityV1Args.
    ///
    /// # Arguments
    /// * `acting_role_id` - ID of the role performing the update
    /// * `authority_to_update_id` - ID of the authority to update
    /// * `actions_data_len` - Length of the actions data
    pub fn new(acting_role_id: u32, authority_to_update_id: u32, actions_data_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::ManageAuthorizationLocksV1,
            acting_role_id,
            authority_to_update_id,
            actions_data_len,
            _padding: [0; 4],
        }
    }
}

impl IntoBytes for ManageAuthorizationLocksV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> ManageAuthorizationLocksV1<'a> {
    /// Parses the instruction data bytes into an UpdateAuthorityV1 instance.
    ///
    /// # Arguments
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < ManageAuthorizationLocksV1Args::LEN {
            return Err(SwigError::InvalidAuthLockInstructionData.into());
        }

        let (inst, rest) = data.split_at(ManageAuthorizationLocksV1Args::LEN);
        let args = unsafe { ManageAuthorizationLocksV1Args::load_unchecked(inst)? };
        let (actions_payload, authority_payload) = rest.split_at(args.actions_data_len as usize);

        Ok(Self {
            args,
            operation_data: actions_payload,
            authority_payload,
            data_payload: &data
                [..ManageAuthorizationLocksV1Args::LEN + args.actions_data_len as usize],
        })
    }

    /// Gets the operation type for this instruction.
    pub fn get_operation(&self) -> Result<ManageAuthorizationLocksOperation, ProgramError> {
        ManageAuthorizationLocksOperation::from_u8(self.operation_data[0])
    }

    /// Gets the operation data as actions for ReplaceAll and AddActions
    /// operations.
    pub fn get_actions_data(&self) -> Result<&[u8], ProgramError> {
        match self.get_operation()? {
            ManageAuthorizationLocksOperation::AddLock => Ok(&self.operation_data[1..]),
            ManageAuthorizationLocksOperation::RemoveLock => Ok(&self.operation_data[1..]),
            ManageAuthorizationLocksOperation::UpdateLock => Ok(&self.operation_data[1..]),
        }
    }

    /// Validates and collects authorization lock data from action data.
    ///
    /// # Arguments
    /// * `action_data` - Action data to validate and collect authorization lock data from
    /// * `operation` - Operation type
    ///
    /// # Returns
    /// * `Result<Vec<AuthorizationLock>, ProgramError>` - Authorization lock data or error
    pub fn validate_and_collect_authlock_data(
        &self,
    ) -> Result<Vec<AuthorizationLock>, ProgramError> {
        let action_data = self.get_actions_data()?;
        let mut authlock_data: Vec<AuthorizationLock> = Vec::new();
        let mut mints = Vec::new();
        match self.get_operation()? {
            ManageAuthorizationLocksOperation::AddLock
            | ManageAuthorizationLocksOperation::UpdateLock => {
                for action in action_data.chunks_exact(Action::LEN + AuthorizationLock::LEN) {
                    let authorization_lock =
                        unsafe { AuthorizationLock::load_unchecked(&action[Action::LEN..]) };
                    if authorization_lock.is_err() {
                        return Err(SwigError::InvalidAuthLockInstructionData.into());
                    }
                    let authorization_lock = authorization_lock.unwrap();

                    if mints.contains(&authorization_lock.mint) {
                        return Err(SwigError::DuplicateMintInAuthLockInstructionData.into());
                    }
                    mints.push(authorization_lock.mint);
                    authlock_data.push(AuthorizationLock {
                        mint: authorization_lock.mint,
                        amount: authorization_lock.amount,
                        expires_at: authorization_lock.expires_at,
                    });
                }
            },
            ManageAuthorizationLocksOperation::RemoveLock => {
                for mint in action_data.chunks_exact(32) {
                    let mint: [u8; 32] = mint.try_into().unwrap();
                    if mints.contains(&mint) {
                        return Err(SwigError::DuplicateMintInAuthLockInstructionData.into());
                    }
                    mints.push(mint);
                    authlock_data.push(AuthorizationLock {
                        mint,
                        amount: 0,
                        expires_at: 0,
                    });
                }
            },
            _ => return Err(ProgramError::InvalidInstructionData),
        }
        Ok(authlock_data)
    }
}

/// Updates an existing authority in a Swig wallet.
///
/// This function handles the complete flow of updating an authority:
/// 1. Validates the acting role's permissions
/// 2. Authenticates the request
/// 3. Verifies the authority exists and can be updated
/// 4. Updates the authority's actions/permissions
/// 5. Handles account reallocation if needed
///
/// # Arguments
/// * `ctx` - The account context for updating authority
/// * `update` - Raw update authority instruction data
/// * `all_accounts` - All accounts involved in the operation
///
/// # Returns
/// * `ProgramResult` - Success or error status
pub fn manage_authorization_locks_v1(
    ctx: Context<ManageAuthorizationLocksV1Accounts>,
    update: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_bytes_match(
        ctx.accounts.system_program.key(),
        &pinocchio_system::ID,
        32,
        SwigError::InvalidSystemProgram,
    )?;

    let manage_authlock_args =
        ManageAuthorizationLocksV1::from_instruction_bytes(update).map_err(|e| {
            msg!("ManageAuthorizationLocksV1 Args Error: {:?}", e);
            ProgramError::InvalidInstructionData
        })?;

    if manage_authlock_args.args.authority_to_update_id == 0 {
        return Err(SwigError::PermissiondeniedGlobalAuthortiy.into());
    }

    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let swig_data_len = swig_account_data.len();

    if swig_account_data[0] != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };

    // Get and validate acting role
    let acting_role = Swig::get_mut_role(manage_authlock_args.args.acting_role_id, swig_roles)?;
    if acting_role.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let acting_role = acting_role.unwrap();

    let mut args_authlock = manage_authlock_args.validate_and_collect_authlock_data()?;

    // Authenticate the caller
    let clock = Clock::get()?;
    let slot = clock.slot;

    if acting_role.authority.session_based() {
        acting_role.authority.authenticate_session(
            all_accounts,
            manage_authlock_args.authority_payload,
            manage_authlock_args.data_payload,
            slot,
        )?;
    } else {
        acting_role.authority.authenticate(
            all_accounts,
            manage_authlock_args.authority_payload,
            manage_authlock_args.data_payload,
            slot,
        )?;
    }

    // Check permissions - same as add/remove authority
    let all = acting_role.get_action::<All>(&[])?;
    let manage_authority = acting_role.get_action::<ManageAuthority>(&[])?;
    let manage_authlock = acting_role.get_action::<ManageAuthorizationLocks>(&[])?;

    if all.is_none() && manage_authority.is_none() && manage_authlock.is_none() {
        return Err(SwigAuthenticateError::PermissionDeniedToManageAuthority.into());
    }

    // Role without all or manage authority cannot update other roles' auth locks
    if ((all.is_none() && manage_authority.is_none()) && manage_authlock.is_some())
        && (manage_authlock_args.args.acting_role_id
            != manage_authlock_args.args.authority_to_update_id)
    {
        return Err(SwigAuthenticateError::PermissionDeniedToManageAuthority.into());
    }

    // Verify the authority to update exists and calculate size difference
    let (current_actions_size, authority_offset, actions_offset) = {
        let mut cursor = 0;
        let mut found = false;
        let mut auth_offset = 0;
        let mut act_offset = 0;
        let mut current_size = 0;

        for _i in 0..swig.roles {
            let position =
                unsafe { Position::load_unchecked(&swig_roles[cursor..cursor + Position::LEN])? };
            if position.id() == manage_authlock_args.args.authority_to_update_id {
                found = true;
                auth_offset = cursor;
                act_offset = cursor + Position::LEN + position.authority_length() as usize;
                current_size = position.boundary() as usize - act_offset;

                break;
            }
            cursor = position.boundary() as usize;
        }

        if !found {
            return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
        }

        (current_size, auth_offset, act_offset)
    };

    let target_role_id = manage_authlock_args.args.authority_to_update_id;
    let existing_authlock_actions = Swig::get_mut_role(target_role_id, swig_roles)?;

    // Calculate size difference first
    let operation = manage_authlock_args.get_operation()?;
    let size_diff = match operation {
        ManageAuthorizationLocksOperation::AddLock => {
            let new_actions = manage_authlock_args.get_actions_data()?;
            new_actions.len() as i64 // Adding to existing, so just the new size
        },
        ManageAuthorizationLocksOperation::RemoveLock => {
            // For remove operations, we need to calculate how much will be removed
            // This is complex, so for now we'll calculate it in the operation function
            0 // Will be calculated in the operation
        },
        ManageAuthorizationLocksOperation::UpdateLock => {
            // For remove operations, we need to calculate how much will be removed
            // This is complex, so for now we'll calculate it in the operation function
            0 // Will be calculated in the operation
        },
    };

    // Handle account reallocation if size changed (before operations)
    let new_reserved_lamports = if size_diff != 0 {
        let new_size = (swig_data_len as i64 + size_diff) as usize;
        let aligned_size =
            core::alloc::Layout::from_size_align(new_size, core::mem::size_of::<u64>())
                .map_err(|_| SwigError::InvalidAlignment)?
                .pad_to_align()
                .size();

        ctx.accounts.swig.realloc(aligned_size, false)?;

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

        cost
    } else {
        // No size change, so no need to transfer additional funds
        0
    };

    // Get fresh references to the swig account data after reallocation
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let _swig = unsafe { Swig::load_mut_unchecked(swig_header)? };

    let mut target_role = Swig::get_mut_role(target_role_id, swig_roles)?.unwrap();

    if target_role
        .get_action::<ManageAuthorizationLocks>(&[])?
        .is_none()
    {
        return Err(SwigError::ManageAuthorizationLocksNotExists.into());
    }

    let mut size_diff: i64;
    let mut global_mints_to_add = Vec::new();
    let mut mints = args_authlock
        .iter()
        .map(|authlock| authlock.mint)
        .collect::<Vec<[u8; 32]>>();
    // Now perform the operation with the reallocated account
    match operation {
        ManageAuthorizationLocksOperation::AddLock => {
            // check the mint is not already locked
            for authlock in &args_authlock {
                let authlock_action =
                    target_role.get_action::<AuthorizationLock>(&authlock.mint)?;
                if authlock_action.is_some() {
                    return Err(SwigError::AuthLockAlreadyExists.into());
                }
            }
            let new_actions = manage_authlock_args.get_actions_data()?;

            perform_add_actions_operation(
                swig_roles,
                swig_data_len,
                authority_offset,
                actions_offset,
                current_actions_size,
                new_actions,
                manage_authlock_args.args.authority_to_update_id,
            )?;

            let swig_data_len = ctx.accounts.swig.data_len();

            let global_role = Swig::get_mut_role(0, swig_roles)?.unwrap();

            for auth_lock in &mut args_authlock {
                let global_has_authlock =
                    global_role.get_action::<AuthorizationLock>(&auth_lock.mint);
                if global_has_authlock.is_ok() {
                    let global_has_authlock = global_has_authlock.unwrap();
                    if global_has_authlock.is_none() {
                        global_mints_to_add.push(auth_lock);
                    } else {
                        // keep such that update flow will handle the update
                    }
                } else {
                    global_mints_to_add.push(auth_lock);
                }
            }

            let mut action_bytes = Vec::new();
            for auth_lock in &global_mints_to_add {
                let action_header = Action::new(
                    Permission::AuthorizationLock,
                    AuthorizationLock::LEN as u16,
                    action_bytes.len() as u32 + Action::LEN as u32 + AuthorizationLock::LEN as u32,
                );
                let action_header_bytes = action_header.into_bytes()?;
                let action_data_bytes = auth_lock.into_bytes()?;
                action_bytes.extend_from_slice(&action_header_bytes);
                action_bytes.extend_from_slice(&action_data_bytes);

                // remove from mints
                mints.remove(mints.iter().position(|x| x == &auth_lock.mint).unwrap());
            }

            {
                let new_size = (swig_data_len + action_bytes.len()) as usize;
                let aligned_size =
                    core::alloc::Layout::from_size_align(new_size, core::mem::size_of::<u64>())
                        .map_err(|_| SwigError::InvalidAlignment)?
                        .pad_to_align()
                        .size();

                ctx.accounts.swig.realloc(aligned_size, false)?;

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
            }

            let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
            let (swig_header, swig_roles) =
                unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
            let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
            let target_role_id = 0;
            let (current_actions_size, authority_offset, actions_offset) = {
                let mut cursor = 0;
                let mut found = false;
                let mut auth_offset = 0;
                let mut act_offset = 0;
                let mut current_size = 0;

                for _i in 0..swig.roles {
                    let position = unsafe {
                        Position::load_unchecked(&swig_roles[cursor..cursor + Position::LEN])?
                    };
                    if position.id() == target_role_id {
                        found = true;
                        auth_offset = cursor;
                        act_offset = cursor + Position::LEN + position.authority_length() as usize;
                        current_size = position.boundary() as usize - act_offset;

                        break;
                    }
                    cursor = position.boundary() as usize;
                }

                if !found {
                    return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
                }

                (current_size, auth_offset, act_offset)
            };

            perform_add_actions_operation(
                swig_roles,
                swig_data_len,
                authority_offset,
                actions_offset,
                current_actions_size,
                &action_bytes,
                0,
            )?;
            msg!("added lock to role");
        },
        ManageAuthorizationLocksOperation::RemoveLock => {
            size_diff = perform_modify_authlock_operation(
                swig_roles,
                swig_data_len,
                authority_offset,
                actions_offset,
                current_actions_size,
                &mut args_authlock,
                manage_authlock_args.args.authority_to_update_id,
                false,
            )?;

            if size_diff < 0 {
                let new_size = (swig_data_len as i64 + size_diff) as usize;
                let aligned_size =
                    core::alloc::Layout::from_size_align(new_size, core::mem::size_of::<u64>())
                        .map_err(|_| SwigError::InvalidAlignment)?
                        .pad_to_align()
                        .size();

                ctx.accounts.swig.resize(aligned_size)?;

                let cost = Rent::get()?.minimum_balance(aligned_size);
                let current_lamports = unsafe { *ctx.accounts.swig.borrow_lamports_unchecked() };

                let additional_cost = current_lamports.saturating_sub(cost);

                if additional_cost > 0 {
                    unsafe {
                        *ctx.accounts.swig.borrow_mut_lamports_unchecked() -= additional_cost;
                        *ctx.accounts.swig.borrow_mut_lamports_unchecked() += additional_cost;
                    }
                }
            }
            msg!("removed lock from role");
        },
        ManageAuthorizationLocksOperation::UpdateLock => {
            perform_modify_authlock_operation(
                swig_roles,
                swig_data_len,
                authority_offset,
                actions_offset,
                current_actions_size,
                &mut args_authlock,
                manage_authlock_args.args.authority_to_update_id,
                true,
            )?;
            msg!("updated lock in role");
        },
    }

    // Get fresh references to the swig account data after reallocation
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let swig_data_len = swig_account_data.len();
    let size_diff = modify_global_auth_locks(swig_account_data, mints)?;

    if size_diff < 0 {
        let new_size = (swig_data_len as i64 + size_diff) as usize;
        let aligned_size =
            core::alloc::Layout::from_size_align(new_size, core::mem::size_of::<u64>())
                .map_err(|_| SwigError::InvalidAlignment)?
                .pad_to_align()
                .size();

        ctx.accounts.swig.resize(aligned_size)?;

        let cost = Rent::get()?.minimum_balance(aligned_size);
        let current_lamports = unsafe { *ctx.accounts.swig.borrow_lamports_unchecked() };

        let additional_cost = current_lamports.saturating_sub(cost);

        if additional_cost > 0 {
            unsafe {
                *ctx.accounts.swig.borrow_mut_lamports_unchecked() -= additional_cost;
                *ctx.accounts.swig.borrow_mut_lamports_unchecked() += additional_cost;
            }
        }
    }

    Ok(())
}
