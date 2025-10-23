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
};

/// Calculates the actual number of actions in the provided actions data.
///
/// This function iterates through the actions data and counts the number of
/// valid actions by parsing action headers and their boundaries.
///
/// # Arguments
/// * `actions_data` - Raw bytes containing action data
///
/// # Returns
/// * `Result<u8, ProgramError>` - The number of actions found, or error if
///   invalid data
fn calculate_num_actions(actions_data: &[u8]) -> Result<u8, ProgramError> {
    let mut cursor = 0;
    let mut count = 0u8;

    while cursor < actions_data.len() {
        if cursor + Action::LEN > actions_data.len() {
            break;
        }

        let action_header =
            unsafe { Action::load_unchecked(&actions_data[cursor..cursor + Action::LEN])? };
        cursor += Action::LEN;

        let action_len = action_header.length() as usize;
        if cursor + action_len > actions_data.len() {
            return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
        }

        cursor += action_len;
        count += 1;

        // Prevent overflow
        if count == u8::MAX {
            return Err(ProgramError::InvalidInstructionData);
        }
    }

    if count == 0 {
        return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
    }

    Ok(count)
}

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

/// Performs a replace-all operation on an authority's actions.
fn perform_replace_all_operation(
    swig_roles: &mut [u8],
    swig_data_len: usize,
    authority_offset: usize,
    actions_offset: usize,
    current_actions_size: usize,
    new_actions: &[u8],
    authority_to_update_id: u32,
) -> Result<i64, ProgramError> {
    let new_actions_size = new_actions.len();
    let size_diff = new_actions_size as i64 - current_actions_size as i64;

    if size_diff != 0 {
        // Need to shift data if size changed
        let role_end = actions_offset + current_actions_size;
        let original_data_len = (swig_data_len as i64 - Swig::LEN as i64) as usize;
        let remaining_data_len = original_data_len - role_end;

        if size_diff > 0 {
            // Growing: shift data to the right
            if remaining_data_len > 0 {
                let new_role_end = (role_end as i64 + size_diff) as usize;
                if new_role_end + remaining_data_len <= swig_roles.len() {
                    swig_roles.copy_within(role_end..role_end + remaining_data_len, new_role_end);
                } else {
                    return Err(SwigError::StateError.into());
                }
            }
        } else {
            // Shrinking: shift data to the left
            if remaining_data_len > 0 {
                let new_role_end = (role_end as i64 + size_diff) as usize;
                swig_roles.copy_within(role_end..role_end + remaining_data_len, new_role_end);
            }
        }

        // Update boundaries of all roles after this one
        let mut cursor = 0;
        for _i in 0..swig_roles.len() / Position::LEN {
            if cursor + Position::LEN > swig_roles.len() {
                break;
            }
            let position = unsafe {
                Position::load_mut_unchecked(&mut swig_roles[cursor..cursor + Position::LEN])?
            };

            if position.boundary() as usize > role_end {
                position.boundary = (position.boundary() as i64 + size_diff) as u32;
            }

            // Update the position for the role we're updating
            if position.id() == authority_to_update_id {
                position.boundary = (position.boundary() as i64 + size_diff) as u32;
                position.num_actions = calculate_num_actions(new_actions)? as u16;
            }

            cursor = position.boundary() as usize;
        }
    } else {
        // Same size: just update the position's num_actions
        let position = unsafe {
            Position::load_mut_unchecked(
                &mut swig_roles[authority_offset..authority_offset + Position::LEN],
            )?
        };
        position.num_actions = calculate_num_actions(new_actions)? as u16;
    }

    if actions_offset + new_actions_size > swig_roles.len() {
        return Err(SwigError::StateError.into());
    }

    // Copy actions data and recalculate boundaries
    let mut cursor = actions_offset;
    let mut action_cursor = 0;

    while action_cursor < new_actions.len() {
        if action_cursor + Action::LEN > new_actions.len() {
            break;
        }

        let action_header = unsafe {
            Action::load_unchecked(&new_actions[action_cursor..action_cursor + Action::LEN])?
        };
        let action_len = action_header.length() as usize;
        let total_action_size = Action::LEN + action_len;

        if action_cursor + total_action_size > new_actions.len() {
            return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
        }

        // Copy action header and update boundary
        swig_roles[cursor..cursor + Action::LEN]
            .copy_from_slice(&new_actions[action_cursor..action_cursor + Action::LEN]);
        let next_boundary = (cursor - actions_offset + total_action_size) as u32;
        swig_roles[cursor + 4..cursor + 8].copy_from_slice(&next_boundary.to_le_bytes());

        // Copy action data
        swig_roles[cursor + Action::LEN..cursor + total_action_size].copy_from_slice(
            &new_actions[action_cursor + Action::LEN..action_cursor + total_action_size],
        );

        cursor += total_action_size;
        action_cursor += total_action_size;
    }

    Ok(size_diff)
}

/// Performs an add-actions operation on an authority.
fn perform_add_actions_operation(
    swig_roles: &mut [u8],
    swig_data_len: usize,
    authority_offset: usize,
    actions_offset: usize,
    current_actions_size: usize,
    new_actions: &[u8],
    authority_to_update_id: u32,
) -> Result<i64, ProgramError> {
    // For add operation, we need to append new actions to existing ones
    let mut combined_actions = Vec::new();

    // Copy existing actions
    combined_actions
        .extend_from_slice(&swig_roles[actions_offset..actions_offset + current_actions_size]);

    // Add new actions
    combined_actions.extend_from_slice(new_actions);

    // Use replace_all logic with combined actions
    perform_replace_all_operation(
        swig_roles,
        swig_data_len,
        authority_offset,
        actions_offset,
        current_actions_size,
        &combined_actions,
        authority_to_update_id,
    )
}

/// Performs a remove-actions-by-type operation on an authority.
fn perform_modify_authlock_operation(
    swig_roles: &mut [u8],
    swig_data_len: usize,
    authority_offset: usize,
    actions_offset: usize,
    current_actions_size: usize,
    authlocks: &mut Vec<AuthorizationLock>,
    authority_to_update_id: u32,
    update_op: bool,
) -> Result<i64, ProgramError> {
    let mut filtered_actions = Vec::new();

    let mut cursor = 0;
    let current_actions = &swig_roles[actions_offset..actions_offset + current_actions_size];

    // Parse existing actions and filter out the ones to remove
    while cursor < current_actions.len() {
        if cursor + Action::LEN > current_actions.len() {
            break;
        }

        let action_header =
            unsafe { Action::load_unchecked(&current_actions[cursor..cursor + Action::LEN])? };
        let action_len = action_header.length() as usize;
        let total_action_size = Action::LEN + action_len;

        if cursor + total_action_size > current_actions.len() {
            return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
        }

        // Check if this action type should be removed
        let permission = action_header.permission()?;
        let action_discriminator = permission as u8;
        if action_discriminator == Permission::AuthorizationLock as u8 {
            let authorization_lock = unsafe {
                AuthorizationLock::load_unchecked(
                    &current_actions[cursor + Action::LEN..cursor + total_action_size],
                )?
            };

            let authlock_action =
                get_matching_args_action_by_mint(authlocks, authorization_lock.mint);
            if authlock_action.is_some() {
                // For update operation, we need to update the authlock data with the new data,
                // otherwise, we need to keep the existing authlock data for removal operation.
                if update_op {
                    let authlock = authlock_action.unwrap();

                    let action_data = Action::new(
                        Permission::AuthorizationLock,
                        authlock.into_bytes()?.len() as u16,
                        (cursor + Action::LEN + actions_offset + total_action_size) as u32,
                    );

                    filtered_actions.extend_from_slice(&action_data.into_bytes()?);
                    filtered_actions.extend_from_slice(&authlock.into_bytes()?);
                }
            } else {
                filtered_actions
                    .extend_from_slice(&current_actions[cursor..cursor + total_action_size]);
            }
        } else {
            filtered_actions
                .extend_from_slice(&current_actions[cursor..cursor + total_action_size]);
        }

        cursor += total_action_size;
    }

    // Ensure we don't remove all actions
    if filtered_actions.is_empty() {
        return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
    }

    // Check if all the arg mints are updated or removed
    if !authlocks.is_empty() {
        return Err(SwigError::AuthLockNotExists.into());
    }

    // Use replace_all logic with filtered actions
    let size_diff = perform_replace_all_operation(
        swig_roles,
        swig_data_len,
        authority_offset,
        actions_offset,
        current_actions_size,
        &filtered_actions,
        authority_to_update_id,
    )?;
    Ok(size_diff)
}

fn get_matching_args_action_by_mint(
    authlocks: &mut Vec<AuthorizationLock>,
    mint: [u8; 32],
) -> Option<AuthorizationLock> {
    let mut found_index = None;
    for (index, authlock) in authlocks.iter().enumerate() {
        if authlock.mint == mint {
            found_index = Some(index);
            break;
        }
    }
    if found_index.is_none() {
        return None;
    }
    let index = found_index.unwrap();
    Some(authlocks.remove(index))
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

    if all.is_none() && manage_authority.is_none() {
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

            size_diff = perform_add_actions_operation(
                swig_roles,
                swig_data_len,
                authority_offset,
                actions_offset,
                current_actions_size,
                new_actions,
                manage_authlock_args.args.authority_to_update_id,
            )?;
            msg!("size_diff: {:?}", size_diff);

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

            size_diff = perform_add_actions_operation(
                swig_roles,
                swig_data_len,
                authority_offset,
                actions_offset,
                current_actions_size,
                &action_bytes,
                0,
            )?;
            msg!("global size_diff: {:?}", size_diff);
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
        },
        ManageAuthorizationLocksOperation::UpdateLock => {
            size_diff = perform_modify_authlock_operation(
                swig_roles,
                swig_data_len,
                authority_offset,
                actions_offset,
                current_actions_size,
                &mut args_authlock,
                manage_authlock_args.args.authority_to_update_id,
                true,
            )?;
            msg!("size_diff: {:?}", size_diff);
        },
    }

    // Get fresh references to the swig account data after reallocation
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };

    let (mut to_be_updated, mut to_be_removed) = get_authlock_by_mints(swig, swig_roles, mints)?;

    let target_role_id = 0;
    let (current_actions_size, authority_offset, actions_offset) = {
        let mut cursor = 0;
        let mut found = false;
        let mut auth_offset = 0;
        let mut act_offset = 0;
        let mut current_size = 0;

        for _i in 0..swig.roles {
            let position =
                unsafe { Position::load_unchecked(&swig_roles[cursor..cursor + Position::LEN])? };
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

    if !to_be_updated.is_empty() {
        msg!("performing to be updated");
        size_diff = perform_modify_authlock_operation(
            swig_roles,
            swig_data_len,
            authority_offset,
            actions_offset,
            current_actions_size,
            &mut to_be_updated,
            target_role_id,
            true,
        )?;
        msg!("size_diff: {:?}", size_diff);
    }

    if !to_be_removed.is_empty() {
        msg!("performing to be removed");
        size_diff = perform_modify_authlock_operation(
            swig_roles,
            swig_data_len,
            authority_offset,
            actions_offset,
            current_actions_size,
            &mut to_be_removed,
            target_role_id,
            false,
        )?;
        msg!("size_diff: {:?}", size_diff);
    }

    Ok(())
}

pub fn get_authlock_by_mints(
    swig: &Swig,
    swig_roles: &mut [u8],
    mints: Vec<[u8; 32]>,
) -> Result<(Vec<AuthorizationLock>, Vec<AuthorizationLock>), ProgramError> {
    let mut cursor = 0;
    let mut roles = Vec::new();
    let mut to_be_updated: Vec<AuthorizationLock> = Vec::new();
    let mut to_be_removed: Vec<AuthorizationLock> = Vec::new();

    while cursor < swig_roles.len() {
        let position =
            unsafe { Position::load_unchecked(&swig_roles[cursor..cursor + Position::LEN])? };

        roles.push(position.id());
        cursor = position.boundary() as usize;
    }

    for (index, mint) in mints.iter().enumerate() {
        let mut mint_found = false;
        let mut new_auth_lock = AuthorizationLock {
            mint: mint.clone(),
            amount: 0,
            expires_at: u64::MAX,
        };

        for role in &roles {
            let role = Swig::get_mut_role(*role, swig_roles)?.unwrap();

            let auth_lock = role.get_action::<AuthorizationLock>(mint);
            if auth_lock.is_ok() {
                let auth_lock = auth_lock.unwrap();

                if auth_lock.is_some() {
                    mint_found = true;
                    new_auth_lock.update_for_global(auth_lock.unwrap());
                }
            }
        }

        if mint_found {
            to_be_removed.push(new_auth_lock);
        } else {
            to_be_updated.push(new_auth_lock);
        }
    }

    Ok((to_be_updated, to_be_removed))
}
