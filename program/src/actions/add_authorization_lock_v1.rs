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
use pinocchio_pubkey::pubkey;
use pinocchio_system::instructions::Transfer;
use swig_assertions::*;
use swig_state::{
    action::{
        all::All, manage_authorization_locks::ManageAuthorizationLocks, sol_limit::SolLimit,
        sol_recurring_limit::SolRecurringLimit, token_limit::TokenLimit,
        token_recurring_limit::TokenRecurringLimit,
    },
    role::Position,
    swig::{AuthorizationLock, Swig, SwigBuilder, SwigWithRoles},
    Discriminator, IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable, TransmutableMut,
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
/// * `acting_role_id` - ID of the role performing the operation
#[derive(Debug, NoPadding)]
#[repr(C, align(8))]
pub struct AddAuthorizationLockV1Args {
    instruction: SwigInstruction,
    _padding: [u8; 2], // Reduced padding for new field
    pub acting_role_id: u32,
    pub token_mint: [u8; 32],
    pub amount: u64,
    pub expiry_slot: u64,
}

impl AddAuthorizationLockV1Args {
    /// Creates a new instance of AddAuthorizationLockV1Args.
    ///
    /// # Arguments
    /// * `acting_role_id` - ID of the role performing the operation
    /// * `token_mint` - The mint of the token to lock
    /// * `amount` - The maximum amount that can be spent
    /// * `expiry_slot` - The slot when this lock expires
    pub fn new(acting_role_id: u32, token_mint: [u8; 32], amount: u64, expiry_slot: u64) -> Self {
        Self {
            instruction: SwigInstruction::AddAuthorizationLockV1,
            _padding: [0; 2],
            acting_role_id,
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

/// Structured data for the add authorization lock instruction.
pub struct AddAuthorizationLockV1<'a> {
    pub args: &'a AddAuthorizationLockV1Args,
    data_payload: &'a [u8],
    authority_payload: &'a [u8],
}

impl<'a> AddAuthorizationLockV1<'a> {
    /// Parses the instruction data bytes into an AddAuthorizationLockV1
    /// instance.
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < AddAuthorizationLockV1Args::LEN {
            return Err(SwigError::InvalidSwigSignInstructionDataTooShort.into());
        }

        let (inst, authority_payload) = data.split_at(AddAuthorizationLockV1Args::LEN);
        let args = unsafe { AddAuthorizationLockV1Args::load_unchecked(inst)? };

        Ok(Self {
            args,
            data_payload: inst,
            authority_payload,
        })
    }
}

/// Adds an authorization lock to a Swig wallet.
///
/// This function:
/// 1. Validates the acting role's permissions (All or ManageAuthorizationLocks)
/// 2. Authenticates the request
/// 3. Validates the Swig account and lock parameters
/// 4. Reallocates the account to accommodate the new lock
/// 5. Adds the authorization lock to the end of the account data
///
/// # Arguments
/// * `ctx` - The account context for the operation
/// * `data` - Raw instruction data bytes
/// * `all_accounts` - All accounts involved in the operation
///
/// # Returns
/// * `ProgramResult` - Success or error status
#[inline(always)]
pub fn add_authorization_lock_v1(
    ctx: Context<AddAuthorizationLockV1Accounts>,
    data: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    check_stack_height(1, SwigError::Cpi)?;

    let add_lock = AddAuthorizationLockV1::from_instruction_bytes(data)?;

    // Get current slot to validate expiry
    let clock = Clock::get()?;
    if add_lock.args.expiry_slot <= clock.slot {
        return Err(SwigError::InvalidAuthorizationLockExpiry.into());
    }

    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    // Authentication and permission checking - consolidate loads
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account_data).unwrap();
    let role = swig_with_roles.get_role(add_lock.args.acting_role_id)?;

    // Get existing authorization locks for this role using a smaller array to avoid
    // stack overflow
    const MAX_LOCKS: usize = 10; // Smaller bound to prevent stack overflow
    let (existing_locks, _count) = swig_with_roles
        .get_authorization_locks_by_role::<MAX_LOCKS>(add_lock.args.acting_role_id)?;

    // Convert Option array to Vec of actual locks
    let existing_locks_vec: Vec<swig_state::swig::AuthorizationLock> = existing_locks
        .iter()
        .filter_map(|opt_lock| *opt_lock)
        .collect();

    // TODO need to merge in fix for getting all roles because of action boundary
    // cursor positions
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
    let acting_role = Swig::get_mut_role(add_lock.args.acting_role_id, swig_roles)?;
    if acting_role.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let acting_role = acting_role.unwrap();

    // Authenticate the caller
    let slot = clock.slot;
    if acting_role.authority.session_based() {
        acting_role.authority.authenticate_session(
            all_accounts,
            add_lock.authority_payload,
            add_lock.data_payload,
            slot,
        )?;
    } else {
        acting_role.authority.authenticate(
            all_accounts,
            add_lock.authority_payload,
            add_lock.data_payload,
            slot,
        )?;
    }

    // Check permissions: must have All or ManageAuthorizationLocks
    let all = acting_role.get_action::<All>(&[])?;
    let manage_auth_locks = acting_role.get_action::<ManageAuthorizationLocks>(&[])?;

    if all.is_none() && manage_auth_locks.is_none() {
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    }

    // Validate the new lock against existing token limits
    validate_authorization_lock_against_limits(
        &acting_role,
        add_lock.args.token_mint,
        add_lock.args.amount,
        &existing_locks_vec,
    )?;

    // Validate the new lock against current balance (balance_account at index 4)
    validate_authorization_lock_against_balance(
        all_accounts,
        add_lock.args.token_mint,
        add_lock.args.amount,
        &existing_locks_vec,
    )?;

    // Re-borrow data after authentication
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (swig_header, remaining_data) =
        unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };

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

    // Write the new lock at the end of the authorization locks section using
    // zero-copy
    let auth_locks_start = Swig::LEN + roles_end;
    let new_lock_offset = auth_locks_start + current_auth_locks_size;

    // Zero-copy: write directly to the account data buffer
    let lock_slice = &mut swig_account_data[new_lock_offset..new_lock_offset + new_lock_size];
    let new_lock = unsafe { &mut *(lock_slice.as_mut_ptr() as *mut AuthorizationLock) };

    // Initialize the lock fields directly in memory
    new_lock.token_mint = add_lock.args.token_mint;
    new_lock.amount = add_lock.args.amount;
    new_lock.expiry_slot = add_lock.args.expiry_slot;
    new_lock.role_id = add_lock.args.acting_role_id;
    new_lock._padding = [0; 4];

    // Update the authorization locks count in the header
    let (swig_header, _) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
    swig.authorization_locks += 1;

    Ok(())
}

/// Validates that the new authorization lock doesn't exceed existing token
/// limits for the role.
///
/// This function checks if adding the new authorization lock would cause the
/// total authorization locks for the token to exceed any existing token limits
/// (simple or recurring) that the acting role has for that specific token.
/// For SOL (wrapped SOL mint), it also checks against SOL limits.
///
/// # Arguments
/// * `acting_role` - The role that is creating the authorization lock
/// * `token_mint` - The mint of the token
/// * `new_lock_amount` - The amount of the new authorization lock
/// * `existing_locks` - All existing authorization locks for this role and
///   token
///
/// # Returns
/// * `Ok(())` - If the new lock is within limits
/// * `Err(ProgramError)` - If the new lock would exceed limits
fn validate_authorization_lock_against_limits<'a>(
    acting_role: &'a swig_state::role::RoleMut<'a>,
    token_mint: [u8; 32],
    new_lock_amount: u64,
    existing_locks: &[AuthorizationLock],
) -> ProgramResult {
    // Wrapped SOL mint address
    const WRAPPED_SOL_MINT: [u8; 32] = pubkey!("So11111111111111111111111111111111111111112");

    // Calculate total existing authorization lock amount for this token
    let existing_total = existing_locks
        .iter()
        .filter(|lock| lock.token_mint == token_mint)
        .map(|lock| lock.amount)
        .sum::<u64>();

    let total_with_new_lock = existing_total.saturating_add(new_lock_amount);

    // Check if this is the wrapped SOL mint
    if token_mint == WRAPPED_SOL_MINT {
        // Check against SOL limits first
        if let Ok(Some(sol_limit)) = acting_role.get_action::<SolLimit>(&[]) {
            if total_with_new_lock > sol_limit.amount {
                return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
            }
        }

        // Check against recurring SOL limit
        if let Ok(Some(sol_recurring_limit)) = acting_role.get_action::<SolRecurringLimit>(&[]) {
            if total_with_new_lock > sol_recurring_limit.recurring_amount {
                return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
            }
        }
    } else {
        // Check token limits for non-SOL tokens
        let mint_data = &token_mint[..];

        // Check against simple token limit
        if let Ok(Some(token_limit)) = acting_role.get_action::<TokenLimit>(mint_data) {
            if total_with_new_lock > token_limit.current_amount {
                return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
            }
        }

        // Check against recurring token limit
        if let Ok(Some(token_recurring_limit)) =
            acting_role.get_action::<TokenRecurringLimit>(mint_data)
        {
            if total_with_new_lock > token_recurring_limit.limit {
                return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
            }
        }
    }

    Ok(())
}

/// Validates that the authorization lock amount doesn't exceed the current balance.
///
/// # Arguments
/// * `all_accounts` - All accounts (balance_account expected at index 4)
/// * `token_mint` - Token mint (all zeros for native SOL)
/// * `new_lock_amount` - Amount for the new lock
/// * `existing_locks` - Existing authorization locks for this mint
fn validate_authorization_lock_against_balance(
    all_accounts: &[AccountInfo],
    token_mint: [u8; 32],
    new_lock_amount: u64,
    existing_locks: &[AuthorizationLock],
) -> ProgramResult {
    const NATIVE_SOL_MINT: [u8; 32] = [0u8; 32];
    const TOKEN_BALANCE_OFFSET: usize = 64;
    const TOKEN_BALANCE_SIZE: usize = 8;

    // Balance account is at index 4
    if all_accounts.len() <= 4 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    let balance_account = unsafe { all_accounts.get_unchecked(4) };

    // Calculate total authorization lock amount with new lock
    let existing_total = existing_locks
        .iter()
        .filter(|lock| lock.token_mint == token_mint)
        .map(|lock| lock.amount)
        .sum::<u64>();
    let total_with_new_lock = existing_total.saturating_add(new_lock_amount);

    if token_mint == NATIVE_SOL_MINT {
        // For native SOL, check swig_wallet_address balance
        let balance = balance_account.lamports();

        if total_with_new_lock > balance {
            msg!(
                "Authorization lock validation failed: total lock amount ({}) exceeds swig_wallet_address balance ({})",
                total_with_new_lock,
                balance
            );
            return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
        }
    } else {
        // For SPL tokens, check token account balance
        // Token account validation is optional - if the account isn't a valid token account, skip validation
        let account_data = unsafe { balance_account.borrow_data_unchecked() };

        if account_data.len() >= TOKEN_BALANCE_OFFSET + TOKEN_BALANCE_SIZE {
            // Valid token account structure, check balance
            let balance = u64::from_le_bytes(
                account_data[TOKEN_BALANCE_OFFSET..TOKEN_BALANCE_OFFSET + TOKEN_BALANCE_SIZE]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidAccountData)?
            );

            if total_with_new_lock > balance {
                msg!(
                    "Authorization lock validation failed: total lock amount ({}) exceeds token account balance ({})",
                    total_with_new_lock,
                    balance
                );
                return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
            }
        }
        // If account data is too small, skip validation (caller can pass swig_wallet_address for token locks)
    }

    Ok(())
}
