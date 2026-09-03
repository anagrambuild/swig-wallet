/// Module for migrating Swig accounts to support wallet address feature.
///
/// This module implements the migration from the old Swig account structure
/// (with reserved_lamports field) to the new structure (with wallet_bump +
/// padding). It also creates the associated wallet address account for each
/// migrated Swig account.
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use swig_assertions::{check_bytes_match, check_self_owned, check_system_owner, check_zero_data};
use swig_state::{
    action::{all::All, manage_authority::ManageAuthority, Action, ActionLoader},
    role::Position,
    swig::{swig_wallet_address_seeds, Swig},
    Discriminator, IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, MigrateToWalletAddressV1Accounts},
        SwigInstruction,
    },
};

/// Arguments for migrating a Swig account to wallet address feature.
///
/// # Fields
/// * `discriminator` - The instruction type identifier
/// * `wallet_address_bump` - Bump seed for the wallet address PDA
/// * `role_id` - ID of the role authorizing the migration
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct MigrateToWalletAddressV1Args {
    discriminator: SwigInstruction,
    pub wallet_address_bump: u8,
    pub _padding: u8,
    pub role_id: u32,
}

impl MigrateToWalletAddressV1Args {
    /// Creates a new instance of MigrateToWalletAddressV1Args.
    ///
    /// # Arguments
    /// * `wallet_address_bump` - Bump seed for wallet address PDA derivation
    /// * `role_id` - ID of the role authorizing the migration
    pub fn new(wallet_address_bump: u8, role_id: u32) -> Self {
        Self {
            discriminator: SwigInstruction::MigrateToWalletAddressV1,
            wallet_address_bump,
            _padding: 0,
            role_id,
        }
    }
}

impl Transmutable for MigrateToWalletAddressV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for MigrateToWalletAddressV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Struct representing the complete migrate instruction data.
pub struct MigrateToWalletAddressV1<'a> {
    pub args: &'a MigrateToWalletAddressV1Args,
    pub authority_payload: &'a [u8],
    pub data_payload: &'a [u8],
}

impl<'a> MigrateToWalletAddressV1<'a> {
    /// Parses the instruction data bytes into a MigrateToWalletAddressV1
    /// instance.
    ///
    /// # Arguments
    /// * `bytes` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(bytes: &'a [u8]) -> Result<Self, ProgramError> {
        if bytes.len() < MigrateToWalletAddressV1Args::LEN {
            return Err(SwigError::InvalidSwigCreateInstructionDataTooShort.into());
        }
        let (args_data, authority_payload) = bytes.split_at(MigrateToWalletAddressV1Args::LEN);
        let args = unsafe { MigrateToWalletAddressV1Args::load_unchecked(args_data)? };
        Ok(Self {
            args,
            authority_payload,
            data_payload: args_data,
        })
    }
}

/// Old Swig account structure with reserved_lamports field.
/// Used for reading existing account data before migration.
#[repr(C, align(8))]
#[derive(Debug, PartialEq, NoPadding)]
pub struct OldSwig {
    /// Account type discriminator
    pub discriminator: u8,
    /// PDA bump seed
    pub bump: u8,
    /// Unique identifier for this Swig account
    pub id: [u8; 32],
    /// Number of roles in this account
    pub roles: u16,
    /// Counter for generating unique role IDs
    pub role_counter: u32,
    /// Amount of lamports reserved for rent (to be replaced)
    pub reserved_lamports: u64,
}

impl Transmutable for OldSwig {
    const LEN: usize = core::mem::size_of::<Self>();
}

/// Migrates a Swig account to support the wallet address feature.
///
/// This function:
/// 1. Validates the authority has All or ManageAuthority permission
/// 2. Reads the old Swig account structure
/// 3. Creates a new Swig structure with wallet_bump field
/// 4. Updates the account in-place (preserving all role/action data)
/// 5. Creates the associated wallet address account
///
/// # Arguments
/// * `ctx` - The account context for the migration
/// * `migrate_data` - Raw migration instruction data
/// * `all_accounts` - All accounts passed to the instruction for authority auth
///
/// # Returns
/// * `ProgramResult` - Success or error status
#[inline(always)]
pub fn migrate_to_wallet_address_v1(
    ctx: Context<MigrateToWalletAddressV1Accounts>,
    migrate_data: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_bytes_match(
        ctx.accounts.system_program.key(),
        &pinocchio_system::ID,
        32,
        SwigError::InvalidSystemProgram,
    )?;

    let migrate = MigrateToWalletAddressV1::from_instruction_bytes(migrate_data)?;

    let (old_swig_id, old_swig_bump, old_swig_roles, old_swig_role_counter) = {
        // Validate that the swig account has the correct discriminator
        let swig_data = unsafe { ctx.accounts.swig.borrow_data_unchecked() };
        if swig_data.len() < OldSwig::LEN {
            return Err(SwigError::StateError.into());
        }

        let discriminator = swig_data[0];
        if discriminator != Discriminator::SwigConfigAccount as u8 {
            return Err(SwigError::InvalidSwigAccountDiscriminator.into());
        }

        let old_swig = unsafe { OldSwig::load_unchecked(&swig_data[..OldSwig::LEN])? };

        (
            old_swig.id,
            old_swig.bump,
            old_swig.roles,
            old_swig.role_counter,
        )
    };

    // Authenticate and validate authority has All or ManageAuthority permission
    {
        let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
        let swig_roles = Swig::split_parts_mut(swig_account_data)?.roles;
        let role = Swig::get_mut_role(migrate.args.role_id, swig_roles)?
            .ok_or(SwigStateError::RoleNotFound)?;

        let slot = Clock::get()?.slot;
        if role.authority.session_based() {
            role.authority.authenticate_session(
                all_accounts,
                migrate.authority_payload,
                migrate.data_payload,
                slot,
            )?;
        } else {
            role.authority.authenticate(
                all_accounts,
                migrate.authority_payload,
                migrate.data_payload,
                slot,
            )?;
        }

        let has_all_permission = role.get_action::<All>(&[])?.is_some();
        let has_manage_authority = role.get_action::<ManageAuthority>(&[])?.is_some();
        if !has_all_permission && !has_manage_authority {
            msg!("Authority lacks All or ManageAuthority permission");
            return Err(SwigAuthenticateError::PermissionDeniedToManageAuthority.into());
        }
    }

    // Migration resets the overlaid V2 counter to zero while preserving every
    // role. Reject any scoped V2 permission already stored on the V1 account so
    // it cannot become a future grant after migration.
    {
        let swig_data = unsafe { ctx.accounts.swig.borrow_data_unchecked() };
        let parts = Swig::split_parts(swig_data)?;
        let mut cursor = 0usize;
        for _ in 0..old_swig_roles {
            let position_end = cursor
                .checked_add(Position::LEN)
                .ok_or(ProgramError::InvalidAccountData)?;
            let position_bytes = parts
                .roles
                .get(cursor..position_end)
                .ok_or(ProgramError::InvalidAccountData)?;
            let position = unsafe { Position::load_unchecked(position_bytes)? };
            let boundary = position.boundary() as usize;
            let actions_start = position_end
                .checked_add(position.authority_length() as usize)
                .ok_or(ProgramError::InvalidAccountData)?;
            let actions = parts
                .roles
                .get(actions_start..boundary)
                .ok_or(ProgramError::InvalidAccountData)?;
            ActionLoader::validate_v2_actions(actions, 0)?;
            cursor = boundary;
        }
    }

    // The wallet-address PDA is canonical. Accepting any caller-selected valid
    // bump would let a re-migration bind the Swig to a different signer PDA.
    let (expected_wallet_address, canonical_wallet_bump) = pinocchio::pubkey::find_program_address(
        &swig_wallet_address_seeds(ctx.accounts.swig.key().as_ref()),
        &crate::ID,
    );
    if expected_wallet_address != *ctx.accounts.swig_wallet_address.key()
        || migrate.args.wallet_address_bump != canonical_wallet_bump
    {
        return Err(SwigError::InvalidSeedSwigAccount.into());
    }

    // V2 stores the canonical wallet bump followed by three immutable zero
    // padding bytes. Ignore bytes 44..48: they hold the mutable V2 sub-account
    // counter. V1 stored one rent-reserve u64 across the full eight-byte window.
    {
        let swig_data = unsafe { ctx.accounts.swig.borrow_data_unchecked() };
        let current_swig = unsafe { Swig::load_unchecked(&swig_data[..Swig::LEN])? };
        if current_swig.wallet_bump == canonical_wallet_bump && current_swig._padding == [0u8; 3] {
            msg!("Swig account is already migrated");
            return Err(SwigError::SwigAlreadyMigrated.into());
        }
    }

    // Validate wallet address account
    check_system_owner(
        ctx.accounts.swig_wallet_address,
        SwigError::OwnerMismatchSwigAccount,
    )?;
    check_zero_data(
        ctx.accounts.swig_wallet_address,
        SwigError::AccountNotEmptySwigAccount,
    )?;

    // Create the new Swig structure with wallet_bump
    let new_swig = Swig::new(old_swig_id, old_swig_bump, canonical_wallet_bump);

    // Ensure the role counter and roles count are preserved
    let mut new_swig_with_preserved_data = new_swig;
    new_swig_with_preserved_data.roles = old_swig_roles;
    new_swig_with_preserved_data.role_counter = old_swig_role_counter;

    // Update the Swig account data in-place
    // Only modify the first 48 bytes (Swig struct), leaving all role/action data
    // intact
    {
        let mut swig_data_mut = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
        let new_swig_bytes = new_swig_with_preserved_data.into_bytes()?;
        swig_data_mut[..Swig::LEN].copy_from_slice(new_swig_bytes);
    }

    // Create the wallet address account by transferring rent-exempt lamports
    let wallet_address_rent_exemption = Rent::get()?.minimum_balance(0); // 0 space for system account

    // Get current lamports in wallet address account
    let current_wallet_lamports =
        unsafe { *ctx.accounts.swig_wallet_address.borrow_lamports_unchecked() };

    // Only transfer if the account needs more lamports for rent exemption
    let wallet_lamports_to_transfer = if current_wallet_lamports >= wallet_address_rent_exemption {
        0
    } else {
        wallet_address_rent_exemption - current_wallet_lamports
    };

    if wallet_lamports_to_transfer > 0 {
        // Use CPI to system program for clean lamport transfer
        pinocchio_system::instructions::Transfer {
            from: ctx.accounts.payer,
            to: ctx.accounts.swig_wallet_address,
            lamports: wallet_lamports_to_transfer,
        }
        .invoke()?;
    }

    Ok(())
}
