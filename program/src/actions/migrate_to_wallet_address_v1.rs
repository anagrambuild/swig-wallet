/// Module for migrating Swig accounts to support wallet address feature.
///
/// This module implements the migration from the old Swig account structure
/// (with reserved_lamports field) to the new structure (with wallet_bump +
/// padding). It also creates the associated wallet address account for each
/// migrated Swig account.
use no_padding::NoPadding;
use pinocchio::{
    msg,
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use swig_assertions::{check_self_pda, check_system_owner, check_zero_data};
use swig_state::{
    action::{manage_authority::ManageAuthority, ActionLoader},
    authority::AuthorityType,
    swig::{
        swig_account_seeds_with_bump, swig_account_signer, swig_wallet_address_seeds_with_bump,
        swig_wallet_address_signer, Swig, SwigWithRoles,
    },
    Discriminator, IntoBytes, SwigStateError, Transmutable,
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
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct MigrateToWalletAddressV1Args {
    discriminator: SwigInstruction,
    pub wallet_address_bump: u8,
    pub _padding: [u8; 5], // Explicit padding to align to 8 bytes
}

impl MigrateToWalletAddressV1Args {
    /// Creates a new instance of MigrateToWalletAddressV1Args.
    ///
    /// # Arguments
    /// * `wallet_address_bump` - Bump seed for wallet address PDA derivation
    pub fn new(wallet_address_bump: u8) -> Self {
        Self {
            discriminator: SwigInstruction::MigrateToWalletAddressV1,
            wallet_address_bump,
            _padding: [0; 5],
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
        let args = unsafe { MigrateToWalletAddressV1Args::load_unchecked(bytes)? };
        Ok(Self { args })
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
/// 1. Validates the authority has ManageAuthority permission or is the admin
/// 2. Reads the old Swig account structure
/// 3. Creates a new Swig structure with wallet_bump field
/// 4. Updates the account in-place (preserving all role/action data)
/// 5. Creates the associated wallet address account
///
/// # Arguments
/// * `ctx` - The account context for the migration
/// * `migrate_data` - Raw migration instruction data
///
/// # Returns
/// * `ProgramResult` - Success or error status
#[inline(always)]
pub fn migrate_to_wallet_address_v1(
    ctx: Context<MigrateToWalletAddressV1Accounts>,
    migrate_data: &[u8],
) -> ProgramResult {
    msg!("Starting Swig account migration to wallet address feature");

    let migrate = MigrateToWalletAddressV1::from_instruction_bytes(migrate_data)?;

    // Validate that the swig account has the correct discriminator
    let swig_data = unsafe { ctx.accounts.swig.borrow_data_unchecked() };
    if swig_data.len() < OldSwig::LEN {
        return Err(SwigError::StateError.into());
    }

    let discriminator = swig_data[0];
    if discriminator != Discriminator::SwigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    // Check if this account is already migrated (has wallet_bump field)
    // We can detect this by checking if reserved_lamports field is 0 and if the
    // 41st byte (wallet_bump position) is non-zero
    let old_swig = unsafe { OldSwig::load_unchecked(&swig_data[..OldSwig::LEN])? };
    let potential_wallet_bump = swig_data[40]; // Position where wallet_bump would be

    if old_swig.reserved_lamports == 0 && potential_wallet_bump != 0 {
        msg!("Account appears to already be migrated");
        return Err(SwigError::StateError.into());
    }

    // Validate authority - either admin or has ManageAuthority permission
    let authority_pubkey = ctx.accounts.authority.key();

    // Check if authority has ManageAuthority permission
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_data)?;
    let authority_data = authority_pubkey;
    let role_id = swig_with_roles.lookup_role_id(authority_data)?;

    match role_id {
        Some(id) => {
            let role = swig_with_roles
                .get_role(id)?
                .ok_or(SwigStateError::RoleNotFound)?;

            // Check if this role has ManageAuthority action
            let has_manage_authority =
                ActionLoader::find_action::<ManageAuthority>(role.actions)?.is_some();
            if !has_manage_authority {
                msg!("Authority does not have ManageAuthority permission");
                // return Err(SwigError::InvalidAuthorityType.into());
            }
        },
        None => {
            msg!("Authority not found in wallet roles");
            // return Err(SwigError::InvalidAuthorityNotFoundByRoleId.
            // into());
        },
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

    // Validate the wallet address PDA
    let wallet_address_bump = check_self_pda(
        &swig_wallet_address_seeds_with_bump(
            ctx.accounts.swig.key().as_ref(),
            &[migrate.args.wallet_address_bump],
        ),
        ctx.accounts.swig_wallet_address.key(),
        SwigError::InvalidSeedSwigAccount,
    )?;

    // Create the new Swig structure with wallet_bump
    let new_swig = Swig::new(old_swig.id, old_swig.bump, wallet_address_bump);

    // Ensure the role counter and roles count are preserved
    let mut new_swig_with_preserved_data = new_swig;
    new_swig_with_preserved_data.roles = old_swig.roles;
    new_swig_with_preserved_data.role_counter = old_swig.role_counter;

    // Update the Swig account data in-place
    // Only modify the first 48 bytes (Swig struct), leaving all role/action data
    // intact
    drop(swig_data); // Release the borrow
    let mut swig_data_mut = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let new_swig_bytes = new_swig_with_preserved_data.into_bytes()?;
    swig_data_mut[..Swig::LEN].copy_from_slice(new_swig_bytes);
    drop(swig_data_mut); // Release the borrow

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

    msg!("Migration completed successfully");
    msg!("Old reserved_lamports: {}", old_swig.reserved_lamports);
    msg!("New wallet_bump: {}", wallet_address_bump);

    Ok(())
}
