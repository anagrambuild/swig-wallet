/// Module for creating a new Swig wallet account with initial settings and
/// authorities. This module handles the creation of new wallet accounts with
/// specified authority types and associated actions.
use no_padding::NoPadding;
use pinocchio::{
    msg,
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_pubkey::pubkey;
use pinocchio_system::instructions::CreateAccount;
use swig_assertions::{check_self_pda, check_system_owner, check_zero_data};
use swig_state::{
    action::{all::All, manage_authority::ManageAuthority, ActionLoader, Actionable},
    authority::{authority_type_to_length, AuthorityType},
    role::Position,
    swig::{
        swig_account_seeds_with_bump, swig_account_signer, swig_wallet_address_seeds_with_bump,
        swig_wallet_address_signer, Swig, SwigBuilder,
    },
    IntoBytes, Transmutable,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, CreateV1Accounts},
        SwigInstruction,
    },
};

/// Arguments for creating a new Swig wallet account.
///
/// # Fields
/// * `discriminator` - The instruction type identifier
/// * `authority_type` - Type of authority to be created
/// * `authority_data_len` - Length of the authority data
/// * `bump` - Bump seed for PDA derivation
/// * `wallet_address_bump` - Bump seed for wallet address PDA derivation
/// * `id` - Unique identifier for the wallet
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct CreateV1Args {
    discriminator: SwigInstruction,
    pub authority_type: u16,
    pub authority_data_len: u16,
    pub bump: u8,
    pub wallet_address_bump: u8,
    pub id: [u8; 32],
}

impl CreateV1Args {
    /// Creates a new instance of CreateV1Args.
    ///
    /// # Arguments
    /// * `id` - Unique identifier for the wallet
    /// * `bump` - Bump seed for PDA derivation
    /// * `wallet_address_bump` - Bump seed for wallet address PDA derivation
    /// * `authority_type` - Type of authority to create
    /// * `authority_data_len` - Length of the authority data
    pub fn new(
        id: [u8; 32],
        bump: u8,
        authority_type: AuthorityType,
        authority_data_len: u16,
        wallet_address_bump: u8,
    ) -> Self {
        Self {
            discriminator: SwigInstruction::CreateV1,
            id,
            bump,
            authority_type: authority_type as u16,
            authority_data_len,
            wallet_address_bump,
        }
    }
}

impl Transmutable for CreateV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for CreateV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Struct representing the complete create wallet instruction data.
///
/// # Fields
/// * `args` - The creation arguments
/// * `authority_data` - Raw authority data
/// * `actions` - Raw actions data
pub struct CreateV1<'a> {
    pub args: &'a CreateV1Args,
    pub authority_data: &'a [u8],
    pub actions: &'a [u8],
}

impl<'a> CreateV1<'a> {
    /// Parses the instruction data bytes into a CreateV1 instance.
    ///
    /// # Arguments
    /// * `bytes` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(bytes: &'a [u8]) -> Result<Self, ProgramError> {
        if bytes.len() < CreateV1Args::LEN {
            return Err(SwigError::InvalidSwigCreateInstructionDataTooShort.into());
        }
        let (args, rest) = unsafe { bytes.split_at_unchecked(CreateV1Args::LEN) };
        let args = unsafe { CreateV1Args::load_unchecked(args)? };
        let (authority_data, actions) =
            unsafe { rest.split_at_unchecked(args.authority_data_len as usize) };
        Ok(Self {
            args,
            authority_data,
            actions,
        })
    }

    /// Retrieves a specific action from the actions data.
    ///
    /// # Type Parameters
    /// * `T` - The action type to retrieve
    ///
    /// # Returns
    /// * `Result<Option<&'a T>, ProgramError>` - The action if found
    pub fn get_action<T: Actionable<'a>>(&'a self) -> Result<Option<&'a T>, ProgramError> {
        ActionLoader::find_action::<T>(self.actions)
    }
}

/// Creates a new Swig wallet account with the specified configuration.
///
/// # Arguments
/// * `ctx` - The account context for the creation
/// * `create` - Raw creation instruction data
///
/// # Returns
/// * `ProgramResult` - Success or error status
#[inline(always)]
pub fn create_v1(ctx: Context<CreateV1Accounts>, create: &[u8]) -> ProgramResult {
    check_system_owner(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_zero_data(ctx.accounts.swig, SwigError::AccountNotEmptySwigAccount)?;

    let create_v1 = CreateV1::from_instruction_bytes(create)?;
    let bump = check_self_pda(
        &swig_account_seeds_with_bump(&create_v1.args.id, &[create_v1.args.bump]),
        ctx.accounts.swig.key(),
        SwigError::InvalidSeedSwigAccount,
    )?;

    // Validate swig wallet address account
    check_system_owner(
        ctx.accounts.swig_wallet_address,
        SwigError::OwnerMismatchSwigAccount,
    )?;
    check_zero_data(
        ctx.accounts.swig_wallet_address,
        SwigError::AccountNotEmptySwigAccount,
    )?;

    let wallet_address_bump = check_self_pda(
        &swig_wallet_address_seeds_with_bump(
            ctx.accounts.swig.key().as_ref(),
            &[create_v1.args.wallet_address_bump],
        ),
        ctx.accounts.swig_wallet_address.key(),
        SwigError::InvalidSeedSwigAccount,
    )?;

    // Validate swig wallet address PDA
    let wallet_address_bump = check_self_pda(
        &swig_wallet_address_seeds_with_bump(
            ctx.accounts.swig.key().as_ref(),
            &[create_v1.args.wallet_address_bump],
        ),
        ctx.accounts.swig_wallet_address.key(),
        SwigError::InvalidSeedSwigAccount,
    )?;

    let manage_authority_action = create_v1.get_action::<ManageAuthority>()?;
    let all_action = create_v1.get_action::<All>()?;
    if manage_authority_action.is_none() && all_action.is_none() {
        msg!("Root authority type must had one of the following actions: ManageAuthority or All");
        return Err(SwigError::InvalidAuthorityType.into());
    }
    let authority_type = AuthorityType::try_from(create_v1.args.authority_type)?;
    let authority_length = authority_type_to_length(&authority_type)?;
    let account_size = core::alloc::Layout::from_size_align(
        Swig::LEN + Position::LEN + authority_length + create_v1.actions.len() + Position::LEN + 32,
        core::mem::size_of::<u64>(),
    )
    .map_err(|_| SwigError::InvalidAlignment)?
    .pad_to_align()
    .size();
    let lamports_needed = Rent::get()?.minimum_balance(account_size);
    let swig = Swig::new(create_v1.args.id, bump, wallet_address_bump);

    // Get current lamports in the account
    let current_lamports = unsafe { *ctx.accounts.swig.borrow_lamports_unchecked() };

    // Only transfer additional lamports if needed for rent exemption
    let lamports_to_transfer = if current_lamports >= lamports_needed {
        0
    } else {
        lamports_needed - current_lamports
    };

    CreateAccount {
        from: ctx.accounts.payer,
        to: ctx.accounts.swig,
        lamports: lamports_to_transfer,
        space: account_size as u64,
        owner: &crate::ID,
    }
    .invoke_signed(&[swig_account_signer(&swig.id, &[swig.bump])
        .as_slice()
        .into()])?;

    // Transfer lamports to the swig_wallet_address via CPI to system program
    // This creates a system program owned account by transferring SOL to it
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

    let swig_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let mut swig_builder = SwigBuilder::create(swig_data, swig)?;

    swig_builder.add_role(
        AuthorityType::Ed25519,
        pubkey!("111111111111111111111111111111111111111111").as_ref(),
        &[],
    )?;

    swig_builder.add_role(authority_type, create_v1.authority_data, create_v1.actions)?;
    Ok(())
}
