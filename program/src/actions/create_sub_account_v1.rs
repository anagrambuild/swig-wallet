/// Module for creating sub-accounts within a Swig wallet.
/// This module implements functionality to create and initialize sub-accounts
/// that operate under the authority of a main wallet account with specific
/// permissions and constraints.
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use swig_assertions::*;
use swig_state::{
    action::{
        all::All, manage_authority::ManageAuthority, sub_account::SubAccount, Action, ActionLoader,
        Actionable, Permission,
    },
    authority::AuthorityType,
    role::RoleMut,
    swig::{
        sub_account_seeds_with_bump, sub_account_seeds_with_index_and_bump, sub_account_signer,
        swig_account_seeds_with_bump, swig_account_signer, Swig,
    },
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, CreateSubAccountV1Accounts},
        SwigInstruction,
    },
};

/// Arguments for creating a new sub-account in a Swig wallet.
///
/// # Fields
/// * `discriminator` - The instruction type identifier
/// * `_padding1` - Padding bytes for alignment
/// * `role_id` - ID of the role creating the sub-account
/// * `sub_account_bump` - Bump seed for sub-account PDA derivation
/// * `_padding2` - Additional padding bytes for alignment
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct CreateSubAccountV1Args {
    discriminator: SwigInstruction,
    _padding1: u16,
    pub role_id: u32,
    pub sub_account_bump: u8,
    /// Index of this sub-account (0-254). Enables multiple sub-accounts per role.
    /// Index 0 uses legacy PDA derivation for backwards compatibility.
    pub sub_account_index: u8,
    _padding2: [u8; 6],
}

impl CreateSubAccountV1Args {
    /// Creates a new instance of CreateSubAccountV1Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the role creating the sub-account
    /// * `sub_account_bump` - Bump seed for sub-account PDA derivation
    pub fn new(role_id: u32, sub_account_bump: u8, sub_account_index: u8) -> Self {
        Self {
            discriminator: SwigInstruction::CreateSubAccountV1,
            _padding1: 0,
            role_id,
            sub_account_bump,
            sub_account_index,
            _padding2: [0; 6],
        }
    }
}

impl Transmutable for CreateSubAccountV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for CreateSubAccountV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Struct representing the complete create sub-account instruction data.
///
/// # Fields
/// * `args` - The sub-account creation arguments
/// * `authority_payload` - Authority-specific payload data
/// * `data_payload` - Raw instruction data payload
pub struct CreateSubAccountV1<'a> {
    pub args: &'a CreateSubAccountV1Args,
    pub authority_payload: &'a [u8],
    pub data_payload: &'a [u8],
}

impl<'a> CreateSubAccountV1<'a> {
    /// Parses the instruction data bytes into a CreateSubAccountV1 instance.
    ///
    /// # Arguments
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < CreateSubAccountV1Args::LEN {
            return Err(SwigError::InvalidSwigCreateInstructionDataTooShort.into());
        }

        // Split the data into args and the rest (authority payload)
        let (args_data, authority_payload) = data.split_at(CreateSubAccountV1Args::LEN);

        let args = unsafe { CreateSubAccountV1Args::load_unchecked(args_data)? };

        Ok(Self {
            args,
            authority_payload,
            data_payload: args_data,
        })
    }
}

/// Creates a new sub-account under a Swig wallet.
///
/// This function handles the complete flow of sub-account creation:
/// 1. Validates the parent wallet and authority
/// 2. Verifies the role has sub-account creation permission
/// 3. Derives and validates the sub-account address
/// 4. Creates and initializes the sub-account with proper settings
///
/// # Arguments
/// * `ctx` - The account context for sub-account creation
/// * `data` - Raw sub-account creation instruction data
/// * `all_accounts` - All accounts involved in the operation
///
/// # Returns
/// * `ProgramResult` - Success or error status
#[inline(always)]
pub fn create_sub_account_v1(
    ctx: Context<CreateSubAccountV1Accounts>,
    data: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    // Check that the swig account is owned by our program
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    // Check that the sub_account is system owned (will hold assets)
    check_system_owner(ctx.accounts.sub_account, SwigError::OwnerMismatchSubAccount)?;

    // Parse the instruction data
    let create_sub_account = CreateSubAccountV1::from_instruction_bytes(data)?;

    // Verify the swig account data
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    // Split the swig account data to get the header and roles
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_unchecked(swig_header)? };

    // Get the role using the role_id from the instruction
    let role_opt = Swig::get_mut_role(create_sub_account.args.role_id, swig_roles)?;
    if role_opt.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let role = role_opt.unwrap();
    // Authenticate the authority
    let clock = Clock::get()?;
    let slot = clock.slot;
    // Authenticate based on authority type (session-based or not)
    if role.authority.session_based() {
        role.authority.authenticate_session(
            &all_accounts,
            create_sub_account.authority_payload,
            create_sub_account.data_payload,
            slot,
        )?;
    } else {
        role.authority.authenticate(
            &all_accounts,
            create_sub_account.authority_payload,
            create_sub_account.data_payload,
            slot,
        )?;
    }
    let sub_account_index = create_sub_account.args.sub_account_index;
    
    // Validate index is within bounds (0-254, reserve 255 for future use)
    if sub_account_index >= 255 {
        return Err(SwigError::InvalidSubAccountIndex.into());
    }
    
    // First check if the role has SubAccount permission at all
    let mut has_sub_account_permission = false;
    let mut cursor = 0;
    let end_pos = role.actions.len();
    
    while cursor < end_pos {
        let action_header = unsafe {
            Action::load_unchecked(&role.actions[cursor..cursor + Action::LEN])?
        };
        cursor += Action::LEN;
        
        if action_header.permission()? == Permission::SubAccount {
            has_sub_account_permission = true;
            break;
        }
        
        cursor = action_header.boundary() as usize;
    }
    
    if !has_sub_account_permission {
        return Err(SwigError::AuthorityCannotCreateSubAccount.into());
    }
    
    // Find the SubAccount action for this specific index
    // We need custom logic to match by index since multiple SubAccount actions may exist
    let mut found_action_offset: Option<usize> = None;
    let mut cursor = 0;
    
    while cursor < end_pos {
        let action_header = unsafe {
            Action::load_unchecked(&role.actions[cursor..cursor + Action::LEN])?
        };
        cursor += Action::LEN;
        
        if action_header.permission()? == Permission::SubAccount {
            let action_obj = unsafe {
                SubAccount::load_unchecked(&role.actions[cursor..cursor + SubAccount::LEN])?
            };
            
            // Match on index and empty sub_account field (creation state)
            if action_obj.sub_account_index == sub_account_index 
                && action_obj.sub_account == [0u8; 32] {
                found_action_offset = Some(cursor);
                break;
            }
        }
        
        cursor = action_header.boundary() as usize;
    }
    
    if found_action_offset.is_none() {
        return Err(SwigError::SubAccountActionNotFound.into());
    }
    
    // SEQUENTIAL INDEX VALIDATION:
    // If creating index N > 0, verify index N-1 exists and is populated
    if sub_account_index > 0 {
        let mut prev_index_exists = false;
        let mut cursor = 0;
        
        while cursor < end_pos {
            let action_header = unsafe {
                Action::load_unchecked(&role.actions[cursor..cursor + Action::LEN])?
            };
            cursor += Action::LEN;
            
            if action_header.permission()? == Permission::SubAccount {
                let action_obj = unsafe {
                    SubAccount::load_unchecked(&role.actions[cursor..cursor + SubAccount::LEN])?
                };
                
                // Check if previous index exists and is created (not zeroed)
                if action_obj.sub_account_index == sub_account_index - 1
                    && action_obj.sub_account != [0u8; 32] {
                    prev_index_exists = true;
                    break;
                }
            }
            
            cursor = action_header.boundary() as usize;
        }
        
        if !prev_index_exists {
            return Err(SwigError::SubAccountIndexNotSequential.into());
        }
    }
    
    // Derive sub-account PDA based on index
    // Index 0 uses legacy derivation (3 seeds) for backwards compatibility
    // Index 1+ uses new derivation (4 seeds) with index
    let role_id_bytes = create_sub_account.args.role_id.to_le_bytes();
    let bump_byte = [create_sub_account.args.sub_account_bump];
    
    let bump = if sub_account_index == 0 {
        // Legacy derivation for backwards compatibility
        let sub_account_seeds = sub_account_seeds_with_bump(&swig.id, &role_id_bytes, &bump_byte);
        check_self_pda(
            &sub_account_seeds,
            ctx.accounts.sub_account.key(),
            SwigError::InvalidSeedSwigAccount,
        )?
    } else {
        // New derivation with index
        let index_bytes = [sub_account_index];
        let sub_account_seeds = sub_account_seeds_with_index_and_bump(
            &swig.id,
            &role_id_bytes,
            &index_bytes,
            &bump_byte,
        );
        check_self_pda(
            &sub_account_seeds,
            ctx.accounts.sub_account.key(),
            SwigError::InvalidSeedSwigAccount,
        )?
    };

    // Transfer lamports to the sub_account to make it system-owned and rent-exempt
    // This follows the same pattern as swig_wallet_address creation in create_v1.rs
    let sub_account_rent_exemption = Rent::get()?.minimum_balance(0); // 0 space for system account

    // Get current lamports in sub-account
    let current_sub_account_lamports =
        unsafe { *ctx.accounts.sub_account.borrow_lamports_unchecked() };

    // Only transfer if the account needs more lamports for rent exemption
    let sub_account_lamports_to_transfer =
        if current_sub_account_lamports >= sub_account_rent_exemption {
            0
        } else {
            sub_account_rent_exemption - current_sub_account_lamports
        };

    if sub_account_lamports_to_transfer > 0 {
        // Use CPI to system program for clean lamport transfer
        pinocchio_system::instructions::Transfer {
            from: ctx.accounts.payer,
            to: ctx.accounts.sub_account,
            lamports: sub_account_lamports_to_transfer,
        }
        .invoke()?;
    }

    // Update the SubAccount action to store all sub-account metadata
    let action_offset = found_action_offset.unwrap();
    let sub_account_action_mut = unsafe {
        SubAccount::load_mut_unchecked(
            &mut role.actions[action_offset..action_offset + SubAccount::LEN]
        )?
    };
    
    sub_account_action_mut
        .sub_account
        .copy_from_slice(ctx.accounts.sub_account.key().as_ref());
    sub_account_action_mut.bump = create_sub_account.args.sub_account_bump;
    sub_account_action_mut.enabled = true; // Default to enabled
    sub_account_action_mut.role_id = create_sub_account.args.role_id;
    sub_account_action_mut.swig_id = swig.id;
    sub_account_action_mut.sub_account_index = sub_account_index;

    Ok(())
}
