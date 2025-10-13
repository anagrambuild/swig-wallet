/// Module for transferring assets from swig account to swig wallet address.
///
/// This module implements functionality to transfer all assets (SOL and SPL
/// tokens) held by the swig account to the swig wallet address account. This is
/// particularly useful after migration where assets need to be moved from the
/// old swig account to the new wallet address structure.
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    instruction::Signer,
    memory::sol_memcmp,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_assertions::{check_self_owned, check_self_pda};
use swig_state::{
    action::{all::All, manage_authority::ManageAuthority},
    role::RoleMut,
    swig::{swig_account_signer, swig_wallet_address_seeds_with_bump, Swig},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, TransferAssetsV1Accounts},
        SwigInstruction,
    },
    util::TokenTransfer,
    AccountClassification, SPL_TOKEN_2022_ID, SPL_TOKEN_ID,
};

/// Arguments for transferring assets from swig account to swig wallet address.
///
/// # Fields
/// * `discriminator` - The instruction type identifier
/// * `_padding` - Padding bytes for alignment
/// * `role_id` - ID of the role performing the transfer (must have All or
///   ManageAuthority permissions)
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct TransferAssetsV1Args {
    discriminator: SwigInstruction,
    pub _padding: u16,
    pub role_id: u32,
}

impl TransferAssetsV1Args {
    /// Creates a new instance of TransferAssetsV1Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the role performing the transfer
    pub fn new(role_id: u32) -> Self {
        Self {
            discriminator: SwigInstruction::TransferAssetsV1,
            _padding: 0,
            role_id,
        }
    }
}

impl Transmutable for TransferAssetsV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for TransferAssetsV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Struct for parsing the TransferAssetsV1 instruction data
pub struct TransferAssetsV1<'a> {
    pub args: &'a TransferAssetsV1Args,
    pub authority_payload: &'a [u8],
}

impl<'a> TransferAssetsV1<'a> {
    /// Parses the instruction data bytes into a TransferAssetsV1 instance.
    ///
    /// # Arguments
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < TransferAssetsV1Args::LEN {
            return Err(SwigError::InvalidSwigSignInstructionDataTooShort.into());
        }

        // Split the data into args and authority payload
        let (args_data, authority_payload) = data.split_at(TransferAssetsV1Args::LEN);

        let args = unsafe { TransferAssetsV1Args::load_unchecked(args_data)? };

        Ok(Self {
            args,
            authority_payload,
        })
    }
}

/// Transfers all assets from swig account to swig wallet address.
///
/// This function:
/// 1. Validates that the swig account has been migrated (has wallet_bump)
/// 2. Authenticates the authority has All or ManageAuthority permissions
/// 3. Transfers all SOL from swig account to swig wallet address
/// 4. Transfers all SPL tokens from swig account to swig wallet address
///
/// # Arguments
/// * `ctx` - Account context containing swig, wallet address, payer accounts
/// * `accounts` - All accounts passed to the instruction (for token accounts)
/// * `data` - Raw instruction data
/// * `account_classification` - Classification of accounts for token operations
///
/// # Returns
/// * `ProgramResult` - Success or error status
pub fn transfer_assets_v1(
    ctx: Context<TransferAssetsV1Accounts>,
    accounts: &[AccountInfo],
    data: &[u8],
    account_classification: &[AccountClassification],
) -> ProgramResult {
    // Verify the swig account is owned by this program
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;

    let transfer_ix = TransferAssetsV1::from_instruction_bytes(data)?;

    // Load and validate swig account
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_unchecked(&swig_header)? };

    let (swig_roles, _) =
        unsafe { swig_roles.split_at_mut_unchecked(swig.roles_boundary as usize) };

    // Verify the swig account has the correct discriminator
    if unsafe { *swig_header.get_unchecked(0) } != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    // Ensure this is a migrated swig account (has wallet_bump)
    if swig.wallet_bump == 0 {
        return Err(SwigError::InvalidSwigCreateInstructionDataTooShort.into());
    }

    // Verify swig wallet address derivation using PDA check
    check_self_pda(
        &swig_wallet_address_seeds_with_bump(ctx.accounts.swig.key().as_ref(), &[swig.wallet_bump]),
        ctx.accounts.swig_wallet_address.key(),
        SwigError::InvalidSeedSwigAccount,
    )?;

    // Get the role and authenticate the authority
    let role_id = transfer_ix.args.role_id;
    let role_opt = Swig::get_mut_role(role_id, swig_roles)?;
    if role_opt.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let role = role_opt.unwrap();

    // Authenticate the authority
    let current_slot = Clock::get()?.slot;

    if role.authority.session_based() {
        role.authority.authenticate_session(
            accounts,
            transfer_ix.authority_payload,
            transfer_ix.args.into_bytes()?,
            current_slot,
        )?;
    } else {
        role.authority.authenticate(
            accounts,
            transfer_ix.authority_payload,
            transfer_ix.args.into_bytes()?,
            current_slot,
        )?;
    }

    // Check if the role has All or ManageAuthority permissions
    let has_all_permission = role.get_action::<All>(&[])?.is_some();
    let has_manage_authority = role.get_action::<ManageAuthority>(&[])?.is_some();
    if !has_all_permission && !has_manage_authority {
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    }

    // Create signer seeds for the swig account
    let bump = [swig.bump];
    let swig_signer = swig_account_signer(ctx.accounts.swig.key().as_ref(), &bump);

    // Transfer SOL from swig to swig wallet address
    let swig_lamports = ctx.accounts.swig.lamports();
    let rent = pinocchio::sysvars::rent::Rent::get()?;
    let swig_data_len = ctx.accounts.swig.data_len();
    let min_rent = rent.minimum_balance(swig_data_len);

    if swig_lamports > min_rent {
        let transfer_amount = swig_lamports - min_rent;
        // Transfer SOL by directly manipulating lamports
        unsafe {
            *ctx.accounts.swig.borrow_mut_lamports_unchecked() -= transfer_amount;
            *ctx.accounts
                .swig_wallet_address
                .borrow_mut_lamports_unchecked() += transfer_amount;
        }
    }

    // Transfer SPL tokens
    // We need to iterate through the remaining accounts to find token accounts
    let base_account_count = 4; // swig, swig_wallet_address, payer, system_program

    if accounts.len() > base_account_count {
        for i in (base_account_count..accounts.len()).step_by(3) {
            // Each token transfer requires 3 accounts: source, destination, token_program
            if i + 2 >= accounts.len() {
                break;
            }

            let source_token_account = &accounts[i];
            let dest_token_account = &accounts[i + 1];
            let token_program = &accounts[i + 2];

            // Verify this is a valid token program
            if token_program.key() != &SPL_TOKEN_ID && token_program.key() != &SPL_TOKEN_2022_ID {
                continue;
            }

            // Check if source account is owned by swig account
            let source_data = source_token_account.try_borrow_data()?;
            if source_data.len() < 72 {
                continue;
            }

            let source_owner_bytes = &source_data[32..64];
            if unsafe { sol_memcmp(source_owner_bytes, ctx.accounts.swig.key().as_ref(), 32) } != 0
            {
                continue;
            }

            // Check if destination account is owned by swig wallet address
            let dest_data = dest_token_account.try_borrow_data()?;
            if dest_data.len() < 72 {
                drop(source_data);
                continue;
            }

            let dest_owner_bytes = &dest_data[32..64];
            if unsafe {
                sol_memcmp(
                    dest_owner_bytes,
                    ctx.accounts.swig_wallet_address.key().as_ref(),
                    32,
                )
            } != 0
            {
                drop(source_data);
                drop(dest_data);
                continue;
            }

            // Get the token balance
            let amount_bytes = &source_data[64..72];
            let amount = unsafe {
                u64::from_le_bytes([
                    amount_bytes[0],
                    amount_bytes[1],
                    amount_bytes[2],
                    amount_bytes[3],
                    amount_bytes[4],
                    amount_bytes[5],
                    amount_bytes[6],
                    amount_bytes[7],
                ])
            };

            if amount > 0 {
                drop(source_data); // Release borrow
                drop(dest_data); // Release borrow

                // Transfer tokens using CPI
                let token_transfer = TokenTransfer {
                    token_program: token_program.key(),
                    from: source_token_account,
                    to: dest_token_account,
                    authority: ctx.accounts.swig,
                    amount,
                };
                token_transfer.invoke_signed(&[(&swig_signer).into()])?;
            }
        }
    }

    Ok(())
}
