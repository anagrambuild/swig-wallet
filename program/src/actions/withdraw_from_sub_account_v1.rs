/// Module for withdrawing funds from sub-accounts to their parent Swig wallet.
/// This module implements functionality to transfer both SOL and SPL tokens
/// from sub-accounts back to their parent wallet, with proper authentication
/// and permission checks.
use core::mem::MaybeUninit;

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
use pinocchio_token::instructions::Transfer;
use swig_assertions::*;
use swig_state::{
    action::{all::All, manage_authority::ManageAuthority, sub_account::SubAccount},
    role::{Position, Role, RoleMut},
    swig::{sub_account_signer, swig_wallet_address_seeds, Swig, SwigWithRoles},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, WithdrawFromSubAccountV1Accounts},
        SwigInstruction,
    },
    util::TokenTransfer,
    AccountClassification, SPL_TOKEN_2022_ID, SPL_TOKEN_ID,
};

/// Arguments for withdrawing funds from a sub-account.
///
/// # Fields
/// * `discriminator` - The instruction type identifier
/// * `_padding` - Padding bytes for alignment
/// * `role_id` - ID of the role performing the withdrawal
/// * `amount` - Amount of tokens/SOL to withdraw
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct WithdrawFromSubAccountV1Args {
    discriminator: SwigInstruction,
    _padding: u16,
    pub role_id: u32,
    pub amount: u64,
}

impl WithdrawFromSubAccountV1Args {
    /// Creates a new instance of WithdrawFromSubAccountV1Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the role performing the withdrawal
    /// * `amount` - Amount of tokens/SOL to withdraw
    pub fn new(role_id: u32, amount: u64) -> Self {
        Self {
            discriminator: SwigInstruction::WithdrawFromSubAccountV1,
            _padding: 0,
            role_id,
            amount,
        }
    }
}

impl Transmutable for WithdrawFromSubAccountV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for WithdrawFromSubAccountV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Struct for parsing the WithdrawFromSubAccountV1 instruction data
pub struct WithdrawFromSubAccountV1<'a> {
    pub args: &'a WithdrawFromSubAccountV1Args,
    pub authority_payload: &'a [u8],
    pub data_payload: &'a [u8],
}

impl<'a> WithdrawFromSubAccountV1<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < WithdrawFromSubAccountV1Args::LEN {
            return Err(SwigError::InvalidSwigSignInstructionDataTooShort.into());
        }

        // Split the data into args and the rest (authority payload)
        let (args_data, authority_payload) = data.split_at(WithdrawFromSubAccountV1Args::LEN);

        let args = unsafe { WithdrawFromSubAccountV1Args::load_unchecked(args_data)? };

        Ok(Self {
            args,
            authority_payload,
            data_payload: args_data,
        })
    }
}

/// Implementation of the WithdrawFromSubAccountV1 instruction handler
#[inline(always)]
pub fn withdraw_from_sub_account_v1(
    ctx: Context<WithdrawFromSubAccountV1Accounts>,
    all_accounts: &[AccountInfo],
    data: &[u8],
    account_classifiers: &[AccountClassification],
) -> ProgramResult {
    // Verify that the swig account is owned by our program and sub_account is
    // system owned
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_system_owner(ctx.accounts.sub_account, SwigError::OwnerMismatchSubAccount)?;
    check_system_owner(
        ctx.accounts.swig_wallet_address,
        SwigError::OwnerMismatchSwigAccount,
    )?;
    let withdraw = WithdrawFromSubAccountV1::from_instruction_bytes(data)?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_unchecked(&swig_header)? };

    let swig_wallet_address_seeds = swig_wallet_address_seeds(ctx.accounts.swig.key().as_ref());
    // Validate that the swig wallet address is the correct PDA derived from the
    // swig account
    let (expected_swig_wallet_address, _swig_wallet_bump) =
        pinocchio::pubkey::find_program_address(&swig_wallet_address_seeds, &crate::ID);
    if expected_swig_wallet_address != *ctx.accounts.swig_wallet_address.key() {
        msg!("Invalid swig wallet address PDA for sub account");
        return Err(SwigError::InvalidSwigSubAccountSwigIdMismatch.into());
    }

    // Verify the swig account has the correct discriminator
    if unsafe { *swig_header.get_unchecked(0) } != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }
    // We'll get sub-account metadata from the SubAccount action later after
    // authentication
    let role_opt = Swig::get_mut_role(withdraw.args.role_id, swig_roles)?;
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
            all_accounts,
            withdraw.authority_payload,
            withdraw.data_payload,
            slot,
        )?;
    } else {
        role.authority.authenticate(
            all_accounts,
            withdraw.authority_payload,
            withdraw.data_payload,
            slot,
        )?;
    }
    // Check if the role has the required permissions
    let all_action = role.get_action::<All>(&[])?;
    let manage_authority_action = role.get_action::<ManageAuthority>(&[])?;
    let sub_account_action =
        role.get_action::<SubAccount>(ctx.accounts.sub_account.key().as_ref())?;

    if all_action.is_none() && manage_authority_action.is_none() && sub_account_action.is_none() {
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    }

    // Get sub-account metadata from the SubAccount action
    // Validate permissions and sub-account relationship
    if let Some(action) = sub_account_action {
        // Validate sub-account relationship
        if action.swig_id != swig.id {
            return Err(SwigError::InvalidSwigSubAccountSwigIdMismatch.into());
        }
        if action.role_id != withdraw.args.role_id {
            return Err(SwigError::InvalidSwigSubAccountRoleIdMismatch.into());
        }
        if !action.enabled {
            return Err(SwigError::InvalidSwigSubAccountDisabled.into());
        }
    } else if all_action.is_some() || manage_authority_action.is_some() {
        let permission_type = if all_action.is_some() {
            "All"
        } else {
            "ManageAuthority"
        };

        // For All permission, allow withdrawal from any sub-account (no validation
        // needed) For ManageAuthority permission, restrict to sub-accounts
        // created by the withdrawing role
        if manage_authority_action.is_some() {
            let role_id_bytes = withdraw.args.role_id.to_le_bytes();
            let sub_account_seeds = swig_state::swig::sub_account_seeds(&swig.id, &role_id_bytes);
            let (expected_sub_account, _expected_bump) =
                pinocchio::pubkey::find_program_address(&sub_account_seeds, &crate::ID);

            if expected_sub_account != *ctx.accounts.sub_account.key() {
                return Err(SwigError::InvalidSwigSubAccountSwigIdMismatch.into());
            }
        }
    } else {
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    }

    let action_accounts_index = 4;
    let action_accounts_len = 7;
    let amount = withdraw.args.amount;

    // For signing, we need the correct role_id and bump
    // If we have a SubAccount action, use its metadata
    // If we have All/ManageAuthority permission, we need to find which role created
    // this sub-account
    let (signing_role_id, signing_bump) = if let Some(action) = sub_account_action {
        (action.role_id, action.bump)
    } else {
        // For All/ManageAuthority cases without SubAccount action, we need to find the
        // role that created this sub-account We'll try different role IDs to
        // see which one matches the given sub-account address
        let mut found_role_id = None;
        let mut found_bump = None;

        // Try role IDs from 0 to some reasonable maximum (let's try up to 10)
        for potential_role_id in 0u32..=10u32 {
            let role_id_bytes = potential_role_id.to_le_bytes();
            let sub_account_seeds = swig_state::swig::sub_account_seeds(&swig.id, &role_id_bytes);
            let (derived_address, bump) =
                pinocchio::pubkey::find_program_address(&sub_account_seeds, &crate::ID);

            if derived_address == *ctx.accounts.sub_account.key() {
                found_role_id = Some(potential_role_id);
                found_bump = Some(bump);
                break;
            }
        }

        match (found_role_id, found_bump) {
            (Some(role_id), Some(bump)) => (role_id, bump),
            _ => {
                msg!("Could not find the role_id that created this sub-account");
                return Err(SwigError::InvalidSwigSubAccountSwigIdMismatch.into());
            },
        }
    };

    if all_accounts.len() >= action_accounts_len {
        let token_account = &all_accounts[action_accounts_index + 2];
        let token_account_data = unsafe { token_account.borrow_data_unchecked() };
        // we dont need to check the owner of the token account because the token
        // program will check it in transfer

        let swig_token_account = &all_accounts[action_accounts_index + 3];
        let swig_token_account_data = unsafe { swig_token_account.borrow_data_unchecked() };
        let swig_token_account_owner = unsafe { swig_token_account_data.get_unchecked(32..64) };
        if unsafe {
            sol_memcmp(
                ctx.accounts.swig_wallet_address.key(),
                swig_token_account_owner,
                32,
            )
        } != 0
        {
            return Err(SwigError::InvalidSwigTokenAccountOwner.into());
        }

        let token_program = &all_accounts[action_accounts_index + 4];
        let token_account_program_owner = token_account.owner();
        let destination_program_owner = swig_token_account.owner();
        if token_account_program_owner != &SPL_TOKEN_ID
            && token_account_program_owner != &SPL_TOKEN_2022_ID
        {
            return Err(SwigError::OwnerMismatchTokenAccount.into());
        }
        if destination_program_owner != token_account_program_owner {
            return Err(SwigError::InvalidOperation.into());
        }
        let token_transfer = TokenTransfer {
            from: token_account,
            to: swig_token_account,
            authority: ctx.accounts.sub_account,
            amount,
            token_program: token_account_program_owner,
        };

        let role_id_bytes = signing_role_id.to_le_bytes();
        let bump_byte = [signing_bump];
        let seeds = sub_account_signer(&swig.id, &role_id_bytes, &bump_byte);
        let signer = seeds.as_slice();
        // Invoke the token transfer with the PDA signer
        token_transfer.invoke_signed(&[signer.into()])?;
    } else {
        // SOL transfer from system-owned sub-account to swig account
        if amount > ctx.accounts.sub_account.lamports() {
            return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
        }

        // Use the signing parameters we already discovered above
        // Create system transfer instruction using PDA as signer
        let role_id_bytes = signing_role_id.to_le_bytes();
        let bump_byte = [signing_bump];
        let seeds = sub_account_signer(&swig.id, &role_id_bytes, &bump_byte);
        let signer = seeds.as_slice();
        // Use system program transfer
        let transfer_instruction = pinocchio_system::instructions::Transfer {
            from: ctx.accounts.sub_account,
            to: ctx.accounts.swig_wallet_address,
            lamports: amount,
        };

        transfer_instruction.invoke_signed(&[signer.into()])?;
    }
    Ok(())
}
