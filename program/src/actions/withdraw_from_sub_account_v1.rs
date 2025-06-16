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
use swig_state_x::{
    action::{all::All, manage_authority::ManageAuthority, sub_account::SubAccount},
    authority::AuthorityType,
    role::RoleMut,
    swig::{sub_account_signer, Swig, SwigSubAccount},
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
    // Verify that both the swig account and sub_account are owned by the current
    // program
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_self_owned(ctx.accounts.sub_account, SwigError::OwnerMismatchSubAccount)?;
    let withdraw = WithdrawFromSubAccountV1::from_instruction_bytes(data)?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_unchecked(&swig_header)? };

    // Verify the swig account has the correct discriminator
    if unsafe { *swig_header.get_unchecked(0) } != Discriminator::SwigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }
    let sub_account_data = unsafe { ctx.accounts.sub_account.borrow_data_unchecked() };
    if unsafe { *sub_account_data.get_unchecked(0) } != Discriminator::SwigSubAccount as u8 {
        return Err(SwigError::InvalidSwigSubAccountDiscriminator.into());
    }
    let sub_account = unsafe { SwigSubAccount::load_unchecked(sub_account_data)? };
    if swig.id != sub_account.swig_id {
        return Err(SwigError::InvalidAuthorityMustHaveAtLeastOneAction.into());
    }
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
    let (action_accounts_index, action_accounts_len) =
        if role.position.authority_type()? == AuthorityType::Secp256k1 {
            (3, 6)
        } else {
            (4, 7)
        };
    let manage_authority_action = role.get_action::<ManageAuthority>(&[])?;
    let all_action = role.get_action::<All>(&[])?;
    if manage_authority_action.is_none() && all_action.is_none() {
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    }
    let amount = withdraw.args.amount;
    if all_accounts.len() >= action_accounts_len {
        let token_account = &all_accounts[action_accounts_index];
        let token_account_data = unsafe { token_account.borrow_data_unchecked() };
        // we dont need to check the owner of the token account because the token
        // program will check it in transfer
        let swig_token_account = &all_accounts[action_accounts_index + 1];
        let swig_token_account_data = unsafe { swig_token_account.borrow_data_unchecked() };
        let swig_token_account_owner = unsafe { swig_token_account_data.get_unchecked(32..64) };
        if unsafe { sol_memcmp(ctx.accounts.swig.key(), swig_token_account_owner, 32) } != 0 {
            return Err(SwigError::InvalidSwigTokenAccountOwner.into());
        }
        let token_program = &all_accounts[action_accounts_index + 2];
        let token_account_program_owner = unsafe { token_account.owner() };
        let destination_program_owner = unsafe { swig_token_account.owner() };
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
        msg!("amount: {}", amount);
        let role_id_bytes = sub_account.role_id.to_le_bytes();
        let bump_byte = [sub_account.bump];
        let seeds = sub_account_signer(&swig.id, &role_id_bytes, &bump_byte);
        let signer = seeds.as_slice();
        // Invoke the token transfer with the PDA signer
        token_transfer.invoke_signed(&[signer.into()])?;
    } else {
        // SOL transfer
        if amount > ctx.accounts.sub_account.lamports() {
            return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
        }
        unsafe {
            *ctx.accounts.sub_account.borrow_mut_lamports_unchecked() -= amount;
            *ctx.accounts.swig.borrow_mut_lamports_unchecked() += amount;
        }
    }
    Ok(())
}
