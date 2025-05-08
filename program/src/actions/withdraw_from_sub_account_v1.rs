use core::mem::MaybeUninit;

use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    instruction::Signer,
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

/// Arguments for the WithdrawFromSubAccountV1 instruction
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct WithdrawFromSubAccountV1Args {
    discriminator: SwigInstruction,
    _padding: u16,
    pub role_id: u32,
    pub amount: u64,
}

impl WithdrawFromSubAccountV1Args {
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
}

impl<'a> WithdrawFromSubAccountV1<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < WithdrawFromSubAccountV1Args::LEN {
            return Err(SwigError::InvalidSwigSignInstructionDataTooShort.into());
        }
        let args = unsafe { WithdrawFromSubAccountV1Args::load_unchecked(data)? };
        Ok(Self { args })
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
    // Check that the accounts are owned by our program
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_self_owned(
        ctx.accounts.sub_account,
        SwigError::OwnerMismatchSwigAccount,
    )?;

    let withdraw = WithdrawFromSubAccountV1::from_instruction_bytes(data)?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_unchecked(&swig_header)? };
    let sub_account_data = unsafe { ctx.accounts.sub_account.borrow_data_unchecked() };
    if unsafe { *sub_account_data.get_unchecked(0) } != Discriminator::SwigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
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

    let manage_authority_action = role.get_action::<ManageAuthority>(&[])?;
    let all_action = role.get_action::<All>(&[])?;
    if manage_authority_action.is_none() && all_action.is_none() {
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    }
    let amount = withdraw.args.amount;
    if all_accounts.len() >= 6 {
        let token_account = &all_accounts[3];
        let token_account_data = unsafe { token_account.borrow_data_unchecked() };
        let token_account_owner = unsafe { token_account_data.get_unchecked(0) };

        let swig_token_account = &all_accounts[4];
        let swig_token_account_data = unsafe { swig_token_account.borrow_data_unchecked() };

        let token_program = &all_accounts[5];

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

        let role_id_bytes = withdraw.args.role_id.to_le_bytes();
        let bump_byte = [swig.bump];
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

    let lamports_after = unsafe { *ctx.accounts.sub_account.borrow_lamports_unchecked() };
    if lamports_after < sub_account.reserved_lamports {
        return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
    }

    Ok(())
}
