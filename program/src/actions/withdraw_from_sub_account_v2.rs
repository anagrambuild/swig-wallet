//! Module for withdrawing assets from a V2 sub-account to the swig wallet
//! address.
//!
//! Authorization is default-deny and scoped: the acting role must hold a
//! `SubAccountV2Withdraw { subacc_id }` or `SubAccountV2All { subacc_id }`
//! action. Unlike V1, wallet-level `All` / `ManageAuthority` grant nothing, and
//! the destination is always the swig wallet address.
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    memory::sol_memcmp,
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_assertions::*;
use swig_state::{
    action::Permission,
    swig::{sub_account_v2_asset_signer, swig_wallet_address_seeds_with_bump, Swig},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable,
};

use crate::{
    actions::sub_account_sign_v2::{authorize_scoped_v2, validate_v2_state},
    error::SwigError,
    instruction::{
        accounts::{Context, WithdrawFromSubAccountV2Accounts},
        SwigInstruction,
    },
    util::TokenTransfer,
    AccountClassification, SPL_TOKEN_2022_ID, SPL_TOKEN_ID,
};

/// Number of named accounts in the WithdrawFromSubAccountV2 context. Token
/// accounts, if any, follow at this base index.
const NAMED_ACCOUNTS: usize = 7;

/// Arguments for withdrawing from a V2 sub-account.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct WithdrawFromSubAccountV2Args {
    discriminator: SwigInstruction,
    _padding: u16,
    pub role_id: u32,
    pub subacc_id: u32,
    _padding2: u32,
    pub amount: u64,
}

impl WithdrawFromSubAccountV2Args {
    pub fn new(role_id: u32, subacc_id: u32, amount: u64) -> Self {
        Self {
            discriminator: SwigInstruction::WithdrawFromSubAccountV2,
            _padding: 0,
            role_id,
            subacc_id,
            _padding2: 0,
            amount,
        }
    }
}

impl Transmutable for WithdrawFromSubAccountV2Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for WithdrawFromSubAccountV2Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Parsed withdraw instruction.
pub struct WithdrawFromSubAccountV2<'a> {
    pub args: &'a WithdrawFromSubAccountV2Args,
    pub authority_payload: &'a [u8],
    pub data_payload: &'a [u8],
}

impl<'a> WithdrawFromSubAccountV2<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < WithdrawFromSubAccountV2Args::LEN {
            return Err(SwigError::InvalidSwigSignInstructionDataTooShort.into());
        }
        let (args_data, authority_payload) = data.split_at(WithdrawFromSubAccountV2Args::LEN);
        let args = unsafe { WithdrawFromSubAccountV2Args::load_unchecked(args_data)? };
        Ok(Self {
            args,
            authority_payload,
            data_payload: args_data,
        })
    }
}

/// Withdraws SOL or SPL tokens from a V2 sub-account to the swig wallet address.
#[inline(always)]
pub fn withdraw_from_sub_account_v2(
    ctx: Context<WithdrawFromSubAccountV2Accounts>,
    all_accounts: &[AccountInfo],
    data: &[u8],
    _account_classifiers: &[AccountClassification],
) -> ProgramResult {
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_system_owner(ctx.accounts.sub_account, SwigError::OwnerMismatchSubAccount)?;
    check_system_owner(
        ctx.accounts.swig_wallet_address,
        SwigError::OwnerMismatchSwigAccount,
    )?;

    let withdraw = WithdrawFromSubAccountV2::from_instruction_bytes(data)?;

    let swig_id = {
        let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
        if swig_account_data[0] != Discriminator::SwigConfigAccount as u8 {
            return Err(SwigError::InvalidSwigAccountDiscriminator.into());
        }
        let parts = Swig::split_parts_mut(swig_account_data)?;
        let swig = parts.state;
        let swig_roles = parts.roles;
        if swig.wallet_bump == 0 {
            return Err(SwigError::SignV2CannotBeUsedWithSwigV1.into());
        }
        let swig_id = swig.id;

        // Validate the destination is the canonical swig wallet address PDA.
        let wallet_bump = [swig.wallet_bump];
        let wallet_seeds =
            swig_wallet_address_seeds_with_bump(ctx.accounts.swig.key().as_ref(), &wallet_bump);
        let expected_wallet_address =
            pinocchio::pubkey::create_program_address(&wallet_seeds, &crate::ID)?;
        if expected_wallet_address != *ctx.accounts.swig_wallet_address.key() {
            return Err(SwigError::InvalidSwigSubAccountV2SwigIdMismatch.into());
        }

        let role_opt = Swig::get_mut_role(withdraw.args.role_id, swig_roles)?;
        if role_opt.is_none() {
            return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
        }
        let role = role_opt.unwrap();
        let clock = Clock::get()?;
        if role.authority.session_based() {
            role.authority.authenticate_session(
                all_accounts,
                withdraw.authority_payload,
                withdraw.data_payload,
                clock.slot,
            )?;
        } else {
            role.authority.authenticate(
                all_accounts,
                withdraw.authority_payload,
                withdraw.data_payload,
                clock.slot,
            )?;
        }
        authorize_scoped_v2(
            &role,
            Permission::SubAccountV2Withdraw,
            withdraw.args.subacc_id,
        )?;
        swig_id
    };

    // Validate the state account and bind the asset account.
    let asset_bump = validate_v2_state(
        ctx.accounts.sub_account_state,
        ctx.accounts.sub_account,
        &swig_id,
        withdraw.args.subacc_id,
    )?;

    let id_le = withdraw.args.subacc_id.to_le_bytes();
    let bump_byte = [asset_bump];
    let seeds = sub_account_v2_asset_signer(&swig_id, &id_le, &bump_byte);
    let signer = seeds.as_slice();
    let amount = withdraw.args.amount;

    // Token accounts (source, destination, token_program) follow the named
    // accounts. Accept exactly the SOL or token layout so unrelated trailing
    // accounts cannot silently change the operation type.
    if all_accounts.len() == NAMED_ACCOUNTS + 3 {
        let token_account = &all_accounts[NAMED_ACCOUNTS];
        let swig_token_account = &all_accounts[NAMED_ACCOUNTS + 1];
        let token_program = &all_accounts[NAMED_ACCOUNTS + 2];

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
        if token_program.key() != token_account_program_owner {
            return Err(SwigError::OwnerMismatchTokenAccount.into());
        }

        // Both Token and Token-2022 use the same 165-byte base account layout.
        // Extensions may follow it, so validate the base before reading it.
        const TOKEN_ACCOUNT_BASE_LEN: usize = 165;
        if token_account.data_len() < TOKEN_ACCOUNT_BASE_LEN
            || swig_token_account.data_len() < TOKEN_ACCOUNT_BASE_LEN
        {
            return Err(ProgramError::InvalidAccountData);
        }
        let token_account_data = unsafe { token_account.borrow_data_unchecked() };
        let swig_token_account_data = unsafe { swig_token_account.borrow_data_unchecked() };

        // Only initialized, transferable token accounts are accepted.
        if token_account_data[108] != 1 || swig_token_account_data[108] != 1 {
            return Err(ProgramError::InvalidAccountData);
        }
        if unsafe {
            sol_memcmp(
                &token_account_data[..32],
                &swig_token_account_data[..32],
                32,
            )
        } != 0
        {
            return Err(SwigError::InvalidOperation.into());
        }
        if unsafe {
            sol_memcmp(
                ctx.accounts.sub_account.key(),
                &token_account_data[32..64],
                32,
            )
        } != 0
        {
            return Err(SwigError::InvalidSwigTokenAccountOwner.into());
        }
        if unsafe {
            sol_memcmp(
                ctx.accounts.swig_wallet_address.key(),
                &swig_token_account_data[32..64],
                32,
            )
        } != 0
        {
            return Err(SwigError::InvalidSwigTokenAccountOwner.into());
        }

        let token_transfer = TokenTransfer {
            from: token_account,
            to: swig_token_account,
            authority: ctx.accounts.sub_account,
            amount,
            token_program: token_program.key(),
        };
        token_transfer.invoke_signed(&[signer.into()])?;
    } else if all_accounts.len() == NAMED_ACCOUNTS {
        if amount > ctx.accounts.sub_account.lamports() {
            return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
        }
        pinocchio_system::instructions::Transfer {
            from: ctx.accounts.sub_account,
            to: ctx.accounts.swig_wallet_address,
            lamports: amount,
        }
        .invoke_signed(&[signer.into()])?;
    } else {
        return Err(SwigError::InvalidAccountsLength.into());
    }
    Ok(())
}
