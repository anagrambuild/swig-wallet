//! Closes a disabled V1 sub-account, returning operational SOL to the Swig
//! wallet PDA and rent to the configured rent claimer.

use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use swig_assertions::{check_bytes_match, check_self_owned, check_self_pda, check_system_owner};
use swig_state::{
    action::sub_account::{SubAccount, CLOSED_SUB_ACCOUNT},
    role::RoleMut,
    swig::{sub_account_seeds_with_bump, sub_account_signer, swig_wallet_address_seeds, Swig},
    tail::rent_claimer,
    Discriminator, IntoBytes, Transmutable,
};

use crate::{
    actions::sub_account_lifecycle::{adjust_active_count, authenticate_close_authority},
    error::SwigError,
    instruction::{
        accounts::{CloseSubAccountV1Accounts, Context},
        SwigInstruction,
    },
};

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct CloseSubAccountV1Args {
    pub discriminator: SwigInstruction,
    pub _padding: u16,
    pub auth_role_id: u32,
    pub sub_account_role_id: u32,
    pub _padding2: u32,
}

impl CloseSubAccountV1Args {
    pub fn new(auth_role_id: u32, sub_account_role_id: u32) -> Self {
        Self {
            discriminator: SwigInstruction::CloseSubAccountV1,
            _padding: 0,
            auth_role_id,
            sub_account_role_id,
            _padding2: 0,
        }
    }
}

impl Transmutable for CloseSubAccountV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for CloseSubAccountV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

struct CloseSubAccountV1<'a> {
    args: &'a CloseSubAccountV1Args,
    authority_payload: &'a [u8],
    data_payload: &'a [u8],
}

impl<'a> CloseSubAccountV1<'a> {
    fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < CloseSubAccountV1Args::LEN {
            return Err(SwigError::InvalidInstructionDataTooShort.into());
        }
        let (args_data, authority_payload) = data.split_at(CloseSubAccountV1Args::LEN);
        Ok(Self {
            args: unsafe { CloseSubAccountV1Args::load_unchecked(args_data)? },
            authority_payload,
            data_payload: args_data,
        })
    }
}

pub fn close_sub_account_v1(
    ctx: Context<CloseSubAccountV1Accounts>,
    data: &[u8],
    accounts: &[AccountInfo],
) -> ProgramResult {
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_system_owner(ctx.accounts.sub_account, SwigError::OwnerMismatchSubAccount)?;
    check_system_owner(
        ctx.accounts.swig_wallet_address,
        SwigError::OwnerMismatchSubAccount,
    )?;
    check_bytes_match(
        ctx.accounts.system_program.key(),
        &pinocchio_system::ID,
        32,
        SwigError::InvalidSystemProgram,
    )?;
    let close = CloseSubAccountV1::from_instruction_bytes(data)?;

    let (swig_id, child_bump, configured_rent_claimer) = {
        let swig_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
        if swig_data[0] != Discriminator::SwigConfigAccount as u8 {
            return Err(SwigError::InvalidSwigAccountDiscriminator.into());
        }
        crate::require_swig_v2(swig_data)?;
        let parts = Swig::split_parts_mut(swig_data)?;
        authenticate_close_authority(
            parts.roles,
            close.args.auth_role_id,
            accounts,
            close.authority_payload,
            close.data_payload,
        )?;

        let child_role = Swig::get_mut_role(close.args.sub_account_role_id, parts.roles)?
            .ok_or(SwigError::InvalidAuthorityNotFoundByRoleId)?;
        let child = RoleMut::get_action_mut::<SubAccount>(
            child_role.actions,
            ctx.accounts.sub_account.key().as_ref(),
        )?
        .ok_or(SwigError::InvalidSeedSubAccount)?;
        if child.enabled {
            return Err(SwigError::SubAccountMustBeDisabled.into());
        }
        if child.swig_id != parts.state.id {
            return Err(SwigError::InvalidSwigSubAccountSwigIdMismatch.into());
        }
        if child.role_id != close.args.sub_account_role_id {
            return Err(SwigError::InvalidSwigSubAccountRoleIdMismatch.into());
        }
        (
            parts.state.id,
            child.bump,
            rent_claimer::read_strict(parts.tail)?.copied(),
        )
    };

    let role_id = close.args.sub_account_role_id.to_le_bytes();
    let bump = [child_bump];
    check_self_pda(
        &sub_account_seeds_with_bump(&swig_id, &role_id, &bump),
        ctx.accounts.sub_account.key(),
        SwigError::InvalidSeedSubAccount,
    )?;
    let (expected_wallet, _) = pinocchio::pubkey::find_program_address(
        &swig_wallet_address_seeds(ctx.accounts.swig.key().as_ref()),
        &crate::ID,
    );
    if ctx.accounts.swig_wallet_address.key() != &expected_wallet {
        return Err(SwigError::InvalidSeedSwigAccount.into());
    }
    let rent_destination = match (
        configured_rent_claimer.as_ref(),
        ctx.accounts.rent_claimer_destination,
    ) {
        (Some(expected), Some(provided))
            if provided.key() == expected && provided.key() != ctx.accounts.sub_account.key() =>
        {
            provided
        },
        (None, None) => ctx.accounts.swig_wallet_address,
        (None, Some(provided)) if provided.key() == ctx.accounts.swig_wallet_address.key() => {
            ctx.accounts.swig_wallet_address
        },
        _ => return Err(SwigError::InvalidRentClaimerDestination.into()),
    };

    adjust_active_count(ctx.accounts.swig, ctx.accounts.payer, -1)?;

    let lamports = ctx.accounts.sub_account.lamports();
    if lamports > 0 {
        let rent_lamports =
            lamports.min(Rent::get()?.minimum_balance(ctx.accounts.sub_account.data_len()));
        let operational_lamports = lamports.saturating_sub(rent_lamports);
        let signer = sub_account_signer(&swig_id, &role_id, &bump);
        if rent_destination.key() == ctx.accounts.swig_wallet_address.key() {
            pinocchio_system::instructions::Transfer {
                from: ctx.accounts.sub_account,
                to: ctx.accounts.swig_wallet_address,
                lamports,
            }
            .invoke_signed(&[signer.as_slice().into()])?;
        } else {
            if operational_lamports > 0 {
                pinocchio_system::instructions::Transfer {
                    from: ctx.accounts.sub_account,
                    to: ctx.accounts.swig_wallet_address,
                    lamports: operational_lamports,
                }
                .invoke_signed(&[signer.as_slice().into()])?;
            }
            if rent_lamports > 0 {
                pinocchio_system::instructions::Transfer {
                    from: ctx.accounts.sub_account,
                    to: rent_destination,
                    lamports: rent_lamports,
                }
                .invoke_signed(&[signer.as_slice().into()])?;
            }
        }
    }

    let swig_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let parts = Swig::split_parts_mut(swig_data)?;
    let child_role = Swig::get_mut_role(close.args.sub_account_role_id, parts.roles)?
        .ok_or(SwigError::InvalidAuthorityNotFoundByRoleId)?;
    let child = RoleMut::get_action_mut::<SubAccount>(
        child_role.actions,
        ctx.accounts.sub_account.key().as_ref(),
    )?
    .ok_or(SwigError::InvalidSeedSubAccount)?;
    child.sub_account = CLOSED_SUB_ACCOUNT;
    child.enabled = false;
    Ok(())
}
