use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use swig_assertions::{check_bytes_match, check_self_owned};
use swig_state::{
    action::{all::All, close_swig_authority::CloseSwigAuthority},
    swig::Swig,
    tail::rent_claimer,
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, SetRentClaimerV1Accounts},
        SwigInstruction,
    },
};

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct SetRentClaimerV1Args {
    pub discriminator: SwigInstruction,
    pub _padding: [u8; 2],
    pub role_id: u32,
    pub rent_claimer: [u8; 32],
}

impl SetRentClaimerV1Args {
    pub fn new(role_id: u32, rent_claimer: [u8; 32]) -> Self {
        Self {
            discriminator: SwigInstruction::SetRentClaimerV1,
            _padding: [0; 2],
            role_id,
            rent_claimer,
        }
    }
}

impl Transmutable for SetRentClaimerV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for SetRentClaimerV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

pub struct SetRentClaimerV1<'a> {
    pub args: &'a SetRentClaimerV1Args,
    pub authority_payload: &'a [u8],
    pub data_payload: &'a [u8],
}

impl<'a> SetRentClaimerV1<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < SetRentClaimerV1Args::LEN {
            return Err(SwigError::InvalidSwigSetRentClaimerInstructionDataTooShort.into());
        }
        let (args_data, authority_payload) = data.split_at(SetRentClaimerV1Args::LEN);
        let args = unsafe { SetRentClaimerV1Args::load_unchecked(args_data)? };
        Ok(Self {
            args,
            authority_payload,
            data_payload: args_data,
        })
    }
}

pub fn set_rent_claimer_v1(
    ctx: Context<SetRentClaimerV1Accounts>,
    data: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_bytes_match(
        ctx.accounts.system_program.key(),
        &pinocchio_system::ID,
        32,
        SwigError::InvalidSystemProgram,
    )?;

    let set_ix = SetRentClaimerV1::from_instruction_bytes(data)?;
    if set_ix.args.rent_claimer == [0u8; 32] {
        return Err(SwigError::InvalidRentClaimerValue.into());
    }
    if &set_ix.args.rent_claimer == ctx.accounts.swig.key() {
        return Err(SwigError::InvalidRentClaimerValue.into());
    }

    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if swig_account_data[0] != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }
    let old_len = swig_account_data.len();

    {
        let parts = Swig::split_parts_mut(swig_account_data)?;
        let _swig = parts.state;
        let acting_role = Swig::get_mut_role(set_ix.args.role_id, parts.roles)?
            .ok_or(SwigError::InvalidAuthorityNotFoundByRoleId)?;

        let slot = Clock::get()?.slot;
        if acting_role.authority.session_based() {
            acting_role.authority.authenticate_session(
                all_accounts,
                set_ix.authority_payload,
                set_ix.data_payload,
                slot,
            )?;
        } else {
            acting_role.authority.authenticate(
                all_accounts,
                set_ix.authority_payload,
                set_ix.data_payload,
                slot,
            )?;
        }

        let has_all = acting_role.get_action::<All>(&[])?.is_some();
        let has_close = acting_role.get_action::<CloseSwigAuthority>(&[])?.is_some();
        if !has_all && !has_close {
            return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
        }

        if rent_claimer::read_strict(parts.tail)?.is_some() {
            return Err(SwigError::RentClaimerAlreadySet.into());
        }
    }

    let new_len = old_len
        .checked_add(rent_claimer::ENTRY_LEN)
        .ok_or(ProgramError::InvalidAccountData)?;
    ctx.accounts.swig.resize(new_len)?;

    let current_lamports = ctx.accounts.swig.lamports();
    let required_lamports = Rent::get()?.minimum_balance(new_len);
    let cost = required_lamports
        .checked_sub(current_lamports)
        .unwrap_or_default();
    if cost > 0 {
        Transfer {
            from: ctx.accounts.payer,
            to: ctx.accounts.swig,
            lamports: cost,
        }
        .invoke()?;
    }

    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let entry = rent_claimer::entry(&set_ix.args.rent_claimer);
    swig_account_data[old_len..old_len + rent_claimer::ENTRY_LEN].copy_from_slice(&entry);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_instruction_bytes_rejects_short_data() {
        let data = vec![0u8; SetRentClaimerV1Args::LEN - 1];
        assert!(matches!(
            SetRentClaimerV1::from_instruction_bytes(&data),
            Err(ProgramError::Custom(code))
                if code == SwigError::InvalidSwigSetRentClaimerInstructionDataTooShort as u32
        ));
    }
}
