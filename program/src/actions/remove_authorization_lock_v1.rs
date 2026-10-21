//! Remove authorization lock instruction.
//!
//! The creating role may release its lock at any time; this is how a
//! reservation is captured (release and spend in one transaction) or voided.
//! Once a lock has expired it no longer binds anything, so a role with `All`,
//! `AllButManageAuthority`, `ManageAuthority`, or `ManageAuthorizationLocks`
//! may also remove it to reclaim space.

extern crate alloc;
use alloc::vec::Vec;

use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use swig_assertions::{check_bytes_match, check_self_owned, check_writable_signer};
use swig_state::{
    action::{
        all::All, all_but_manage_authority::AllButManageAuthority,
        manage_authority::ManageAuthority, manage_authorization_locks::ManageAuthorizationLocks,
    },
    swig::Swig,
    tail::{
        authorization_locks::{self, AuthorizationLock},
        rent_claimer,
    },
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, RemoveAuthorizationLockV1Accounts},
        SwigInstruction,
    },
};

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct RemoveAuthorizationLockV1Args {
    pub instruction: SwigInstruction,
    _padding: [u8; 2],
    pub acting_role_id: u32,
    pub lock_id: u32,
    _reserved: [u8; 4],
}

impl RemoveAuthorizationLockV1Args {
    pub fn new(acting_role_id: u32, lock_id: u32) -> Self {
        Self {
            instruction: SwigInstruction::RemoveAuthorizationLockV1,
            _padding: [0; 2],
            acting_role_id,
            lock_id,
            _reserved: [0; 4],
        }
    }
}

impl Transmutable for RemoveAuthorizationLockV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for RemoveAuthorizationLockV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

pub struct RemoveAuthorizationLockV1<'a> {
    pub args: &'a RemoveAuthorizationLockV1Args,
    pub authority_payload: &'a [u8],
    pub data_payload: &'a [u8],
}

impl<'a> RemoveAuthorizationLockV1<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < RemoveAuthorizationLockV1Args::LEN {
            return Err(SwigError::InvalidAuthorizationLockInstructionDataTooShort.into());
        }
        let (args_data, authority_payload) = data.split_at(RemoveAuthorizationLockV1Args::LEN);
        let args = unsafe { RemoveAuthorizationLockV1Args::load_unchecked(args_data)? };
        Ok(Self {
            args,
            authority_payload,
            data_payload: args_data,
        })
    }
}

pub fn remove_authorization_lock_v1(
    ctx: Context<RemoveAuthorizationLockV1Accounts>,
    data: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_writable_signer(ctx.accounts.payer, SwigError::PayerMustBeWritableSigner)?;
    check_bytes_match(
        ctx.accounts.system_program.key(),
        &pinocchio_system::ID,
        32,
        SwigError::InvalidSystemProgram,
    )?;

    let remove = RemoveAuthorizationLockV1::from_instruction_bytes(data)?;
    let args = remove.args;
    let slot = Clock::get()?.slot;

    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if swig_account_data[0] != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }
    crate::require_swig_v2(swig_account_data)?;
    let old_len = swig_account_data.len();

    let (roles_end, new_tail, refund_destination) = {
        let parts = Swig::split_parts_mut(swig_account_data)?;
        let entry = authorization_locks::read_strict(parts.tail)?
            .ok_or(SwigError::AuthorizationLockNotFound)?;
        let target = entry
            .iter()
            .find(|lock| lock.lock_id == args.lock_id)
            .ok_or(SwigError::AuthorizationLockNotFound)?;

        let acting_role = Swig::get_mut_role(args.acting_role_id, parts.roles)?
            .ok_or(SwigError::InvalidAuthorityNotFoundByRoleId)?;
        if acting_role.authority.session_based() {
            acting_role.authority.authenticate_session(
                all_accounts,
                remove.authority_payload,
                remove.data_payload,
                slot,
            )?;
        } else {
            acting_role.authority.authenticate(
                all_accounts,
                remove.authority_payload,
                remove.data_payload,
                slot,
            )?;
        }

        if target.role_id != args.acting_role_id {
            if target.is_active(slot) {
                return Err(SwigError::AuthorizationLockNotOwner.into());
            }
            let may_prune = acting_role.get_action::<All>(&[])?.is_some()
                || acting_role
                    .get_action::<AllButManageAuthority>(&[])?
                    .is_some()
                || acting_role.get_action::<ManageAuthority>(&[])?.is_some()
                || acting_role
                    .get_action::<ManageAuthorizationLocks>(&[])?
                    .is_some();
            if !may_prune {
                return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
            }
        }

        let remaining: Vec<AuthorizationLock> = entry
            .iter()
            .filter(|lock| lock.lock_id != args.lock_id)
            .collect();
        let new_tail =
            authorization_locks::rebuild_tail(parts.tail, entry.next_lock_id(), &remaining)?;
        let refund_destination = crate::util::rent::refund_destination(
            rent_claimer::read_strict(parts.tail)?,
            ctx.accounts.swig,
            ctx.accounts.payer,
            all_accounts,
        )?;
        (Swig::LEN + parts.roles.len(), new_tail, refund_destination)
    };

    let new_len = roles_end
        .checked_add(new_tail.len())
        .ok_or(ProgramError::InvalidAccountData)?;
    swig_account_data[roles_end..new_len].copy_from_slice(&new_tail);
    swig_account_data[new_len..].fill(0);

    let rent = Rent::get()?;
    let swig_lamports = ctx.accounts.swig.lamports();
    let new_rent = rent.minimum_balance(new_len);
    let refund = rent
        .minimum_balance(old_len)
        .saturating_sub(new_rent)
        .min(swig_lamports.saturating_sub(new_rent));
    unsafe {
        *ctx.accounts.swig.borrow_mut_lamports_unchecked() = swig_lamports - refund;
        *refund_destination.borrow_mut_lamports_unchecked() = refund_destination
            .lamports()
            .checked_add(refund)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }
    ctx.accounts.swig.resize(new_len)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_layout_is_stable() {
        assert_eq!(RemoveAuthorizationLockV1Args::LEN, 16);
    }

    #[test]
    fn from_instruction_bytes_rejects_short_data() {
        let data = [0u8; RemoveAuthorizationLockV1Args::LEN - 1];
        assert!(matches!(
            RemoveAuthorizationLockV1::from_instruction_bytes(&data),
            Err(ProgramError::Custom(code))
                if code == SwigError::InvalidAuthorizationLockInstructionDataTooShort as u32
        ));
    }
}
