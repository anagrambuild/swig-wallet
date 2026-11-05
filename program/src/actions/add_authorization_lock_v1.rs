//! Add authorization lock instruction.
//!
//! Reserves `amount` of one wallet asset account until `expiry_slot`. Every
//! lock requires `ManageAuthorizationLocks`, and no lock may outlast the role's
//! `max_duration_slots`. A role that may spend everything (`All` or
//! `AllButManageAuthority`) may lock any balance; any other role may lock at
//! most what its own limits would let it spend of that asset. Locking charges
//! no limit: the role's limits are charged when SignV2 spends the funds, which
//! also captures the lock.

use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use swig_assertions::{check_bytes_match, check_self_owned, check_self_pda, check_writable_signer};
use swig_state::{
    action::{
        all::All, all_but_manage_authority::AllButManageAuthority,
        manage_authorization_locks::ManageAuthorizationLocks,
    },
    swig::{swig_wallet_address_seeds_with_bump, Swig},
    tail::authorization_locks::{
        self, AuthorizationLock, LockRecord, LOCK_LEN, MAX_AUTHORIZATION_LOCKS,
    },
    Discriminator, IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable,
};

use crate::{
    authorization_lock::{
        check_lockable_mint, lockable_lamports, lockable_token_balance, remaining_spend_capacity,
    },
    error::SwigError,
    instruction::{
        accounts::{AddAuthorizationLockV1Accounts, Context},
        SwigInstruction,
    },
};

/// Token-2022 locks also pass the mint so its extensions can be checked.
const MINT_ACCOUNT_INDEX: usize = 5;

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct AddAuthorizationLockV1Args {
    pub instruction: SwigInstruction,
    _padding: [u8; 2],
    pub acting_role_id: u32,
    /// Swig wallet address (native SOL) or a token account it owns.
    pub asset_account: [u8; 32],
    /// Token mint, or all zeros for native SOL.
    pub mint: [u8; 32],
    pub amount: u64,
    pub expiry_slot: u64,
}

impl AddAuthorizationLockV1Args {
    pub fn new(
        acting_role_id: u32,
        asset_account: [u8; 32],
        mint: [u8; 32],
        amount: u64,
        expiry_slot: u64,
    ) -> Self {
        Self {
            instruction: SwigInstruction::AddAuthorizationLockV1,
            _padding: [0; 2],
            acting_role_id,
            asset_account,
            mint,
            amount,
            expiry_slot,
        }
    }
}

impl Transmutable for AddAuthorizationLockV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for AddAuthorizationLockV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

pub struct AddAuthorizationLockV1<'a> {
    pub args: &'a AddAuthorizationLockV1Args,
    pub authority_payload: &'a [u8],
    pub data_payload: &'a [u8],
}

impl<'a> AddAuthorizationLockV1<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < AddAuthorizationLockV1Args::LEN {
            return Err(SwigError::InvalidAuthorizationLockInstructionDataTooShort.into());
        }
        let (args_data, authority_payload) = data.split_at(AddAuthorizationLockV1Args::LEN);
        let args = unsafe { AddAuthorizationLockV1Args::load_unchecked(args_data)? };
        Ok(Self {
            args,
            authority_payload,
            data_payload: args_data,
        })
    }
}

pub fn add_authorization_lock_v1(
    ctx: Context<AddAuthorizationLockV1Accounts>,
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

    let add = AddAuthorizationLockV1::from_instruction_bytes(data)?;
    let args = add.args;
    if args.amount == 0 {
        return Err(SwigError::InvalidAuthorizationLockAmount.into());
    }
    let slot = Clock::get()?.slot;
    if args.expiry_slot <= slot {
        return Err(SwigError::InvalidAuthorizationLockExpiry.into());
    }
    if ctx.accounts.asset_account.key() != &args.asset_account {
        return Err(SwigError::InvalidAuthorizationLockAsset.into());
    }

    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if swig_account_data[0] != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }
    crate::require_swig_v2(swig_account_data)?;
    let old_len = swig_account_data.len();

    let (tail_start, tail_len, growth, new_lock) = {
        let parts = Swig::split_parts_mut(swig_account_data)?;
        let bump = [parts.state.wallet_bump];
        check_self_pda(
            &swig_wallet_address_seeds_with_bump(ctx.accounts.swig.key().as_ref(), &bump),
            ctx.accounts.swig_wallet_address.key(),
            SwigError::InvalidSeedSwigAccount,
        )?;

        // Validate the tail once; every later read uses its raw records.
        let entry = authorization_locks::read_strict(parts.tail)?;
        let (next_lock_id, records) = match entry {
            Some(entry) => (entry.next_lock_id(), entry.records()),
            None => (0, &[][..]),
        };
        if records.len() / LOCK_LEN >= MAX_AUTHORIZATION_LOCKS {
            return Err(SwigStateError::AuthorizationLockLimitReached.into());
        }

        let (acting_role, _) = swig_state::authority::counter::authenticate_role(
            parts.roles,
            args.acting_role_id,
            all_accounts,
            add.authority_payload,
            add.data_payload,
            false,
        )?
        .ok_or(SwigError::InvalidAuthorityNotFoundByRoleId)?;

        let Some(manage) = acting_role.get_action::<ManageAuthorizationLocks>(&[])? else {
            return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
        };
        if args.expiry_slot - slot > manage.max_duration_slots {
            return Err(SwigError::InvalidAuthorizationLockExpiry.into());
        }
        let unrestricted = acting_role.get_action::<All>(&[])?.is_some()
            || acting_role
                .get_action::<AllButManageAuthority>(&[])?
                .is_some();

        // One pass: the role's active total for this mint, and every role's
        // active total on this asset account.
        let mut role_reserved = 0u64;
        let mut account_reserved = 0u64;
        for bytes in records.chunks_exact(LOCK_LEN) {
            let lock = LockRecord::new(bytes).ok_or(ProgramError::InvalidAccountData)?;
            let amount = lock.amount();
            if amount == 0 || lock.expiry_slot() <= slot {
                continue;
            }
            if lock.asset_account() == &args.asset_account {
                account_reserved = account_reserved
                    .checked_add(amount)
                    .ok_or(ProgramError::ArithmeticOverflow)?;
            }
            if !unrestricted && lock.role_id() == args.acting_role_id && lock.mint() == &args.mint {
                role_reserved = role_reserved
                    .checked_add(amount)
                    .ok_or(ProgramError::ArithmeticOverflow)?;
            }
        }
        if !unrestricted {
            let reserved_with_new = role_reserved
                .checked_add(args.amount)
                .ok_or(ProgramError::ArithmeticOverflow)?;
            if reserved_with_new > remaining_spend_capacity(acting_role.actions, &args.mint, slot)?
            {
                return Err(SwigError::AuthorizationLockExceedsSpendLimit.into());
            }
        }

        let balance = if args.mint == authorization_locks::NATIVE_SOL_MINT {
            if &args.asset_account != ctx.accounts.swig_wallet_address.key() {
                return Err(SwigError::InvalidAuthorizationLockAsset.into());
            }
            lockable_lamports(ctx.accounts.swig_wallet_address)?
        } else {
            let balance = lockable_token_balance(
                ctx.accounts.asset_account,
                &args.mint,
                ctx.accounts.swig_wallet_address.key(),
                false,
            )
            .ok_or(SwigError::InvalidAuthorizationLockAsset)?;
            check_lockable_mint(
                ctx.accounts.asset_account,
                all_accounts.get(MINT_ACCOUNT_INDEX),
                &args.mint,
            )?;
            balance
        };
        if account_reserved
            .checked_add(args.amount)
            .ok_or(ProgramError::ArithmeticOverflow)?
            > balance
        {
            return Err(SwigError::AuthorizationLockExceedsBalance.into());
        }

        let new_lock = AuthorizationLock {
            asset_account: args.asset_account,
            mint: args.mint,
            amount: args.amount,
            expiry_slot: args.expiry_slot,
            role_id: args.acting_role_id,
            lock_id: next_lock_id,
        };
        (
            Swig::LEN + parts.roles.len(),
            parts.tail.len(),
            authorization_locks::append_growth(parts.tail)?,
            new_lock,
        )
    };

    let new_len = old_len
        .checked_add(growth)
        .ok_or(ProgramError::InvalidAccountData)?;
    ctx.accounts.swig.resize(new_len)?;

    let cost = crate::util::rent::growth_cost(
        &Rent::get()?,
        ctx.accounts.swig.lamports(),
        old_len,
        new_len,
    );
    if cost > 0 {
        Transfer {
            from: ctx.accounts.payer,
            to: ctx.accounts.swig,
            lamports: cost,
        }
        .invoke()?;
    }

    // Append the record in place; only the bytes after the lock entry move.
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let written = authorization_locks::append_in_place(
        &mut swig_account_data[tail_start..],
        tail_len,
        &new_lock,
    )?;
    if tail_start + written != new_len {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_layout_is_stable() {
        assert_eq!(AddAuthorizationLockV1Args::LEN, 88);
    }

    #[test]
    fn from_instruction_bytes_rejects_short_data() {
        let data = [0u8; AddAuthorizationLockV1Args::LEN - 1];
        assert!(matches!(
            AddAuthorizationLockV1::from_instruction_bytes(&data),
            Err(ProgramError::Custom(code))
                if code == SwigError::InvalidAuthorizationLockInstructionDataTooShort as u32
        ));
    }
}
