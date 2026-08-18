//! Shared lifecycle helpers for V1 and V2 sub-accounts.

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
};
use pinocchio_system::instructions::Transfer;
use swig_state::{
    action::{
        all::All, close_swig_authority::CloseSwigAuthority, manage_authority::ManageAuthority,
    },
    role::RoleMut,
    swig::Swig,
    tail::{active_sub_account_count, validate_strict, SavedTail},
    SwigAuthenticateError,
};

use crate::{error::SwigError, is_swig_v2};

pub(crate) fn authenticate_close_authority(
    roles: &mut [u8],
    role_id: u32,
    accounts: &[AccountInfo],
    authority_payload: &[u8],
    data_payload: &[u8],
) -> Result<(), ProgramError> {
    let role =
        Swig::get_mut_role(role_id, roles)?.ok_or(SwigError::InvalidAuthorityNotFoundByRoleId)?;
    let slot = Clock::get()?.slot;
    if role.authority.session_based() {
        role.authority
            .authenticate_session(accounts, authority_payload, data_payload, slot)?;
    } else {
        role.authority
            .authenticate(accounts, authority_payload, data_payload, slot)?;
    }

    let has_all = role.get_action::<All>(&[])?.is_some();
    let has_manage = role.get_action::<ManageAuthority>(&[])?.is_some();
    let has_close = role.get_action::<CloseSwigAuthority>(&[])?.is_some();
    if !has_all && !has_manage && !has_close {
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    }
    Ok(())
}

/// Returns the active-child count that gates final parent closure.
///
/// A V1 header aliases the V2 `sub_account_counter` with the upper half of
/// `reserved_lamports`. Only trust that allocator after establishing the V2
/// header; legacy V1 reconstruction starts at zero and counts surviving V1
/// actions instead.
pub(crate) fn active_count_for_close(data: &[u8]) -> Result<u32, ProgramError> {
    let parts = Swig::split_parts(data)?;
    validate_strict(parts.tail)?;

    let allocated_v2_count = if unsafe { is_swig_v2(data) } {
        parts.state.sub_account_counter
    } else {
        0
    };

    match active_sub_account_count::read(parts.tail)? {
        Some(count) => Ok(count),
        None => {
            active_sub_account_count::legacy_count(parts.state, parts.roles, allocated_v2_count)
        },
    }
}

/// Applies `delta` to the active-child count, materializing a typed tail entry
/// from legacy state when necessary.
pub(crate) fn adjust_active_count(
    swig_account: &AccountInfo,
    payer: &AccountInfo,
    delta: i8,
) -> Result<(), ProgramError> {
    let (saved_tail, current, had_entry, old_len) = {
        let data = unsafe { swig_account.borrow_data_unchecked() };
        let parts = Swig::split_parts(data)?;
        validate_strict(parts.tail)?;
        let stored = active_sub_account_count::read(parts.tail)?;
        let allocated_v2_count = if unsafe { is_swig_v2(data) } {
            parts.state.sub_account_counter
        } else {
            0
        };
        let current = match stored {
            Some(count) => count,
            None => active_sub_account_count::legacy_count(
                parts.state,
                parts.roles,
                allocated_v2_count,
            )?,
        };
        (
            SavedTail::take(parts.tail)?,
            current,
            stored.is_some(),
            data.len(),
        )
    };

    let updated = if delta >= 0 {
        current
            .checked_add(delta as u32)
            .ok_or(SwigError::StateError)?
    } else {
        current
            .checked_sub(delta.unsigned_abs() as u32)
            .ok_or(SwigError::ActiveSubAccountCountUnderflow)?
    };

    if had_entry {
        let data = unsafe { swig_account.borrow_mut_data_unchecked() };
        let parts = Swig::split_parts_mut(data)?;
        if !active_sub_account_count::write(parts.tail, updated)? {
            return Err(ProgramError::InvalidAccountData);
        }
        return Ok(());
    }

    let new_len = old_len
        .checked_add(active_sub_account_count::ENTRY_LEN)
        .ok_or(ProgramError::InvalidAccountData)?;
    swig_account.resize(new_len)?;

    let required_lamports = Rent::get()?.minimum_balance(new_len);
    let current_lamports = swig_account.lamports();
    let additional_lamports = required_lamports.saturating_sub(current_lamports);
    if additional_lamports > 0 {
        Transfer {
            from: payer,
            to: swig_account,
            lamports: additional_lamports,
        }
        .invoke()?;
    }

    let data = unsafe { swig_account.borrow_mut_data_unchecked() };
    let roles_end = Swig::roles_end_offset(data)?;
    data[roles_end..].fill(0);
    saved_tail.restore_at(data, roles_end)?;
    let count_offset = roles_end
        .checked_add(saved_tail.len())
        .ok_or(ProgramError::InvalidAccountData)?;
    let count_end = count_offset
        .checked_add(active_sub_account_count::ENTRY_LEN)
        .ok_or(ProgramError::InvalidAccountData)?;
    data[count_offset..count_end].copy_from_slice(&active_sub_account_count::entry(updated));
    Ok(())
}
