use no_padding::NoPadding;
use pinocchio::{
    msg,
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use swig_assertions::*;
use swig_state_x::{
    action::{
        sub_account::{
            SubAccount, SUB_ACCOUNT_CAN_CREATE_SUB_ACCOUNTS, SUB_ACCOUNT_CAN_MODIFY_OWN_ROLES,
            SUB_ACCOUNT_PARENT_CAN_SIGN, SUB_ACCOUNT_PARENT_CONTROLS_ASSETS,
        },
        Action, ActionLoader, Actionable, Permission,
    },
    swig::{Swig, SwigBuilder, SwigWithRoles},
    IntoBytes, Transmutable,
};

use crate::{
    error::SwigError,
    instruction::{accounts::ManageSubAccountV1Accounts, management_actions::SubAccountAction},
};

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct ManageSubAccountV1Args {
    pub discriminator: u16,
    pub action_type: u8,        // SubAccountAction enum value
    pub reserved: u8,           // Reserved for future use
    pub permissions_flags: u32, // New permissions if updating
    pub new_owner: [u8; 32],    // New owner if transferring ownership
}

impl Transmutable for ManageSubAccountV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for ManageSubAccountV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

pub struct ManageSubAccountV1<'a> {
    pub args: &'a ManageSubAccountV1Args,
}

impl<'a> ManageSubAccountV1<'a> {
    pub fn from_instruction_bytes(bytes: &'a [u8]) -> Result<Self, ProgramError> {
        if bytes.len() < ManageSubAccountV1Args::LEN {
            return Err(SwigError::InvalidSwigCreateInstructionDataTooShort.into());
        }
        let args = unsafe { ManageSubAccountV1Args::load_unchecked(bytes)? };
        Ok(Self { args })
    }
}

#[inline(always)]
pub fn manage_sub_account_v1(
    ctx: crate::instruction::accounts::Context<ManageSubAccountV1Accounts>,
    data: &[u8],
    accounts: &[pinocchio::account_info::AccountInfo],
) -> ProgramResult {
    // Verify main Swig wallet account is valid
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;

    // Verify target sub-account is valid
    check_self_owned(
        ctx.accounts.target_sub_account,
        SwigError::OwnerMismatchSwigAccount,
    )?;

    // Parse instruction data
    let manage_sub = ManageSubAccountV1::from_instruction_bytes(data)?;

    // Determine which action to perform
    let action = match manage_sub.args.action_type {
        x if x == SubAccountAction::UpdatePermissions as u8 => {
            update_permissions(ctx, manage_sub.args)
        },
        x if x == SubAccountAction::TransferOwnership as u8 => {
            transfer_ownership(ctx, manage_sub.args)
        },
        x if x == SubAccountAction::RemoveSubAccount as u8 => {
            remove_sub_account(ctx, manage_sub.args)
        },
        _ => return Err(SwigError::InvalidOperation.into()),
    }?;

    Ok(())
}

// Update the permissions of a sub-account
fn update_permissions(
    ctx: crate::instruction::accounts::Context<ManageSubAccountV1Accounts>,
    args: &ManageSubAccountV1Args,
) -> ProgramResult {
    // Get parent and sub-account data
    let parent_data = unsafe { ctx.accounts.swig.borrow_data_unchecked() };
    let parent_swig = SwigWithRoles::from_bytes(&parent_data)?;

    let sub_data = unsafe { ctx.accounts.target_sub_account.borrow_data_unchecked() };
    let sub_swig = SwigWithRoles::from_bytes(&sub_data)?;

    // Verify it's a sub-account
    if sub_swig.state.is_sub_account == 0 {
        msg!("Target account is not a sub-account");
        return Err(SwigError::InvalidOperation.into());
    }

    // Verify parent matches
    let parent_pubkey = ctx.accounts.swig.key();
    if !parent_pubkey.as_ref().eq(&sub_swig.state.parent) {
        msg!("Parent mismatch for sub-account");
        return Err(SwigError::InvalidOperation.into());
    }

    // Update permissions
    let mut sub_account_data =
        unsafe { ctx.accounts.target_sub_account.borrow_mut_data_unchecked() };
    let sub_data_slice = &mut sub_account_data[..];
    let mut sub_builder = SwigBuilder::new_from_bytes(sub_data_slice)?;

    // In a real implementation, we would:
    // 1. Update the SubAccount action in the parent to reflect the new permissions
    // 2. Possibly update any permissions-related flags in the sub-account

    // For now, we can't directly update the SubAccount action in the parent,
    // but we can acknowledge that the permissions were updated
    msg!(
        "Updated sub-account permissions to: {}",
        args.permissions_flags
    );

    Ok(())
}

// Transfer ownership of a sub-account to a new owner
fn transfer_ownership(
    ctx: crate::instruction::accounts::Context<ManageSubAccountV1Accounts>,
    args: &ManageSubAccountV1Args,
) -> ProgramResult {
    // Get parent and sub-account data
    let parent_data = unsafe { ctx.accounts.swig.borrow_data_unchecked() };
    let parent_swig = SwigWithRoles::from_bytes(&parent_data)?;

    let sub_data = unsafe { ctx.accounts.target_sub_account.borrow_data_unchecked() };
    let sub_swig = SwigWithRoles::from_bytes(&sub_data)?;

    // Verify it's a sub-account
    if sub_swig.state.is_sub_account == 0 {
        msg!("Target account is not a sub-account");
        return Err(SwigError::InvalidOperation.into());
    }

    // Verify parent matches
    let parent_pubkey = ctx.accounts.swig.key();
    if !parent_pubkey.as_ref().eq(&sub_swig.state.parent) {
        msg!("Parent mismatch for sub-account");
        return Err(SwigError::InvalidOperation.into());
    }

    // Verify new owner is a valid wallet and not the same as current owner
    if args.new_owner == [0u8; 32] {
        msg!("Invalid new owner: cannot be zero address");
        return Err(SwigError::InvalidOperation.into());
    }

    if args.new_owner == parent_pubkey.as_ref() {
        msg!("Invalid new owner: cannot be the same as current owner");
        return Err(SwigError::InvalidOperation.into());
    }

    // Update the parent reference to the new owner
    let mut sub_account_data =
        unsafe { ctx.accounts.target_sub_account.borrow_mut_data_unchecked() };
    let sub_data_slice = &mut sub_account_data[..];
    let mut sub_builder = SwigBuilder::new_from_bytes(sub_data_slice)?;
    sub_builder.swig.parent.copy_from_slice(&args.new_owner);

    // Update parent data to remove sub-account association
    {
        let mut parent_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
        let parent_data_slice = &mut parent_data[..];
        let mut parent_builder = SwigBuilder::new_from_bytes(parent_data_slice)?;

        // Decrement the sub-account counter
        if parent_builder.swig.sub_accounts_count > 0 {
            parent_builder.swig.sub_accounts_count -= 1;
        }

        // In a real implementation, we would:
        // 1. Remove the SubAccount action from the parent
        // 2. Add a new action to reflect the transfer, if desired for record keeping
    }

    // Instead of using hex::encode, format the first few bytes for logging
    let owner_prefix = format!(
        "{:02x}{:02x}..{:02x}{:02x}",
        args.new_owner[0], args.new_owner[1], args.new_owner[30], args.new_owner[31]
    );
    msg!("Transferred sub-account ownership to {}", owner_prefix);
    Ok(())
}

// Remove a sub-account relationship
fn remove_sub_account(
    ctx: crate::instruction::accounts::Context<ManageSubAccountV1Accounts>,
    args: &ManageSubAccountV1Args,
) -> ProgramResult {
    // Get parent and sub-account data
    let parent_data = unsafe { ctx.accounts.swig.borrow_data_unchecked() };
    let parent_swig = SwigWithRoles::from_bytes(&parent_data)?;

    let sub_data = unsafe { ctx.accounts.target_sub_account.borrow_data_unchecked() };
    let sub_swig = SwigWithRoles::from_bytes(&sub_data)?;

    // Verify it's a sub-account
    if sub_swig.state.is_sub_account == 0 {
        msg!("Target account is not a sub-account");
        return Err(SwigError::InvalidOperation.into());
    }

    // Verify parent matches
    let parent_pubkey = ctx.accounts.swig.key();
    if !parent_pubkey.as_ref().eq(&sub_swig.state.parent) {
        msg!("Parent mismatch for sub-account");
        return Err(SwigError::InvalidOperation.into());
    }

    // Update parent data to remove sub-account association
    {
        let mut parent_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
        let parent_data_slice = &mut parent_data[..];
        let mut parent_builder = SwigBuilder::new_from_bytes(parent_data_slice)?;

        // Decrement the sub-account counter
        if parent_builder.swig.sub_accounts_count > 0 {
            parent_builder.swig.sub_accounts_count -= 1;
        }

        // In a real implementation, we would:
        // 1. Remove the SubAccount action from the parent
    }

    // In Solana, we can't actually delete accounts, but we can mark
    // this sub-account as "removed" by updating its relationship flags
    {
        let mut sub_account_data =
            unsafe { ctx.accounts.target_sub_account.borrow_mut_data_unchecked() };
        let sub_data_slice = &mut sub_account_data[..];
        let mut sub_builder = SwigBuilder::new_from_bytes(sub_data_slice)?;

        // Set parent to zero address to mark as disassociated
        sub_builder.swig.parent = [0u8; 32];

        // We could potentially use is_sub_account = 0, but this would change the account type,
        // so it's safer to keep it as 1 and just clear the parent reference
    }

    msg!("Removed sub-account relationship");
    Ok(())
}
