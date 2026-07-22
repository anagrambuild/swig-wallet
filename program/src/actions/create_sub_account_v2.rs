//! Module for creating V2 sub-accounts.
//!
//! A V2 sub-account is identified by a `u32` counter in the Swig header rather
//! than by a role id, so it can be shared across roles. Creation:
//! 1. requires a `SubAccountV2Create` action on the acting role (default-deny;
//!    `All` alone does not suffice),
//! 2. draws a fresh id from the header counter,
//! 3. initializes the program-owned state account and the system-owned asset
//!    account, and
//! 4. appends a scoped `SubAccountV2All { id }` action to the acting role so the
//!    creator can immediately use the sub-account.
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::{CreateAccount, Transfer};
use swig_assertions::*;
use swig_state::{
    action::{sub_account_v2::SubAccountV2Create, Action, Permission},
    sub_account_v2::SubAccountV2,
    swig::{
        sub_account_v2_asset_seeds_with_bump, sub_account_v2_state_seeds_with_bump,
        sub_account_v2_state_signer, Swig,
    },
    Discriminator, IntoBytes, Transmutable, TransmutableMut,
};

use crate::{
    actions::update_authority_v1::append_actions_to_role,
    error::SwigError,
    instruction::{
        accounts::{Context, CreateSubAccountV2Accounts},
        SwigInstruction,
    },
};

/// Arguments for creating a V2 sub-account.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct CreateSubAccountV2Args {
    discriminator: SwigInstruction,
    _padding1: u16,
    /// Role creating (and initially granted access to) the sub-account
    pub role_id: u32,
    /// Bump for the program-owned state PDA
    pub state_bump: u8,
    /// Bump for the system-owned asset PDA
    pub asset_bump: u8,
    _padding2: [u8; 6],
}

impl CreateSubAccountV2Args {
    pub fn new(role_id: u32, state_bump: u8, asset_bump: u8) -> Self {
        Self {
            discriminator: SwigInstruction::CreateSubAccountV2,
            _padding1: 0,
            role_id,
            state_bump,
            asset_bump,
            _padding2: [0; 6],
        }
    }
}

impl Transmutable for CreateSubAccountV2Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for CreateSubAccountV2Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Parsed create instruction.
pub struct CreateSubAccountV2<'a> {
    pub args: &'a CreateSubAccountV2Args,
    pub authority_payload: &'a [u8],
    pub data_payload: &'a [u8],
}

impl<'a> CreateSubAccountV2<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < CreateSubAccountV2Args::LEN {
            return Err(SwigError::InvalidSwigCreateSubAccountV2InstructionDataTooShort.into());
        }
        let (args_data, authority_payload) = data.split_at(CreateSubAccountV2Args::LEN);
        let args = unsafe { CreateSubAccountV2Args::load_unchecked(args_data)? };
        Ok(Self {
            args,
            authority_payload,
            data_payload: args_data,
        })
    }
}

/// Builds the `[Action header][SubAccountV2All body]` bytes for the creator's
/// auto-granted scoped action. Boundary is left zero; it is recomputed when the
/// action is appended to the role.
fn build_all_action_bytes(subacc_id: u32) -> [u8; Action::LEN + 8] {
    let mut buf = [0u8; Action::LEN + 8];
    buf[0..2].copy_from_slice(&(Permission::SubAccountV2All as u16).to_le_bytes());
    buf[2..4].copy_from_slice(&8u16.to_le_bytes());
    // buf[4..8] boundary = 0
    buf[Action::LEN..Action::LEN + 4].copy_from_slice(&subacc_id.to_le_bytes());
    // buf[12..16] padding = 0
    buf
}

/// Creates a new V2 sub-account under a Swig wallet.
#[inline(always)]
pub fn create_sub_account_v2(
    ctx: Context<CreateSubAccountV2Accounts>,
    data: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    // Both PDAs must be uninitialized system accounts before creation.
    check_system_owner(
        ctx.accounts.sub_account_state,
        SwigError::OwnerMismatchSubAccountV2State,
    )?;
    check_system_owner(ctx.accounts.sub_account, SwigError::OwnerMismatchSubAccount)?;

    let create = CreateSubAccountV2::from_instruction_bytes(data)?;

    // Authenticate, authorize creation, and draw a fresh id under one borrow.
    let (new_id, swig_id) = {
        let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
        if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigConfigAccount as u8
        {
            return Err(SwigError::InvalidSwigAccountDiscriminator.into());
        }
        let parts = Swig::split_parts_mut(swig_account_data)?;
        let swig = parts.state;
        let swig_roles = parts.roles;
        if swig.wallet_bump == 0 {
            return Err(SwigError::SignV2CannotBeUsedWithSwigV1.into());
        }

        let role_opt = Swig::get_mut_role(create.args.role_id, swig_roles)?;
        if role_opt.is_none() {
            return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
        }
        let role = role_opt.unwrap();
        let clock = Clock::get()?;
        if role.authority.session_based() {
            role.authority.authenticate_session(
                all_accounts,
                create.authority_payload,
                create.data_payload,
                clock.slot,
            )?;
        } else {
            role.authority.authenticate(
                all_accounts,
                create.authority_payload,
                create.data_payload,
                clock.slot,
            )?;
        }

        // Default-deny: creating requires an explicit SubAccountV2Create action.
        if role.get_action::<SubAccountV2Create>(&[])?.is_none() {
            return Err(SwigError::AuthorityCannotCreateSubAccountV2.into());
        }

        // Draw and consume a fresh sub-account id.
        let new_id = swig.sub_account_counter;
        swig.sub_account_counter = new_id.checked_add(1).ok_or(SwigError::StateError)?;
        (new_id, swig.id)
    };

    // Verify both PDAs match the provided bumps.
    let id_le = new_id.to_le_bytes();
    let state_bump = [create.args.state_bump];
    let asset_bump = [create.args.asset_bump];
    let state_seeds = sub_account_v2_state_seeds_with_bump(&swig_id, &id_le, &state_bump);
    check_self_pda(
        &state_seeds,
        ctx.accounts.sub_account_state.key(),
        SwigError::InvalidSeedSubAccountV2,
    )?;
    let asset_seeds = sub_account_v2_asset_seeds_with_bump(&swig_id, &id_le, &asset_bump);
    check_self_pda(
        &asset_seeds,
        ctx.accounts.sub_account.key(),
        SwigError::InvalidSeedSubAccountV2,
    )?;

    // Create the program-owned state account.
    let rent = Rent::get()?;
    let state_rent = rent.minimum_balance(SubAccountV2::LEN);
    let state_current = unsafe { *ctx.accounts.sub_account_state.borrow_lamports_unchecked() };
    let state_lamports = state_rent.saturating_sub(state_current);
    CreateAccount {
        from: ctx.accounts.payer,
        to: ctx.accounts.sub_account_state,
        lamports: state_lamports,
        space: SubAccountV2::LEN as u64,
        owner: &crate::ID,
    }
    .invoke_signed(&[sub_account_v2_state_signer(&swig_id, &id_le, &state_bump)
        .as_slice()
        .into()])?;

    // Write the state.
    {
        let state_data = unsafe { ctx.accounts.sub_account_state.borrow_mut_data_unchecked() };
        let state = SubAccountV2::new(
            create.args.state_bump,
            create.args.asset_bump,
            new_id,
            swig_id,
            *ctx.accounts.sub_account.key(),
        );
        state_data.copy_from_slice(state.into_bytes()?);
    }

    // Fund the system-owned asset account to rent-exemption (0 data).
    let asset_rent = rent.minimum_balance(0);
    let asset_current = unsafe { *ctx.accounts.sub_account.borrow_lamports_unchecked() };
    let asset_lamports = asset_rent.saturating_sub(asset_current);
    if asset_lamports > 0 {
        Transfer {
            from: ctx.accounts.payer,
            to: ctx.accounts.sub_account,
            lamports: asset_lamports,
        }
        .invoke()?;
    }

    // Auto-grant the creator scoped umbrella access via the shared, tail-preserving
    // append path (grows the swig account and funds the delta from the payer).
    let action_bytes = build_all_action_bytes(new_id);
    append_actions_to_role(
        ctx.accounts.swig,
        ctx.accounts.payer,
        create.args.role_id,
        &action_bytes,
    )?;

    Ok(())
}
