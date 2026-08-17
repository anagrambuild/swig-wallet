//! Closes a disabled V2 state/asset PDA pair, returning operational SOL to the
//! Swig wallet PDA and rent to the configured rent claimer.

use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use swig_assertions::{check_bytes_match, check_self_owned, check_self_pda, check_system_owner};
use swig_state::{
    sub_account_v2::SubAccountV2,
    swig::{
        sub_account_v2_asset_seeds_with_bump, sub_account_v2_asset_signer,
        sub_account_v2_state_seeds_with_bump, swig_wallet_address_seeds, Swig,
    },
    tail::rent_claimer,
    Discriminator, IntoBytes, Transmutable,
};

use crate::{
    actions::sub_account_lifecycle::{adjust_active_count, authenticate_close_authority},
    error::SwigError,
    instruction::{
        accounts::{CloseSubAccountV2Accounts, Context},
        SwigInstruction,
    },
};

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct CloseSubAccountV2Args {
    pub discriminator: SwigInstruction,
    pub _padding: u16,
    pub auth_role_id: u32,
    pub subacc_id: u32,
    pub _padding2: u32,
}

impl CloseSubAccountV2Args {
    pub fn new(auth_role_id: u32, subacc_id: u32) -> Self {
        Self {
            discriminator: SwigInstruction::CloseSubAccountV2,
            _padding: 0,
            auth_role_id,
            subacc_id,
            _padding2: 0,
        }
    }
}

impl Transmutable for CloseSubAccountV2Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for CloseSubAccountV2Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

struct CloseSubAccountV2<'a> {
    args: &'a CloseSubAccountV2Args,
    authority_payload: &'a [u8],
    data_payload: &'a [u8],
}

impl<'a> CloseSubAccountV2<'a> {
    fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < CloseSubAccountV2Args::LEN {
            return Err(SwigError::InvalidInstructionDataTooShort.into());
        }
        let (args_data, authority_payload) = data.split_at(CloseSubAccountV2Args::LEN);
        Ok(Self {
            args: unsafe { CloseSubAccountV2Args::load_unchecked(args_data)? },
            authority_payload,
            data_payload: args_data,
        })
    }
}

pub fn close_sub_account_v2(
    ctx: Context<CloseSubAccountV2Accounts>,
    data: &[u8],
    accounts: &[AccountInfo],
) -> ProgramResult {
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_self_owned(
        ctx.accounts.sub_account_state,
        SwigError::OwnerMismatchSubAccountV2State,
    )?;
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
    let close = CloseSubAccountV2::from_instruction_bytes(data)?;

    let (swig_id, configured_rent_claimer) = {
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
        (
            parts.state.id,
            rent_claimer::read_strict(parts.tail)?.copied(),
        )
    };

    let (state_bump, asset_bump) = {
        let state_data = unsafe { ctx.accounts.sub_account_state.borrow_data_unchecked() };
        let state = unsafe { SubAccountV2::load_unchecked(state_data)? };
        state.check_discriminator()?;
        if state.is_enabled()? {
            return Err(SwigError::SubAccountMustBeDisabled.into());
        }
        if state.swig_id != swig_id {
            return Err(SwigError::InvalidSwigSubAccountV2SwigIdMismatch.into());
        }
        if state.subacc_id != close.args.subacc_id {
            return Err(SwigError::InvalidSwigSubAccountV2IdMismatch.into());
        }
        if state.sub_account != *ctx.accounts.sub_account.key() {
            return Err(SwigError::InvalidSeedSubAccountV2.into());
        }
        (state.bump, state.asset_bump)
    };

    let id_le = close.args.subacc_id.to_le_bytes();
    let state_bump_seed = [state_bump];
    let asset_bump_seed = [asset_bump];
    check_self_pda(
        &sub_account_v2_state_seeds_with_bump(&swig_id, &id_le, &state_bump_seed),
        ctx.accounts.sub_account_state.key(),
        SwigError::InvalidSeedSubAccountV2,
    )?;
    check_self_pda(
        &sub_account_v2_asset_seeds_with_bump(&swig_id, &id_le, &asset_bump_seed),
        ctx.accounts.sub_account.key(),
        SwigError::InvalidSeedSubAccountV2,
    )?;
    let (expected_wallet, _) = pinocchio::pubkey::find_program_address(
        &swig_wallet_address_seeds(ctx.accounts.swig.key().as_ref()),
        &crate::ID,
    );
    if ctx.accounts.swig_wallet_address.key() != &expected_wallet {
        return Err(SwigError::InvalidSeedSwigAccount.into());
    }
    let expected_rent_destination = configured_rent_claimer
        .as_ref()
        .unwrap_or(ctx.accounts.swig_wallet_address.key());
    if ctx.accounts.rent_claimer_destination.key() != expected_rent_destination
        || ctx.accounts.rent_claimer_destination.key() == ctx.accounts.sub_account_state.key()
        || ctx.accounts.rent_claimer_destination.key() == ctx.accounts.sub_account.key()
    {
        return Err(SwigError::InvalidRentClaimerDestination.into());
    }

    adjust_active_count(ctx.accounts.swig, ctx.accounts.payer, -1)?;

    let rent = Rent::get()?;
    let asset_lamports = ctx.accounts.sub_account.lamports();
    if asset_lamports > 0 {
        let asset_rent =
            asset_lamports.min(rent.minimum_balance(ctx.accounts.sub_account.data_len()));
        let asset_operational = asset_lamports.saturating_sub(asset_rent);
        let signer = sub_account_v2_asset_signer(&swig_id, &id_le, &asset_bump_seed);
        if ctx.accounts.rent_claimer_destination.key() == ctx.accounts.swig_wallet_address.key() {
            pinocchio_system::instructions::Transfer {
                from: ctx.accounts.sub_account,
                to: ctx.accounts.swig_wallet_address,
                lamports: asset_lamports,
            }
            .invoke_signed(&[signer.as_slice().into()])?;
        } else {
            if asset_operational > 0 {
                pinocchio_system::instructions::Transfer {
                    from: ctx.accounts.sub_account,
                    to: ctx.accounts.swig_wallet_address,
                    lamports: asset_operational,
                }
                .invoke_signed(&[signer.as_slice().into()])?;
            }
            if asset_rent > 0 {
                pinocchio_system::instructions::Transfer {
                    from: ctx.accounts.sub_account,
                    to: ctx.accounts.rent_claimer_destination,
                    lamports: asset_rent,
                }
                .invoke_signed(&[signer.as_slice().into()])?;
            }
        }
    }

    let state_lamports = ctx.accounts.sub_account_state.lamports();
    if state_lamports > 0 {
        let state_rent =
            state_lamports.min(rent.minimum_balance(ctx.accounts.sub_account_state.data_len()));
        let state_operational = state_lamports.saturating_sub(state_rent);
        let wallet_lamports = ctx.accounts.swig_wallet_address.lamports();
        let destination_is_wallet =
            ctx.accounts.rent_claimer_destination.key() == ctx.accounts.swig_wallet_address.key();
        let destination_lamports = if destination_is_wallet {
            0
        } else {
            ctx.accounts.rent_claimer_destination.lamports()
        };
        unsafe {
            *ctx.accounts
                .sub_account_state
                .borrow_mut_lamports_unchecked() = 0;
            *ctx.accounts
                .swig_wallet_address
                .borrow_mut_lamports_unchecked() = wallet_lamports
                .checked_add(if destination_is_wallet {
                    state_lamports
                } else {
                    state_operational
                })
                .ok_or(SwigError::StateError)?;
            if !destination_is_wallet {
                *ctx.accounts
                    .rent_claimer_destination
                    .borrow_mut_lamports_unchecked() = destination_lamports
                    .checked_add(state_rent)
                    .ok_or(SwigError::StateError)?;
            }
        }
    }
    ctx.accounts.sub_account_state.resize(0)?;
    Ok(())
}
