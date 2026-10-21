use developer_account_registry_state::{
    developer_account_seeds, developer_account_signer, DeveloperAccount, DeveloperTier,
};
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, Transfer};
use swig_assertions::{check_any_pda, check_bytes_match, check_writable, check_writable_signer};
use swig_state::{IntoBytes, Transmutable};

use super::require_registry_admin;
use crate::{
    error::DeveloperAccountRegistryError,
    instruction::{
        accounts::{Context, CreateOrUpdateDeveloperAccountAccounts},
        DeveloperAccountRegistryInstruction,
    },
};

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct CreateOrUpdateDeveloperAccountArgs {
    // `u16` rather than the instruction enum, so loading arbitrary bytes never
    // produces an invalid enum value.
    discriminator: u16,
    pub tier: u8,
    _padding: [u8; 5],
    pub valid_until: i64,
    pub developer_account_id: [u8; 32],
}

impl CreateOrUpdateDeveloperAccountArgs {
    pub fn new(developer_account_id: [u8; 32], tier: DeveloperTier, valid_until: i64) -> Self {
        Self {
            discriminator: DeveloperAccountRegistryInstruction::CreateOrUpdateDeveloperAccount
                .into(),
            tier: tier as u8,
            _padding: [0; 5],
            valid_until,
            developer_account_id,
        }
    }

    fn from_instruction_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(DeveloperAccountRegistryError::InvalidInstructionDataLength.into());
        }
        let args = unsafe { Self::load_unchecked(data)? };
        if args._padding != [0; 5] {
            return Err(DeveloperAccountRegistryError::InvalidInstructionPadding.into());
        }

        Ok(args)
    }
}

impl Transmutable for CreateOrUpdateDeveloperAccountArgs {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for CreateOrUpdateDeveloperAccountArgs {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

#[inline(always)]
pub fn create_or_update_developer_account(
    ctx: Context<CreateOrUpdateDeveloperAccountAccounts>,
    data: &[u8],
) -> ProgramResult {
    require_registry_admin(ctx.accounts.registry_admin)?;
    check_writable_signer(
        ctx.accounts.payer,
        DeveloperAccountRegistryError::PayerMustBeWritableSigner,
    )?;
    check_bytes_match(
        ctx.accounts.system_program.key(),
        &pinocchio_system::ID,
        32,
        DeveloperAccountRegistryError::InvalidSystemProgram,
    )?;

    let args = CreateOrUpdateDeveloperAccountArgs::from_instruction_bytes(data)?;
    let tier = DeveloperTier::try_from(args.tier).map_err(DeveloperAccountRegistryError::from)?;
    if args.developer_account_id == [0; 32] {
        return Err(DeveloperAccountRegistryError::InvalidDeveloperAccountId.into());
    }

    let developer_account = ctx.accounts.developer_account;
    check_writable(
        developer_account,
        DeveloperAccountRegistryError::AccountNotWritable,
    )?;

    if developer_account.is_owned_by(&crate::ID) {
        return update_developer_account(developer_account, args, tier);
    }
    if !developer_account.is_owned_by(&pinocchio_system::ID) || developer_account.data_len() != 0 {
        return Err(DeveloperAccountRegistryError::InvalidAccountState.into());
    }

    create_developer_account(&ctx, args, tier)
}

fn update_developer_account(
    developer_account: &AccountInfo,
    args: &CreateOrUpdateDeveloperAccountArgs,
    tier: DeveloperTier,
) -> ProgramResult {
    let data = unsafe { developer_account.borrow_mut_data_unchecked() };
    let account = DeveloperAccount::load_mut(data).map_err(DeveloperAccountRegistryError::from)?;
    account
        .verify_pda(developer_account.key())
        .map_err(DeveloperAccountRegistryError::from)?;
    if account.developer_account_id != args.developer_account_id {
        return Err(DeveloperAccountRegistryError::InvalidDeveloperAccountPda.into());
    }
    account.set_subscription(tier, args.valid_until);

    Ok(())
}

fn create_developer_account(
    ctx: &Context<CreateOrUpdateDeveloperAccountAccounts>,
    args: &CreateOrUpdateDeveloperAccountArgs,
    tier: DeveloperTier,
) -> ProgramResult {
    let developer_account = ctx.accounts.developer_account;
    let bump = check_any_pda(
        &developer_account_seeds(&args.developer_account_id),
        developer_account.key(),
        &crate::ID,
        DeveloperAccountRegistryError::InvalidDeveloperAccountPda,
    )?;

    // `CreateAccount` fails on a pre-funded PDA, which would block the id for
    // good, so top up, allocate, and assign separately.
    let rent = Rent::get()?.minimum_balance(DeveloperAccount::LEN);
    let shortfall = rent.saturating_sub(developer_account.lamports());
    if shortfall > 0 {
        Transfer {
            from: ctx.accounts.payer,
            to: developer_account,
            lamports: shortfall,
        }
        .invoke()?;
    }

    let bump_seed = [bump];
    let signer = developer_account_signer(&args.developer_account_id, &bump_seed);
    let signers = [signer.as_slice().into()];
    Allocate {
        account: developer_account,
        space: DeveloperAccount::LEN as u64,
    }
    .invoke_signed(&signers)?;
    Assign {
        account: developer_account,
        owner: &crate::ID,
    }
    .invoke_signed(&signers)?;

    let account = DeveloperAccount::new(bump, args.developer_account_id, tier, args.valid_until);
    let data = unsafe { developer_account.borrow_mut_data_unchecked() };
    data.copy_from_slice(account.into_bytes()?);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_layout() {
        assert_eq!(CreateOrUpdateDeveloperAccountArgs::LEN, 48);
        assert_eq!(
            core::mem::offset_of!(CreateOrUpdateDeveloperAccountArgs, valid_until),
            8
        );
        assert_eq!(
            core::mem::offset_of!(CreateOrUpdateDeveloperAccountArgs, developer_account_id),
            16
        );
    }

    #[test]
    fn test_args_bytes() {
        let args = CreateOrUpdateDeveloperAccountArgs::new([5u8; 32], DeveloperTier::Ultra, -1);
        let bytes = args.into_bytes().unwrap();
        assert_eq!(bytes[..2], 0u16.to_le_bytes());
        assert_eq!(bytes[2], DeveloperTier::Ultra as u8);
        assert_eq!(bytes[3..8], [0; 5]);
        assert_eq!(bytes[8..16], (-1i64).to_le_bytes());
        assert_eq!(bytes[16..48], [5u8; 32]);
    }
}
