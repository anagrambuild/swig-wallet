use developer_account_registry_state::DeveloperAccount;
use no_padding::NoPadding;
use pinocchio::{program_error::ProgramError, ProgramResult};
use swig_assertions::{check_owner, check_writable};
use swig_state::{IntoBytes, Transmutable};

use super::require_registry_admin;
use crate::{
    error::DeveloperAccountRegistryError,
    instruction::{
        accounts::{Context, UpdateDeveloperSignerAccounts},
        DeveloperAccountRegistryInstruction,
    },
};

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct UpdateDeveloperSignerArgs {
    // `u16` rather than the instruction enum, so loading arbitrary bytes never
    // produces an invalid enum value.
    discriminator: u16,
    _padding: [u8; 6],
    pub signer: [u8; 32],
}

impl UpdateDeveloperSignerArgs {
    pub fn new(signer: [u8; 32]) -> Self {
        Self {
            discriminator: DeveloperAccountRegistryInstruction::UpdateDeveloperSigner.into(),
            _padding: [0; 6],
            signer,
        }
    }

    fn from_instruction_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(DeveloperAccountRegistryError::InvalidInstructionDataLength.into());
        }
        let args = unsafe { Self::load_unchecked(data)? };
        if args._padding != [0; 6] {
            return Err(DeveloperAccountRegistryError::InvalidInstructionPadding.into());
        }

        Ok(args)
    }
}

impl Transmutable for UpdateDeveloperSignerArgs {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for UpdateDeveloperSignerArgs {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

#[inline(always)]
pub fn update_developer_signer(
    ctx: Context<UpdateDeveloperSignerAccounts>,
    data: &[u8],
) -> ProgramResult {
    require_registry_admin(ctx.accounts.registry_admin)?;

    let developer_account = ctx.accounts.developer_account;
    check_owner(
        developer_account,
        &crate::ID,
        DeveloperAccountRegistryError::InvalidAccountOwner,
    )?;
    check_writable(
        developer_account,
        DeveloperAccountRegistryError::AccountNotWritable,
    )?;

    let args = UpdateDeveloperSignerArgs::from_instruction_bytes(data)?;
    if args.signer == [0; 32] {
        return Err(DeveloperAccountRegistryError::InvalidSigner.into());
    }

    let data = unsafe { developer_account.borrow_mut_data_unchecked() };
    let account = DeveloperAccount::load_mut(data).map_err(DeveloperAccountRegistryError::from)?;
    account
        .verify_pda(developer_account.key())
        .map_err(DeveloperAccountRegistryError::from)?;
    account.signer = args.signer;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_layout() {
        assert_eq!(UpdateDeveloperSignerArgs::LEN, 40);
        assert_eq!(core::mem::offset_of!(UpdateDeveloperSignerArgs, signer), 8);
    }

    #[test]
    fn test_args_bytes() {
        let args = UpdateDeveloperSignerArgs::new([6u8; 32]);
        let bytes = args.into_bytes().unwrap();
        assert_eq!(bytes[..2], 1u16.to_le_bytes());
        assert_eq!(bytes[2..8], [0; 6]);
        assert_eq!(bytes[8..40], [6u8; 32]);
    }
}
