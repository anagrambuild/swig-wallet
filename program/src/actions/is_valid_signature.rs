//! Raw payload signature validation for off-chain proofs.
//!
//! This instruction is intended to be simulated off-chain (never broadcast).
//! It authenticates a Swig role authority against an arbitrary payload without
//! assigning protocol-specific meaning to the payload bytes.

use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::find_program_address,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_assertions::{check_self_owned, check_stack_height, check_system_owner};
use swig_state::{
    swig::{swig_wallet_address_seeds, Swig},
    Discriminator, IntoBytes, Transmutable,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, IsValidSignatureAccounts},
        SwigInstruction,
    },
    AccountClassification,
};

#[derive(Debug, NoPadding)]
#[repr(C, align(8))]
pub struct IsValidSignatureArgs {
    instruction: SwigInstruction,
    pub payload_len: u16,
    pub role_id: u32,
}

impl IsValidSignatureArgs {
    pub fn new(role_id: u32, payload_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::IsValidSignature,
            payload_len,
            role_id,
        }
    }
}

impl Transmutable for IsValidSignatureArgs {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for IsValidSignatureArgs {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

pub struct IsValidSignature<'a> {
    pub args: &'a IsValidSignatureArgs,
    pub payload: &'a [u8],
    pub authority_payload: &'a [u8],
}

impl<'a> IsValidSignature<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < IsValidSignatureArgs::LEN {
            return Err(SwigError::InvalidInstructionDataTooShort.into());
        }

        let (args_data, rest) = unsafe { data.split_at_unchecked(IsValidSignatureArgs::LEN) };
        let args = unsafe { IsValidSignatureArgs::load_unchecked(args_data)? };
        if rest.len() < args.payload_len as usize {
            return Err(SwigError::InvalidInstructionDataTooShort.into());
        }

        let (payload, authority_payload) =
            unsafe { rest.split_at_unchecked(args.payload_len as usize) };

        Ok(Self {
            args,
            payload,
            authority_payload,
        })
    }
}

#[inline(never)]
pub fn is_valid_signature(
    ctx: Context<IsValidSignatureAccounts>,
    all_accounts: &[AccountInfo],
    data: &[u8],
    account_classifiers: &[AccountClassification],
) -> ProgramResult {
    check_stack_height(1, SwigError::Cpi)?;
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_system_owner(
        ctx.accounts.swig_wallet_address,
        SwigError::OwnerMismatchSwigAccount,
    )?;

    if account_classifiers.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    if !matches!(
        account_classifiers[0],
        AccountClassification::ThisSwigV2 { .. }
    ) || !matches!(
        account_classifiers[1],
        AccountClassification::SwigWalletAddress
    ) {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    let validate = IsValidSignature::from_instruction_bytes(data)?;

    let swig_account_data = unsafe { ctx.accounts.swig.borrow_data_unchecked() };
    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_unchecked(swig_header)? };

    let swig_wallet_seeds = swig_wallet_address_seeds(ctx.accounts.swig.key().as_ref());
    let (derived_wallet, _) = find_program_address(&swig_wallet_seeds, &crate::ID);
    if derived_wallet != *ctx.accounts.swig_wallet_address.key() {
        return Err(SwigError::InvalidSeedSwigAccount.into());
    }

    // `IsValidSignature` is intended for off-chain simulation and should not
    // mutate on-chain authority state (e.g. secp signature odometers).
    let mut swig_roles_for_auth = swig_roles.to_vec();
    let role = Swig::get_mut_role(validate.args.role_id, &mut swig_roles_for_auth)?
        .ok_or(SwigError::InvalidAuthorityNotFoundByRoleId)?;

    let clock = Clock::get()?;
    let slot = clock.slot;
    if role.authority.session_based() {
        role.authority.authenticate_session(
            all_accounts,
            validate.authority_payload,
            validate.payload,
            slot,
        )?;
    } else {
        role.authority.authenticate(
            all_accounts,
            validate.authority_payload,
            validate.payload,
            slot,
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{IsValidSignature, IsValidSignatureArgs};
    use swig_state::IntoBytes;

    #[test]
    fn splits_payload_and_authority_payload() {
        let args = IsValidSignatureArgs::new(7, 3);
        let arg_bytes = match args.into_bytes() {
            Ok(bytes) => bytes,
            Err(error) => panic!("IsValidSignatureArgs serialization should succeed: {error:?}"),
        };
        let data = [arg_bytes, &[1, 2, 3], &[4, 5, 6]].concat();

        let parsed = match IsValidSignature::from_instruction_bytes(&data) {
            Ok(parsed) => parsed,
            Err(error) => panic!("IsValidSignature should parse: {error:?}"),
        };

        assert_eq!(parsed.args.role_id, 7);
        assert_eq!(parsed.payload, &[1, 2, 3]);
        assert_eq!(parsed.authority_payload, &[4, 5, 6]);
    }
}
