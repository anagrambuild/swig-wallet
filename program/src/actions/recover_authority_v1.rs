//! Recovery authority instruction.
//!
//! This instruction rotates one Secp256r1 authority to another while preserving
//! the target role and permissions. Authentication is delegated to the acting
//! role, which is expected to be a ProgramExec recovery role.

use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_assertions::check_self_owned;
use swig_state::{
    action::recovery_authority::RecoveryAuthority,
    authority::{secp256r1::Secp256r1Authority, AuthorityType},
    role::Position,
    swig::Swig,
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, RecoverAuthorityV1Accounts},
        SwigInstruction,
    },
};

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct RecoverAuthorityV1Args {
    pub instruction: SwigInstruction,
    pub authority_payload_len: u16,
    pub acting_role_id: u32,
    pub target_role_id: u32,
    pub old_authority: [u8; 33],
    pub new_authority: [u8; 33],
    _padding: [u8; 2],
}

impl Transmutable for RecoverAuthorityV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for RecoverAuthorityV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl RecoverAuthorityV1Args {
    pub fn new(
        acting_role_id: u32,
        target_role_id: u32,
        old_authority: [u8; 33],
        new_authority: [u8; 33],
        authority_payload_len: u16,
    ) -> Self {
        Self {
            instruction: SwigInstruction::RecoverAuthorityV1,
            authority_payload_len,
            acting_role_id,
            target_role_id,
            old_authority,
            new_authority,
            _padding: [0; 2],
        }
    }
}

pub struct RecoverAuthorityV1<'a> {
    pub args: &'a RecoverAuthorityV1Args,
    data_payload: &'a [u8],
    authority_payload: &'a [u8],
}

impl<'a> RecoverAuthorityV1<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < RecoverAuthorityV1Args::LEN {
            return Err(SwigError::InvalidSwigRecoverAuthorityInstructionDataTooShort.into());
        }

        let (args_bytes, authority_payload) = data.split_at(RecoverAuthorityV1Args::LEN);
        let args = unsafe { RecoverAuthorityV1Args::load_unchecked(args_bytes)? };
        if authority_payload.len() != args.authority_payload_len as usize {
            return Err(ProgramError::InvalidInstructionData);
        }

        Ok(Self {
            args,
            data_payload: args_bytes,
            authority_payload,
        })
    }
}

pub fn recover_authority_v1(
    ctx: Context<RecoverAuthorityV1Accounts>,
    data: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;

    let recover = RecoverAuthorityV1::from_instruction_bytes(data)?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if swig_account_data[0] != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };

    {
        let acting_role = Swig::get_mut_role(recover.args.acting_role_id, swig_roles)?
            .ok_or(SwigError::InvalidAuthorityNotFoundByRoleId)?;
        let slot = Clock::get()?.slot;
        if acting_role.authority.session_based() {
            acting_role.authority.authenticate_session(
                all_accounts,
                recover.authority_payload,
                recover.data_payload,
                slot,
            )?;
        } else {
            acting_role.authority.authenticate(
                all_accounts,
                recover.authority_payload,
                recover.data_payload,
                slot,
            )?;
        }

        if acting_role.get_action::<RecoveryAuthority>(&[])?.is_none() {
            return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
        }
    }

    rotate_target_passkey(swig, swig_roles, recover.args)
}

fn rotate_target_passkey(
    swig: &Swig,
    swig_roles: &mut [u8],
    args: &RecoverAuthorityV1Args,
) -> ProgramResult {
    let mut cursor = 0;
    for _ in 0..swig.roles {
        let position =
            unsafe { Position::load_unchecked(&swig_roles[cursor..cursor + Position::LEN])? };
        if position.id() == args.target_role_id {
            if position.authority_type()? != AuthorityType::Secp256r1 {
                return Err(SwigError::OnlyPasskeyRecoverySupported.into());
            }

            let authority_start = cursor + Position::LEN;
            let authority_end = authority_start + Secp256r1Authority::LEN;
            let authority = unsafe {
                Secp256r1Authority::load_mut_unchecked(
                    &mut swig_roles[authority_start..authority_end],
                )?
            };
            if authority.public_key != args.old_authority {
                return Err(SwigError::RecoveryOldAuthorityMismatch.into());
            }

            authority.public_key = args.new_authority;
            authority.signature_odometer = 0;
            return Ok(());
        }

        cursor = position.boundary() as usize;
    }

    Err(SwigError::InvalidAuthorityNotFoundByRoleId.into())
}
