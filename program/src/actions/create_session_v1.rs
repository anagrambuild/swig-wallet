use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_assertions::check_self_owned;
use swig_state_x::{
    swig::Swig, Discriminator, IntoBytes, SwigAuthenticateError, Transmutable,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, CreateSessionV1Accounts},
        SwigInstruction,
    },
};

#[derive(Debug, NoPadding)]
#[repr(C, align(8))]
pub struct CreateSessionV1Args {
    pub instruction: SwigInstruction,
    pub authority_payload_len: u16,
    pub role_id: u32,
    pub session_duration: u64,
    pub session_key: [u8; 32],
}

impl Transmutable for CreateSessionV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for CreateSessionV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl CreateSessionV1Args {
    pub fn new(
        role_id: u32,
        authority_payload_len: u16,
        session_duration: u64,
        session_key: [u8; 32],
    ) -> Self {
        Self {
            instruction: SwigInstruction::CreateSessionV1,
            role_id,
            authority_payload_len,
            session_duration,
            session_key,
        }
    }
}

pub struct CreateSessionV1<'a> {
    pub args: &'a CreateSessionV1Args,
    pub authority_payload: &'a [u8],
    pub session_data: &'a [u8],
}

impl<'a> CreateSessionV1<'a> {
    pub fn load(data: &'a [u8]) -> Result<Self, ProgramError> {
        let (inst, rest) = unsafe { data.split_at_unchecked(CreateSessionV1Args::LEN) };
        let args = unsafe {
            CreateSessionV1Args::load_unchecked(inst).map_err(|e| {
                msg!("CreateSessionV1Args Args Error: {:?}", e);
                ProgramError::InvalidInstructionData
            })?
        };

        let (authority_payload, session_data) = rest.split_at(args.authority_payload_len as usize);

        Ok(Self {
            args,
            authority_payload,
            session_data,
        })
    }
}

pub fn create_session_v1(
    ctx: Context<CreateSessionV1Accounts>,
    data: &[u8],
    account_infos: &[AccountInfo],
) -> ProgramResult {
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    let create_session_v1 = CreateSessionV1::load(data).map_err(|e| {
        msg!("CreateSessionV1Args Error: {:?}", e);
        ProgramError::InvalidInstructionData
    })?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }
    let (_swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let role = Swig::get_mut_role(create_session_v1.args.role_id, swig_roles)?;
    if role.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let role = role.unwrap();
    let clock = Clock::get()?;
    let slot = clock.slot;
    if !role.authority.session_based() {
        return Err(SwigAuthenticateError::AuthorityDoesNotSupportSessionBasedAuth.into());
    }
    role.authority.authenticate(
        account_infos,
        create_session_v1.authority_payload,
        create_session_v1.session_data,
        slot,
    )?;

    role.authority.start_session(
        create_session_v1.args.session_key,
        slot,
        create_session_v1.args.session_duration,
    )?;

    Ok(())
}
