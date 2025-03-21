use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_state::{
    authority::{Ed25519SessionAuthorityData, Ed25519SessionAuthorityDataMut},
    AuthorityType, Role, Swig,
};

use crate::{
    authority_models::{StartSession, ValidSession},
    error::SwigError,
    instruction::{
        accounts::{Context, CreateSessionV1Accounts},
        Authenticatable, SwigInstruction,
    },
    util::ZeroCopy,
};

#[derive(Pod, Zeroable, Copy, Clone)]
#[repr(C, align(8))]
pub struct CreateSessionV1Args {
    pub instruction: u8,
    pub role_id: u8,
    _padding: [u8; 4],
    pub authority_payload_len: u16,
    pub session_duration: u64, // in slots
}

impl<'a> ZeroCopy<'a, CreateSessionV1Args> for CreateSessionV1Args {}

impl CreateSessionV1Args {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    pub fn new(role_id: u8, authority_payload_len: u16, session_duration: u64) -> Self {
        Self {
            instruction: SwigInstruction::CreateSessionV1 as u8,
            role_id,
            _padding: [0; 4],
            authority_payload_len,
            session_duration,
        }
    }
}

pub struct CreateSessionV1<'a> {
    pub args: &'a CreateSessionV1Args,
    pub authority_payload: &'a [u8],
    pub session_data: &'a [u8],
}

impl Authenticatable for CreateSessionV1<'_> {
    fn data_payload(&self) -> &[u8] {
        self.session_data
    }

    fn authority_payload(&self) -> &[u8] {
        self.authority_payload
    }
}

impl<'a> CreateSessionV1<'a> {
    pub fn load(data: &'a [u8]) -> Result<Self, ProgramError> {
        let (inst, rest) = data.split_at(CreateSessionV1Args::SIZE);
        let args = CreateSessionV1Args::load(inst).map_err(|e| {
            msg!("CreateSessionV1Args Args Error: {:?}", e);
            ProgramError::InvalidInstructionData
        })?;

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
    let create_session_v1 = CreateSessionV1::load(data).map_err(|e| {
        msg!("CreateSessionV1Args Error: {:?}", e);
        ProgramError::InvalidInstructionData
    })?;
    // Extract swig account data
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (offset, mut role) =
        Swig::raw_get_role(swig_account_data, create_session_v1.args.role_id as usize)
            .ok_or(SwigError::InvalidAuthority)?;
    let clock = Clock::get()?;
    let current_slot = clock.slot;
    // Check if authority type supports sessions
    match role.authority_type {
        AuthorityType::Ed25519Session => {
            let session_data = Ed25519SessionAuthorityDataMut::load(&mut role.authority_data)
                .map_err(|e| SwigError::StateError(e))?;
            session_data.start_session(
                create_session_v1.args.session_duration,
                create_session_v1.session_data,
                current_slot,
            )?;
        },
        _ => return Err(SwigError::AuthorityTypeDoesNotSupportSessions.into()),
    };
    create_session_v1.authenticate(account_infos, &role, current_slot)?;
    role.serialize(&mut &mut swig_account_data[offset..offset + role.size()])
        .map_err(|_| SwigError::SerializationError)?;
    Ok(())
}
