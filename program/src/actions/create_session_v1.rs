/// Module for creating temporary authentication sessions in a Swig wallet.
/// This module implements functionality to create time-limited sessions that
/// allow authorities to authenticate without providing full credentials each
/// time.
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_assertions::check_self_owned;
use swig_state_x::{swig::Swig, Discriminator, IntoBytes, SwigAuthenticateError, Transmutable};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, CreateSessionV1Accounts},
        SwigInstruction,
    },
};

/// Arguments for creating a new session in a Swig wallet.
///
/// # Fields
/// * `instruction` - The instruction type identifier
/// * `authority_payload_len` - Length of the authority payload
/// * `role_id` - ID of the role creating the session
/// * `session_duration` - Duration of the session in slots
/// * `session_key` - Unique key for the session
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
    /// Creates a new instance of CreateSessionV1Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the role creating the session
    /// * `authority_payload_len` - Length of the authority payload
    /// * `session_duration` - Duration of the session in slots
    /// * `session_key` - Unique key for the session
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

/// Struct representing the complete create session instruction data.
///
/// # Fields
/// * `args` - The session creation arguments
/// * `authority_payload` - Authority-specific payload data
/// * `data_payload` - Raw instruction data payload
pub struct CreateSessionV1<'a> {
    pub args: &'a CreateSessionV1Args,
    pub authority_payload: &'a [u8],
    pub data_payload: &'a [u8],
}

impl<'a> CreateSessionV1<'a> {
    /// Parses the instruction data bytes into a CreateSessionV1 instance.
    ///
    /// # Arguments
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn load(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < CreateSessionV1Args::LEN {
            return Err(SwigError::InvalidSwigCreateSessionInstructionDataTooShort.into());
        }
        let (inst, rest) = unsafe { data.split_at_unchecked(CreateSessionV1Args::LEN) };
        let args = unsafe {
            CreateSessionV1Args::load_unchecked(inst).map_err(|e| {
                msg!("CreateSessionV1Args Args Error: {:?}", e);
                ProgramError::InvalidInstructionData
            })?
        };

        Ok(Self {
            args,
            authority_payload: rest,
            data_payload: &data[..CreateSessionV1Args::LEN],
        })
    }
}

/// Creates a new authentication session for a wallet authority.
///
/// This function handles the complete flow of session creation:
/// 1. Validates the authority and role
/// 2. Verifies session support
/// 3. Authenticates the request
/// 4. Creates and initializes the session
///
/// # Arguments
/// * `ctx` - The account context for session creation
/// * `data` - Raw session creation instruction data
/// * `account_infos` - All accounts involved in the operation
///
/// # Returns
/// * `ProgramResult` - Success or error status
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
        create_session_v1.data_payload,
        slot,
    )?;

    role.authority.start_session(
        create_session_v1.args.session_key,
        slot,
        create_session_v1.args.session_duration,
    )?;

    Ok(())
}
