//! Session-based program execution authority implementation.

use core::any::Any;

use pinocchio::{account_info::AccountInfo, program_error::ProgramError};

use super::{
    super::{ed25519::ed25519_authenticate, Authority, AuthorityInfo, AuthorityType},
    program_exec_authenticate, MAX_INSTRUCTION_PREFIX_LEN,
};
use crate::{
    authority::programexec::assert_program_exec_cant_be_swig, IntoBytes, SwigAuthenticateError,
    SwigStateError, Transmutable, TransmutableMut,
};

/// Creation parameters for a session-based program execution authority.
#[repr(C, align(8))]
#[derive(Debug, PartialEq, no_padding::NoPadding)]
pub struct CreateProgramExecSessionAuthority {
    /// The program ID that must execute the preceding instruction
    pub program_id: [u8; 32],
    /// Length of the instruction prefix to match (0-32)
    pub instruction_prefix_len: u8,
    /// Padding for alignment
    _padding: [u8; 7],
    /// The instruction data prefix that must match
    pub instruction_prefix: [u8; MAX_INSTRUCTION_PREFIX_LEN],
    /// The session key for temporary authentication
    pub session_key: [u8; 32],
    /// Maximum duration a session can be valid for
    pub max_session_length: u64,
}

impl CreateProgramExecSessionAuthority {
    /// Creates a new set of session authority parameters.
    ///
    /// # Arguments
    /// * `program_id` - The program ID to validate against
    /// * `instruction_prefix` - The instruction data prefix to match
    /// * `instruction_prefix_len` - Length of the prefix to match
    /// * `session_key` - The initial session key
    /// * `max_session_length` - Maximum allowed session duration
    pub fn new(
        program_id: [u8; 32],
        instruction_prefix_len: u8,
        instruction_prefix: [u8; MAX_INSTRUCTION_PREFIX_LEN],
        session_key: [u8; 32],
        max_session_length: u64,
    ) -> Self {
        Self {
            program_id,
            instruction_prefix,
            instruction_prefix_len,
            _padding: [0; 7],
            session_key,
            max_session_length,
        }
    }
}

impl Transmutable for CreateProgramExecSessionAuthority {
    const LEN: usize = core::mem::size_of::<ProgramExecSessionAuthority>();
}

impl IntoBytes for CreateProgramExecSessionAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

/// Session-based Program Execution authority implementation.
///
/// This struct represents a program execution authority that supports temporary
/// session keys with expiration times. It validates preceding instructions
/// and maintains session state.
#[repr(C, align(8))]
#[derive(Debug, PartialEq, no_padding::NoPadding)]
pub struct ProgramExecSessionAuthority {
    /// The program ID that must execute the preceding instruction
    pub program_id: [u8; 32],
    /// Length of the instruction prefix to match (0-32)
    pub instruction_prefix_len: u8,
    /// Padding for alignment
    _padding: [u8; 7],
    /// The instruction data prefix that must match
    pub instruction_prefix: [u8; MAX_INSTRUCTION_PREFIX_LEN],

    /// The current session key
    pub session_key: [u8; 32],
    /// Maximum allowed session duration
    pub max_session_length: u64,
    /// Slot when the current session expires
    pub current_session_expiration: u64,
}

impl ProgramExecSessionAuthority {
    /// Creates a new session-based program execution authority.
    ///
    /// # Arguments
    /// * `program_id` - The program ID to validate against
    /// * `instruction_prefix` - The instruction data prefix to match
    /// * `instruction_prefix_len` - Length of the prefix to match
    /// * `session_key` - The initial session key
    /// * `max_session_length` - Maximum allowed session duration
    pub fn new(
        program_id: [u8; 32],
        instruction_prefix_len: u8,
        instruction_prefix: [u8; MAX_INSTRUCTION_PREFIX_LEN],
        session_key: [u8; 32],
        max_session_length: u64,
    ) -> Self {
        Self {
            program_id,
            instruction_prefix_len,
            _padding: [0; 7],
            instruction_prefix,
            session_key,
            max_session_length,
            current_session_expiration: 0,
        }
    }
}

impl Transmutable for ProgramExecSessionAuthority {
    const LEN: usize = core::mem::size_of::<ProgramExecSessionAuthority>();
}

impl TransmutableMut for ProgramExecSessionAuthority {}

impl IntoBytes for ProgramExecSessionAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

impl Authority for ProgramExecSessionAuthority {
    const TYPE: AuthorityType = AuthorityType::ProgramExecSession;
    const SESSION_BASED: bool = true;

    fn set_into_bytes(create_data: &[u8], bytes: &mut [u8]) -> Result<(), ProgramError> {
        let create = unsafe { CreateProgramExecSessionAuthority::load_unchecked(create_data)? };
        let authority = unsafe { ProgramExecSessionAuthority::load_mut_unchecked(bytes)? };

        if create_data.len() != Self::LEN {
            return Err(SwigStateError::InvalidRoleData.into());
        }

        let prefix_len = create_data[32] as usize;
        if prefix_len > MAX_INSTRUCTION_PREFIX_LEN {
            return Err(SwigStateError::InvalidRoleData.into());
        }
        let create_data_program_id = &create_data[..32];
        assert_program_exec_cant_be_swig(create_data_program_id)?;
        authority.program_id = create.program_id;
        authority.instruction_prefix = create.instruction_prefix;
        authority.instruction_prefix_len = create.instruction_prefix_len;
        authority.session_key = create.session_key;
        authority.max_session_length = create.max_session_length;
        authority.current_session_expiration = 0;

        Ok(())
    }
}

impl AuthorityInfo for ProgramExecSessionAuthority {
    fn authority_type(&self) -> AuthorityType {
        Self::TYPE
    }

    fn length(&self) -> usize {
        Self::LEN
    }

    fn session_based(&self) -> bool {
        Self::SESSION_BASED
    }

    fn identity(&self) -> Result<&[u8], ProgramError> {
        Ok(&self.instruction_prefix[..self.instruction_prefix_len as usize])
    }

    fn signature_odometer(&self) -> Option<u32> {
        None
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn match_data(&self, data: &[u8]) -> bool {
        use swig_assertions::sol_assert_bytes_eq;

        if data.len() < 33 {
            return false;
        }
        let prefix_len = data[32] as usize;
        if prefix_len != self.instruction_prefix_len as usize {
            return false;
        }
        if data.len() != 33 + prefix_len {
            return false;
        }
        sol_assert_bytes_eq(&self.program_id, &data[..32], 32)
            && sol_assert_bytes_eq(
                &self.instruction_prefix[..prefix_len],
                &data[33..33 + prefix_len],
                prefix_len,
            )
    }

    fn start_session(
        &mut self,
        session_key: [u8; 32],
        current_slot: u64,
        duration: u64,
    ) -> Result<(), ProgramError> {
        if duration > self.max_session_length {
            return Err(SwigAuthenticateError::InvalidSessionDuration.into());
        }
        self.current_session_expiration = current_slot + duration;
        self.session_key = session_key;
        Ok(())
    }

    fn authenticate_session(
        &mut self,
        account_infos: &[AccountInfo],
        authority_payload: &[u8],
        _data_payload: &[u8],
        slot: u64,
    ) -> Result<(), ProgramError> {
        if authority_payload.len() != 1 {
            return Err(SwigAuthenticateError::InvalidAuthorityPayload.into());
        }
        if slot > self.current_session_expiration {
            return Err(SwigAuthenticateError::PermissionDeniedSessionExpired.into());
        }
        ed25519_authenticate(
            account_infos,
            authority_payload[0] as usize,
            &self.session_key,
        )
    }

    fn authenticate(
        &mut self,
        account_infos: &[AccountInfo],
        authority_payload: &[u8],
        _data_payload: &[u8],
        _slot: u64,
    ) -> Result<(), ProgramError> {
        // authority_payload format: [instruction_sysvar_index: 1 byte]
        if authority_payload.len() != 1 {
            return Err(SwigAuthenticateError::InvalidAuthorityPayload.into());
        }

        let instruction_sysvar_index = authority_payload[0] as usize;
        let config_account_index = 0;
        let wallet_account_index = 1;

        program_exec_authenticate(
            account_infos,
            instruction_sysvar_index,
            config_account_index,
            wallet_account_index,
            &self.program_id,
            &self.instruction_prefix,
            self.instruction_prefix_len as usize,
        )
    }
}
