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
    /// Length of the instruction prefix to match (0-32)
    pub instruction_prefix_len: u8,
    /// Padding for alignment
    _padding: [u8; 7],
    /// The session key for temporary authentication
    pub session_key: [u8; 32],
    /// Maximum duration a session can be valid for
    pub max_session_length: u64,
    /// The program ID that must execute the preceding instruction
    pub program_id: [u8; 32],
    /// The instruction data prefix that must match
    pub instruction_prefix: [u8; MAX_INSTRUCTION_PREFIX_LEN],
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
    /// Length of the instruction prefix to match (0-32)
    pub instruction_prefix_len: u8,
    /// Padding for alignment
    _padding: [u8; 7],
    /// The current session key
    pub session_key: [u8; 32],
    /// Maximum allowed session duration
    pub max_session_length: u64,
    /// Slot when the current session expires
    pub current_session_expiration: u64,
    /// The program ID that must execute the preceding instruction
    pub program_id: [u8; 32],
    /// The instruction data prefix that must match
    pub instruction_prefix: [u8; MAX_INSTRUCTION_PREFIX_LEN],
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
        // program_id and instruction_prefix are contiguous in memory
        let len = 32 + self.instruction_prefix_len as usize;
        let bytes = unsafe { core::slice::from_raw_parts(self.program_id.as_ptr(), len) };
        Ok(bytes)
    }

    fn signature_odometer(&self) -> Option<u32> {
        None
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn match_data(&self, data: &[u8]) -> bool {
        use swig_assertions::sol_assert_bytes_eq;

        // Data format should match identity(): program_id (32) + instruction_prefix (prefix_len)
        let expected_len = 32 + self.instruction_prefix_len as usize;
        if data.len() != expected_len {
            return false;
        }
        sol_assert_bytes_eq(&self.program_id, &data[..32], 32)
            && sol_assert_bytes_eq(
                &self.instruction_prefix[..self.instruction_prefix_len as usize],
                &data[32..],
                self.instruction_prefix_len as usize,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_session_authority(
        program_id: [u8; 32],
        prefix: &[u8],
    ) -> ProgramExecSessionAuthority {
        let mut instruction_prefix = [0u8; MAX_INSTRUCTION_PREFIX_LEN];
        instruction_prefix[..prefix.len()].copy_from_slice(prefix);

        ProgramExecSessionAuthority::new(
            program_id,
            prefix.len() as u8,
            instruction_prefix,
            [0u8; 32], // session_key
            3600,      // max_session_length
        )
    }

    #[test]
    fn test_identity_returns_program_id_and_prefix() {
        let program_id = [1u8; 32];
        let prefix = [0x01, 0xAB, 0xCD];
        let authority = create_test_session_authority(program_id, &prefix);

        let identity = authority.identity().unwrap();

        // Identity should be program_id (32 bytes) + instruction_prefix (prefix_len bytes)
        assert_eq!(identity.len(), 32 + prefix.len());
        assert_eq!(&identity[..32], &program_id);
        assert_eq!(&identity[32..], &prefix);
    }

    #[test]
    fn test_identity_with_33_byte_prefix() {
        // Test the IDP use case: 1 byte discriminator + 32 byte sub_hash
        let program_id = [2u8; 32];
        let mut prefix = [0u8; 33];
        prefix[0] = 0x01; // VerifyJwt discriminator
        prefix[1..33].copy_from_slice(&[0xAB; 32]); // sub_hash

        let authority = create_test_session_authority(program_id, &prefix);

        let identity = authority.identity().unwrap();

        assert_eq!(identity.len(), 65); // 32 + 33
        assert_eq!(&identity[..32], &program_id);
        assert_eq!(identity[32], 0x01); // discriminator
        assert_eq!(&identity[33..65], &[0xAB; 32]); // sub_hash
    }

    #[test]
    fn test_identity_with_zero_prefix_len() {
        let program_id = [3u8; 32];
        let authority = create_test_session_authority(program_id, &[]);

        let identity = authority.identity().unwrap();

        assert_eq!(identity.len(), 32);
        assert_eq!(identity, &program_id);
    }

    #[test]
    fn test_match_data_matches_identity() {
        let program_id = [4u8; 32];
        let prefix = [0x01, 0x02, 0x03, 0x04];
        let authority = create_test_session_authority(program_id, &prefix);

        let identity = authority.identity().unwrap();

        // match_data should return true when given the identity
        assert!(authority.match_data(identity));
    }

    #[test]
    fn test_match_data_with_33_byte_prefix() {
        let program_id = [5u8; 32];
        let mut prefix = [0u8; 33];
        prefix[0] = 0x01;
        prefix[1..33].copy_from_slice(&[0xCD; 32]);

        let authority = create_test_session_authority(program_id, &prefix);

        let identity = authority.identity().unwrap();

        assert!(authority.match_data(identity));
        assert_eq!(identity.len(), 65);
    }

    #[test]
    fn test_match_data_rejects_wrong_program_id() {
        let program_id = [6u8; 32];
        let prefix = [0x01, 0x02];
        let authority = create_test_session_authority(program_id, &prefix);

        // Create data with wrong program_id
        let mut wrong_data = vec![7u8; 32];
        wrong_data.extend_from_slice(&prefix);

        assert!(!authority.match_data(&wrong_data));
    }

    #[test]
    fn test_match_data_rejects_wrong_prefix() {
        let program_id = [8u8; 32];
        let prefix = [0x01, 0x02];
        let authority = create_test_session_authority(program_id, &prefix);

        // Create data with wrong prefix
        let mut wrong_data = program_id.to_vec();
        wrong_data.extend_from_slice(&[0xFF, 0xFF]);

        assert!(!authority.match_data(&wrong_data));
    }

    #[test]
    fn test_match_data_rejects_wrong_length() {
        let program_id = [9u8; 32];
        let prefix = [0x01, 0x02];
        let authority = create_test_session_authority(program_id, &prefix);

        // Too short
        assert!(!authority.match_data(&program_id));

        // Too long
        let mut too_long = program_id.to_vec();
        too_long.extend_from_slice(&[0x01, 0x02, 0x03]);
        assert!(!authority.match_data(&too_long));
    }

    #[test]
    fn test_struct_size() {
        // Verify the struct size is as expected
        // prefix_len(1) + padding(7) + session_key(32) + max_session_length(8) +
        // current_session_expiration(8) + program_id(32) + instruction_prefix(40) = 128
        assert_eq!(ProgramExecSessionAuthority::LEN, 128);
    }

    #[test]
    fn test_program_id_and_instruction_prefix_are_contiguous() {
        let program_id = [0xAA; 32];
        let prefix = [0xBB; 10];
        let authority = create_test_session_authority(program_id, &prefix);

        // The identity() method relies on program_id and instruction_prefix being contiguous
        // This test verifies the memory layout assumption
        let identity = authority.identity().unwrap();

        // First 32 bytes should be program_id
        assert_eq!(&identity[..32], &program_id);
        // Next prefix_len bytes should be instruction_prefix
        assert_eq!(&identity[32..42], &prefix);
    }
}
