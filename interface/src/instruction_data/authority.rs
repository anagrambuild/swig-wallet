use super::SwigInstruction;
use pinocchio::program_error::ProgramError;
use swig_state::IntoBytes;

use swig_state::authority::AuthorityType;

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct AddAuthorityV1Args {
    pub instruction: SwigInstruction,
    pub new_authority_data_len: u16,
    pub actions_data_len: u16,
    pub new_authority_type: u16,
    pub num_actions: u8,
    _padding: [u8; 3],
    pub acting_role_id: u32,
}

impl AddAuthorityV1Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// Creates a new instance of AddAuthorityV1Args.
    ///
    /// # Arguments
    /// * `acting_role_id` - ID of the role performing the addition
    /// * `authority_type` - Type of the new authority
    /// * `new_authority_data_len` - Length of the new authority's data
    /// * `actions_data_len` - Length of the actions data
    /// * `num_actions` - Number of actions for the new authority
    pub fn new(
        acting_role_id: u32,
        authority_type: AuthorityType,
        new_authority_data_len: u16,
        actions_data_len: u16,
        num_actions: u8,
    ) -> Self {
        Self {
            instruction: SwigInstruction::AddAuthorityV1,
            acting_role_id,
            new_authority_type: authority_type as u16,
            new_authority_data_len,
            actions_data_len,
            num_actions,
            _padding: [0; 3],
        }
    }
}

impl IntoBytes for AddAuthorityV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct RemoveAuthorityV1Args {
    pub instruction: SwigInstruction,
    pub authority_payload_len: u16,
    _padding: [u16; 2],
    pub acting_role_id: u32,
    pub authority_to_remove_id: u32,
}

impl RemoveAuthorityV1Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// Creates a new instance of RemoveAuthorityV1Args.
    ///
    /// # Arguments
    /// * `acting_role_id` - ID of the role performing the removal
    /// * `authority_to_remove_id` - ID of the authority to remove
    /// * `authority_payload_len` - Length of the authority payload
    pub fn new(
        acting_role_id: u32,
        authority_to_remove_id: u32,
        authority_payload_len: u16,
    ) -> Self {
        Self {
            instruction: SwigInstruction::RemoveAuthorityV1,
            acting_role_id,
            authority_to_remove_id,
            authority_payload_len,
            _padding: [0; 2],
        }
    }
}

impl IntoBytes for RemoveAuthorityV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct UpdateAuthorityV1Args {
    pub instruction: SwigInstruction,
    pub actions_data_len: u16,
    pub num_actions: u8,
    _padding: [u8; 3],
    pub acting_role_id: u32,
    pub authority_to_update_id: u32,
}

impl UpdateAuthorityV1Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// Creates a new instance of UpdateAuthorityV1Args.
    ///
    /// # Arguments
    /// * `acting_role_id` - ID of the role performing the update
    /// * `authority_to_update_id` - ID of the authority to update
    /// * `actions_data_len` - Length of the actions data
    /// * `num_actions` - Number of actions for the authority update
    pub fn new(
        acting_role_id: u32,
        authority_to_update_id: u32,
        actions_data_len: u16,
        num_actions: u8,
    ) -> Self {
        Self {
            instruction: SwigInstruction::UpdateAuthorityV1,
            acting_role_id,
            authority_to_update_id,
            actions_data_len,
            num_actions,
            _padding: [0; 3],
        }
    }
}

impl IntoBytes for UpdateAuthorityV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct ReplaceAuthorityV1Args {
    pub instruction: SwigInstruction,
    _padding: [u8; 2],
    /// Role authenticating and authorizing this replacement.
    pub acting_role_id: u32,
    /// Existing role whose signer will be replaced.
    pub target_role_id: u32,
    /// Length of the new authority bytes immediately following this header.
    pub new_authority_len: u16,
    _trailing_padding: [u8; 2],
}

impl ReplaceAuthorityV1Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn new(acting_role_id: u32, target_role_id: u32, new_authority_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::ReplaceAuthorityV1,
            _padding: [0; 2],
            acting_role_id,
            target_role_id,
            new_authority_len,
            _trailing_padding: [0; 2],
        }
    }
}

impl IntoBytes for ReplaceAuthorityV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct CreateSessionV1Args {
    pub instruction: SwigInstruction,
    _padding: u16,
    pub role_id: u32,
    pub session_duration: u64,
    pub session_key: [u8; 32],
}

impl CreateSessionV1Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// Creates a new instance of CreateSessionV1Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the role creating the session
    /// * `session_duration` - Duration of the session in slots
    /// * `session_key` - Unique key for the session
    pub fn new(role_id: u32, session_duration: u64, session_key: [u8; 32]) -> Self {
        Self {
            instruction: SwigInstruction::CreateSessionV1,
            _padding: 0,
            role_id,
            session_duration,
            session_key,
        }
    }
}

impl IntoBytes for CreateSessionV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum AuthorityUpdateOperation {
    ReplaceAll = 0,
    AddActions = 1,
    RemoveActionsByType = 2,
    RemoveActionsByIndex = 3,
}

pub const REPLACE_AUTHORITY_PROOF_V1_DISCRIMINATOR: [u8; 8] = *b"rplauth1";
pub const REPLACE_AUTHORITY_PROOF_V1_DOMAIN: &[u8] = b"swig-replace-authority-v1";
