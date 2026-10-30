use super::SwigInstruction;
use pinocchio::program_error::ProgramError;
use swig_state::IntoBytes;

use swig_state::authority::AuthorityType;

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct CreateV1Args {
    discriminator: SwigInstruction,
    pub authority_type: u16,
    pub authority_data_len: u16,
    pub bump: u8,
    pub wallet_address_bump: u8,
    pub id: [u8; 32],
}

impl CreateV1Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// Creates a new instance of CreateV1Args.
    ///
    /// # Arguments
    /// * `id` - Unique identifier for the wallet
    /// * `bump` - Bump seed for PDA derivation
    /// * `wallet_address_bump` - Bump seed for wallet address PDA derivation
    /// * `authority_type` - Type of authority to create
    /// * `authority_data_len` - Length of the authority data
    pub fn new(
        id: [u8; 32],
        bump: u8,
        authority_type: AuthorityType,
        authority_data_len: u16,
        wallet_address_bump: u8,
    ) -> Self {
        Self {
            discriminator: SwigInstruction::CreateV1,
            id,
            bump,
            authority_type: authority_type as u16,
            authority_data_len,
            wallet_address_bump,
        }
    }
}

impl IntoBytes for CreateV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct SignV2Args {
    instruction: SwigInstruction,
    pub instruction_payload_len: u16,
    pub role_id: u32,
}

impl SignV2Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// Creates a new instance of SignV2Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the signing role
    /// * `instruction_payload_len` - Length of the instruction payload
    pub fn new(role_id: u32, instruction_payload_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::SignV2,
            role_id,
            instruction_payload_len,
        }
    }
}

impl IntoBytes for SignV2Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct CloseSwigV1Args {
    pub discriminator: SwigInstruction,
    pub _padding: [u8; 2],
    pub role_id: u32,
}

impl CloseSwigV1Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn new(role_id: u32) -> Self {
        Self {
            discriminator: SwigInstruction::CloseSwigV1,
            _padding: [0; 2],
            role_id,
        }
    }
}

impl IntoBytes for CloseSwigV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct CloseTokenAccountV1Args {
    pub discriminator: SwigInstruction,
    pub token_account_offset: u16,
    pub role_id: u32,
}

impl CloseTokenAccountV1Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn new(role_id: u32, token_account_offset: u16) -> Self {
        Self {
            discriminator: SwigInstruction::CloseTokenAccountV1,
            token_account_offset,
            role_id,
        }
    }
}

impl IntoBytes for CloseTokenAccountV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct SetRentClaimerV1Args {
    pub discriminator: SwigInstruction,
    pub _padding: [u8; 2],
    pub role_id: u32,
    pub rent_claimer: [u8; 32],
}

impl SetRentClaimerV1Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn new(role_id: u32, rent_claimer: [u8; 32]) -> Self {
        Self {
            discriminator: SwigInstruction::SetRentClaimerV1,
            _padding: [0; 2],
            role_id,
            rent_claimer,
        }
    }
}

impl IntoBytes for SetRentClaimerV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct TransferAssetsV1Args {
    discriminator: SwigInstruction,
    pub _padding: u16,
    pub role_id: u32,
}

impl TransferAssetsV1Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// Creates a new instance of TransferAssetsV1Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the role performing the transfer
    pub fn new(role_id: u32) -> Self {
        Self {
            discriminator: SwigInstruction::TransferAssetsV1,
            _padding: 0,
            role_id,
        }
    }
}

impl IntoBytes for TransferAssetsV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}
