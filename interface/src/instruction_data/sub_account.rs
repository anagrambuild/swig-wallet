use super::SwigInstruction;
use pinocchio::program_error::ProgramError;
use swig_state::IntoBytes;

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct CreateSubAccountV1Args {
    discriminator: SwigInstruction,
    _padding1: u16,
    pub role_id: u32,
    pub sub_account_bump: u8,
    _padding2: [u8; 7],
}

impl CreateSubAccountV1Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// Creates a new instance of CreateSubAccountV1Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the role creating the sub-account
    /// * `sub_account_bump` - Bump seed for sub-account PDA derivation
    pub fn new(role_id: u32, sub_account_bump: u8) -> Self {
        Self {
            discriminator: SwigInstruction::CreateSubAccountV1,
            _padding1: 0,
            role_id,
            sub_account_bump,
            _padding2: [0; 7],
        }
    }
}

impl IntoBytes for CreateSubAccountV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct CreateSubAccountV2Args {
    discriminator: SwigInstruction,
    _padding1: u16,
    /// Role creating (and initially granted access to) the sub-account
    pub role_id: u32,
    /// Reserved; PDA bumps are derived by the program, not supplied by callers.
    _padding2: [u8; 8],
}

impl CreateSubAccountV2Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn new(role_id: u32) -> Self {
        Self {
            discriminator: SwigInstruction::CreateSubAccountV2,
            _padding1: 0,
            role_id,
            _padding2: [0; 8],
        }
    }
}

impl IntoBytes for CreateSubAccountV2Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct CloseSubAccountV1Args {
    pub discriminator: SwigInstruction,
    pub _padding: u16,
    pub auth_role_id: u32,
    pub sub_account_role_id: u32,
    pub _padding2: u32,
}

impl CloseSubAccountV1Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn new(auth_role_id: u32, sub_account_role_id: u32) -> Self {
        Self {
            discriminator: SwigInstruction::CloseSubAccountV1,
            _padding: 0,
            auth_role_id,
            sub_account_role_id,
            _padding2: 0,
        }
    }
}

impl IntoBytes for CloseSubAccountV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct CloseSubAccountV2Args {
    pub discriminator: SwigInstruction,
    pub _padding: u16,
    pub auth_role_id: u32,
    pub subacc_id: u32,
    pub _padding2: u32,
}

impl CloseSubAccountV2Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn new(auth_role_id: u32, subacc_id: u32) -> Self {
        Self {
            discriminator: SwigInstruction::CloseSubAccountV2,
            _padding: 0,
            auth_role_id,
            subacc_id,
            _padding2: 0,
        }
    }
}

impl IntoBytes for CloseSubAccountV2Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct SubAccountSignV1Args {
    instruction: SwigInstruction,
    pub instruction_payload_len: u16,
    pub role_id: u32,
    _padding: [u8; 8],
}

impl SubAccountSignV1Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// Creates a new instance of SubAccountSignV1Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the role attempting to sign
    /// * `instruction_payload_len` - Length of the instruction payload
    pub fn new(role_id: u32, instruction_payload_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::SubAccountSignV1,
            instruction_payload_len,
            role_id,
            _padding: [0; 8],
        }
    }
}

impl IntoBytes for SubAccountSignV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct SubAccountSignV2Args {
    instruction: SwigInstruction,
    pub instruction_payload_len: u16,
    pub role_id: u32,
    pub subacc_id: u32,
    _padding: [u8; 4],
}

impl SubAccountSignV2Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn new(role_id: u32, subacc_id: u32, instruction_payload_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::SubAccountSignV2,
            instruction_payload_len,
            role_id,
            subacc_id,
            _padding: [0; 4],
        }
    }
}

impl IntoBytes for SubAccountSignV2Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct ToggleSubAccountV1Args {
    discriminator: SwigInstruction,
    pub enabled: bool,
    _padding: [u8; 5],
    pub role_id: u32,
    pub auth_role_id: u32,
}

impl ToggleSubAccountV1Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// Creates a new instance of ToggleSubAccountV1Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the role performing the toggle
    /// * `enabled` - The desired enabled state
    pub fn new(role_id: u32, auth_role_id: u32, enabled: bool) -> Self {
        Self {
            discriminator: SwigInstruction::ToggleSubAccountV1,
            _padding: [0; 5],
            role_id,
            auth_role_id,
            enabled,
        }
    }
}

impl IntoBytes for ToggleSubAccountV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct ToggleSubAccountV2Args {
    discriminator: SwigInstruction,
    /// Desired enabled state
    pub enabled: u8,
    _padding: u8,
    /// Role performing the toggle
    pub auth_role_id: u32,
    /// Sub-account being toggled
    pub subacc_id: u32,
    _padding2: u32,
}

impl ToggleSubAccountV2Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn new(auth_role_id: u32, subacc_id: u32, enabled: bool) -> Self {
        Self {
            discriminator: SwigInstruction::ToggleSubAccountV2,
            enabled: u8::from(enabled),
            _padding: 0,
            auth_role_id,
            subacc_id,
            _padding2: 0,
        }
    }
}

impl IntoBytes for ToggleSubAccountV2Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct WithdrawFromSubAccountV1Args {
    discriminator: SwigInstruction,
    _padding: u16,
    pub role_id: u32,
    pub amount: u64,
}

impl WithdrawFromSubAccountV1Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// Creates a new instance of WithdrawFromSubAccountV1Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the role performing the withdrawal
    /// * `amount` - Amount of tokens/SOL to withdraw
    pub fn new(role_id: u32, amount: u64) -> Self {
        Self {
            discriminator: SwigInstruction::WithdrawFromSubAccountV1,
            _padding: 0,
            role_id,
            amount,
        }
    }
}

impl IntoBytes for WithdrawFromSubAccountV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct WithdrawFromSubAccountV2Args {
    discriminator: SwigInstruction,
    _padding: u16,
    pub role_id: u32,
    pub subacc_id: u32,
    _padding2: u32,
    pub amount: u64,
}

impl WithdrawFromSubAccountV2Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn new(role_id: u32, subacc_id: u32, amount: u64) -> Self {
        Self {
            discriminator: SwigInstruction::WithdrawFromSubAccountV2,
            _padding: 0,
            role_id,
            subacc_id,
            _padding2: 0,
            amount,
        }
    }
}

impl IntoBytes for WithdrawFromSubAccountV2Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}
