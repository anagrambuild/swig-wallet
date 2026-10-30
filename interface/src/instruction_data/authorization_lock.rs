use super::SwigInstruction;
use pinocchio::program_error::ProgramError;
use swig_state::IntoBytes;

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct AddAuthorizationLockV1Args {
    pub instruction: SwigInstruction,
    _padding: [u8; 2],
    pub acting_role_id: u32,
    /// Swig wallet address (native SOL) or a token account it owns.
    pub asset_account: [u8; 32],
    /// Token mint, or all zeros for native SOL.
    pub mint: [u8; 32],
    pub amount: u64,
    pub expiry_slot: u64,
}

impl AddAuthorizationLockV1Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn new(
        acting_role_id: u32,
        asset_account: [u8; 32],
        mint: [u8; 32],
        amount: u64,
        expiry_slot: u64,
    ) -> Self {
        Self {
            instruction: SwigInstruction::AddAuthorizationLockV1,
            _padding: [0; 2],
            acting_role_id,
            asset_account,
            mint,
            amount,
            expiry_slot,
        }
    }
}

impl IntoBytes for AddAuthorizationLockV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}

#[derive(Clone, Copy, Debug, bytemuck::NoUninit)]
#[repr(C, align(8))]
pub struct RemoveAuthorizationLockV1Args {
    pub instruction: SwigInstruction,
    _padding: [u8; 2],
    pub acting_role_id: u32,
    pub lock_id: u32,
    _reserved: [u8; 4],
}

impl RemoveAuthorizationLockV1Args {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn new(acting_role_id: u32, lock_id: u32) -> Self {
        Self {
            instruction: SwigInstruction::RemoveAuthorizationLockV1,
            _padding: [0; 2],
            acting_role_id,
            lock_id,
            _reserved: [0; 4],
        }
    }
}

impl IntoBytes for RemoveAuthorizationLockV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(bytemuck::bytes_of(self))
    }
}
