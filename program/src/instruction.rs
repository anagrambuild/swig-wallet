use num_enum::{FromPrimitive, IntoPrimitive};
use pinocchio::{account_info::AccountInfo, program_error::ProgramError};
use shank::{ShankContext, ShankInstruction};

#[derive(Clone, Copy, Debug, ShankContext, ShankInstruction, FromPrimitive, IntoPrimitive)]
#[rustfmt::skip]
#[repr(u16)]
pub enum SwigInstruction {
  #[account(0, writable, name="swig", desc="the swig smart wallet")]
  #[account(1, writable, signer, name="payer", desc="the payer")]
  #[account(2, writable, name="system_program", desc="the system program")]
  #[num_enum(default)]
  CreateV1 = 0,
  #[account(0, writable, signer, name="swig", desc="the swig smart wallet")]
  #[account(1, writable, signer, name="payer", desc="the payer")]
  #[account(2, name="system_program", desc="the system program")]
  AddAuthorityV1 = 1,
  #[account(0, writable, signer, name="swig", desc="the swig smart wallet")]
  #[account(1, writable, signer, name="payer", desc="the payer")]
  #[account(2, name="system_program", desc="the system program")]
  RemoveAuthorityV1 = 2,
  #[account(0, writable, signer, name="swig", desc="the swig smart wallet")]
  #[account(1, writable, signer, name="payer", desc="the payer")]
  #[account(2, name="system_program", desc="the system program")]
  // additional ix data will be appended to the end of the ix the ix_payload and auth_payload have offset and length tuples to locate the data
  // Extra accounts will be sent over CPI to any of the IXs in the ix payload which resembles a txn
  SignV1 = 4,
  #[account(0, writable, signer, name="swig", desc="the swig smart wallet")]
  #[account(1, writable, signer, name="payer", desc="the payer")]
  #[account(2, name="system_program", desc="the system program")]
  CreateSessionV1 = 5,
  #[account(0, writable, signer, name="parent_swig", desc="the parent swig wallet")]
  #[account(1, writable, name="sub_account", desc="the new sub-account to be created")]
  #[account(2, writable, signer, name="payer", desc="the payer")]
  #[account(3, name="system_program", desc="the system program")]
  CreateSubAccountV1 = 6,
  #[account(0, writable, signer, name="swig", desc="the swig wallet (parent or sub)")]
  #[account(1, writable, name="target_sub_account", desc="the sub-account to manage")]
  #[account(2, writable, signer, name="payer", desc="the payer")]
  #[account(3, name="system_program", desc="the system program")]
  ManageSubAccountV1 = 7,
}

pub mod management_actions {
    /// Sub-account management operations
    #[derive(Clone, Copy, Debug, PartialEq)]
    #[repr(u8)]
    pub enum SubAccountAction {
        UpdatePermissions = 0,
        TransferOwnership = 1,
        RemoveSubAccount = 2,
    }
}
