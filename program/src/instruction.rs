use num_enum::{FromPrimitive, IntoPrimitive};
use pinocchio::{account_info::AccountInfo, program_error::ProgramError};
use shank::{ShankContext, ShankInstruction};
use swig_state::Role;

use crate::{authority_models::authenticate, error::SwigError};

pub const SWIG_ACCOUNT_NAME: &str = "swig"; // shank replacement wit h 'static str names for accounts

#[derive(Clone, Debug, ShankContext, ShankInstruction, FromPrimitive, IntoPrimitive)]
#[rustfmt::skip]
#[repr(u8)]
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
  ReplaceAuthorityV1 = 3,
  #[account(0, writable, name="swig", desc="the swig smart wallet")]
  #[account(1, writable, signer, name="payer", desc="the payer")]
  // additional ix data will be appended to the end of the ix the ix_payload and auth_payload have offset and length tuples to locate the data
  // Extra accounts will be sent over CPI to any of the IXs in the ix payload which resembles a txn
  SignV1 = 4,
  #[account(0, writable, name="bytecode_account", desc="the account storing VM bytecode")]
  #[account(1, writable, signer, name="authority", desc="the authority that owns the bytecode")]
  #[account(2, writable, name="system_program", desc="the system program")]
  InitializeBytecode = 5,
  #[account(0, writable, name="plugin_bytecode_account", desc="the account storing plugin bytecode")]
  #[account(1, writable, name="target_program", desc="the program this plugin is for")]
  #[account(2, writable, name="program_data", desc="the program's data account")]
  #[account(3, writable, signer, name="authority", desc="the upgrade authority of the target program")]
  #[account(4, writable, name="system_program", desc="the system program")]
  CreatePluginBytecode = 6,
  #[account(0, writable, name="bytecode_account", desc="the account storing VM bytecode")]
  #[account(1, writable, name="result_account", desc="the account storing execution results")]
  #[account(2, writable, signer, name="payer", desc="the payer")]
  #[account(3, writable, name="system_program", desc="the system program")]
  Execute = 7,
  #[account(0, writable, name="plugin_bytecode_account", desc="the account storing plugin bytecode")]
  #[account(1, writable, name="target_program", desc="the program this plugin is for")]
  #[account(2, writable, name="result_account", desc="the account storing execution results")]
  #[account(3, writable, signer, name="payer", desc="the payer")]
  #[account(4, writable, name="system_program", desc="the system program")]
  ExecutePlugin = 8,
}

pub trait Authenticatable {
    fn data_payload(&self) -> &[u8];
    fn authority_payload(&self) -> &[u8];
    fn authenticate(&self, account_infos: &[AccountInfo], role: &Role) -> Result<(), SwigError> {
        authenticate(
            role.authority_type,
            &role.authority_data,
            self.authority_payload(),
            self.data_payload(),
            account_infos,
        )
    }
}
