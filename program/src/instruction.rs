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
  #[account(0, writable, name="swig", desc="the swig smart wallet")]
  #[account(1, writable, signer, name="payer", desc="the payer")]
  CreateSessionV1 = 5,
  #[account(0, writable, name="plugin_bytecode_account", desc="the account storing plugin bytecode")]
  #[account(1, writable, name="target_program", desc="the program this plugin is for")]
  #[account(2, writable, name="program_data", desc="the program's data account")]
  #[account(3, writable, signer, name="authority", desc="the upgrade authority of the target program")]
  #[account(4, writable, name="system_program", desc="the system program")]
  CreatePluginBytecodeV1 = 6,
}

pub trait Authenticatable {
    fn data_payload(&self) -> &[u8];
    fn authority_payload(&self) -> &[u8];
    fn authenticate_session(
        &self,
        account_infos: &[AccountInfo],
        role: &Role,
        current_slot: u64,
    ) -> Result<(), SwigError> {
        authenticate(
            role.authority_type,
            &role.authority_data,
            self.authority_payload(),
            self.data_payload(),
            account_infos,
            current_slot,
            true,
        )
    }

    fn authenticate(
        &self,
        account_infos: &[AccountInfo],
        role: &Role,
        current_slot: u64,
    ) -> Result<(), SwigError> {
        if role.start_slot > 0 && current_slot < role.start_slot {
            return Err(SwigError::PermissionDenied("Role is not valid at current slot").into());
        }
        if role.end_slot > 0 && current_slot >= role.end_slot {
            return Err(SwigError::PermissionDenied("Role is not valid at current slot").into());
        }

        authenticate(
            role.authority_type,
            &role.authority_data,
            self.authority_payload(),
            self.data_payload(),
            account_infos,
            current_slot,
            false,
        )
    }
}
