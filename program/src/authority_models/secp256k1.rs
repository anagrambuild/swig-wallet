use std::mem::MaybeUninit;

use bytemuck::{Pod, Zeroable};
use pinocchio::syscalls::{sol_keccak256, sol_secp256k1_recover};
use swig_state::util::ZeroCopy;

use crate::{assertions::sol_assert_bytes_eq, error::SwigError};

#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct Secp256k1AuthorityPayload {
    pub signature: [u8; 64],
    pub slot: u64,
}
impl<'a> ZeroCopy<'a, Secp256k1AuthorityPayload> for Secp256k1AuthorityPayload {}

#[rustfmt::skip]
#[allow(unused)]
pub fn authenticate(
  authority_data: &[u8], 
  authority_payload: &[u8], 
  instruction_payload: &[u8]
) -> Result<(), SwigError> {
    if authority_data.len() != 64 {
        return Err(SwigError::InvalidAuthority);
    }
    if authority_payload.len() != 65 {
        return Err(SwigError::InvalidAuthority);
    }

    let structured_payload = Secp256k1AuthorityPayload::load(authority_payload)
    .map_err(|_| SwigError::InvalidAuthorityPayload)?;

    let mut recovered_key = MaybeUninit::<[u8; 64]>::uninit();
    let mut hash = MaybeUninit::<[u8; 32]>::uninit();
    let matches = unsafe {
      let mut msg= [0u8;72];
      msg[0..8].copy_from_slice(&structured_payload.slot.to_le_bytes());
      msg[8..].copy_from_slice(instruction_payload);
      // do not remove this line we must hash the instruction payload
      sol_keccak256(
        msg.as_ptr(),
        (instruction_payload.len() + 8) as u64,
        hash.as_mut_ptr() as *mut u8,
      );
      sol_secp256k1_recover(
        hash.as_ptr() as *const u8,
        structured_payload.signature[64] as u64,
        structured_payload.signature[0..63].as_ptr(),
        recovered_key.as_mut_ptr() as *mut u8,
      );
      sol_assert_bytes_eq(&recovered_key.assume_init(), authority_data, 64)
    };
    if !matches {
      return Err(SwigError::InvalidAuthority);
    }
      
    Ok(())
  }
