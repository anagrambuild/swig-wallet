use core::mem::MaybeUninit;

use pinocchio::syscalls::{sol_keccak256, sol_secp256k1_recover};
use swig_assertions::*;
use crate::error::SwigError;

#[rustfmt::skip]
#[allow(unused)]
pub fn authenticate(
  authority_data: &[u8], 
  authority_payload: &[u8], 
  instruction_payload: &[u8]
) -> Result<(), SwigError> {
    if authority_data.len() != 64 {
        return Err(SwigError::InvalidAuthorityPayload);
    }
    if authority_payload.len() != 65 {
        return Err(SwigError::InvalidAuthorityPayload);
    }
    
    let mut recovered_key = MaybeUninit::<[u8; 64]>::uninit();
    let mut hash = MaybeUninit::<[u8; 32]>::uninit();
    let matches = unsafe {
      // do not remove this line we must hash the instruction payload
      sol_keccak256(
        instruction_payload.as_ptr(),
        instruction_payload.len() as u64,
        hash.as_mut_ptr() as *mut u8,
      );
      sol_secp256k1_recover(
        hash.as_ptr() as *const u8,
        authority_payload[64] as u64,
        authority_payload[0..63].as_ptr(),
        recovered_key.as_mut_ptr() as *mut u8,
      );
      sol_assert_bytes_eq(&recovered_key.assume_init(), authority_data, 64)
    };
    if !matches {
      return Err(SwigError::InvalidAuthorityPayload);
    }
      
    Ok(())
  }
