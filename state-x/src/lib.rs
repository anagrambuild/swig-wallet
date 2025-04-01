//#![no_std]


extern crate static_assertions;

use pinocchio::{program_error::ProgramError};

pub mod action;
pub mod authority;
pub mod role;
pub mod swig;

pub enum SwigStateError {
    InvalidAccountData = 1000,
    InvalidActionData,
    InvalidAuthorityData,
    InvalidRoleData,
    InvalidSwigData,
}


impl From<SwigStateError> for ProgramError {
    fn from(e: SwigStateError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

/// Marker trait for types that can be cast from a raw pointer.
///
/// It is up to the type implementing this trait to guarantee that the cast is
/// safe, i.e., the fields of the type are well aligned and there are no padding
/// bytes.
pub trait Transmutable: Sized {
    /// The length of the type.
    ///
    /// This must be equal to the size of each individual field in the type.
    const LEN: usize;

    /// Return a `T` reference from the given bytes.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `bytes` contains a valid representation of `T`.
    #[inline(always)]
    unsafe fn load_unchecked(bytes: &[u8]) -> Result<&Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(&*(bytes.as_ptr() as *const Self))
    }
}

/// Marker trait for types that can be mutably cast from a raw pointer.
///
/// It is up to the type implementing this trait to guarantee that the cast is
/// safe, i.e., the fields of the type are well aligned and there are no padding
/// bytes.
pub trait TransmutableMut: Transmutable {
    /// Return a mutable `T` reference from the given bytes.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `bytes` contains a valid representation of `T`.
    #[inline(always)]
    unsafe fn load_mut_unchecked(bytes: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(&mut *(bytes.as_mut_ptr() as *mut Self))
    }
}

pub trait FromBytes<'a>: Sized {
    fn from_bytes(bytes: &'a [u8]) -> Result<Self, ProgramError>;
}

pub trait FromBytesMut<'a>: Sized {
    fn from_bytes_mut(bytes: &'a mut [u8]) -> Result<Self, ProgramError>;
}

pub trait IntoBytes<'a> {
    fn into_bytes(&'a self) -> Result<&'a [u8], ProgramError>;
}
