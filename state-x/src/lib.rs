#![no_std]

use pinocchio::program_error::ProgramError;

pub mod action;
pub mod authority;
pub mod role;
pub mod swig;

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
    unsafe fn from_bytes_unchecked<T: Transmutable>(bytes: &[u8]) -> Result<&T, ProgramError> {
        if bytes.len() != T::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(&*(bytes.as_ptr() as *const T))
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
    unsafe fn from_bytes_mut_unchecked<T: Transmutable>(
        bytes: &mut [u8],
    ) -> Result<&mut T, ProgramError> {
        if bytes.len() != T::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(&mut *(bytes.as_mut_ptr() as *mut T))
    }
}
