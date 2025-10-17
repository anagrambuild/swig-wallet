use pinocchio::program_error::ProgramError;

/// Marker trait for types that can be safely cast from a raw pointer.
///
/// Types implementing this trait must guarantee that the cast is safe,
/// ensuring proper field alignment and absence of padding bytes.
pub trait Transmutable: Sized {
    /// The length of the type in bytes.
    ///
    /// Must equal the total size of all fields in the type.
    const LEN: usize;

    /// Creates a reference to `Self` from a byte slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `bytes` contains a valid representation of
    /// the implementing type.
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
/// Types implementing this trait must guarantee that the mutable cast is safe,
/// ensuring proper field alignment and absence of padding bytes.
pub trait TransmutableMut: Transmutable {
    /// Creates a mutable reference to `Self` from a mutable byte slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `bytes` contains a valid representation of
    /// the implementing type.
    #[inline(always)]
    unsafe fn load_mut_unchecked(bytes: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(&mut *(bytes.as_mut_ptr() as *mut Self))
    }
}

/// Trait for types that can be converted into a byte slice representation.
pub trait IntoBytes {
    /// Converts the implementing type into a byte slice.
    fn into_bytes(&self) -> Result<&[u8], ProgramError>;
}
