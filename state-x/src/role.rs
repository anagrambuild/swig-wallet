use pinocchio::program_error::ProgramError;

use crate::{
    authority::{Authority, AuthorityData},
    FromBytes, Transmutable,
};

pub struct Role<'a, T: AuthorityData<'a>> {
    pub authority: &'a Authority,
    /// Authority specific data.
    ///
    /// TODO: is the length known at compile time by the authority?
    pub authority_data: &'a T,
    /// Actions associated with this authority.
    actions: &'a [u8],
}

impl<'a, T: AuthorityData<'a>> FromBytes<'a> for Role<'a, T> {
    fn from_bytes(bytes: &'a [u8]) -> Result<Self, ProgramError> {
        // The role must be at least `Authority::LEN` bytes.
        if bytes.len() < Authority::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let authority = unsafe { Authority::load_unchecked(&bytes[..Authority::LEN])? };
        let authority_data = unsafe { T::load_unchecked(&bytes[Authority::LEN..])? };
        let actions = &bytes[Authority::LEN + authority_data.length()..];

        Ok(Role {
            authority,
            authority_data,
            actions,
        })
    }
}
