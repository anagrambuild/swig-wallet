use pinocchio::program_error::ProgramError;

use crate::{
    authority::{Authority, AuthorityData, AuthorityType},
    role::Role,
    Transmutable, TransmutableMut,
};

#[repr(C)]
pub struct Swig {
    pub discriminator: u8,
    pub id: [u8; 32],
    pub bump: u8,
    /// The number of roles (might not need this).
    pub roles: u16,
    /// Padding for alignment.
    _padding: [u16; 2],
}

impl Transmutable for Swig {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl TransmutableMut for Swig {}

pub struct SwigWithRoles<'a> {
    pub swig: &'a Swig,

    roles: &'a [u8],
}

impl<'a> SwigWithRoles<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ProgramError> {
        if bytes.len() < Swig::LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        let swig = unsafe { Swig::from_bytes_unchecked(bytes)? };
        let roles = &bytes[Swig::LEN..];

        Ok(SwigWithRoles { swig, roles })
    }

    pub fn get<T: AuthorityData<'a> + Transmutable + 'a>(&'a self, id: u16) -> Option<Role<T>> {
        let mut cursor = 0;

        while (cursor + Authority::LEN) <= self.roles.len() {
            let role_authority: &Authority = unsafe {
                // TODO: Fix the unwrap.
                Authority::from_bytes_unchecked(&self.roles[cursor..cursor + Authority::LEN])
                    .unwrap()
            };

            match role_authority.authority_type() {
                Ok(t) if t == T::TYPE && role_authority.id() == id => {
                    let start = cursor + Authority::LEN;
                    let end = start + role_authority.length() as usize;
                    return Some(unsafe {
                        Role::<T>::from_bytes_unchecked(&self.roles[start..end])
                    });
                },
                Ok(AuthorityType::None) => return None,
                _ => cursor = role_authority.boundary() as usize,
            }
        }

        None
    }
}
