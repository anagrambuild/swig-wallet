use pinocchio::program_error::ProgramError;

use crate::{
    authority::{Authority, AuthorityData, AuthorityType},
    role::Role,
    FromBytes, Transmutable, TransmutableMut,
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
    pub state: &'a Swig,

    roles: &'a [u8],
}

impl<'a> SwigWithRoles<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ProgramError> {
        if bytes.len() < Swig::LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        let state = unsafe { Swig::load_unchecked(&bytes[..Swig::LEN])? };
        let roles = &bytes[Swig::LEN..];

        Ok(SwigWithRoles { state, roles })
    }

    pub fn get<T: AuthorityData<'a> + Transmutable + 'a>(&'a self, id: u16) -> Option<Role<T>> {
        let mut cursor = 0;

        while (cursor + Authority::LEN) <= self.roles.len() {
            let offset = cursor + Authority::LEN;
            let role_authority: &Authority =
                unsafe { Authority::load_unchecked(&self.roles[cursor..offset]).unwrap() };

            match role_authority.authority_type() {
                Ok(t) if t == T::TYPE && role_authority.id() == id => {
                    let end = offset + role_authority.length() as usize;

                    match Role::<T>::from_bytes(&self.roles[cursor..end]) {
                        Ok(role) => return Some(role),
                        Err(_) => return None,
                    }
                },
                Ok(AuthorityType::None) => return None,
                _ => cursor = offset + role_authority.boundary() as usize,
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use crate::{authority::ed25519::ED25519, swig::SwigWithRoles, Transmutable};

    use super::Swig;

    #[test]
    fn test_swig_from_bytes() {
        let bytes = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0,
        ];
        let swig = unsafe { Swig::load_unchecked(&bytes).unwrap() };

        assert_eq!(swig.discriminator, 1);
        assert_eq!(swig.id, [0; 32]);
        assert_eq!(swig.bump, 255);
        assert_eq!(swig.roles, 0);
    }

    #[test]
    fn test_swig_with_roles_from_bytes() {
        let bytes = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 255, 1, 0, 0, 0, 0, 0, // role 1
            1, 0, 0, 0, 32, 0, 32, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // role 2
            1, 0, 1, 0, 32, 0, 32, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        ];
        let swig = SwigWithRoles::from_bytes(&bytes).unwrap();

        assert_eq!(swig.state.discriminator, 1);
        assert_eq!(swig.state.id, [0; 32]);
        assert_eq!(swig.state.bump, 255);
        assert_eq!(swig.state.roles, 1);

        let role1 = swig.get::<ED25519>(0);
        assert!(role1.is_some());
        assert_eq!(role1.unwrap().authority_data.proof, [1; 32]);

        let role2 = swig.get::<ED25519>(1);
        assert!(role2.is_some());
        assert_eq!(role2.unwrap().authority_data.proof, [2; 32]);
    }
}
