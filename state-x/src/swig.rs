use pinocchio::program_error::ProgramError;

use crate::{
    action::{Action, ActionLoader},
    authority::{Authority, AuthorityType},
    role::{Position, Role, RoleMut},
    FromBytes, FromBytesMut, Transmutable, TransmutableMut,
};

// SANITY CHECK: Make sure the type size is a multiple of 8 bytes.
static_assertions::const_assert!(core::mem::size_of::<Swig>() % 8 == 0);

#[repr(C)]
pub struct Swig {
    pub discriminator: u8,
    pub bump: u8,
    pub id: [u8; 32],
    pub roles: u16,
    pub role_counter: u32, // ensure unique ids up to 2^32
    _padding: [u16; 4],
}

impl Swig {
    pub fn new(id: [u8; 32], bump: u8) -> Self {
        Self {
            discriminator: 0,
            id,
            bump,
            roles: 0,
            role_counter: 0,
            _padding: [0; 4],
        }
    }

    pub fn get_role_mut<'a, T: Authority<'a>>(
        swig_data: &'a mut [u8],
        id: u32,
    ) -> Option<RoleMut<T>> {
        let mut cursor = Swig::LEN;

        while (cursor + Position::LEN) <= swig_data.len() {
            let offset = cursor + Position::LEN;
            let position = unsafe { Position::load_unchecked(&swig_data[cursor..offset]).unwrap() };

            match position.authority_type() {
                Ok(t) if t == T::TYPE && position.id() == id => {
                    let end = offset + position.length() as usize;
                    return RoleMut::<T>::from_bytes_mut(&mut swig_data[cursor..end]).ok();
                },
                Ok(AuthorityType::None) => return None,
                _ => cursor = offset + position.boundary() as usize,
            }
        }

        None
    }
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

    pub fn get<T: Authority<'a> + 'a>(&'a self, id: u32) -> Option<Role<T>> {
        let mut cursor = 0;

        while (cursor + Position::LEN) <= self.roles.len() {
            let offset = cursor + Position::LEN;
            let position =
                unsafe { Position::load_unchecked(&self.roles[cursor..offset]).unwrap() };

            match position.authority_type() {
                Ok(t) if t == T::TYPE && position.id() == id => {
                    let end = offset + position.length() as usize;
                    return Role::<T>::from_bytes(&self.roles[cursor..end]).ok();
                },
                Ok(AuthorityType::None) => return None,
                _ => cursor = offset + position.boundary() as usize,
            }
        }

        None
    }
}

pub struct SwigBuilder<'a> {
    pub role_buffer: &'a mut [u8],
    pub swig: &'a mut Swig,
}

impl<'a> SwigBuilder<'a> {
    pub fn create(account_buffer: &'a mut [u8], swig: Swig) -> Result<Self, ProgramError> {
        let (swig_bytes, roles_bytes) = account_buffer.split_at_mut(Swig::LEN);
        let bytes = swig.as_bytes();
        swig_bytes[0..].copy_from_slice(bytes);
        let builder = Self {
            role_buffer: roles_bytes,
            swig: unsafe { Swig::load_mut_unchecked(swig_bytes)? },
        };
        Ok(builder)
    }

    pub fn new_from_bytes(account_buffer: &'a mut [u8]) -> Result<Self, ProgramError> {
        let (swig_bytes, roles_bytes) = account_buffer.split_at_mut(Swig::LEN);
        let swig = unsafe { Swig::load_mut_unchecked(swig_bytes)? };
        let builder = Self {
            role_buffer: roles_bytes,
            swig,
        };
        Ok(builder)
    }

    pub fn add_role<T: Authority<'a>>(
        &mut self,
        authority: &'a T,
        num_actions: u8,
        actions_data: &'a [u8],
    ) -> Result<(), ProgramError> {
        // check number of roles and iterate to last boundary
        let mut cursor = 0;
        // iterate and transmute each position to get boundary if not the last then jump to next boundary
        for _i in 0..self.swig.roles {
            let position = unsafe {
                Position::load_unchecked(&self.role_buffer[cursor..cursor + Position::LEN]).unwrap()
            };
            cursor += position.boundary() as usize;
        }
        let size = T::LEN + num_actions as usize * Action::LEN + actions_data.len();
        let boundary = cursor + size;
        // add role to the end of the buffer
        let new_position = Position::new(
            T::TYPE,
            self.swig.role_counter,
            size as u16,
            boundary as u32,
        );
        self.role_buffer[cursor..cursor + Position::LEN].copy_from_slice(new_position.as_bytes());
        cursor += Position::LEN;
        self.role_buffer[cursor..cursor + T::LEN].copy_from_slice(authority.as_bytes());
        cursor += T::LEN;
        let mut action_cursor = 0;
        for _i in 0..num_actions {
            let (header, data) = actions_data.split_at(action_cursor + Action::LEN);
            let action_header = unsafe { Action::load_unchecked(header)? };
            action_cursor += Action::LEN;
            let action_slice = &data[0..action_header.length() as usize];
            action_cursor += action_header.length() as usize;
            if ActionLoader::validate_layout(action_header.permission()?, action_slice)? {
                self.role_buffer[cursor..cursor + Action::LEN].copy_from_slice(header);
                // change boundary to the new boundary
                self.role_buffer[cursor + 2..cursor + 6].copy_from_slice(
                    &((cursor + Action::LEN + action_header.length() as usize) as u32)
                        .to_le_bytes(),
                );
                cursor += Action::LEN;
                self.role_buffer[cursor..cursor + action_header.length() as usize]
                    .copy_from_slice(action_slice);
                cursor += action_header.length() as usize;
            } else {
                return Err(ProgramError::InvalidAccountData);
            }
        }
        self.swig.roles += 1;
        self.swig.role_counter += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        action::{sol_limit::SolLimit, token_limit::TokenLimit},
        authority::ed25519::ED25519Authority,
        swig::SwigWithRoles,
        Transmutable,
    };

    use super::Swig;

    #[test]
    fn test_swig_from_bytes() {
        let bytes = [
            1, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let swig = unsafe { Swig::load_unchecked(&bytes).unwrap() };

        assert_eq!(swig.discriminator, 1);
        assert_eq!(swig.bump, 255);
        assert_eq!(swig.id, [0; 32]);
        assert_eq!(swig.roles, 0);
        assert_eq!(swig.as_bytes(), &bytes);
    }

    #[test]
    fn test_swig_with_roles_from_bytes() {
        let bytes = [
            1, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // role 1
            1, 0, 32, 0, 1, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // role 2
            1, 0, 32, 0, 2, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        ];
        let swig = SwigWithRoles::from_bytes(&bytes).unwrap();

        assert_eq!(swig.state.discriminator, 1);
        assert_eq!(swig.state.bump, 255);
        assert_eq!(swig.state.id, [0; 32]);
        assert_eq!(swig.state.roles, 2);

        let role1 = swig.get::<ED25519Authority>(1);
        assert!(role1.is_some());
        assert_eq!(role1.unwrap().authority.proof, [1; 32]);

        let role2 = swig.get::<ED25519Authority>(2);
        assert!(role2.is_some());
        assert_eq!(role2.unwrap().authority.proof, [2; 32]);
    }

    #[test]
    fn test_swig_with_role_and_action_from_bytes() {
        let bytes = [
            1, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // role
            1, 0, 96, 0, 1, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // action 1
            1, 0, 8, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, // action 2
            4, 0, 40, 0, 40, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 100, 0, 0, 0, 0, 0, 0, 0,
        ];

        let swig = SwigWithRoles::from_bytes(&bytes).unwrap();

        assert_eq!(swig.state.discriminator, 1);
        assert_eq!(swig.state.bump, 255);
        assert_eq!(swig.state.id, [0; 32]);
        assert_eq!(swig.state.roles, 2);

        // role

        let role = swig.get::<ED25519Authority>(1);
        assert!(role.is_some());

        let role = role.unwrap();
        assert_eq!(role.authority.proof, [1; 32]);

        // action 1

        let action1 = role.get::<SolLimit>();
        assert!(action1.is_some());

        let action1 = action1.unwrap();
        assert_eq!(action1.amount, 1);

        // action 2
        let action2 = role.get::<TokenLimit>();
        assert!(action2.is_some());

        let action2 = action2.unwrap();
        assert_eq!(action2.token_mint, [1; 32]);
        assert_eq!(action2.current_amount, 100);
    }

    #[test]
    fn test_get_role_mut() {
        let mut bytes = [
            1, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // role
            1, 0, 48, 0, 1, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // action
            1, 0, 8, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        ];

        // Assert the original state

        let swig = SwigWithRoles::from_bytes(&bytes).unwrap();

        assert_eq!(swig.state.roles, 1);

        let role = swig.get::<ED25519Authority>(1);
        assert!(role.is_some());

        let role = role.unwrap();
        assert_eq!(role.authority.proof, [1; 32]);

        let action = role.get::<SolLimit>();
        assert!(action.is_some());

        let action = action.unwrap();
        assert_eq!(action.amount, 1);

        // Mutate the state

        let role_mut = Swig::get_role_mut::<ED25519Authority>(&mut bytes, 1);
        assert!(role_mut.is_some());

        let mut role_mut = role_mut.unwrap();
        assert_eq!(role_mut.authority.proof, [1; 32]);

        let action_mut = role_mut.get_mut::<SolLimit>();
        assert!(action_mut.is_some());

        let action_mut = action_mut.unwrap();
        action_mut.amount = 42;

        // Assert the mutated state

        let swig = SwigWithRoles::from_bytes(&bytes).unwrap();

        assert_eq!(swig.state.roles, 1);

        let role = swig.get::<ED25519Authority>(1);
        assert!(role.is_some());

        let role = role.unwrap();
        assert_eq!(role.authority.proof, [1; 32]);

        let action = role.get::<SolLimit>();
        assert!(action.is_some());

        let action = action.unwrap();
        assert_eq!(action.amount, 42);
    }
}
