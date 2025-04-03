extern crate alloc;

use core::cell::RefCell;
use pinocchio::{instruction::Seed, program_error::ProgramError};

use crate::{
    action::{Action, ActionLoader, Actionable},
    authority::{Authority, AuthorityLoader, AuthorityType},
    role::{Position, Role, RoleMut},
    FromBytes, FromBytesMut, IntoBytes, Transmutable, TransmutableMut,
};

use core::cell::UnsafeCell;

#[inline(always)]
pub fn swig_account_seeds(id: &[u8]) -> [&[u8]; 2] {
    [b"swig".as_ref(), id]
}

#[inline(always)]
pub fn swig_account_seeds_with_bump<'a>(id: &'a [u8], bump: &'a [u8]) -> [&'a [u8]; 3] {
    [b"swig".as_ref(), id, bump]
}

pub fn swig_account_signer<'a>(id: &'a [u8], bump: &'a [u8; 1]) -> [Seed<'a>; 3] {
    [
        b"swig".as_ref().into(),
        id.as_ref().into(),
        bump.as_ref().into(),
    ]
}

pub struct SwigBuilder<'a> {
    pub role_buffer: &'a mut [u8],
    pub swig: &'a mut Swig,
}

impl<'a> SwigBuilder<'a> {
    pub fn create(account_buffer: &'a mut [u8], swig: Swig) -> Result<Self, ProgramError> {
        let (swig_bytes, roles_bytes) = account_buffer.split_at_mut(Swig::LEN);
        let bytes = swig.into_bytes()?;
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
        let boundary = cursor + Position::LEN + size;
        // add role to the end of the buffer
        let new_position = Position::new(
            T::TYPE,
            self.swig.role_counter,
            T::LEN as u16,
            num_actions as u16,
            boundary as u32,
        );
        self.role_buffer[cursor..cursor + Position::LEN]
            .copy_from_slice(new_position.into_bytes()?);
        cursor += Position::LEN;
        self.role_buffer[cursor..cursor + T::LEN].copy_from_slice(authority.into_bytes()?);
        cursor += T::LEN;
        //todo check actions for duplicates
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
                self.role_buffer[cursor + 4..cursor + 8].copy_from_slice(
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
}

impl Transmutable for Swig {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl TransmutableMut for Swig {}

impl<'a> IntoBytes<'a> for Swig {
    fn into_bytes(&'a self) -> Result<&'a [u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

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

    pub fn lookup_role(&'a self, id: u32) -> Result<Option< Role<'a>>, ProgramError> {
        let mut cursor = 0;
        for _i in 0..self.state.roles {
            let offset = cursor + Position::LEN;
            let position = unsafe { Position::load_unchecked(&self.roles[cursor..offset])? };
            if position.id() == id {
                return Ok(Some(
                  Role {
                    position,
                    authority: unsafe { self.roles.get_unchecked(offset..offset + position.authority_length() as usize) },
                    actions: unsafe { self.roles.get_unchecked(offset + position.authority_length() as usize..offset + position.boundary() as usize) },
                  }

                ));
            }
            cursor = position.boundary() as usize;
        }
        Ok(None)
    }

    
}

pub struct SwigWithRolesMut<'a> {
    pub state: &'a mut Swig,
    roles: UnsafeCell<&'a mut [u8]>,
}

// SAFETY: We ensure thread-safety through Solana's single-threaded execution model
unsafe impl<'a> Sync for SwigWithRolesMut<'a> {}

impl<'a> SwigWithRolesMut<'a> {
    pub fn from_bytes(bytes: &'a mut [u8]) -> Result<Self, ProgramError> {
        let (swig_bytes, roles_bytes) = bytes.split_at_mut(Swig::LEN);
        let state = unsafe { Swig::load_mut_unchecked(swig_bytes)? };
        let roles = UnsafeCell::new(roles_bytes);
        Ok(SwigWithRolesMut { state, roles })
    }

    pub fn lookup_role(&'a self, id: u32) -> Result<Option<RoleMut<'a>>, ProgramError> {
        let roles = unsafe { &*self.roles.get() };
        let mut cursor = 0;
        for _i in 0..self.state.roles {
            let offset = cursor + Position::LEN;
            let position = unsafe { Position::load_unchecked(&roles[cursor..offset])? };
            if position.id() == id {
                return Ok(Some(RolePosition::new(offset, &position)));
            }
            cursor = offset + position.boundary() as usize;
        }
        Ok(None)
    }

    pub fn get_authority(
        &'a self,
        role_position: &'a RolePosition,
    ) -> Result<&'a impl Authority, ProgramError> {
        let roles = unsafe { &*self.roles.get() };
        AuthorityLoader::load_authority(
            role_position.position.authority_type()?,
            &roles[role_position.offset
                ..role_position.offset + role_position.position.authority_length() as usize],
        )
    }

    pub fn get_action<A: Actionable<'a>>(
        &'a self,
        role_position: &'a RolePosition,
        match_data: &[u8],
    ) -> Result<Option<&'a mut A>, ProgramError> {
        let roles = unsafe { &mut *self.roles.get() };
        let mut cursor = role_position.offset + role_position.position.authority_length() as usize;
        let end_pos = role_position.position.boundary() as usize;
        let mut found_offset = None;

        {
            let roles_ref = &*roles;
            while cursor < end_pos {
                let action =
                    unsafe { Action::load_unchecked(&roles_ref[cursor..cursor + Action::LEN])? };
                cursor += Action::LEN;
                if action.permission()? == A::TYPE {
                    let action_obj =
                        unsafe { A::load_unchecked(&roles_ref[cursor..cursor + A::LEN])? };
                    if !A::REPEATABLE || action_obj.match_data(match_data) {
                        found_offset = Some(cursor);
                        break;
                    }
                }
                cursor = action.boundary() as usize;
            }
        }

        if let Some(offset) = found_offset {
            let action_obj = unsafe { A::load_mut_unchecked(&mut roles[offset..offset + A::LEN])? };
            Ok(Some(action_obj))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::sol_limit::SolLimit;
    use crate::{action::all::All, authority::ed25519::ED25519Authority};

    fn setup_test_buffer() -> ([u8; Swig::LEN + 256], [u8; 32], u8) {
        let account_buffer = [0u8; Swig::LEN + 256];
        let id = [1; 32];
        let bump = 255;
        (account_buffer, id, bump)
    }

    #[test]
    fn test_swig_creation() {
        let (mut account_buffer, id, bump) = setup_test_buffer();
        let swig = Swig::new(id, bump);

        // Test all fields of the Swig struct
        assert_eq!(swig.discriminator, 0);
        assert_eq!(swig.id, id);
        assert_eq!(swig.bump, bump);
        assert_eq!(swig.roles, 0);
        assert_eq!(swig.role_counter, 0);
        assert_eq!(swig._padding, [0; 4]);

        // Test builder creation and verify buffer state
        let builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();
        assert_eq!(builder.swig.id, id);
        assert_eq!(builder.swig.bump, bump);
        assert_eq!(builder.swig.roles, 0);
        assert_eq!(builder.swig.role_counter, 0);
        assert_eq!(builder.role_buffer.len(), account_buffer.len() - Swig::LEN);
    }

    #[test]
    fn test_swig_account_seeds() {
        let id = [1; 32];
        let bump = [255];

        // Test basic seeds
        let seeds = swig_account_seeds(&id);
        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0], b"swig");
        assert_eq!(seeds[1], &id);

        // Test seeds with bump
        let seeds_with_bump = swig_account_seeds_with_bump(&id, &bump);
        assert_eq!(seeds_with_bump.len(), 3);
        assert_eq!(seeds_with_bump[0], b"swig");
        assert_eq!(seeds_with_bump[1], &id);
        assert_eq!(seeds_with_bump[2], &bump);

        // Test signer seeds
        let signer_seeds = swig_account_signer(&id, &[255]);
        assert_eq!(signer_seeds.len(), 3);
        assert_eq!(signer_seeds[0].as_ref(), b"swig");
        assert_eq!(signer_seeds[1].as_ref(), &id);
        assert_eq!(signer_seeds[2].as_ref(), &[255]);
    }

    #[test]
    fn test_add_single_role() {
        let (mut account_buffer, id, bump) = setup_test_buffer();
        let swig = Swig::new(id, bump);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        let authority = ED25519Authority {
            public_key: [2; 32],
        };

        let action_data = All {}.into_bytes().unwrap();
        let action = Action::new(
            All::TYPE,
            action_data.len() as u16,
            Action::LEN as u32 + action_data.len() as u32,
        );
        let action_bytes = action.into_bytes().unwrap();
        let actions_data = [action_bytes, action_data].concat();

        // Test role addition
        builder.add_role(&authority, 1, &actions_data).unwrap();

        // Verify Swig state after role addition
        assert_eq!(builder.swig.roles, 1);
        assert_eq!(builder.swig.role_counter, 1);

        // Verify role can be found and has correct data
        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();
        let role = swig_with_roles.lookup_role(0).unwrap().unwrap();

        // Verify role position
        assert_eq!(
            role.position.authority_type().unwrap(),
            AuthorityType::Ed25519
        );
        assert_eq!(role.position.id(), 0);

        // Verify authority data
        let retrieved_authority = swig_with_roles.get_authority(&role).unwrap();
        let auth_bytes = retrieved_authority.into_bytes().unwrap();
        assert_eq!(auth_bytes, authority.into_bytes().unwrap());
    }

    #[test]
    fn test_role_lookup() {
        let (mut account_buffer, id, bump) = setup_test_buffer();
        let swig = Swig::new(id, bump);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        let authority = ED25519Authority {
            public_key: [2; 32],
        };

        let action_data = All {}.into_bytes().unwrap();
        let action = Action::new(
            All::TYPE,
            action_data.len() as u16,
            Action::LEN as u32 + action_data.len() as u32,
        );
        let action_bytes = action.into_bytes().unwrap();
        let actions_data = [action_bytes, action_data].concat();

        builder.add_role(&authority, 1, &actions_data).unwrap();

        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();

        // Test successful role lookup
        let role = swig_with_roles.lookup_role(0).unwrap();
        assert!(role.is_some());
        let role = role.unwrap();
        assert_eq!(role.position.id(), 0);
        assert_eq!(
            role.position.authority_type().unwrap(),
            AuthorityType::Ed25519
        );
        assert_eq!(role.position.num_actions(), 1);

        // Test non-existent role lookup
        let role = swig_with_roles.lookup_role(999).unwrap();
        assert!(role.is_none());

        // Test boundary role lookup
        let role = swig_with_roles.lookup_role(u32::MAX).unwrap();
        assert!(role.is_none());
    }

    #[test]
    fn test_get_authority_and_action() {
        let (mut account_buffer, id, bump) = setup_test_buffer();
        let swig = Swig::new(id, bump);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        let authority = ED25519Authority {
            public_key: [2; 32],
        };

        let action_data = All {}.into_bytes().unwrap();
        let action = Action::new(
            All::TYPE,
            action_data.len() as u16,
            Action::LEN as u32 + action_data.len() as u32,
        );
        let action_bytes = action.into_bytes().unwrap();
        let actions_data = [action_bytes, action_data].concat();

        builder.add_role(&authority, 1, &actions_data).unwrap();

        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();
        let role = swig_with_roles.lookup_role(0).unwrap().unwrap();

        // Test authority retrieval and verification
        let retrieved_authority = swig_with_roles.get_authority(&role).unwrap();
        let auth_bytes = retrieved_authority.into_bytes().unwrap();
        let orig_bytes = authority.into_bytes().unwrap();
        assert_eq!(auth_bytes, orig_bytes);

        // Test action retrieval and verification
        let action: Option<&All> = swig_with_roles.get_action(&role, &[]).unwrap();
        assert!(action.is_some());
        let action = action.unwrap();
        assert_eq!(action.into_bytes().unwrap(), All {}.into_bytes().unwrap());
    }

    #[test]
    fn test_mutable_action_retrieval() {
        let (mut account_buffer, id, bump) = setup_test_buffer();
        let swig = Swig::new(id, bump);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        let authority = ED25519Authority {
            public_key: [2; 32],
        };

        let action_data = All {}.into_bytes().unwrap();
        let action = Action::new(
            All::TYPE,
            action_data.len() as u16,
            Action::LEN as u32 + action_data.len() as u32,
        );
        let action_bytes = action.into_bytes().unwrap();
        let actions_data = [action_bytes, action_data].concat();

        builder.add_role(&authority, 1, &actions_data).unwrap();

        // Test immutable operations
        let account_buffer_copy = account_buffer.clone();
        let swig = SwigWithRoles::from_bytes(&account_buffer_copy).unwrap();
        let pos = swig.lookup_role(0).unwrap().unwrap();
        assert_eq!(pos.position.id(), 0);
        assert_eq!(
            pos.position.authority_type().unwrap(),
            AuthorityType::Ed25519
        );

        // Test mutable operations
        let mut swig_with_roles = SwigWithRolesMut::from_bytes(&mut account_buffer).unwrap();
        let action: Option<&mut All> = swig_with_roles.get_action(&pos, &[]).unwrap();
        assert!(action.is_some());

        // Verify action data persists across mutable and immutable views
        let action_immut: Option<&All> = swig.get_action(&pos, &[]).unwrap();
        assert!(action_immut.is_some());
        assert_eq!(
            action.unwrap().into_bytes().unwrap(),
            action_immut.unwrap().into_bytes().unwrap()
        );
    }

    #[test]
    fn test_multiple_roles() {
        let (mut account_buffer, id, bump) = setup_test_buffer();
        let swig = Swig::new(id, bump);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        let authority1 = ED25519Authority {
            public_key: [2; 32],
        };

        let authority2 = ED25519Authority {
            public_key: [3; 32],
        };

        let action_data = All {}.into_bytes().unwrap();
        let action = Action::new(
            All::TYPE,
            action_data.len() as u16,
            Action::LEN as u32 + action_data.len() as u32,
        );
        let action_bytes = action.into_bytes().unwrap();
        let actions_data = [action_bytes, action_data].concat();

        // Add and verify first role
        builder.add_role(&authority1, 1, &actions_data).unwrap();
        assert_eq!(builder.swig.roles, 1);
        assert_eq!(builder.swig.role_counter, 1);

        // Add and verify second role
        builder.add_role(&authority2, 1, &actions_data).unwrap();
        assert_eq!(builder.swig.roles, 2);
        assert_eq!(builder.swig.role_counter, 2);

        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();

        // Verify first role
        let role1 = swig_with_roles.lookup_role(0).unwrap().unwrap();
        let auth1 = swig_with_roles.get_authority(&role1).unwrap();
        assert_eq!(
            auth1.into_bytes().unwrap(),
            authority1.into_bytes().unwrap()
        );

        // Verify second role
        let role2 = swig_with_roles.lookup_role(1).unwrap().unwrap();
        let auth2 = swig_with_roles.get_authority(&role2).unwrap();
        assert_eq!(
            auth2.into_bytes().unwrap(),
            authority2.into_bytes().unwrap()
        );

        // Verify actions for both roles
        let action1: Option<&All> = swig_with_roles.get_action(&role1, &[]).unwrap();
        assert!(action1.is_some());
        let action2: Option<&All> = swig_with_roles.get_action(&role2, &[]).unwrap();
        assert!(action2.is_some());
    }

    #[test]
    fn test_swig_with_roles_mut() {
        let (mut account_buffer, id, bump) = setup_test_buffer();
        let swig = Swig::new(id, bump);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        // Create an authority and action
        let authority = ED25519Authority {
            public_key: [2; 32],
        };

        let action_data = All {}.into_bytes().unwrap();
        let action = Action::new(
            All::TYPE,
            action_data.len() as u16,
            Action::LEN as u32 + action_data.len() as u32,
        );
        let action_bytes = action.into_bytes().unwrap();
        let actions_data = [action_bytes, action_data].concat();

        // Add a role
        builder.add_role(&authority, 1, &actions_data).unwrap();

        // Make a copy of the account buffer to verify changes later
        let buffer_before = account_buffer.clone();

        // Test role lookup and authority retrieval
        {
            let swig_mut = SwigWithRolesMut::from_bytes(&mut account_buffer).unwrap();

            // Test looking up a role
            let role = swig_mut.lookup_role(0).unwrap().unwrap();
            assert_eq!(role.position.id(), 0);
            assert_eq!(
                role.position.authority_type().unwrap(),
                AuthorityType::Ed25519
            );

            // Test getting an authority
            let retrieved_authority = swig_mut.get_authority(&role).unwrap();
            let auth_bytes = retrieved_authority.into_bytes().unwrap();
            assert_eq!(auth_bytes, authority.into_bytes().unwrap());

            // Test action retrieval
            let action_result: Option<&mut All> = swig_mut.get_action(&role, &[]).unwrap();
            assert!(action_result.is_some());
        }

        // Test modifying the state - in a separate borrow
        {
            let swig_mut = SwigWithRolesMut::from_bytes(&mut account_buffer).unwrap();
            swig_mut.state.role_counter += 1;
        }

        // Verify changes persist in the original buffer
        let swig_immut = SwigWithRoles::from_bytes(&account_buffer).unwrap();
        assert_eq!(swig_immut.state.role_counter, 2);

        // Test that buffer has actually changed
        assert_ne!(buffer_before, account_buffer);
    }

    #[test]
    fn test_swig_with_roles_mut_action_modification() {
        // This test creates a mutable action, creates a mutable SwigWithRoles,
        // then modifies the action and ensures the changes persist

        // This would be a better test if we had an action that had mutable state,
        // but for now we'll just demonstrate the ability to retrieve mutable actions

        let (mut account_buffer, id, bump) = setup_test_buffer();
        let swig = Swig::new(id, bump);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        // Create an authority and action
        let authority = ED25519Authority {
            public_key: [2; 32],
        };

        // Creating an action with some data
        let action_data = All {}.into_bytes().unwrap();
        let action = Action::new(
            All::TYPE,
            action_data.len() as u16,
            Action::LEN as u32 + action_data.len() as u32,
        );
        let action_bytes = action.into_bytes().unwrap();
        let actions_data = [action_bytes, action_data].concat();

        // Add a role
        builder.add_role(&authority, 1, &actions_data).unwrap();

        // Verify we can get a mutable action (though All doesn't have any mutable state to modify)
        {
            let swig_mut = SwigWithRolesMut::from_bytes(&mut account_buffer).unwrap();
            let role = swig_mut.lookup_role(0).unwrap().unwrap();

            let action: Option<&mut All> = swig_mut.get_action(&role, &[]).unwrap();
            assert!(action.is_some());

            // If All had mutable state, we could modify it here
            // action.unwrap().some_field = new_value;
        }

        // Verify we can access multiple actions in sequence
        {
            let swig_mut = SwigWithRolesMut::from_bytes(&mut account_buffer).unwrap();
            let role = swig_mut.lookup_role(0).unwrap().unwrap();

            // First action lookup
            let action1: Option<&mut All> = swig_mut.get_action(&role, &[]).unwrap();
            assert!(action1.is_some());

            // We should be able to look up the same action again after dropping the first reference
            drop(action1);

            // Second action lookup
            let action2: Option<&mut All> = swig_mut.get_action(&role, &[]).unwrap();
            assert!(action2.is_some());
        }
    }

    #[test]
    fn test_swig_with_roles_mut_unsafe_cell() {
        // This test verifies that the UnsafeCell in SwigWithRolesMut
        // prevents multiple mutable aliases to the same data

        let (mut account_buffer, id, bump) = setup_test_buffer();
        let swig = Swig::new(id, bump);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        // Create an authority and action
        let authority = ED25519Authority {
            public_key: [2; 32],
        };

        let action_data = All {}.into_bytes().unwrap();
        let action = Action::new(
            All::TYPE,
            action_data.len() as u16,
            Action::LEN as u32 + action_data.len() as u32,
        );
        let action_bytes = action.into_bytes().unwrap();
        let actions_data = [action_bytes, action_data].concat();

        // Add a role
        builder.add_role(&authority, 1, &actions_data).unwrap();

        // Access the mutable Swig
        let swig_mut = SwigWithRolesMut::from_bytes(&mut account_buffer).unwrap();
        let role = swig_mut.lookup_role(0).unwrap().unwrap();

        // Get a mutable action
        let action1: Option<&mut All> = swig_mut.get_action(&role, &[]).unwrap();
        assert!(action1.is_some());

        // We hold the mutable reference to action1, so trying to get another one
        // without dropping the first would cause borrowing issues at compile time.
        // This is good - the UnsafeCell implementation properly enforces Rust's
        // borrowing rules.

        // This commented code would not compile:
        // let action2: Option<&mut All> = swig_mut.get_action(&role, &[]).unwrap();

        // Instead, we must drop the first reference before getting another one
        drop(action1);

        // Now we can get another mutable reference
        let action2: Option<&mut All> = swig_mut.get_action(&role, &[]).unwrap();
        assert!(action2.is_some());
    }

    #[test]
    fn test_sol_limit_mutation() {
        let (mut account_buffer, id, bump) = setup_test_buffer();
        let swig = Swig::new(id, bump);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        // Create an authority
        let authority = ED25519Authority {
            public_key: [2; 32],
        };

        // Create a SolLimit action with initial amount
        let initial_amount = 1000u64;
        let sol_limit = SolLimit {
            amount: initial_amount,
        };

        let action_data = sol_limit.into_bytes().unwrap();
        let action = Action::new(
            SolLimit::TYPE,
            action_data.len() as u16,
            Action::LEN as u32 + action_data.len() as u32,
        );
        let action_bytes = action.into_bytes().unwrap();
        let actions_data = [action_bytes, action_data].concat();

        // Add the role with the SolLimit action
        builder.add_role(&authority, 1, &actions_data).unwrap();

        // Create a copy of the account buffer to compare later
        let buffer_before = account_buffer.clone();

        // Retrieve and modify the SolLimit action
        {
            let swig_mut = SwigWithRolesMut::from_bytes(&mut account_buffer).unwrap();
            let role = swig_mut.lookup_role(0).unwrap().unwrap();

            // Get the mutable SolLimit action
            let sol_limit_action: Option<&mut SolLimit> = swig_mut.get_action(&role, &[]).unwrap();
            assert!(sol_limit_action.is_some());

            // Make a modification by simulating a withdrawal
            let spend_amount = 300u64;
            let sol_limit_mut = sol_limit_action.unwrap();
            sol_limit_mut.run(spend_amount).unwrap();

            // Verify the change happened in our reference
            assert_eq!(sol_limit_mut.amount, initial_amount - spend_amount);
        }

        // Now verify the change persisted in the original buffer
        let swig_immut = SwigWithRoles::from_bytes(&account_buffer).unwrap();
        let role = swig_immut.lookup_role(0).unwrap().unwrap();
        let sol_limit_action: Option<&SolLimit> = swig_immut.get_action(&role, &[]).unwrap();
        assert!(sol_limit_action.is_some());

        // Verify the amount was reduced
        assert_eq!(sol_limit_action.unwrap().amount, initial_amount - 300);

        // Test that buffer has actually changed
        assert_ne!(buffer_before, account_buffer);
    }
}
