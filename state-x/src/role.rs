use pinocchio::program_error::ProgramError;

use crate::{
    authority::{Authority, AuthorityData},
    Transmutable,
};

pub struct Role<'a, T: AuthorityData<'a> + Transmutable> {
    pub authority: &'a Authority,
    /// Authority specific data.
    ///
    /// TODO: is the length known at compile time by the authority?
    pub authority_data: &'a T,
    /// Actions associated with this authority.
    actions: &'a [u8],
}

impl<'a, T: AuthorityData<'a> + Transmutable> Role<'a, T> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ProgramError> {
        if bytes.len() < Authority::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        unsafe { Ok(Self::from_bytes_unchecked(bytes)) }
    }

    /// # Safety
    ///
    /// The caller must ensure that the length of `bytes` is at least `Authority::LEN`.
    pub unsafe fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        //TODO: Fix the unwrap.
        let authority = Authority::from_bytes_unchecked(&bytes[..Authority::LEN]).unwrap();
        let authority_data = T::from_bytes(&bytes[Authority::LEN..]);
        let actions = &bytes[Authority::LEN + authority_data.length()..];

        Role {
            authority,
            authority_data,
            actions,
        }
    }

    /*
    /// Returns the extension data of a given type.
    ///
    /// This function will return the first extension of the given type. If the
    /// extension is not found, `None` is returned.
    pub fn get<U: Actionable<'a> + 'a>(&self) -> Option<&U> {
        let mut cursor = 0;

        while (cursor + Action::LEN) <= self.actions.len() {
            let action: &Action = unsafe {
                // TODO: Fix the unwrap.
                Action::from_bytes_unchecked(&self.actions[cursor..cursor + Action::LEN]).unwrap()
            };

            match action.permission() {
                Ok(t) if t == U::TYPE => {
                    let start = cursor + Action::LEN;
                    let end = start + action.length() as usize;
                    return Some(U::from_bytes(&self.actions[start..end]));
                },
                Ok(Permission::None) => return None,
                _ => cursor = action.boundary() as usize,
            }
        }

        None
    }

    pub fn validate(&mut self) {
        let mut cursor = 0;

        while (cursor + Action::LEN) <= self.actions.len() {
            let action: &Action = unsafe {
                // TODO: Fix the unwrap.
                Action::from_bytes_unchecked(&self.actions[cursor..cursor + Action::LEN]).unwrap()
            };

            // TODO: conditionally validate the action.
            action.validate();
        }
    }
    */
}

impl<'a, T: AuthorityData<'a> + Transmutable> Role<'a, T> {}
