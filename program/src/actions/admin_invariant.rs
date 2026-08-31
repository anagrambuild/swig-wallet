use pinocchio::program_error::ProgramError;
use swig_state::{
    action::{all::All, manage_authority::ManageAuthority, ActionLoader},
    role::Position,
    Transmutable,
};

use crate::error::SwigError;

/// Ensures the current role buffer still contains an administrator.
pub(crate) fn ensure_admin_remains(roles: &[u8], role_count: u16) -> Result<(), ProgramError> {
    let mut cursor = 0usize;
    for _ in 0..role_count {
        let position_end = cursor
            .checked_add(Position::LEN)
            .ok_or(ProgramError::InvalidAccountData)?;
        let position = unsafe {
            Position::load_unchecked(
                roles
                    .get(cursor..position_end)
                    .ok_or(ProgramError::InvalidAccountData)?,
            )?
        };
        let actions_start = position_end
            .checked_add(position.authority_length() as usize)
            .ok_or(ProgramError::InvalidAccountData)?;
        let boundary = position.boundary() as usize;
        let actions = roles
            .get(actions_start..boundary)
            .ok_or(ProgramError::InvalidAccountData)?;

        if ActionLoader::find_action::<All>(actions)?.is_some()
            || ActionLoader::find_action::<ManageAuthority>(actions)?.is_some()
        {
            return Ok(());
        }
        cursor = boundary;
    }

    Err(SwigError::NoAdminAuthorityWouldRemain.into())
}
