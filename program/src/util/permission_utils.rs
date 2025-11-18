use pinocchio::{msg, program_error::ProgramError};
use swig_state::{
    action::{Action, Permission},
    Transmutable,
};

pub fn get_permissions(data: &[u8]) -> Result<Vec<Permission>, ProgramError> {
    let mut permissions = Vec::new();
    let mut cursor = 0;
    while cursor < data.len() {
        let action =
            unsafe { Action::load_unchecked(data.get_unchecked(cursor..cursor + Action::LEN)) }
                .map_err(|_| ProgramError::InvalidAccountData)?;
        cursor += action.boundary() as usize;
        permissions.push(action.permission()?);
    }
    Ok(permissions)
}

pub fn permissions_to_mask<I>(permissions: I) -> u64
where
    I: IntoIterator<Item = Permission>,
{
    permissions
        .into_iter()
        .fold(0u64, |mask, permission| mask | permission_bit(permission))
}

#[inline(always)]
fn permission_bit(permission: Permission) -> u64 {
    1u64 << (permission as u16)
}

#[inline(always)]
pub fn check_valid_permissions(allowed: u64, requested: u64) -> bool {
    (requested & !allowed) == 0
}
