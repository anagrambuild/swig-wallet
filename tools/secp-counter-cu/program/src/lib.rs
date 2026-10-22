//! Hermetic auth-component benchmark: real signatures, no permissions or CPI.
use pinocchio::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey, ProgramResult,
};
use swig_state::{authority::counter::authenticate_role, swig::Swig, Transmutable};
pinocchio::entrypoint!(process_instruction);
fn process_instruction(_: &Pubkey, accounts: &[AccountInfo], ix: &[u8]) -> ProgramResult {
    let mode = ix[0];
    let selected = u32::from_le_bytes(ix[1..5].try_into().unwrap());
    let root = ix[5] != 0;
    let data = unsafe { accounts[0].borrow_mut_data_unchecked() };
    let count = u16::from_le_bytes(data[34..36].try_into().unwrap());
    if mode == 3 {
        // Only the existing complete role walk.
        let end = Swig::roles_end_offset(data)?;
        unsafe { pinocchio::syscalls::sol_set_return_data(end.to_le_bytes().as_ptr(), 8) };
    } else if mode == 0 {
        // Control: original role walks and single-role authentication.
        let parts = Swig::split_parts_mut(data)?;
        let role = Swig::get_mut_role(selected, parts.roles)?.unwrap();
        if role.authority.session_based() && !root {
            role.authority
                .authenticate_session(accounts, &ix[6..], b"counter-cu", 100)?;
        } else {
            role.authority
                .authenticate(accounts, &ix[6..], b"counter-cu", 100)?;
        }
    } else {
        let (roles, bound) = if mode == 1 {
            (&mut data[Swig::LEN..], Some(count))
        } else {
            (Swig::split_parts_mut(data)?.roles, None)
        };
        authenticate_role(
            roles,
            bound,
            selected,
            accounts,
            &ix[6..],
            b"counter-cu",
            100,
            root,
        )?
        .ok_or(ProgramError::InvalidAccountData)?;
    }
    Ok(())
}
