//! Hermetic auth-component benchmark: real signatures, no permissions or CPI.
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_state::{authority::counter::authenticate_role, swig::Swig};
pinocchio::entrypoint!(process_instruction);
fn process_instruction(_: &Pubkey, accounts: &[AccountInfo], ix: &[u8]) -> ProgramResult {
    let mode = ix[0];
    let selected = u32::from_le_bytes(ix[1..5].try_into().unwrap());
    let root = ix[5] != 0;
    let data = unsafe { accounts[0].borrow_mut_data_unchecked() };
    if mode == 3 {
        // Only the existing complete role walk.
        let end = Swig::roles_end_offset(data)?;
        unsafe { pinocchio::syscalls::sol_set_return_data(end.to_le_bytes().as_ptr(), 8) };
    } else if mode == 0 {
        // Control: original role walks and single-role authentication.
        let parts = Swig::split_parts_mut(data)?;
        let slot = Clock::get()?.slot;
        let role = Swig::get_mut_role(selected, parts.roles)?.unwrap();
        if role.authority.session_based() && !root {
            role.authority
                .authenticate_session(accounts, &ix[6..], b"counter-cu", slot)?;
        } else {
            role.authority
                .authenticate(accounts, &ix[6..], b"counter-cu", slot)?;
        }
    } else {
        authenticate_role(
            Swig::split_parts_mut(data)?.roles,
            selected,
            accounts,
            &ix[6..],
            b"counter-cu",
            root,
        )?
        .ok_or(ProgramError::InvalidAccountData)?;
        if mode == 4 {
            // Inject a downstream failure after synchronization to prove rollback.
            return Err(ProgramError::Custom(9999));
        }
    }
    Ok(())
}
