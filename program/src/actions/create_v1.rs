use crate::{
    assertions::*,
    error::SwigError,
    instruction::{
        accounts::{Context, CreateV1Accounts},
        SWIG_ACCOUNT_NAME,
    },
};
use borsh::{BorshDeserialize, BorshSerialize};
use pinocchio::{
    memory::sol_memmove, program_error::ProgramError, sysvars::{rent::Rent, Sysvar}, ProgramResult
};
use pinocchio_system::instructions::CreateAccount;
use swig_state::{swig_account_seeds_with_bump, swig_account_signer, Action, CreateV1, Role, Swig};

#[inline(always)]
pub fn create_v1(ctx: Context<CreateV1Accounts>, create: &[u8]) -> ProgramResult {
    check_system_owner(
        ctx.accounts.swig,
        SwigError::OwnerMismatch(SWIG_ACCOUNT_NAME),
    )?;
    check_zero_balance(
        ctx.accounts.swig,
        SwigError::AccountNotEmpty(SWIG_ACCOUNT_NAME),
    )?;
    let borsh_create =
        CreateV1::try_from_slice(create).map_err(|_| ProgramError::InvalidInstructionData)?;
    let bump = check_self_pda(
        &swig_account_seeds_with_bump(&borsh_create.id, &[borsh_create.bump]),
        ctx.accounts.swig.key(),
        SwigError::InvalidSeed(SWIG_ACCOUNT_NAME),
    )?;
    let swig = Swig::new(
        borsh_create.id,
        bump,
        vec![Role::new(
            borsh_create.initial_authority,
            borsh_create.authority_data,
            borsh_create.start_slot,
            borsh_create.end_slot,
            vec![Action::All]
        )],
    );
    let mut max_initial_swig = Vec::with_capacity(128);
    swig.serialize(&mut max_initial_swig).map_err(|e| {
        SwigError::SerializationError
    })?;
    let space_needed = max_initial_swig.len();
    let lamports_needed = Rent::get()?.minimum_balance(space_needed);
    CreateAccount {
        from: ctx.accounts.payer,
        to: ctx.accounts.swig,
        lamports: lamports_needed,
        space: space_needed as u64,
        owner: &crate::ID,
    }
    .invoke_signed(&[swig_account_signer(&borsh_create.id, &[bump])
        .as_slice()
        .into()])?;
    unsafe {
        let account_data_ptr = ctx.accounts.swig.borrow_mut_data_unchecked();
        sol_memmove(
            account_data_ptr.as_mut_ptr(),
            max_initial_swig.as_mut_ptr(),
            space_needed,
        );
    }
    Ok(())
}
