use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use pinocchio::{
    memory::sol_memmove,
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;
use swig_state::{
    action::Action,
    authority::{
        ed25519::{
            Ed25519Authority, Ed25519AuthorityBuilder, Ed25519SessionAuthority,
            Ed25519SessionAuthorityBuilder,
        },
        Authority, AuthorityData, AuthorityDataBuilder, AuthorityType,
    },
    role::RoleBuilder,
    swig::{Swig, SwigBuilder},
    swig_account_seeds_with_bump, swig_account_signer,
    util::ZeroCopy,
    Role,
};

use crate::{
    assertions::*,
    error::SwigError,
    instruction::{
        accounts::{Context, CreateV1Accounts},
        SWIG_ACCOUNT_NAME,
    },
};

#[derive(Pod, Zeroable, Copy, Clone)]
#[repr(C, align(8))]
pub struct CreateV1Args {
    pub id: [u8; 32],
    pub start_slot: u64,
    pub end_slot: u64,
    pub bump: u8,
    pub authority_data_len: u16,
    pub num_actions: u8,
    _padding: [u8; 3],
}

impl CreateV1Args {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    fn into_authority<'a>(&self, data: &'a [u8]) -> Authority<'a> {
        Authority::from_bytes(data)
    }

    fn into_actions<'a>(&self, data: &'a [u8]) -> Vec<Action<'a>> {
        let mut cursor = 0;
        let mut actions = Vec::with_capacity(self.num_actions as usize);
        for i in 0..self.num_actions {
            let action = Action::from_bytes(&data[cursor..]).unwrap();
            cursor += action.size as usize;
            actions.push(action);
        }
        actions
    }
}

impl<'a> ZeroCopy<'a, CreateV1Args> for CreateV1Args {}

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
    let (create_data, authority_setup_data) = create.split_at(CreateV1Args::SIZE);
    let create_args =
        CreateV1Args::load(create_data).map_err(|_| ProgramError::InvalidInstructionData)?;

    let bump = check_self_pda(
        &swig_account_seeds_with_bump(&create_args.id, &[create_args.bump]),
        ctx.accounts.swig.key(),
        SwigError::InvalidSeed(SWIG_ACCOUNT_NAME),
    )?;

    let space_needed = swig_builder.size();
    let lamports_needed = Rent::get()?.minimum_balance(space_needed);
    CreateAccount {
        from: ctx.accounts.payer,
        to: ctx.accounts.swig,
        lamports: lamports_needed,
        space: space_needed as u64,
        owner: &crate::ID,
    }
    .invoke_signed(&[swig_account_signer(&create_args.id, &[bump])
        .as_slice()
        .into()])?;
    // unsafe {
    //     let account_data_ptr = ctx.accounts.swig.borrow_mut_data_unchecked();
    //     sol_memmove(
    //         account_data_ptr.as_mut_ptr(),
    //         max_initial_swig.as_mut_ptr(),
    //         space_needed,
    //     );
    // }
    Ok(())
}
