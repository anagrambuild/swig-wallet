use pinocchio::{
    log::sol_log_compute_units,
    msg,
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;
use swig_state::{swig_account_seeds_with_bump, swig_account_signer};
use swig_state_x::{
    action::{all::All, manage_authority::ManageAuthority, Action, ActionLoader, Actionable},
    authority::{Authority, AuthorityLoader, AuthorityType},
    role::Position,
    swig::{Swig, SwigBuilder},
    IntoBytes, Transmutable,
};

use crate::{
    assertions::*,
    error::SwigError,
    instruction::{
        accounts::{Context, CreateV1Accounts},
        SwigInstruction,
    },
};

static_assertions::const_assert!(core::mem::size_of::<CreateV1Args>() % 8 == 0);
#[repr(C)]
#[derive(Debug)]
pub struct CreateV1Args {
    discriminator: SwigInstruction,
    pub id: [u8; 32],
    pub bump: u8,
    pub num_actions: u8,
    pub authority_type: u16,
    pub authority_data_len: u16,
}

impl CreateV1Args {
    pub fn new(
        id: [u8; 32],
        bump: u8,
        authority_type: AuthorityType,
        authority_data_len: u16,
        num_actions: u8,
    ) -> Self {
        Self {
            discriminator: SwigInstruction::CreateV1,
            id,
            bump,
            authority_type: authority_type as u16,
            authority_data_len,
            num_actions,
        }
    }
}

impl Transmutable for CreateV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl<'a> IntoBytes<'a> for CreateV1Args {
    fn into_bytes(&'a self) -> Result<&'a [u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

pub struct CreateV1<'a> {
    pub args: &'a CreateV1Args,
    pub authority_data: &'a [u8],
    pub actions: &'a [u8],
}

impl<'a> CreateV1<'a> {
    pub fn from_instruction_bytes(bytes: &'a [u8]) -> Result<Self, ProgramError> {
        if bytes.len() < CreateV1Args::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let args = unsafe { CreateV1Args::load_unchecked(&bytes[..CreateV1Args::LEN])? };
        let authority_data =
            &bytes[CreateV1Args::LEN..CreateV1Args::LEN + args.authority_data_len as usize];
        let actions = &bytes[CreateV1Args::LEN + args.authority_data_len as usize..];
        Ok(Self {
            args,
            authority_data,
            actions,
        })
    }

    pub fn get_authority(&'a self) -> Result<&impl Authority<'a>, ProgramError> {
        let authority_type = AuthorityType::try_from(self.args.authority_type)?;
        AuthorityLoader::load_authority(authority_type, self.authority_data)
    }

    pub fn get_action<T: Actionable<'a>>(&'a self) -> Result<Option<&'a T>, ProgramError> {
        ActionLoader::find_action::<T>(self.actions)
    }
}

#[inline(always)]
pub fn create_v1(ctx: Context<CreateV1Accounts>, create: &[u8]) -> ProgramResult {
    check_system_owner(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_zero_balance(ctx.accounts.swig, SwigError::AccountNotEmptySwigAccount)?;

    let create_v1 = CreateV1::from_instruction_bytes(create)?;
    let authority = create_v1.get_authority()?;
    let bump = check_self_pda(
        &swig_account_seeds_with_bump(&create_v1.args.id, &[create_v1.args.bump]),
        ctx.accounts.swig.key(),
        SwigError::InvalidSeedSwigAccount,
    )?;

    let manage_authority_action = create_v1.get_action::<ManageAuthority>()?;
    let all_action = create_v1.get_action::<All>()?;
    if manage_authority_action.is_none() && all_action.is_none() {
        msg!("Root authority type must had one of the following actions: ManageAuthority or All");
        return Err(SwigError::InvalidAuthorityType.into());
    }

    let account_size = core::alloc::Layout::from_size_align(
        Swig::LEN
            + Position::LEN
            + authority.length()
            + Action::LEN * create_v1.args.num_actions as usize
            + create_v1.actions.len(),
        core::mem::size_of::<u64>(),
    )
    .map_err(|_| SwigError::InvalidAlignment)?
    .pad_to_align()
    .size();
    let swig = Swig::new(create_v1.args.id, bump);
    let lamports_needed = Rent::get()?.minimum_balance(account_size);

    CreateAccount {
        from: ctx.accounts.payer,
        to: ctx.accounts.swig,
        lamports: lamports_needed,
        space: account_size as u64,
        owner: &crate::ID,
    }
    .invoke_signed(&[swig_account_signer(&swig.id, &[swig.bump])
        .as_slice()
        .into()])?;
    let swig_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let mut swig_builder = SwigBuilder::create(swig_data, swig)?;
    swig_builder.add_role(authority, create_v1.args.num_actions, create_v1.actions)?;
    Ok(())
}
