use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;
use swig_assertions::*;
use swig_state_x::{
    action::{
        all::All, manage_authority::ManageAuthority, sub_account::SubAccount, ActionLoader,
        Actionable,
    },
    authority::AuthorityType,
    role::RoleMut,
    swig::{
        sub_account_seeds_with_bump, sub_account_signer, swig_account_seeds_with_bump,
        swig_account_signer, Swig, SwigSubAccount,
    },
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, CreateSubAccountV1Accounts},
        SwigInstruction,
    },
};

/// Arguments for the CreateSubAccountV1 instruction
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct CreateSubAccountV1Args {
    discriminator: SwigInstruction,
    _padding1: u16,
    pub role_id: u32,
    pub sub_account_bump: u8,
    _padding2: [u8; 7],
}

impl CreateSubAccountV1Args {
    pub fn new(role_id: u32, sub_account_bump: u8) -> Self {
        Self {
            discriminator: SwigInstruction::CreateSubAccountV1,
            _padding1: 0,
            role_id,
            sub_account_bump,
            _padding2: [0; 7],
        }
    }
}

impl Transmutable for CreateSubAccountV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for CreateSubAccountV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Struct for parsing the CreateSubAccountV1 instruction data
pub struct CreateSubAccountV1<'a> {
    pub args: &'a CreateSubAccountV1Args,
    pub authority_payload: &'a [u8],
    pub data_payload: &'a [u8],
}

impl<'a> CreateSubAccountV1<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < CreateSubAccountV1Args::LEN {
            return Err(SwigError::InvalidSwigCreateInstructionDataTooShort.into());
        }

        // Split the data into args and the rest (authority payload)
        let (args_data, rest) = data.split_at(CreateSubAccountV1Args::LEN);

        let args = unsafe { CreateSubAccountV1Args::load_unchecked(args_data)? };

        Ok(Self {
            args,
            authority_payload: rest,
            data_payload: args_data,
        })
    }
}

/// Implementation of the CreateSubAccountV1 instruction handler
#[inline(always)]
pub fn create_sub_account_v1(
    ctx: Context<CreateSubAccountV1Accounts>,
    data: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    // Check that the swig account is owned by our program
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_system_owner(ctx.accounts.sub_account, SwigError::OwnerMismatchSubAccount)?;
    check_zero_balance(ctx.accounts.sub_account, SwigError::SubAccountAlreadyExists)?;

    // Parse the instruction data
    let create_sub_account = CreateSubAccountV1::from_instruction_bytes(data)?;

    // Verify the swig account data
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    // Split the swig account data to get the header and roles
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_unchecked(swig_header)? };

    // Get the role using the role_id from the instruction
    let role_opt = Swig::get_mut_role(create_sub_account.args.role_id, swig_roles)?;
    if role_opt.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let role = role_opt.unwrap();
    // Authenticate the authority
    let clock = Clock::get()?;
    let slot = clock.slot;
    // Authenticate based on authority type (session-based or not)
    if role.authority.session_based() {
        role.authority.authenticate_session(
            &all_accounts,
            create_sub_account.authority_payload,
            create_sub_account.data_payload,
            slot,
        )?;
    } else {
        role.authority.authenticate(
            &all_accounts,
            create_sub_account.authority_payload,
            create_sub_account.data_payload,
            slot,
        )?;
    }
    // Check if the role has the SubAccount permission
    let sub_account_action = RoleMut::get_action_mut::<SubAccount>(role.actions, &[])?;
    if sub_account_action.is_none() {
        return Err(SwigError::AuthorityCannotCreateSubAccount.into());
    }
    let sub_account_action = sub_account_action.unwrap();
    // Derive the sub-account address using the authority index as seed
    let role_id_bytes = create_sub_account.args.role_id.to_le_bytes();
    let bump_byte = [create_sub_account.args.sub_account_bump];
    let sub_account_seeds = sub_account_seeds_with_bump(&swig.id, &role_id_bytes, &bump_byte);
    // Check that sub_account passed in matches derived address
    let bump = check_self_pda(
        &sub_account_seeds,
        ctx.accounts.sub_account.key(),
        SwigError::InvalidSeedSwigAccount,
    )?;
    // Create the sub-account
    let account_size = SwigSubAccount::LEN;
    let lamports_needed = Rent::get()?.minimum_balance(account_size);
    // Create account
    let create_account_ix = CreateAccount {
        from: ctx.accounts.payer,
        to: ctx.accounts.sub_account,
        lamports: lamports_needed,
        space: account_size as u64,
        owner: &crate::ID,
    };
    let role_id_bytes = create_sub_account.args.role_id.to_le_bytes();
    let bump_byte = [create_sub_account.args.sub_account_bump];
    let seeds = sub_account_signer(&swig.id, &role_id_bytes, &bump_byte);
    create_account_ix.invoke_signed(&[seeds.as_slice().into()])?;
    // Initialize the sub-account data with a Swig account structure
    let sub_account_data = unsafe { ctx.accounts.sub_account.borrow_mut_data_unchecked() };
    let mut sub_account = unsafe { SwigSubAccount::load_mut_unchecked(sub_account_data)? };
    sub_account.discriminator = Discriminator::SwigSubAccount as u8;
    sub_account.bump = create_sub_account.args.sub_account_bump;
    sub_account.role_id = create_sub_account.args.role_id;
    sub_account.swig_id = swig.id;
    sub_account.enabled = true;
    // Set reserved lamports to the minimum rent-exempt amount
    sub_account.reserved_lamports = lamports_needed;
    Ok(())
}
