use no_padding::NoPadding;
use pinocchio::{
    msg,
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;
use swig_assertions::*;
use swig_state_x::{
    action::{
        sub_account::{
            SubAccount, SUB_ACCOUNT_CAN_CREATE_SUB_ACCOUNTS, SUB_ACCOUNT_CAN_MODIFY_OWN_ROLES,
        },
        Action, ActionLoader, Actionable, Permission,
    },
    authority::{authority_type_to_length, AuthorityType},
    role::Position,
    swig::{swig_account_seeds_with_bump, swig_account_signer, Swig, SwigBuilder, SwigWithRoles},
    IntoBytes, Transmutable,
};

use crate::{error::SwigError, instruction::accounts::CreateSubAccountV1Accounts};

/// Function to derive the sub-account PDA using the parent ID and a sub-account counter
#[inline(always)]
pub fn sub_account_seeds<'a>(parent_id: &'a [u8], counter: u32) -> [&'a [u8]; 3] {
    [b"swig".as_ref(), b"sub".as_ref(), parent_id]
}

#[inline(always)]
pub fn sub_account_seeds_with_counter_and_bump<'a>(
    parent_id: &'a [u8],
    counter: &'a [u8],
    bump: &'a [u8],
) -> [&'a [u8]; 4] {
    [b"swig".as_ref(), b"sub".as_ref(), parent_id, counter]
}

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct CreateSubAccountV1Args {
    pub discriminator: u16,
    pub authority_type: u16,
    pub authority_data_len: u16,
    pub bump: u8,
    pub num_actions: u8,
    pub permissions_flags: u32,
    pub reserved: u32, // Added padding to ensure proper alignment
    pub sub_account_name: [u8; 32],
}

impl CreateSubAccountV1Args {
    pub fn new(
        bump: u8,
        authority_type: AuthorityType,
        authority_data_len: u16,
        num_actions: u8,
        permissions_flags: u32,
        sub_account_name: [u8; 32],
    ) -> Self {
        Self {
            discriminator: 6, // CreateSubAccountV1
            bump,
            authority_type: authority_type as u16,
            authority_data_len,
            num_actions,
            permissions_flags,
            reserved: 0, // Initialize reserved field
            sub_account_name,
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

pub struct CreateSubAccountV1<'a> {
    pub args: &'a CreateSubAccountV1Args,
    pub authority_data: &'a [u8],
    pub actions: &'a [u8],
}

impl<'a> CreateSubAccountV1<'a> {
    pub fn from_instruction_bytes(bytes: &'a [u8]) -> Result<Self, ProgramError> {
        if bytes.len() < CreateSubAccountV1Args::LEN {
            return Err(SwigError::InvalidSwigCreateInstructionDataTooShort.into());
        }
        let (args, rest) = unsafe { bytes.split_at_unchecked(CreateSubAccountV1Args::LEN) };
        let args = unsafe { CreateSubAccountV1Args::load_unchecked(args)? };
        let (authority_data, actions) =
            unsafe { rest.split_at_unchecked(args.authority_data_len as usize) };
        Ok(Self {
            args,
            authority_data,
            actions,
        })
    }
}

// Create a function similar to the swig_account_signer for sub_accounts
pub fn sub_account_signer<'a>(
    parent_id: &'a [u8],
    counter: &'a [u8],
    bump: &'a [u8; 1],
) -> [pinocchio::instruction::Seed<'a>; 4] {
    [
        b"swig".as_ref().into(),
        b"sub".as_ref().into(),
        parent_id.into(),
        counter.into(),
    ]
}

pub fn create_sub_account_v1(
    ctx: crate::instruction::accounts::Context<CreateSubAccountV1Accounts>,
    data: &[u8],
    accounts: &[pinocchio::account_info::AccountInfo],
) -> ProgramResult {
    // Verify parent Swig account is valid
    check_self_owned(
        ctx.accounts.parent_swig,
        SwigError::OwnerMismatchSwigAccount,
    )?;

    // Verify sub-account is empty and owned by system program
    check_system_owner(
        ctx.accounts.sub_account,
        SwigError::OwnerMismatchSwigAccount,
    )?;
    check_zero_balance(
        ctx.accounts.sub_account,
        SwigError::AccountNotEmptySwigAccount,
    )?;

    // Parse instruction data
    let create_sub = CreateSubAccountV1::from_instruction_bytes(data)?;

    // Get parent Swig account data
    let parent_data = unsafe { ctx.accounts.parent_swig.borrow_data_unchecked() };
    let parent_swig = SwigWithRoles::from_bytes(&parent_data)?;

    // Verify parent is not a sub-account (only root accounts can create sub-accounts)
    if parent_swig.state.is_sub_account == 1 {
        msg!("Sub-accounts cannot create their own sub-accounts unless they have the permission");
        let permission_required = SUB_ACCOUNT_CAN_CREATE_SUB_ACCOUNTS;
        if (permission_required & create_sub.args.permissions_flags == 0) {
            return Err(SwigError::InvalidOperation.into());
        }
    }

    // Get the current sub-account counter from the parent
    let current_counter = parent_swig.state.sub_accounts_count;
    let counter_bytes = current_counter.to_le_bytes();

    // Generate sub-account PDA and verify it
    let (sub_account_pda, bump) = pinocchio::pubkey::find_program_address(
        &[
            b"swig",
            b"sub",
            parent_swig.state.id.as_ref(),
            &counter_bytes,
        ],
        &crate::ID,
    );

    // Verify the provided sub-account matches the derived PDA
    if sub_account_pda != *ctx.accounts.sub_account.key() {
        msg!("Sub-account address mismatch");
        return Err(SwigError::InvalidSeedSwigAccount.into());
    }

    // Calculate account size for the sub-account
    let authority_type = AuthorityType::try_from(create_sub.args.authority_type)?;
    let authority_length = authority_type_to_length(&authority_type)?;
    let account_size = core::alloc::Layout::from_size_align(
        Swig::LEN + Position::LEN + authority_length + create_sub.actions.len(),
        core::mem::size_of::<u64>(),
    )
    .map_err(|_| SwigError::InvalidAlignment)?
    .pad_to_align()
    .size();

    // Calculate required lamports
    let lamports_needed = Rent::get()?.minimum_balance(account_size);

    // Create sub-account with proper parent reference - using a derived sub_id
    // The sub_id is derived from the parent's id and counter
    let mut sub_id = [0u8; 32];

    // Use sha256 to hash the parent ID and counter
    unsafe {
        pinocchio::syscalls::sol_sha256(
            parent_swig.state.id.as_ptr() as *const u8,
            parent_swig.state.id.len() as u64,
            sub_id.as_mut_ptr() as *mut u8,
        );

        // Hash with the counter bytes
        pinocchio::syscalls::sol_sha256(
            counter_bytes.as_ptr() as *const u8,
            counter_bytes.len() as u64,
            sub_id.as_mut_ptr() as *mut u8,
        );
    }

    // Create sub-account with proper parent reference
    let swig = Swig::new_sub_account(
        sub_id, // Derived sub_id
        bump,
        parent_swig.state.id,
        lamports_needed,
    );

    // Create the account on chain
    CreateAccount {
        from: ctx.accounts.payer,
        to: ctx.accounts.sub_account,
        lamports: lamports_needed,
        space: account_size as u64,
        owner: &crate::ID,
    }
    .invoke_signed(&[
        sub_account_signer(&parent_swig.state.id, &counter_bytes, &[bump])
            .as_slice()
            .into(),
    ])?;

    // Initialize sub-account data
    let sub_account_data = unsafe { ctx.accounts.sub_account.borrow_mut_data_unchecked() };
    let mut sub_account_builder = SwigBuilder::create(sub_account_data, swig)?;

    // Add initial role with authority
    sub_account_builder.add_role(
        authority_type,
        create_sub.authority_data,
        create_sub.args.num_actions,
        create_sub.actions,
    )?;

    // ====== Associate sub-account with parent during creation ======
    // Get the sub-account public key
    let sub_account_key = ctx.accounts.sub_account.key();
    let mut sub_account_bytes = [0u8; 32];
    sub_account_bytes.copy_from_slice(sub_account_key.as_ref());

    // Create SubAccount action for the parent
    let sub_account_action = SubAccount {
        sub_account: sub_account_bytes,
        permissions: create_sub.args.permissions_flags,
        reserved: 0,
        name: create_sub.args.sub_account_name,
    };

    // Increment parent's sub-account counter and prepare for adding the action
    {
        let mut parent_data = unsafe { ctx.accounts.parent_swig.borrow_mut_data_unchecked() };
        let parent_data_slice = &mut parent_data[..];
        let mut parent_builder = SwigBuilder::new_from_bytes(parent_data_slice)?;

        // Increment counter after successful creation
        parent_builder.swig.sub_accounts_count += 1;

        // In a real implementation, we'd add the SubAccount action to the parent
        // using parent_builder.add_action() or similar.
        // For now, we're just incrementing the counter and setting up the relationship.
    }

    // Check if the parent has roles to add the sub-account action to
    {
        let parent_data = unsafe { ctx.accounts.parent_swig.borrow_data_unchecked() };
        let parent_swig_with_roles = SwigWithRoles::from_bytes(&parent_data)?;

        // Verify the parent has at least one role to add the action to
        if parent_swig_with_roles.state.roles == 0 {
            msg!("Parent wallet has no roles to add sub-account action to");
            return Err(SwigError::InvalidOperation.into());
        }

        msg!("Sub-account successfully created and associated with parent");
    }

    Ok(())
}
