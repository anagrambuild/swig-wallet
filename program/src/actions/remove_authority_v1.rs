use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use swig_assertions::{check_bytes_match, check_self_owned};
use swig_state_x::{
    action::{all::All, manage_authority::ManageAuthority},
    swig::{Swig, SwigBuilder},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, RemoveAuthorityV1Accounts},
        SwigInstruction,
    },
};

pub struct RemoveAuthorityV1<'a> {
    pub args: &'a RemoveAuthorityV1Args,
    data_payload: &'a [u8],
    authority_payload: &'a [u8],
}

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct RemoveAuthorityV1Args {
    pub instruction: SwigInstruction,
    pub authority_payload_len: u16,
    _padding: [u16; 2],
    pub acting_role_id: u32,
    pub authority_to_remove_id: u32,
}

impl Transmutable for RemoveAuthorityV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl RemoveAuthorityV1Args {
    pub fn new(
        acting_role_id: u32,
        authority_to_remove_id: u32,
        authority_payload_len: u16,
    ) -> Self {
        Self {
            instruction: SwigInstruction::RemoveAuthorityV1,
            acting_role_id,
            authority_to_remove_id,
            authority_payload_len,
            _padding: [0; 2],
        }
    }
}

impl IntoBytes for RemoveAuthorityV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> RemoveAuthorityV1<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < RemoveAuthorityV1Args::LEN {
            return Err(SwigError::InvalidSwigRemoveAuthorityInstructionDataTooShort.into());
        }
        let (inst, authority_payload) = data.split_at(RemoveAuthorityV1Args::LEN);
        let args = unsafe { RemoveAuthorityV1Args::load_unchecked(inst)? };
        Ok(Self {
            args,
            authority_payload,
            data_payload: &data[..RemoveAuthorityV1Args::LEN],
        })
    }
}

pub fn remove_authority_v1(
    ctx: Context<RemoveAuthorityV1Accounts>,
    remove: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    // Basic account validations
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_bytes_match(
        ctx.accounts.system_program.key(),
        &pinocchio_system::ID,
        32,
        SwigError::InvalidSystemProgram,
    )?;

    // Parse instruction data
    let remove_authority_v1 = RemoveAuthorityV1::from_instruction_bytes(remove).map_err(|e| {
        msg!("RemoveAuthorityV1 Args Error: {:?}", e);
        ProgramError::InvalidInstructionData
    })?;

    if remove_authority_v1.args.authority_to_remove_id == 0 {
        return Err(SwigAuthenticateError::PermissionDeniedCannotRemoveRootAuthority.into());
    }
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    // All validation and processing as a closure to avoid borrowing
    // swig_account_data for too long
    {
        if swig_account_data[0] != Discriminator::SwigAccount as u8 {
            return Err(SwigError::InvalidSwigAccountDiscriminator.into());
        }
        let (_swig_header, swig_roles) =
            unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
        {
            let acting_role =
                Swig::get_mut_role(remove_authority_v1.args.acting_role_id, swig_roles)?;
            if acting_role.is_none() {
                return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
            }
            let acting_role = acting_role.unwrap();

            // Authenticate the caller
            let clock = Clock::get()?;
            let slot = clock.slot;

            if acting_role.authority.session_based() {
                acting_role.authority.authenticate_session(
                    all_accounts,
                    remove_authority_v1.authority_payload,
                    remove_authority_v1.data_payload,
                    slot,
                )?;
            } else {
                acting_role.authority.authenticate(
                    all_accounts,
                    remove_authority_v1.authority_payload,
                    remove_authority_v1.data_payload,
                    slot,
                )?;
            }
            let all = acting_role.get_action::<All>(&[])?;
            let manage_authority = acting_role.get_action::<ManageAuthority>(&[])?;
            let not_self = remove_authority_v1.args.acting_role_id
                != remove_authority_v1.args.authority_to_remove_id;
            let no_permission = all.is_none() && manage_authority.is_none();

            if no_permission && not_self {
                return Err(SwigAuthenticateError::PermissionDeniedToManageAuthority.into());
            }
        }

        // Get the role to remove
        let role_to_remove =
            Swig::get_mut_role(remove_authority_v1.args.authority_to_remove_id, swig_roles)?;

        if role_to_remove.is_none() {
            return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
        }
    }

    // Calculate the new size and remove the role
    let data_len = swig_account_data.len();
    let swig_lamports = unsafe { *ctx.accounts.swig.borrow_lamports_unchecked() };
    let mut swig_builder = SwigBuilder::new_from_bytes(swig_account_data)?;
    // Remove the role
    let removed = swig_builder.remove_role(remove_authority_v1.args.authority_to_remove_id)?;
    // realloc the account

    let new_size = data_len - removed.1;
    let rent = Rent::get()?;
    let rent_lamports = rent.minimum_balance(new_size);
    let diff = swig_lamports - rent_lamports;
    swig_builder.swig.reserved_lamports = rent_lamports;
    unsafe {
        *ctx.accounts.swig.borrow_mut_lamports_unchecked() = rent_lamports;
        *ctx.accounts.payer.borrow_mut_lamports_unchecked() = ctx.accounts.payer.lamports() + diff;
    };
    ctx.accounts.swig.realloc(new_size, false)?;

    Ok(())
}
