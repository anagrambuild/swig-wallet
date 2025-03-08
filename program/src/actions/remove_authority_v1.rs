use crate::{
    assertions::{check_bytes_match, check_self_owned, check_self_pda, find_self_pda},
    error::SwigError,
    instruction::{
        accounts::{Context, RemoveAuthorityV1Accounts},
        Authenticatable, SwigInstruction, SWIG_ACCOUNT_NAME,
    },
    util::ZeroCopy,
};
use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::AccountInfo, msg, program_error::ProgramError, sysvars::Sysvar, ProgramResult,
};
use swig_state::{swig_account_seeds_with_bump, Action, Role, Swig};

pub struct RemoveAuthorityV1<'a> {
    pub args: &'a RemoveAuthorityV1Args,
    data_payload: &'a [u8],
    authority_payload: &'a [u8],
}

#[derive(Pod, Zeroable, Copy, Clone)]
#[repr(C, align(8))]
pub struct RemoveAuthorityV1Args {
    pub instruction: u8,
    pub acting_role_id: u8,
    pub authority_to_remove_id: u8,
    pub padding1: u8,
    pub authority_payload_len: u16,
    pub padding2: [u8; 2],
    pub dummy: u64,
}

impl Authenticatable for RemoveAuthorityV1<'_> {
    fn data_payload(&self) -> &[u8] {
        self.data_payload
    }
    fn authority_payload(&self) -> &[u8] {
        self.authority_payload
    }
}

impl RemoveAuthorityV1Args {
    pub fn new(acting_role_id: u8, authority_to_remove_id: u8, authority_payload_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::RemoveAuthorityV1 as u8,
            acting_role_id,
            authority_to_remove_id,
            padding1: 0,
            authority_payload_len,
            padding2: [0; 2],
            dummy: 0,
        }
    }
}

impl<'a> ZeroCopy<'a, RemoveAuthorityV1Args> for RemoveAuthorityV1Args {}

impl RemoveAuthorityV1Args {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl<'a> RemoveAuthorityV1<'a> {
    pub fn load(data: &'a [u8]) -> Result<Self, ProgramError> {
        let (inst, rest) = data.split_at(RemoveAuthorityV1Args::SIZE);
        let args = RemoveAuthorityV1Args::load(inst).map_err(|e| {
            msg!("RemoveAuthorityV1 Args Error: {:?}", e);
            ProgramError::InvalidInstructionData
        })?;

        let (authority_payload, data_payload) = rest.split_at(args.authority_payload_len as usize);

        Ok(Self {
            args: &args,
            authority_payload,
            data_payload,
        })
    }
}

pub fn remove_authority_v1(
    ctx: Context<RemoveAuthorityV1Accounts>,
    remove: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    check_self_owned(
        ctx.accounts.swig,
        SwigError::OwnerMismatch(SWIG_ACCOUNT_NAME),
    )?;
    check_bytes_match(
        ctx.accounts.system_program.key(),
        &pinocchio_system::ID,
        32,
        SwigError::InvalidSystemProgram,
    )?;

    let remove_authority_v1 = RemoveAuthorityV1::load(remove).map_err(|e| {
        msg!("RemoveAuthorityV1 Args Error: {:?}", e);
        ProgramError::InvalidInstructionData
    })?;

    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };

    let id = Swig::raw_get_id(&swig_account_data);
    let bump = Swig::raw_get_bump(&swig_account_data);

    let mut swig =
        Swig::try_from_slice(&swig_account_data).map_err(|_| SwigError::SerializationError)?;

    if swig.roles.len() <= 1 {
        msg!(
            "Cannot remove the last authority. Current role count: {}",
            swig.roles.len()
        );
        return Err(SwigError::PermissionDenied("Cannot remove the last authority").into());
    }

    if remove_authority_v1.args.authority_to_remove_id as usize >= swig.roles.len() {
        msg!(
            "Invalid authority ID to remove: {}",
            remove_authority_v1.args.authority_to_remove_id
        );
        return Err(SwigError::InvalidAuthority.into());
    }

    let (_, role) = Swig::raw_get_role(
        &swig_account_data,
        remove_authority_v1.args.acting_role_id as usize,
    )
    .ok_or(SwigError::InvalidAuthority)?;

    let clock = pinocchio::sysvars::clock::Clock::get()?;
    let current_slot = clock.slot;

    if (role.start_slot > 0 && current_slot < role.start_slot)
        || (role.end_slot > 0 && current_slot >= role.end_slot)
    {
        msg!(
            "Role is not valid at current slot {}. Valid range: {} to {}",
            current_slot,
            role.start_slot,
            role.end_slot
        );
        return Err(SwigError::PermissionDenied("Role is not valid at current slot").into());
    }

    remove_authority_v1.authenticate(&all_accounts, &role)?;

    let b = [bump];
    let seeds = swig_account_seeds_with_bump(&id, &b);
    check_self_pda(
        &seeds,
        ctx.accounts.swig.key(),
        SwigError::InvalidSeed(SWIG_ACCOUNT_NAME),
    )?;

    let authorized = role.actions.iter().any(|action| match action {
        Action::ManageAuthority => true,
        Action::All => true,
        _ => false,
    });

    if !authorized {
        return Err(SwigError::PermissionDenied("No permission to manage authority").into());
    }

    swig.roles
        .remove(remove_authority_v1.args.authority_to_remove_id as usize);

    let new_size = swig.size();
    ctx.accounts.swig.realloc(new_size, false)?;

    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    swig.serialize(&mut &mut swig_account_data[..])
        .map_err(|_| SwigError::SerializationError)?;

    msg!(
        "Authority removed successfully. New role count: {}",
        swig.roles.len()
    );
    Ok(())
}
