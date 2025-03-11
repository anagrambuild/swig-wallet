use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::AccountInfo, msg, program_error::ProgramError, sysvars::Sysvar, ProgramResult,
};
use swig_state::{swig_account_seeds_with_bump, Action, Swig};

use crate::{
    assertions::{check_bytes_match, check_self_owned, check_self_pda},
    error::SwigError,
    instruction::{
        accounts::{Context, RemoveAuthorityV1Accounts},
        Authenticatable, SwigInstruction, SWIG_ACCOUNT_NAME,
    },
    util::ZeroCopy,
};

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
            args,
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
    // Basic account validations
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

    // Parse instruction data
    let remove_authority_v1 = RemoveAuthorityV1::load(remove).map_err(|e| {
        msg!("RemoveAuthorityV1 Args Error: {:?}", e);
        ProgramError::InvalidInstructionData
    })?;

    // Get account data and deserialize once
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_data_unchecked() };
    let id = Swig::raw_get_id(swig_account_data);
    let bump = Swig::raw_get_bump(swig_account_data);

    // Deserialize the Swig account to check role count
    let mut swig =
        Swig::try_from_slice(swig_account_data).map_err(|_| SwigError::SerializationError)?;

    // Check if we're trying to remove the last authority
    if swig.roles.len() <= 1 {
        msg!(
            "Cannot remove the last authority. Current role count: {}",
            swig.roles.len()
        );
        return Err(SwigError::PermissionDenied("Cannot remove the last authority").into());
    }

    // Check if the acting role and authority to remove exist
    if remove_authority_v1.args.acting_role_id as usize >= swig.roles.len() {
        msg!(
            "Invalid acting role ID: {}",
            remove_authority_v1.args.acting_role_id
        );
        return Err(SwigError::InvalidAuthority.into());
    }

    if remove_authority_v1.args.authority_to_remove_id as usize >= swig.roles.len() {
        msg!(
            "Invalid authority ID to remove: {}",
            remove_authority_v1.args.authority_to_remove_id
        );
        return Err(SwigError::InvalidAuthority.into());
    }

    // Get the acting role and role to remove directly by index
    let acting_role = &swig.roles[remove_authority_v1.args.acting_role_id as usize];
    let role_to_remove = &swig.roles[remove_authority_v1.args.authority_to_remove_id as usize];

    // Check for self-removal with no other managers
    if remove_authority_v1.args.acting_role_id == remove_authority_v1.args.authority_to_remove_id {
        msg!("Warning: Authority is removing itself");

        // Ensure there's at least one other authority with management permissions
        let has_other_manager = swig.roles.iter().enumerate().any(|(i, r)| {
            i != remove_authority_v1.args.acting_role_id as usize
                && r.actions
                    .iter()
                    .any(|action| matches!(action, Action::ManageAuthority | Action::All))
        });

        if !has_other_manager {
            return Err(SwigError::PermissionDenied(
                "Cannot remove self when no other authority has management permissions",
            )
            .into());
        }
    }

    // Check for privilege escalation
    let acting_has_all = acting_role
        .actions
        .iter()
        .any(|action| matches!(action, Action::All));
    if !acting_has_all {
        let removing_has_all = role_to_remove
            .actions
            .iter()
            .any(|action| matches!(action, Action::All));
        if removing_has_all {
            return Err(SwigError::PermissionDenied(
                "Cannot remove an authority with higher privileges",
            )
            .into());
        }
    }

    // Validate slot range
    let clock = pinocchio::sysvars::clock::Clock::get()?;
    let current_slot = clock.slot;

    if (acting_role.start_slot > 0 && current_slot < acting_role.start_slot)
        || (acting_role.end_slot > 0 && current_slot >= acting_role.end_slot)
    {
        msg!(
            "Role is not valid at current slot {}. Valid range: {} to {}",
            current_slot,
            acting_role.start_slot,
            acting_role.end_slot
        );
        return Err(SwigError::PermissionDenied("Role is not valid at current slot").into());
    }

    // Authenticate the caller
    remove_authority_v1.authenticate(all_accounts, acting_role)?;

    // Verify PDA derivation
    let b = [bump];
    let seeds = swig_account_seeds_with_bump(&id, &b);
    check_self_pda(
        &seeds,
        ctx.accounts.swig.key(),
        SwigError::InvalidSeed(SWIG_ACCOUNT_NAME),
    )?;

    // Check if the role has permission to manage authorities
    let authorized = acting_role.actions.iter().any(|action| match action {
        Action::ManageAuthority => true,
        Action::All => true,
        _ => false,
    });

    if !authorized {
        return Err(SwigError::PermissionDenied("No permission to manage authority").into());
    }

    // Calculate new size without cloning
    let role_size = role_to_remove.size();
    let new_size = swig.size() - role_size;

    // Execution - All validations passed, now make state changes

    // Log the operation
    msg!(
        "Removing authority {} by authority {}",
        remove_authority_v1.args.authority_to_remove_id,
        remove_authority_v1.args.acting_role_id
    );

    // Remove the role
    swig.roles
        .remove(remove_authority_v1.args.authority_to_remove_id as usize);

    // Reallocate the account
    ctx.accounts.swig.realloc(new_size, false)?;

    // Serialize the updated swig account back to the data
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    swig.serialize(&mut &mut swig_account_data[..])
        .map_err(|_| SwigError::SerializationError)?;

    // Log success
    msg!(
        "Authority removed successfully. New role count: {}",
        swig.roles.len()
    );

    Ok(())
}
