use crate::{
    assertions::{check_bytes_match, check_self_owned, check_self_pda, find_self_pda},
    error::SwigError,
    instruction::{
        accounts::{Context, ReplaceAuthorityV1Accounts},
        Authenticatable, SwigInstruction, SWIG_ACCOUNT_NAME,
    },
};
use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use swig_state::{swig_account_seeds_with_bump, util::ZeroCopy, Action, AuthorityType, Role, Swig};

pub struct ReplaceAuthorityV1<'a> {
    pub args: &'a ReplaceAuthorityV1Args,
    data_payload: &'a [u8],
    authority_payload: &'a [u8],
    actions_payload: &'a [u8],
    authority_data: &'a [u8],
}

#[derive(Pod, Zeroable, Copy, Clone)]
#[repr(C, align(8))]
pub struct ReplaceAuthorityV1Args {
    pub instruction: u8,
    pub acting_role_id: u8,
    pub authority_to_replace_id: u8,
    pub padding1: u8,
    pub authority_data_len: u16,
    pub actions_payload_len: u16,
    pub authority_type: AuthorityType,
    pub padding2: [u8; 7],
    pub start_slot: u64,
    pub end_slot: u64,
}

impl Authenticatable for ReplaceAuthorityV1<'_> {
    fn data_payload(&self) -> &[u8] {
        self.data_payload
    }
    fn authority_payload(&self) -> &[u8] {
        self.authority_payload
    }
}

impl ReplaceAuthorityV1Args {
    pub fn new(
        acting_role_id: u8,
        authority_to_replace_id: u8,
        authority_type: AuthorityType,
        authority_data_len: u16,
        actions_payload_len: u16,
        start_slot: u64,
        end_slot: u64,
    ) -> Self {
        Self {
            instruction: SwigInstruction::ReplaceAuthorityV1 as u8,
            acting_role_id,
            authority_to_replace_id,
            padding1: 0,
            authority_type,
            authority_data_len,
            actions_payload_len,
            padding2: [0; 7],
            start_slot,
            end_slot,
        }
    }
}

impl<'a> ZeroCopy<'a, ReplaceAuthorityV1Args> for ReplaceAuthorityV1Args {}

impl ReplaceAuthorityV1Args {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl<'a> ReplaceAuthorityV1<'a> {
    pub fn load(data: &'a [u8]) -> Result<Self, ProgramError> {
        let (inst, rest) = data.split_at(ReplaceAuthorityV1Args::SIZE);
        let args = ReplaceAuthorityV1Args::load(inst).map_err(|e| {
            msg!("ReplaceAuthorityV1 Args Error: {:?}", e);
            ProgramError::InvalidInstructionData
        })?;

        let (authority_data, rest) = rest.split_at(args.authority_data_len as usize);
        let (actions_payload, rest) = rest.split_at(args.actions_payload_len as usize);

        Ok(Self {
            args: &args,
            authority_data,
            authority_payload: rest,
            actions_payload,
            data_payload: &data[ReplaceAuthorityV1Args::SIZE
                ..ReplaceAuthorityV1Args::SIZE
                    + (args.authority_data_len + args.actions_payload_len) as usize],
        })
    }
}

pub fn replace_authority_v1(
    ctx: Context<ReplaceAuthorityV1Accounts>,
    replace: &[u8],
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
    let replace_authority_v1 = ReplaceAuthorityV1::load(replace).map_err(|e| {
        msg!("ReplaceAuthorityV1 Args Error: {:?}", e);
        ProgramError::InvalidInstructionData
    })?;

    // Get account data and deserialize once
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_data_unchecked() };
    let id = Swig::raw_get_id(&swig_account_data);
    let bump = Swig::raw_get_bump(&swig_account_data);

    // Deserialize the Swig account to check role count
    let mut swig =
        Swig::try_from_slice(&swig_account_data).map_err(|_| SwigError::SerializationError)?;

    // Check if the acting role and authority to replace exist
    if replace_authority_v1.args.acting_role_id as usize >= swig.roles.len() {
        msg!(
            "Invalid acting role ID: {}",
            replace_authority_v1.args.acting_role_id
        );
        return Err(SwigError::InvalidAuthority.into());
    }

    if replace_authority_v1.args.authority_to_replace_id as usize >= swig.roles.len() {
        msg!(
            "Invalid authority ID to replace: {}",
            replace_authority_v1.args.authority_to_replace_id
        );
        return Err(SwigError::InvalidAuthority.into());
    }

    // Get the acting role and role to replace directly by index
    let acting_role = &swig.roles[replace_authority_v1.args.acting_role_id as usize];
    let role_to_replace = &swig.roles[replace_authority_v1.args.authority_to_replace_id as usize];

    // Deserialize new actions
    let new_actions =
        Vec::<Action>::try_from_slice(replace_authority_v1.actions_payload).map_err(|e| {
            msg!("ReplaceAuthorityV1 Actions Error: {:?}", e);
            ProgramError::InvalidInstructionData
        })?;

    // Check for self-replacement with different permissions
    if replace_authority_v1.args.acting_role_id == replace_authority_v1.args.authority_to_replace_id
    {
        // Ensure there's at least one other authority with management permissions
        let has_other_manager = swig.roles.iter().enumerate().any(|(i, r)| {
            i != replace_authority_v1.args.acting_role_id as usize
                && r.actions
                    .iter()
                    .any(|action| matches!(action, Action::ManageAuthority | Action::All))
        });

        if !has_other_manager {
            // Check if management permissions are being removed
            let new_has_management = new_actions
                .iter()
                .any(|action| matches!(action, Action::ManageAuthority | Action::All));

            if !new_has_management {
                return Err(SwigError::PermissionDenied(
                    "Cannot remove management permissions from self when no other authority has management permissions",
                ).into());
            }
        }
    }

    // Check for privilege escalation
    let acting_has_all = acting_role
        .actions
        .iter()
        .any(|action| matches!(action, Action::All));

    if !acting_has_all {
        let replacing_has_all = role_to_replace
            .actions
            .iter()
            .any(|action| matches!(action, Action::All));

        if replacing_has_all {
            // If replacing an All authority, check if the new authority also has All
            let new_has_all = new_actions
                .iter()
                .any(|action| matches!(action, Action::All));

            if !new_has_all {
                return Err(SwigError::PermissionDenied(
                    "Cannot downgrade an authority with higher privileges",
                )
                .into());
            }
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

    if replace_authority_v1.args.start_slot > 0
        && replace_authority_v1.args.end_slot > 0
        && replace_authority_v1.args.start_slot >= replace_authority_v1.args.end_slot
    {
        msg!("Start slot must be less than end slot");
        return Err(SwigError::InvalidAuthority.into());
    }

    // Authenticate the caller
    replace_authority_v1.authenticate(&all_accounts, &acting_role)?;

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

    // Parse the new authority data
    let new_auth_data = replace_authority_v1.authority_data;

    // Check if the new authority data already exists in another role
    if Swig::raw_lookup_role(&swig_account_data, &new_auth_data).is_some() {
        msg!("Authority data already exists in another role");
        return Err(SwigError::InvalidAuthority.into());
    }

    // Create the new role
    let new_role = Role::new(
        replace_authority_v1.args.authority_type,
        new_auth_data.to_vec(),
        replace_authority_v1.args.start_slot,
        replace_authority_v1.args.end_slot,
        new_actions,
    );

    // Calculate size difference between old and new role
    let old_role_size = role_to_replace.size() as usize;
    let new_role_size = new_role.size() as usize;
    let size_diff = new_role_size as isize - old_role_size as isize;

    // Calculate new account size
    let new_account_size = (swig_account_data.len() as isize + size_diff) as usize;

    // Execution - All validations passed, now make state changes

    // Log the operation
    msg!(
        "Replacing authority {} with new authority by authority {}",
        replace_authority_v1.args.authority_to_replace_id,
        replace_authority_v1.args.acting_role_id
    );

    // Replace the role directly at its index
    swig.roles[replace_authority_v1.args.authority_to_replace_id as usize] = new_role;

    // Reallocate the account if needed
    if size_diff != 0 {
        ctx.accounts.swig.realloc(new_account_size, false)?;

        // If we need more space, transfer lamports to cover rent
        if size_diff > 0 {
            let cost = Rent::get()?
                .minimum_balance(new_account_size)
                .checked_sub(ctx.accounts.swig.lamports())
                .unwrap_or_default();

            if cost > 0 {
                Transfer {
                    from: ctx.accounts.payer,
                    to: ctx.accounts.swig,
                    lamports: cost,
                }
                .invoke()?;
            }
        }
    }

    // Serialize the updated swig account back to the data
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    swig.serialize(&mut &mut swig_account_data[..])
        .map_err(|_| SwigError::SerializationError)?;

    Ok(())
}
