use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use swig_state::{swig_account_seeds_with_bump, Action, AuthorityType, Role, Swig};

use crate::{
    assertions::{check_bytes_match, check_self_owned, check_self_pda},
    error::SwigError,
    instruction::{
        accounts::{AddAuthorityV1Accounts, Context},
        Authenticatable, SwigInstruction, SWIG_ACCOUNT_NAME,
    },
    util::ZeroCopy,
};

pub struct AddAuthorityV1<'a> {
    pub args: &'a AddAuthorityV1Args,
    data_payload: &'a [u8],
    authority_payload: &'a [u8],
    actions_payload: &'a [u8],
    authority_data: &'a [u8],
}

static_assertions::const_assert!(core::mem::size_of::<AddAuthorityV1Args>() % 8 == 0);
#[repr(C)]
pub struct AddAuthorityV1Args {
    pub instruction: u8,
    pub acting_role_id: u8,
    pub authority_data_len: u16,
    pub actions_payload_len: u16,
    pub authority_type: AuthorityType,
    pub padding2: [u8; 1],
    pub start_slot: u64,
    pub end_slot: u64,
}

impl Authenticatable for AddAuthorityV1<'_> {
    fn data_payload(&self) -> &[u8] {
        self.data_payload
    }
    fn authority_payload(&self) -> &[u8] {
        self.authority_payload
    }
}

impl AddAuthorityV1Args {
    pub fn new(
        acting_role_id: u8,
        authority_type: AuthorityType,
        authority_data_len: u16,
        actions_payload_len: u16,
        start_slot: u64,
        end_slot: u64,
    ) -> Self {
        Self {
            instruction: SwigInstruction::AddAuthorityV1 as u8,
            acting_role_id,
            authority_type,
            actions_payload_len,
            authority_data_len,
            padding2: [0; 1],
            start_slot,
            end_slot,
        }
    }
}

impl<'a> ZeroCopy<'a, AddAuthorityV1Args> for AddAuthorityV1Args {}

impl AddAuthorityV1Args {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl<'a> AddAuthorityV1<'a> {
    pub fn load(data: &'a [u8]) -> Result<Self, ProgramError> {
        let (inst, rest) = data.split_at(AddAuthorityV1Args::SIZE);
        let args = AddAuthorityV1Args::load(inst).map_err(|_| {
            msg!("AddAuthorityV1 Args Error:");
            ProgramError::InvalidInstructionData
        })?;

        let (authority_data, rest) = rest.split_at(args.authority_data_len as usize);
        let (actions_payload, rest) = rest.split_at(args.actions_payload_len as usize);

        Ok(Self {
            args,
            authority_data,
            authority_payload: rest,
            actions_payload,
            data_payload: &data[AddAuthorityV1Args::SIZE
                ..AddAuthorityV1Args::SIZE
                    + (args.authority_data_len + args.actions_payload_len) as usize],
        })
    }
}

pub fn add_authority_v1(
    ctx: Context<AddAuthorityV1Accounts>,
    add: &[u8],
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
    let add_authority_v1 = AddAuthorityV1::load(add).map_err(|e| {
        msg!("AddAuthorityV1 Args Error: {:?}", e);
        ProgramError::InvalidInstructionData
    })?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let id = Swig::raw_get_id(swig_account_data);
    let bump = Swig::raw_get_bump(swig_account_data);
    let (_, role) = Swig::raw_get_role(
        swig_account_data,
        add_authority_v1.args.acting_role_id as usize,
    )
    .ok_or(SwigError::InvalidAuthority)?;
    add_authority_v1.authenticate(all_accounts, &role)?;
    let b = [bump];
    let seeds = swig_account_seeds_with_bump(&id, &b);
    check_self_pda(
        &seeds,
        ctx.accounts.swig.key(),
        SwigError::InvalidSeed(SWIG_ACCOUNT_NAME),
    )?;
    let authorized = role.actions.iter().find(|action| match action {
        Action::ManageAuthority => true,
        Action::All => true,
        _ => false,
    });
    if authorized.is_none() {
        return Err(SwigError::PermissionDenied("No permission to manage authority").into());
    };
    let actions = Vec::<Action>::try_from_slice(add_authority_v1.actions_payload).map_err(|e| {
        msg!("AddAuthorityV1 Actions Error: {:?}", e);
        ProgramError::InvalidInstructionData
    })?;
    let new_auth_data = add_authority_v1.authority_data;
    let existing_role = Swig::raw_lookup_role(swig_account_data, new_auth_data);
    if existing_role.is_some() {
        return Err(SwigError::InvalidAuthority.into());
    }
    let role = Role::new(
        add_authority_v1.args.authority_type,
        new_auth_data.to_vec(),
        add_authority_v1.args.start_slot,
        add_authority_v1.args.end_slot,
        actions,
    );
    let role_size = swig_account_data.len() + role.size();
    ctx.accounts.swig.realloc(role_size, false)?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let cost = Rent::get()?
        .minimum_balance(role_size)
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
    Swig::raw_add_role(swig_account_data, &role).map_err(|e| {
        msg!("AddAuthorityV1 Role Error: {:?}", e);
        SwigError::SerializationError
    })?;
    Ok(())
}
