use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use swig_assertions::{check_bytes_match, check_self_owned};
use swig_state_x::{
    action::{all::All, manage_authority::ManageAuthority, Action},
    authority::{Authority, AuthorityLoader, AuthorityType},
    role::Position,
    swig::{SwigBuilder, SwigWithRoles},
    Discriminator, IntoBytes, Transmutable,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{AddAuthorityV1Accounts, Context},
        SwigInstruction,
    },
};

pub struct AddAuthorityV1<'a> {
    pub args: &'a AddAuthorityV1Args,
    data_payload: &'a [u8],
    authority_payload: &'a [u8],
    actions: &'a [u8],
    authority_data: &'a [u8],
}

static_assertions::const_assert!(core::mem::size_of::<AddAuthorityV1Args>() % 8 == 0);
#[repr(C)]
pub struct AddAuthorityV1Args {
    pub instruction: SwigInstruction,
    pub acting_role_id: u32,
    pub new_authority_data_len: u16,
    pub actions_data_len: u16,
    pub new_authority_type: u16,
    pub num_actions: u8,
}

impl Transmutable for AddAuthorityV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl AddAuthorityV1Args {
    pub fn new(
        acting_role_id: u32,
        authority_type: AuthorityType,
        new_authority_data_len: u16,
        actions_data_len: u16,
        num_actions: u8,
    ) -> Self {
        Self {
            instruction: SwigInstruction::AddAuthorityV1,
            acting_role_id,
            new_authority_type: authority_type as u16,
            new_authority_data_len,
            actions_data_len,
            num_actions,
        }
    }
}

impl AddAuthorityV1Args {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl<'a> IntoBytes<'a> for AddAuthorityV1Args {
    fn into_bytes(&'a self) -> Result<&'a [u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> AddAuthorityV1<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        let (inst, rest) = data.split_at(AddAuthorityV1Args::SIZE);
        let args = unsafe { AddAuthorityV1Args::load_unchecked(inst)? };

        let (authority_data, rest) = rest.split_at(args.new_authority_data_len as usize);
        let (actions_payload, authority_payload) = rest.split_at(args.actions_data_len as usize);

        Ok(Self {
            args,
            authority_data,
            authority_payload,
            actions: actions_payload,
            data_payload: &data[AddAuthorityV1Args::SIZE
                ..AddAuthorityV1Args::SIZE
                    + (args.new_authority_data_len + args.actions_data_len) as usize],
        })
    }

    pub fn get_authority(&'a self) -> Result<&impl Authority<'a>, ProgramError> {
        let authority_type = AuthorityType::try_from(self.args.new_authority_type)?;
        AuthorityLoader::load_authority(authority_type, self.authority_data)
    }
}

pub fn add_authority_v1(
    ctx: Context<AddAuthorityV1Accounts>,
    add: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_bytes_match(
        ctx.accounts.system_program.key(),
        &pinocchio_system::ID,
        32,
        SwigError::InvalidSystemProgram,
    )?;
    let add_authority_v1 = AddAuthorityV1::from_instruction_bytes(add).map_err(|e| {
        msg!("AddAuthorityV1 Args Error: {:?}", e);
        ProgramError::InvalidInstructionData
    })?;
    // closure here to avoid borrowing swig_account_data for the whole function so that we can mutate after realloc

    if add_authority_v1.args.num_actions == 0 {
        return Err(SwigError::InvalidAuthorityMustHaveAtLeastOneAction.into());
    }
    let new_reserved_lamports = {
        let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
        if swig_account_data[0] != Discriminator::SwigAccount as u8 {
            return Err(SwigError::InvalidSwigAccountDiscriminator.into());
        }
        let swig = SwigWithRoles::from_bytes(swig_account_data)?;
        let role = swig.get_role(add_authority_v1.args.acting_role_id)?;

        if role.is_none() {
            return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
        }
        let role = role.unwrap();
        let clock = Clock::get()?;
        let slot = clock.slot;
        if role.authority.session_based() {
            role.authority.authenticate_session(
                all_accounts,
                add_authority_v1.authority_payload,
                add_authority_v1.data_payload,
                slot,
            )?;
        } else {
            role.authority.authenticate(
                all_accounts,
                add_authority_v1.authority_payload,
                add_authority_v1.data_payload,
                slot,
            )?;
        }

        let all = role.get_action::<All>(&[])?;
        let manage_authority = role.get_action::<ManageAuthority>(&[])?;

        if all.is_none() && manage_authority.is_none() {
            return Err(SwigError::PermissionDeniedToManageAuthority.into());
        }
        let new_authority = add_authority_v1.get_authority()?;
        let role_size = Position::LEN
            + new_authority.length()
            + Action::LEN * add_authority_v1.args.num_actions as usize
            + add_authority_v1.actions.len();

        let account_size = core::alloc::Layout::from_size_align(
            swig_account_data.len() + role_size,
            core::mem::size_of::<u64>(),
        )
        .map_err(|_| SwigError::InvalidAlignment)?
        .pad_to_align()
        .size();
        ctx.accounts.swig.realloc(account_size, false)?;
        let cost = Rent::get()?
            .minimum_balance(account_size)
            .checked_sub(swig.state.reserved_lamports)
            .unwrap_or_default();
        if cost > 0 {
            Transfer {
                from: ctx.accounts.payer,
                to: ctx.accounts.swig,
                lamports: cost,
            }
            .invoke()?;
        }
        swig.state.reserved_lamports + cost
    };
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let authority = add_authority_v1.get_authority()?;
    let mut swig_builder = SwigBuilder::new_from_bytes(swig_account_data)?;
    swig_builder.swig.reserved_lamports = new_reserved_lamports;
    swig_builder.add_role(
        authority,
        add_authority_v1.args.num_actions,
        add_authority_v1.actions,
    )?;
    Ok(())
}
