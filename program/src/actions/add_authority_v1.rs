/// Module for adding new authorities to an existing Swig wallet.
/// This module implements the functionality to add additional authorities with
/// specific permissions and action sets to a wallet.
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use swig_assertions::{check_bytes_match, check_self_owned};
use swig_state::{
    action::{all::All, manage_authority::ManageAuthority},
    authority::{authority_type_to_length, AuthorityType},
    role::Position,
    swig::{Swig, SwigBuilder},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{AddAuthorityV1Accounts, Context},
        SwigInstruction,
    },
    util::validate_external_kill_switch,
};

/// Struct representing the complete add authority instruction data.
///
/// # Fields
/// * `args` - The add authority arguments
/// * `data_payload` - Raw data payload
/// * `authority_payload` - Authority-specific payload data
/// * `actions` - Actions data for the new authority
/// * `authority_data` - Raw authority data
pub struct AddAuthorityV1<'a> {
    pub args: &'a AddAuthorityV1Args,
    data_payload: &'a [u8],
    authority_payload: &'a [u8],
    actions: &'a [u8],
    authority_data: &'a [u8],
}

/// Arguments for adding a new authority to a Swig wallet.
///
/// # Fields
/// * `instruction` - The instruction type identifier
/// * `new_authority_data_len` - Length of the new authority's data
/// * `actions_data_len` - Length of the actions data
/// * `new_authority_type` - Type of the new authority
/// * `num_actions` - Number of actions for the new authority
/// * `_padding` - Padding bytes for alignment
/// * `acting_role_id` - ID of the role performing the addition
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct AddAuthorityV1Args {
    pub instruction: SwigInstruction,
    pub new_authority_data_len: u16,
    pub actions_data_len: u16,
    pub new_authority_type: u16,
    pub num_actions: u8,
    _padding: [u8; 3],
    pub acting_role_id: u32,
}

impl Transmutable for AddAuthorityV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl AddAuthorityV1Args {
    /// Creates a new instance of AddAuthorityV1Args.
    ///
    /// # Arguments
    /// * `acting_role_id` - ID of the role performing the addition
    /// * `authority_type` - Type of the new authority
    /// * `new_authority_data_len` - Length of the new authority's data
    /// * `actions_data_len` - Length of the actions data
    /// * `num_actions` - Number of actions for the new authority
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
            _padding: [0; 3],
        }
    }
}

impl IntoBytes for AddAuthorityV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> AddAuthorityV1<'a> {
    /// Parses the instruction data bytes into an AddAuthorityV1 instance.
    ///
    /// # Arguments
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < AddAuthorityV1Args::LEN {
            return Err(SwigError::InvalidSwigAddAuthorityInstructionDataTooShort.into());
        }

        let (inst, rest) = data.split_at(AddAuthorityV1Args::LEN);
        let args = unsafe { AddAuthorityV1Args::load_unchecked(inst)? };
        let (authority_data, rest) = rest.split_at(args.new_authority_data_len as usize);
        let (actions_payload, authority_payload) = rest.split_at(args.actions_data_len as usize);

        Ok(Self {
            args,
            authority_data,
            authority_payload,
            actions: actions_payload,
            data_payload: &data[..AddAuthorityV1Args::LEN
                + args.new_authority_data_len as usize
                + args.actions_data_len as usize],
        })
    }
}

/// Adds a new authority to an existing Swig wallet.
///
/// This function handles the complete flow of adding a new authority:
/// 1. Validates the acting role's permissions
/// 2. Authenticates the request
/// 3. Allocates space for the new authority
/// 4. Adds the authority with specified actions
///
/// # Arguments
/// * `ctx` - The account context for adding authority
/// * `add` - Raw add authority instruction data
/// * `all_accounts` - All accounts involved in the operation
///
/// # Returns
/// * `ProgramResult` - Success or error status
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
    // closure here to avoid borrowing swig_account_data for the whole function so
    // that we can mutate after realloc

    // Note: num_actions validation is now done internally in add_role
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let swig_data_len = swig_account_data.len();
    let new_authority_type = AuthorityType::try_from(add_authority_v1.args.new_authority_type)?;
    {
        if swig_account_data[0] != Discriminator::SwigConfigAccount as u8 {
            return Err(SwigError::InvalidSwigAccountDiscriminator.into());
        }
        let (swig_header, swig_roles) =
            unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
        let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
        let acting_role = Swig::get_mut_role(add_authority_v1.args.acting_role_id, swig_roles)?;
        if acting_role.is_none() {
            return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
        }
        let mut acting_role = acting_role.unwrap();

        // Validate external kill switch if present
        validate_external_kill_switch(&mut acting_role, all_accounts)?;

        // Authenticate the caller
        let clock = Clock::get()?;
        let slot = clock.slot;

        if acting_role.authority.session_based() {
            acting_role.authority.authenticate_session(
                all_accounts,
                add_authority_v1.authority_payload,
                add_authority_v1.data_payload,
                slot,
            )?;
        } else {
            acting_role.authority.authenticate(
                all_accounts,
                add_authority_v1.authority_payload,
                add_authority_v1.data_payload,
                slot,
            )?;
        }
        let all = acting_role.get_action::<All>(&[])?;
        let manage_authority = acting_role.get_action::<ManageAuthority>(&[])?;

        if all.is_none() && manage_authority.is_none() {
            return Err(SwigAuthenticateError::PermissionDeniedToManageAuthority.into());
        }
        let new_authority_length = authority_type_to_length(&new_authority_type)?;
        let role_size = Position::LEN + new_authority_length + add_authority_v1.actions.len();

        let account_size = core::alloc::Layout::from_size_align(
            swig_data_len + role_size,
            core::mem::size_of::<u64>(),
        )
        .map_err(|_| SwigError::InvalidAlignment)?
        .pad_to_align()
        .size();
        ctx.accounts.swig.realloc(account_size, false)?;

        // Get current account lamports after reallocation
        let current_lamports = ctx.accounts.swig.lamports();
        let required_lamports = Rent::get()?.minimum_balance(account_size);
        let cost = required_lamports
            .checked_sub(current_lamports)
            .unwrap_or_default();

        if cost > 0 {
            Transfer {
                from: ctx.accounts.payer,
                to: ctx.accounts.swig,
                lamports: cost,
            }
            .invoke()?;
        }
    };
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let mut swig_builder = SwigBuilder::new_from_bytes(swig_account_data)?;
    swig_builder.add_role(
        new_authority_type,
        add_authority_v1.authority_data,
        add_authority_v1.actions,
    )?;
    Ok(())
}
