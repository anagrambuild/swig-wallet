/// Module for handling transaction signing through sub-accounts in a Swig
/// wallet. This module implements functionality to authenticate and execute
/// transactions using sub-account authorities, with proper validation and
/// permission checks.
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_assertions::*;
use swig_compact_instructions::InstructionIterator;
use swig_state::{
    action::{all::All, sub_account::SubAccount, ActionLoader, Actionable},
    role::RoleMut,
    swig::{sub_account_signer, Swig},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, SubAccountSignV1Accounts},
        SwigInstruction,
    },
    util::build_restricted_keys,
    AccountClassification,
};

/// Arguments for signing a transaction with a sub-account.
///
/// # Fields
/// * `instruction` - The instruction type identifier
/// * `instruction_payload_len` - Length of the instruction payload
/// * `role_id` - ID of the role attempting to sign
/// * `_padding` - Padding bytes for alignment
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct SubAccountSignV1Args {
    instruction: SwigInstruction,
    pub instruction_payload_len: u16,
    pub role_id: u32,
    _padding: [u8; 8],
}

impl SubAccountSignV1Args {
    /// Creates a new instance of SubAccountSignV1Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the role attempting to sign
    /// * `instruction_payload_len` - Length of the instruction payload
    pub fn new(role_id: u32, instruction_payload_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::SubAccountSignV1,
            instruction_payload_len,
            role_id,
            _padding: [0; 8],
        }
    }
}

impl Transmutable for SubAccountSignV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for SubAccountSignV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Struct representing the complete sub-account sign instruction data.
///
/// # Fields
/// * `args` - The signing arguments
/// * `authority_payload` - Authority-specific payload data
/// * `instruction_payload` - Transaction instruction data
pub struct SubAccountSignV1<'a> {
    pub args: &'a SubAccountSignV1Args,
    authority_payload: &'a [u8],
    instruction_payload: &'a [u8],
}

impl<'a> SubAccountSignV1<'a> {
    /// Parses the instruction data bytes into a SubAccountSignV1 instance.
    ///
    /// # Arguments
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < SubAccountSignV1Args::LEN {
            return Err(SwigError::InvalidSwigSignInstructionDataTooShort.into());
        }
        let (inst, rest) = unsafe { data.split_at_unchecked(SubAccountSignV1Args::LEN) };
        let args = unsafe { SubAccountSignV1Args::load_unchecked(inst)? };
        let (instruction_payload, authority_payload) =
            unsafe { rest.split_at_unchecked(args.instruction_payload_len as usize) };
        Ok(Self {
            args,
            authority_payload,
            instruction_payload,
        })
    }
}

/// Signs and executes a transaction using a sub-account authority.
///
/// This function handles the complete flow of sub-account transaction signing:
/// 1. Validates the sub-account and parent wallet relationship
/// 2. Verifies the sub-account is enabled
/// 3. Authenticates the authority
/// 4. Executes the transaction instructions
/// 5. Ensures sufficient balance is maintained
///
/// # Arguments
/// * `ctx` - The account context for signing
/// * `all_accounts` - All accounts involved in the transaction
/// * `data` - Raw signing instruction data
/// * `account_classifiers` - Classifications for involved accounts
///
/// # Returns
/// * `ProgramResult` - Success or error status
#[inline(always)]
pub fn sub_account_sign_v1(
    ctx: Context<SubAccountSignV1Accounts>,
    all_accounts: &[AccountInfo],
    data: &[u8],
    account_classifiers: &[AccountClassification],
) -> ProgramResult {
    check_stack_height(1, SwigError::Cpi)?;
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSubAccount)?;
    check_system_owner(ctx.accounts.sub_account, SwigError::OwnerMismatchSubAccount)?;
    let sign_v1 = SubAccountSignV1::from_instruction_bytes(data)?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_unchecked(swig_header)? };

    let role_opt = Swig::get_mut_role(sign_v1.args.role_id, swig_roles)?;
    if role_opt.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }

    let role = role_opt.unwrap();

    // Store authority info before authentication (to avoid borrow checker issues)
    let is_session_based = role.authority.session_based();

    let clock = Clock::get()?;
    let slot = clock.slot;

    if is_session_based {
        role.authority.authenticate_session(
            all_accounts,
            sign_v1.authority_payload,
            sign_v1.instruction_payload,
            slot,
        )?;
    } else {
        role.authority.authenticate(
            all_accounts,
            sign_v1.authority_payload,
            sign_v1.instruction_payload,
            slot,
        )?;
    }

    // Find the SubAccount action to get sub-account metadata (after authentication)
    let sub_account_action =
        role.get_action::<SubAccount>(ctx.accounts.sub_account.key().as_ref())?;
    if sub_account_action.is_none() {
        return Err(SwigError::InvalidSwigSubAccountSwigIdMismatch.into());
    }
    let sub_account = sub_account_action.unwrap();

    // Validate sub-account relationship
    if sub_account.swig_id != swig.id {
        return Err(SwigError::InvalidSwigSubAccountSwigIdMismatch.into());
    }
    if sub_account.role_id != sign_v1.args.role_id {
        return Err(SwigError::InvalidSwigSubAccountRoleIdMismatch.into());
    }
    if !sub_account.enabled {
        // All/Manageauthority authorities can disable the sub account which means
        // current auth can't sign
        return Err(SwigError::InvalidSwigSubAccountDisabled.into());
    }

    // Store sub_account info for later use
    let sub_account_bump = sub_account.bump;
    let sub_account_role_id = sub_account.role_id;
    let sub_account_swig_id = sub_account.swig_id;
    let sub_account_index = sub_account.sub_account_index;
    let rkeys: &[&Pubkey] = &[];
    let ix_iter = InstructionIterator::new(
        all_accounts,
        sign_v1.instruction_payload,
        ctx.accounts.sub_account.key(),
        rkeys,
    )?;
    let role_id_bytes = sub_account_role_id.to_le_bytes();
    let bump_byte = [sub_account_bump];

    // Derive signer seeds and execute instructions based on index
    // Index 0 uses legacy 4-seed derivation for backwards compatibility
    // Index 1+ uses new 5-seed derivation with index
    if sub_account_index == 0 {
        let seeds = sub_account_signer(&sub_account_swig_id, &role_id_bytes, &bump_byte);
        let signer = seeds.as_slice();
        for ix in ix_iter {
            if let Ok(instruction) = ix {
                instruction.execute(
                    all_accounts,
                    ctx.accounts.sub_account.key(),
                    &[signer.into()],
                )?;

                // Check after each instruction that we haven't dropped below
                // reserved lamports
            } else {
                return Err(SwigError::InstructionExecutionError.into());
            }
        }
    } else {
        use swig_state::swig::sub_account_signer_with_index;
        let index_bytes = [sub_account_index];
        let seeds = sub_account_signer_with_index(
            &sub_account_swig_id,
            &role_id_bytes,
            &index_bytes,
            &bump_byte,
        );
        let signer = seeds.as_slice();
        for ix in ix_iter {
            if let Ok(instruction) = ix {
                instruction.execute(
                    all_accounts,
                    ctx.accounts.sub_account.key(),
                    &[signer.into()],
                )?;

                // Check after each instruction that we haven't dropped below
                // reserved lamports
            } else {
                return Err(SwigError::InstructionExecutionError.into());
            }
        }
    }

    // Check that the sub-account maintains sufficient lamports for rent exemption
    // Ensure the account has some minimum balance for rent exemption
    let account_data = unsafe { ctx.accounts.sub_account.borrow_data_unchecked() };
    let rent_exempt_minimum =
        pinocchio::sysvars::rent::Rent::get()?.minimum_balance(account_data.len());
    let current_lamports = unsafe { *ctx.accounts.sub_account.borrow_lamports_unchecked() };
    if current_lamports < rent_exempt_minimum {
        return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
    }
    Ok(())
}
