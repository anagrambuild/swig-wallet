/// Module for handling token transfers with destination-specific limits.
/// This module implements the logic for transferring tokens with both general
/// and destination-specific limits applied.
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_state::{
    action::{
        token_destination_limit::TokenDestinationLimit, token_limit::TokenLimit,
        token_recurring_limit::TokenRecurringLimit,
    },
    authority::AuthorityType,
    role::RoleMut,
    swig::{swig_account_signer, Swig},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, SignV1Accounts},
        SwigInstruction,
    },
    util::TokenTransfer,
};

/// Arguments for transferring tokens with destination limits.
///
/// # Fields
/// * `instruction` - The instruction type identifier
/// * `role_id` - ID of the role attempting the transfer
/// * `token_mint` - The token mint pubkey
/// * `destination` - The destination token account pubkey
/// * `amount` - Amount of tokens to transfer
#[derive(Debug)]
#[repr(C, align(8))]
pub struct TokenDestinationLimitV1Args {
    instruction: SwigInstruction,
    pub role_id: u32,
    pub token_mint: Pubkey,
    pub destination: Pubkey,
    pub amount: u64,
}

impl TokenDestinationLimitV1Args {
    /// Creates a new instance of TokenDestinationLimitV1Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the signing role
    /// * `token_mint` - The token mint pubkey
    /// * `destination` - The destination token account pubkey
    /// * `amount` - Amount of tokens to transfer
    pub fn new(role_id: u32, token_mint: Pubkey, destination: Pubkey, amount: u64) -> Self {
        Self {
            instruction: SwigInstruction::TokenDestinationLimitV1,
            role_id,
            token_mint,
            destination,
            amount,
        }
    }
}

impl Transmutable for TokenDestinationLimitV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for TokenDestinationLimitV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Struct representing the complete token destination limit transfer instruction
/// data.
///
/// # Fields
/// * `args` - The transfer arguments
/// * `authority_payload` - Authority-specific payload data
pub struct TokenDestinationLimitV1<'a> {
    pub args: &'a TokenDestinationLimitV1Args,
    authority_payload: &'a [u8],
}

impl<'a> TokenDestinationLimitV1<'a> {
    /// Parses the instruction data bytes into a TokenDestinationLimitV1 instance.
    ///
    /// # Arguments
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < TokenDestinationLimitV1Args::LEN {
            return Err(SwigError::InvalidSwigSignInstructionDataTooShort.into());
        }
        let (inst, authority_payload) =
            unsafe { data.split_at_unchecked(TokenDestinationLimitV1Args::LEN) };
        let args = unsafe { TokenDestinationLimitV1Args::load_unchecked(inst)? };

        Ok(Self {
            args,
            authority_payload,
        })
    }
}

/// Transfers tokens with destination-specific limits applied.
///
/// This function handles token transfers with both general token limits and
/// destination-specific limits. It ensures that:
/// 1. The authority is valid and authenticated
/// 2. General token limits are respected (if they exist)
/// 3. Destination-specific limits are respected (if they exist)
/// 4. The transfer is executed via CPI to the SPL Token program
///
/// # Arguments
/// * `ctx` - The account context for the transfer
/// * `all_accounts` - All accounts involved in the transaction
/// * `data` - Raw transfer instruction data
///
/// # Returns
/// * `ProgramResult` - Success or error status
#[inline(always)]
pub fn token_destination_limit_v1(
    ctx: Context<SignV1Accounts>,
    all_accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let transfer_instruction = TokenDestinationLimitV1::from_instruction_bytes(data)?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };

    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
    let role = Swig::get_mut_role(transfer_instruction.args.role_id, swig_roles)?;

    if role.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let role = role.unwrap();

    let clock = Clock::get()?;
    let slot = clock.slot;

    // Authenticate the authority
    if role.authority.session_based() {
        role.authority.authenticate_session(
            all_accounts,
            transfer_instruction.authority_payload,
            &[], // No instruction payload for simple transfers
            slot,
        )?;
    } else {
        role.authority.authenticate(
            all_accounts,
            transfer_instruction.authority_payload,
            &[], // No instruction payload for simple transfers
            slot,
        )?;
    }

    let amount = transfer_instruction.args.amount;
    let token_mint = transfer_instruction.args.token_mint.as_ref();
    let destination_pubkey = transfer_instruction.args.destination.as_ref();
    let actions = role.actions;

    // Create the data key for destination-specific limit lookup
    let mut limit_data = [0u8; 64];
    limit_data[0..32].copy_from_slice(token_mint);
    limit_data[32..64].copy_from_slice(destination_pubkey);

    // Check destination-specific limit first
    let mut destination_limit_checked = false;
    if let Some(dest_action) =
        RoleMut::get_action_mut::<TokenDestinationLimit>(actions, &limit_data)?
    {
        dest_action.run(amount)?;
        destination_limit_checked = true;
    }

    // Check general token limits (these should be combined with destination limits)
    let mut general_limit_checked = false;
    if let Some(action) = RoleMut::get_action_mut::<TokenLimit>(actions, token_mint)? {
        action.run(amount)?;
        general_limit_checked = true;
    } else if let Some(action) =
        RoleMut::get_action_mut::<TokenRecurringLimit>(actions, token_mint)?
    {
        action.run(amount, slot)?;
        general_limit_checked = true;
    }

    // At least one limit must be present (either destination-specific or general)
    if !destination_limit_checked && !general_limit_checked {
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    }

    // Find the required accounts for the token transfer
    // Note: The accounts are passed in the order defined in the instruction enum
    // [swig, payer, source, destination, mint, token_program]
    if all_accounts.len() < 6 {
        return Err(SwigError::InvalidAccountsLength.into());
    }

    let source_account = &all_accounts[2]; // source token account
    let destination_account = &all_accounts[3]; // destination token account
    let mint_account = &all_accounts[4]; // mint account
    let token_program = &all_accounts[5]; // token program

    // Verify that the source account is owned by the token program
    if unsafe { source_account.owner() } != &crate::SPL_TOKEN_ID
        && unsafe { source_account.owner() } != &crate::SPL_TOKEN_2022_ID
    {
        return Err(SwigError::InvalidAccountsLength.into());
    }

    // Verify that the destination account is owned by the token program
    if unsafe { destination_account.owner() } != &crate::SPL_TOKEN_ID
        && unsafe { destination_account.owner() } != &crate::SPL_TOKEN_2022_ID
    {
        return Err(SwigError::InvalidAccountsLength.into());
    }

    // Verify that the mint account is owned by the token program
    if unsafe { mint_account.owner() } != &crate::SPL_TOKEN_ID
        && unsafe { mint_account.owner() } != &crate::SPL_TOKEN_2022_ID
    {
        return Err(SwigError::InvalidAccountsLength.into());
    }

    // Verify that the token program is the SPL Token program
    if token_program.key() != &crate::SPL_TOKEN_ID
        && token_program.key() != &crate::SPL_TOKEN_2022_ID
    {
        return Err(SwigError::InvalidAccountsLength.into());
    }

    // Perform the token transfer using the TokenTransfer utility
    let token_transfer = TokenTransfer {
        token_program: token_program.key(),
        from: source_account,
        to: destination_account,
        authority: ctx.accounts.swig,
        amount,
    };

    // Execute the token transfer with the Swig account as signer
    token_transfer.invoke_signed(&[swig_account_signer(&swig.id, &[swig.bump])
        .as_slice()
        .into()])?;

    Ok(())
}
