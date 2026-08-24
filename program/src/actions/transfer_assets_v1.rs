/// Module for transferring assets from swig account to swig wallet address.
///
/// This module implements functionality to transfer all assets (SOL and SPL
/// tokens) held by the swig account to the swig wallet address account. This is
/// particularly useful after migration where assets need to be moved from the
/// old swig account to the new wallet address structure.
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    instruction::Signer,
    memory::sol_memcmp,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_assertions::{check_self_owned, check_self_pda};
use swig_state::{
    action::{all::All, manage_authority::ManageAuthority},
    authority::AuthorityType,
    role::RoleMut,
    swig::{swig_account_signer, swig_wallet_address_seeds_with_bump, Swig},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, TransferAssetsV1Accounts},
        SwigInstruction,
    },
    util::TokenTransfer,
    AccountClassification, SPL_TOKEN_2022_ID, SPL_TOKEN_ID,
};

const FIXED_ACCOUNT_COUNT: usize = 4;
const AUTHORITY_CONTEXT_ACCOUNT_COUNT: usize = 1;
const SPL_MIGRATION_ACCOUNT_COUNT: usize = 3;
const TOKEN_ACCOUNT_BASE_LEN: usize = 165;
const TOKEN_ACCOUNT_AMOUNT_START: usize = 64;
const TOKEN_ACCOUNT_AMOUNT_END: usize = 72;
const TOKEN_ACCOUNT_STATE_OFFSET: usize = 108;
const TOKEN_ACCOUNT_STATE_INITIALIZED: u8 = 1;

fn validate_spl_migration(
    source_token_account: &AccountInfo,
    destination_token_account: &AccountInfo,
    token_program: &AccountInfo,
    swig: &Pubkey,
    swig_wallet_address: &Pubkey,
) -> ProgramResult {
    if token_program.key() != &SPL_TOKEN_ID && token_program.key() != &SPL_TOKEN_2022_ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    if !source_token_account.is_writable() || !destination_token_account.is_writable() {
        return Err(SwigError::InvalidOperation.into());
    }
    if source_token_account.owner() != token_program.key()
        || destination_token_account.owner() != token_program.key()
    {
        return Err(SwigError::OwnerMismatchTokenAccount.into());
    }

    let source_data = source_token_account.try_borrow_data()?;
    let destination_data = destination_token_account.try_borrow_data()?;
    if source_data.len() < TOKEN_ACCOUNT_BASE_LEN
        || destination_data.len() < TOKEN_ACCOUNT_BASE_LEN
        || source_data[TOKEN_ACCOUNT_STATE_OFFSET] != TOKEN_ACCOUNT_STATE_INITIALIZED
        || destination_data[TOKEN_ACCOUNT_STATE_OFFSET] != TOKEN_ACCOUNT_STATE_INITIALIZED
    {
        return Err(ProgramError::InvalidAccountData);
    }
    if unsafe { sol_memcmp(&source_data[..32], &destination_data[..32], 32) } != 0 {
        return Err(SwigError::InvalidOperation.into());
    }
    if unsafe { sol_memcmp(&source_data[32..64], swig.as_ref(), 32) } != 0
        || unsafe { sol_memcmp(&destination_data[32..64], swig_wallet_address.as_ref(), 32) } != 0
    {
        return Err(SwigError::InvalidSwigTokenAccountOwner.into());
    }

    Ok(())
}

fn spl_tail_start(
    accounts: &[AccountInfo],
    authority_type: AuthorityType,
    session_based: bool,
    authority_payload: &[u8],
) -> Result<usize, ProgramError> {
    let authority_context_index = if session_based {
        authority_payload.first().copied()
    } else {
        match authority_type {
            AuthorityType::Ed25519 | AuthorityType::ProgramExec => {
                authority_payload.first().copied()
            },
            AuthorityType::Secp256r1 => authority_payload.get(12).copied(),
            AuthorityType::Secp256k1 => accounts
                .get(FIXED_ACCOUNT_COUNT)
                .filter(|account| account.key() == &crate::ID)
                .map(|_| FIXED_ACCOUNT_COUNT as u8),
            _ => return Err(SwigError::InvalidAuthorityType.into()),
        }
    }
    .map(usize::from);

    match authority_context_index {
        // A fixed account, such as the payer, may also authenticate the role.
        None | Some(0..=3) => Ok(FIXED_ACCOUNT_COUNT),
        // Public builders place a dedicated authority context directly after
        // the fixed prefix.
        Some(FIXED_ACCOUNT_COUNT) => Ok(FIXED_ACCOUNT_COUNT + AUTHORITY_CONTEXT_ACCOUNT_COUNT),
        // Reject gaps between the fixed prefix and variadic SPL triples.
        Some(_) => Err(SwigError::InvalidAccountsLength.into()),
    }
}

/// Arguments for transferring assets from swig account to swig wallet address.
///
/// # Fields
/// * `discriminator` - The instruction type identifier
/// * `_padding` - Padding bytes for alignment
/// * `role_id` - ID of the role performing the transfer (must have All or
///   ManageAuthority permissions)
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct TransferAssetsV1Args {
    discriminator: SwigInstruction,
    pub _padding: u16,
    pub role_id: u32,
}

impl TransferAssetsV1Args {
    /// Creates a new instance of TransferAssetsV1Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the role performing the transfer
    pub fn new(role_id: u32) -> Self {
        Self {
            discriminator: SwigInstruction::TransferAssetsV1,
            _padding: 0,
            role_id,
        }
    }
}

impl Transmutable for TransferAssetsV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for TransferAssetsV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Struct for parsing the TransferAssetsV1 instruction data
pub struct TransferAssetsV1<'a> {
    pub args: &'a TransferAssetsV1Args,
    pub authority_payload: &'a [u8],
}

impl<'a> TransferAssetsV1<'a> {
    /// Parses the instruction data bytes into a TransferAssetsV1 instance.
    ///
    /// # Arguments
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < TransferAssetsV1Args::LEN {
            return Err(SwigError::InvalidSwigSignInstructionDataTooShort.into());
        }

        // Split the data into args and authority payload
        let (args_data, authority_payload) = data.split_at(TransferAssetsV1Args::LEN);

        let args = unsafe { TransferAssetsV1Args::load_unchecked(args_data)? };

        Ok(Self {
            args,
            authority_payload,
        })
    }
}

/// Transfers all assets from swig account to swig wallet address.
///
/// This function:
/// 1. Validates that the swig account has been migrated (has wallet_bump)
/// 2. Authenticates the authority has All or ManageAuthority permissions
/// 3. Transfers all SOL from swig account to swig wallet address
/// 4. Transfers all SPL tokens from swig account to swig wallet address
///
/// # Arguments
/// * `ctx` - Account context containing swig, wallet address, payer accounts
/// * `accounts` - All accounts passed to the instruction (for token accounts)
/// * `data` - Raw instruction data
/// * `account_classification` - Classification of accounts for token operations
///
/// # Returns
/// * `ProgramResult` - Success or error status
pub fn transfer_assets_v1(
    ctx: Context<TransferAssetsV1Accounts>,
    accounts: &[AccountInfo],
    data: &[u8],
    account_classification: &[AccountClassification],
) -> ProgramResult {
    // Verify the swig account is owned by this program
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;

    let transfer_ix = TransferAssetsV1::from_instruction_bytes(data)?;

    // Load and validate swig account
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    // Verify the swig account has the correct discriminator
    if swig_account_data[0] != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }
    let parts = Swig::split_parts_mut(swig_account_data)?;
    let swig = parts.state;
    let swig_roles = parts.roles;

    // Ensure this is a migrated swig account (has wallet_bump)
    if swig.wallet_bump == 0 {
        return Err(SwigError::InvalidSwigCreateInstructionDataTooShort.into());
    }

    // Verify swig wallet address derivation using PDA check
    check_self_pda(
        &swig_wallet_address_seeds_with_bump(ctx.accounts.swig.key().as_ref(), &[swig.wallet_bump]),
        ctx.accounts.swig_wallet_address.key(),
        SwigError::InvalidSeedSwigAccount,
    )?;

    // Get the role and authenticate the authority
    let role_id = transfer_ix.args.role_id;
    let role_opt = Swig::get_mut_role(role_id, swig_roles)?;
    if role_opt.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let role = role_opt.unwrap();

    // Authenticate the authority
    let current_slot = Clock::get()?.slot;

    if role.authority.session_based() {
        role.authority.authenticate_session(
            accounts,
            transfer_ix.authority_payload,
            transfer_ix.args.into_bytes()?,
            current_slot,
        )?;
    } else {
        role.authority.authenticate(
            accounts,
            transfer_ix.authority_payload,
            transfer_ix.args.into_bytes()?,
            current_slot,
        )?;
    }

    // Check if the role has All or ManageAuthority permissions
    let has_all_permission = role.get_action::<All>(&[])?.is_some();
    let has_manage_authority = role.get_action::<ManageAuthority>(&[])?.is_some();
    if !has_all_permission && !has_manage_authority {
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    }

    // Derive the tail boundary from the authenticated authority context. The
    // context may reuse a fixed signer account or occupy account 4, while
    // direct Secp256k1 authentication has no context account.
    let spl_tail_start = spl_tail_start(
        accounts,
        role.authority.authority_type(),
        role.authority.session_based(),
        transfer_ix.authority_payload,
    )?;
    let spl_accounts = accounts
        .get(spl_tail_start..)
        .ok_or(SwigError::InvalidAccountsLength)?;

    // Validate the complete variadic layout before sweeping SOL. Returning an
    // error here prevents a successful partial migration and keeps the whole
    // instruction atomic.
    if spl_accounts.len() % SPL_MIGRATION_ACCOUNT_COUNT != 0 {
        return Err(SwigError::InvalidAccountsLength.into());
    }
    for migration_accounts in spl_accounts.chunks_exact(SPL_MIGRATION_ACCOUNT_COUNT) {
        validate_spl_migration(
            &migration_accounts[0],
            &migration_accounts[1],
            &migration_accounts[2],
            ctx.accounts.swig.key(),
            ctx.accounts.swig_wallet_address.key(),
        )?;
    }

    // Create signer seeds for the swig account.
    //
    // The swig state PDA was derived with seeds [b"swig", swig.id, bump], so to
    // sign as it via CPI we must reuse `swig.id` (the random 32-byte id stored
    // in the account struct) — NOT the PDA's pubkey. Matches the convention in
    // create_v1.rs:220 and close_token_account_v1.rs:197.
    let bump = [swig.bump];
    let swig_id = swig.id;
    let swig_signer = swig_account_signer(&swig_id, &bump);

    // Transfer SOL from swig to swig wallet address
    let swig_lamports = ctx.accounts.swig.lamports();
    let rent = pinocchio::sysvars::rent::Rent::get()?;
    let swig_data_len = ctx.accounts.swig.data_len();
    let min_rent = rent.minimum_balance(swig_data_len);

    if swig_lamports > min_rent {
        let transfer_amount = swig_lamports - min_rent;
        // Transfer SOL by directly manipulating lamports
        unsafe {
            *ctx.accounts.swig.borrow_mut_lamports_unchecked() -= transfer_amount;
            *ctx.accounts
                .swig_wallet_address
                .borrow_mut_lamports_unchecked() += transfer_amount;
        }
    }

    // Transfer SPL tokens from the validated variadic account tail.
    for migration_accounts in spl_accounts.chunks_exact(SPL_MIGRATION_ACCOUNT_COUNT) {
        let source_token_account = &migration_accounts[0];
        let dest_token_account = &migration_accounts[1];
        let token_program = &migration_accounts[2];

        // The complete tail was validated before any mutation. Re-read each
        // source amount immediately before its CPI so duplicate source entries
        // cannot transfer a stale balance.
        let source_data = unsafe { source_token_account.borrow_data_unchecked() };
        let amount_bytes = &source_data[TOKEN_ACCOUNT_AMOUNT_START..TOKEN_ACCOUNT_AMOUNT_END];
        let amount = u64::from_le_bytes(amount_bytes.try_into().unwrap());

        // A valid zero-balance account is the only migration entry that may be
        // skipped. Malformed entries always failed during preflight above.
        if amount == 0 {
            continue;
        }

        let token_transfer = TokenTransfer {
            token_program: token_program.key(),
            from: source_token_account,
            to: dest_token_account,
            authority: ctx.accounts.swig,
            amount,
        };
        token_transfer.invoke_signed(&[(&swig_signer).into()])?;
    }

    Ok(())
}
