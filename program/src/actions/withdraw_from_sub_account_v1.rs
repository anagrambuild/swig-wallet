/// Module for withdrawing funds from sub-accounts to their parent Swig wallet.
/// This module implements functionality to transfer both SOL and SPL tokens
/// from sub-accounts back to their parent wallet, with proper authentication
/// and permission checks.
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    memory::sol_memcmp,
    msg,
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_assertions::*;
use swig_state::{
    action::{all::All, manage_authority::ManageAuthority, sub_account::SubAccount},
    authority::AuthorityType,
    swig::{
        sub_account_signer, sub_account_signer_with_index, swig_wallet_address_seeds, Swig,
        SwigWithRoles,
    },
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, WithdrawFromSubAccountV1Accounts},
        SwigInstruction,
    },
    util::TokenTransfer,
    AccountClassification, SPL_TOKEN_2022_ID, SPL_TOKEN_ID,
};

/// Arguments for withdrawing funds from a sub-account.
///
/// # Fields
/// * `discriminator` - The instruction type identifier
/// * `_padding` - Padding bytes for alignment
/// * `role_id` - ID of the role performing the withdrawal
/// * `amount` - Amount of tokens/SOL to withdraw
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct WithdrawFromSubAccountV1Args {
    discriminator: SwigInstruction,
    _padding: u16,
    pub role_id: u32,
    pub amount: u64,
}

impl WithdrawFromSubAccountV1Args {
    /// Creates a new instance of WithdrawFromSubAccountV1Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the role performing the withdrawal
    /// * `amount` - Amount of tokens/SOL to withdraw
    pub fn new(role_id: u32, amount: u64) -> Self {
        Self {
            discriminator: SwigInstruction::WithdrawFromSubAccountV1,
            _padding: 0,
            role_id,
            amount,
        }
    }
}

impl Transmutable for WithdrawFromSubAccountV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for WithdrawFromSubAccountV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Struct for parsing the WithdrawFromSubAccountV1 instruction data
pub struct WithdrawFromSubAccountV1<'a> {
    pub args: &'a WithdrawFromSubAccountV1Args,
    pub authority_payload: &'a [u8],
    pub data_payload: &'a [u8],
}

impl<'a> WithdrawFromSubAccountV1<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < WithdrawFromSubAccountV1Args::LEN {
            return Err(SwigError::InvalidSwigSignInstructionDataTooShort.into());
        }

        // Split the data into args and the rest (authority payload)
        let (args_data, authority_payload) = data.split_at(WithdrawFromSubAccountV1Args::LEN);

        let args = unsafe { WithdrawFromSubAccountV1Args::load_unchecked(args_data)? };

        Ok(Self {
            args,
            authority_payload,
            data_payload: args_data,
        })
    }
}

/// Implementation of the WithdrawFromSubAccountV1 instruction handler
#[inline(always)]
pub fn withdraw_from_sub_account_v1(
    ctx: Context<WithdrawFromSubAccountV1Accounts>,
    all_accounts: &[AccountInfo],
    data: &[u8],
    account_classifiers: &[AccountClassification],
) -> ProgramResult {
    // Verify that the swig account is owned by our program and sub_account is
    // system owned
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_system_owner(ctx.accounts.sub_account, SwigError::OwnerMismatchSubAccount)?;
    check_system_owner(
        ctx.accounts.swig_wallet_address,
        SwigError::OwnerMismatchSwigAccount,
    )?;
    let withdraw = WithdrawFromSubAccountV1::from_instruction_bytes(data)?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_unchecked(&swig_header)? };

    let swig_wallet_address_seeds = swig_wallet_address_seeds(ctx.accounts.swig.key().as_ref());
    // Validate that the swig wallet address is the correct PDA derived from the
    // swig account
    let (expected_swig_wallet_address, _swig_wallet_bump) =
        pinocchio::pubkey::find_program_address(&swig_wallet_address_seeds, &crate::ID);
    if expected_swig_wallet_address != *ctx.accounts.swig_wallet_address.key() {
        msg!("Invalid swig wallet address PDA for sub account");
        return Err(SwigError::InvalidSwigSubAccountSwigIdMismatch.into());
    }

    // Verify the swig account has the correct discriminator
    if unsafe { *swig_header.get_unchecked(0) } != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }
    // We'll get sub-account metadata from the SubAccount action later after
    // authentication
    let role_opt = Swig::get_mut_role(withdraw.args.role_id, swig_roles)?;
    if role_opt.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let role = role_opt.unwrap();

    // Authenticate the authority
    let clock = Clock::get()?;
    let slot = clock.slot;

    // Authenticate based on authority type (session-based or not)
    if role.authority.session_based() {
        role.authority.authenticate_session(
            all_accounts,
            withdraw.authority_payload,
            withdraw.data_payload,
            slot,
        )?;
    } else {
        role.authority.authenticate(
            all_accounts,
            withdraw.authority_payload,
            withdraw.data_payload,
            slot,
        )?;
    }
    // Check if the role has the required permissions
    let all_action = role.get_action::<All>(&[])?;
    let manage_authority_action = role.get_action::<ManageAuthority>(&[])?;
    let sub_account_action =
        role.get_action::<SubAccount>(ctx.accounts.sub_account.key().as_ref())?;

    if all_action.is_none() && manage_authority_action.is_none() && sub_account_action.is_none() {
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    }

    // Validate permissions and get sub-account metadata
    // Permission logic:
    // 1. SubAccount permission: Use action from current role, must be enabled
    // 2. All/ManageAuthority: Search all roles to find the SubAccount action, can
    //    withdraw even if sub-account is disabled (authority override)

    let has_authority_override = all_action.is_some() || manage_authority_action.is_some();

    let sub_account_metadata = if let Some(action) = sub_account_action {
        // Found SubAccount action matching this sub-account address on current role
        // Validate sub-account relationship
        if action.swig_id != swig.id {
            return Err(SwigError::InvalidSwigSubAccountSwigIdMismatch.into());
        }

        // Only check enabled if we don't have authority override
        // Authority holders (All/ManageAuthority) can withdraw even from disabled
        // sub-accounts
        if !has_authority_override && !action.enabled {
            return Err(SwigError::InvalidSwigSubAccountDisabled.into());
        }
        Some((action.role_id, action.bump, action.sub_account_index))
    } else if has_authority_override {
        // All/ManageAuthority permission: Search all roles to find the SubAccount
        // action for this sub-account address (since it might be on a different
        // role)
        let swig_account_data_immutable = unsafe { ctx.accounts.swig.borrow_data_unchecked() };
        let swig_with_roles = SwigWithRoles::from_bytes(swig_account_data_immutable)?;

        // Search through all roles to find a SubAccount action matching this
        // sub-account Uses 32-byte match format (sub_account pubkey) via
        // get_action
        let sub_account_key = ctx.accounts.sub_account.key();
        let mut found_action: Option<(u32, u8, u8)> = None;

        for role_id in 0..swig.role_counter {
            if let Some(search_role) = swig_with_roles.get_role(role_id)? {
                // Use get_action with 32-byte match format (sub_account pubkey)
                if let Some(action_obj) =
                    search_role.get_action::<SubAccount>(sub_account_key.as_ref())?
                {
                    // Verify swig_id matches
                    if action_obj.swig_id == swig.id {
                        // Authority override can withdraw even from disabled sub-accounts
                        found_action = Some((
                            action_obj.role_id,
                            action_obj.bump,
                            action_obj.sub_account_index,
                        ));
                        break;
                    }
                }
            }
        }

        if found_action.is_none() {
            return Err(SwigError::SubAccountActionNotFound.into());
        }

        found_action
    } else {
        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
    };

    let (action_accounts_index, action_accounts_len) =
        if role.position.authority_type()? == AuthorityType::Secp256k1 {
            (3, 6)
        } else {
            (4, 7)
        };
    let amount = withdraw.args.amount;

    // Extract signing parameters from the metadata we found above
    // All paths now have the metadata (or we've already returned with an error)
    let (signing_role_id, signing_bump, signing_index) =
        sub_account_metadata.expect("sub_account_metadata should be Some at this point");

    if all_accounts.len() >= action_accounts_len {
        let token_account = &all_accounts[action_accounts_index + 2];
        let token_account_data = unsafe { token_account.borrow_data_unchecked() };
        // we dont need to check the owner of the token account because the token
        // program will check it in transfer

        let swig_token_account = &all_accounts[action_accounts_index + 3];
        let swig_token_account_data = unsafe { swig_token_account.borrow_data_unchecked() };
        let swig_token_account_owner = unsafe { swig_token_account_data.get_unchecked(32..64) };
        if unsafe {
            sol_memcmp(
                ctx.accounts.swig_wallet_address.key(),
                swig_token_account_owner,
                32,
            )
        } != 0
        {
            return Err(SwigError::InvalidSwigTokenAccountOwner.into());
        }

        let token_program = &all_accounts[action_accounts_index + 4];
        let token_account_program_owner = token_account.owner();
        let destination_program_owner = swig_token_account.owner();
        if token_account_program_owner != &SPL_TOKEN_ID
            && token_account_program_owner != &SPL_TOKEN_2022_ID
        {
            return Err(SwigError::OwnerMismatchTokenAccount.into());
        }
        if destination_program_owner != token_account_program_owner {
            return Err(SwigError::InvalidOperation.into());
        }
        let token_transfer = TokenTransfer {
            from: token_account,
            to: swig_token_account,
            authority: ctx.accounts.sub_account,
            amount,
            token_program: token_account_program_owner,
        };

        let role_id_bytes = signing_role_id.to_le_bytes();
        let bump_byte = [signing_bump];

        // Use correct signer seeds based on index
        // Index 0 uses legacy 4-seed derivation for backwards compatibility
        // Index 1+ uses new 5-seed derivation with index
        if signing_index == 0 {
            let seeds = sub_account_signer(&swig.id, &role_id_bytes, &bump_byte);
            let signer = seeds.as_slice();
            // Invoke the token transfer with the PDA signer
            token_transfer.invoke_signed(&[signer.into()])?;
        } else {
            let index_bytes = [signing_index];
            let seeds =
                sub_account_signer_with_index(&swig.id, &role_id_bytes, &index_bytes, &bump_byte);
            let signer = seeds.as_slice();
            // Invoke the token transfer with the PDA signer
            token_transfer.invoke_signed(&[signer.into()])?;
        }
    } else {
        // SOL transfer from system-owned sub-account to swig account
        if amount > ctx.accounts.sub_account.lamports() {
            return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
        }

        // Use the signing parameters we already discovered above
        // Create system transfer instruction using PDA as signer
        let role_id_bytes = signing_role_id.to_le_bytes();
        let bump_byte = [signing_bump];

        // Use correct signer seeds based on index
        // Index 0 uses legacy 4-seed derivation for backwards compatibility
        // Index 1+ uses new 5-seed derivation with index
        let transfer_instruction = pinocchio_system::instructions::Transfer {
            from: ctx.accounts.sub_account,
            to: ctx.accounts.swig_wallet_address,
            lamports: amount,
        };

        if signing_index == 0 {
            let seeds = sub_account_signer(&swig.id, &role_id_bytes, &bump_byte);
            let signer = seeds.as_slice();
            transfer_instruction.invoke_signed(&[signer.into()])?;
        } else {
            let index_bytes = [signing_index];
            let seeds =
                sub_account_signer_with_index(&swig.id, &role_id_bytes, &index_bytes, &bump_byte);
            let signer = seeds.as_slice();
            transfer_instruction.invoke_signed(&[signer.into()])?;
        }
    }
    Ok(())
}
