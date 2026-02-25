//! SIWS challenge validation for off-chain signature proofs.
//!
//! This instruction is intended to be simulated off-chain (never broadcast).
//! It authenticates a Swig role authority against a SIWS challenge payload and
//! verifies that the role satisfies all requested `urn:swig:v1:scope:*`
//! resources.

use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::find_program_address,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_assertions::{check_self_owned, check_stack_height, check_system_owner};
use swig_state::{
    action::{Action, Permission},
    swig::{swig_wallet_address_seeds, Swig},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable,
};

use super::is_valid_signature_abnf::parse_siws_challenge;
use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, IsValidSignatureAccounts},
        SwigInstruction,
    },
    AccountClassification,
};

const URN_SWIG_PREFIX: &str = "urn:swig:v1:swig:";
const URN_SWIG_WALLET_PREFIX: &str = "urn:swig:v1:swig_wallet_address:";
const URN_SWIG_PROGRAM_PREFIX: &str = "urn:swig:v1:swig_program:";
const URN_ROLE_ID_PREFIX: &str = "urn:swig:v1:role_id:";
const URN_SCOPE_PREFIX: &str = "urn:swig:v1:scope:";

#[derive(Debug, NoPadding)]
#[repr(C, align(8))]
pub struct IsValidSignatureArgs {
    instruction: SwigInstruction,
    pub challenge_len: u16,
    pub role_id: u32,
}

impl IsValidSignatureArgs {
    pub fn new(role_id: u32, challenge_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::IsValidSignature,
            challenge_len,
            role_id,
        }
    }
}

impl Transmutable for IsValidSignatureArgs {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for IsValidSignatureArgs {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

pub struct IsValidSignature<'a> {
    pub args: &'a IsValidSignatureArgs,
    pub challenge_payload: &'a [u8],
    pub authority_payload: &'a [u8],
}

impl<'a> IsValidSignature<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < IsValidSignatureArgs::LEN {
            return Err(SwigError::InvalidInstructionDataTooShort.into());
        }

        let (args_data, rest) = unsafe { data.split_at_unchecked(IsValidSignatureArgs::LEN) };
        let args = unsafe { IsValidSignatureArgs::load_unchecked(args_data)? };
        if rest.len() < args.challenge_len as usize {
            return Err(SwigError::InvalidInstructionDataTooShort.into());
        }

        let (challenge_payload, authority_payload) =
            unsafe { rest.split_at_unchecked(args.challenge_len as usize) };

        Ok(Self {
            args,
            challenge_payload,
            authority_payload,
        })
    }
}

#[inline(never)]
pub fn is_valid_signature(
    ctx: Context<IsValidSignatureAccounts>,
    all_accounts: &[AccountInfo],
    data: &[u8],
    account_classifiers: &[AccountClassification],
) -> ProgramResult {
    check_stack_height(1, SwigError::Cpi)?;
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    check_system_owner(
        ctx.accounts.swig_wallet_address,
        SwigError::OwnerMismatchSwigAccount,
    )?;

    if account_classifiers.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    if !matches!(
        account_classifiers[0],
        AccountClassification::ThisSwigV2 { .. }
    ) || !matches!(
        account_classifiers[1],
        AccountClassification::SwigWalletAddress
    ) {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    let validate = IsValidSignature::from_instruction_bytes(data)?;
    let parsed_challenge = parse_siws_challenge(validate.challenge_payload)?;

    let swig_account_data = unsafe { ctx.accounts.swig.borrow_data_unchecked() };
    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_unchecked(swig_header)? };

    let swig_wallet_seeds = swig_wallet_address_seeds(ctx.accounts.swig.key().as_ref());
    let (derived_wallet, _) = find_program_address(&swig_wallet_seeds, &crate::ID);
    if derived_wallet != *ctx.accounts.swig_wallet_address.key() {
        return Err(SwigError::InvalidSeedSwigAccount.into());
    }

    // `IsValidSignature` is intended for off-chain simulation and should not
    // mutate on-chain authority state (e.g. secp signature odometers).
    let mut swig_roles_for_auth = swig_roles.to_vec();
    let role = Swig::get_mut_role(validate.args.role_id, &mut swig_roles_for_auth)?
        .ok_or(SwigError::InvalidAuthorityNotFoundByRoleId)?;

    let clock = Clock::get()?;
    let slot = clock.slot;
    if role.authority.session_based() {
        role.authority.authenticate_session(
            all_accounts,
            validate.authority_payload,
            validate.challenge_payload,
            slot,
        )?;
    } else {
        role.authority.authenticate(
            all_accounts,
            validate.authority_payload,
            validate.challenge_payload,
            slot,
        )?;
    }

    let expected_swig = bs58::encode(ctx.accounts.swig.key().as_ref()).into_string();
    let expected_wallet =
        bs58::encode(ctx.accounts.swig_wallet_address.key().as_ref()).into_string();
    let expected_program = bs58::encode(crate::ID.as_ref()).into_string();

    if parsed_challenge.address != expected_wallet {
        return Err(SwigAuthenticateError::PermissionDenied.into());
    }

    let parsed_resources = parse_resources(&parsed_challenge.resources)?;
    if parsed_resources.swig != Some(expected_swig.as_str())
        || parsed_resources.swig_wallet_address != Some(expected_wallet.as_str())
        || parsed_resources.swig_program != Some(expected_program.as_str())
        || parsed_resources.role_id != Some(validate.args.role_id)
    {
        return Err(SwigAuthenticateError::PermissionDenied.into());
    }

    let permission_bitmap = collect_permission_bitmap(role.actions)?;
    for scope in parsed_resources.scopes {
        if !scope_is_allowed(scope, &permission_bitmap) {
            return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
        }
    }

    Ok(())
}

struct ParsedResources<'a> {
    swig: Option<&'a str>,
    swig_wallet_address: Option<&'a str>,
    swig_program: Option<&'a str>,
    role_id: Option<u32>,
    scopes: Vec<&'a str>,
}

fn parse_resources<'a>(resources: &[&'a str]) -> Result<ParsedResources<'a>, ProgramError> {
    let mut parsed = ParsedResources {
        swig: None,
        swig_wallet_address: None,
        swig_program: None,
        role_id: None,
        scopes: Vec::new(),
    };

    for resource in resources {
        if let Some(value) = resource.strip_prefix(URN_SWIG_PREFIX) {
            if parsed.swig.is_some() {
                return Err(ProgramError::InvalidInstructionData);
            }
            parsed.swig = Some(value);
            continue;
        }
        if let Some(value) = resource.strip_prefix(URN_SWIG_WALLET_PREFIX) {
            if parsed.swig_wallet_address.is_some() {
                return Err(ProgramError::InvalidInstructionData);
            }
            parsed.swig_wallet_address = Some(value);
            continue;
        }
        if let Some(value) = resource.strip_prefix(URN_SWIG_PROGRAM_PREFIX) {
            if parsed.swig_program.is_some() {
                return Err(ProgramError::InvalidInstructionData);
            }
            parsed.swig_program = Some(value);
            continue;
        }
        if let Some(value) = resource.strip_prefix(URN_ROLE_ID_PREFIX) {
            if parsed.role_id.is_some() {
                return Err(ProgramError::InvalidInstructionData);
            }
            parsed.role_id = Some(
                value
                    .parse::<u32>()
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            );
            continue;
        }
        if let Some(scope) = resource.strip_prefix(URN_SCOPE_PREFIX) {
            parsed.scopes.push(scope);
        }
    }

    Ok(parsed)
}

fn collect_permission_bitmap(actions: &[u8]) -> Result<[bool; 21], ProgramError> {
    let mut bitmap = [false; 21];
    let mut cursor = 0usize;

    while cursor < actions.len() {
        if cursor + Action::LEN > actions.len() {
            return Err(ProgramError::InvalidAccountData);
        }
        let action = unsafe { Action::load_unchecked(&actions[cursor..cursor + Action::LEN])? };
        let permission = action.permission()?;
        let permission_index = permission as usize;
        if permission_index < bitmap.len() {
            bitmap[permission_index] = true;
        }
        let boundary = action.boundary() as usize;
        if boundary <= cursor || boundary > actions.len() {
            return Err(ProgramError::InvalidAccountData);
        }
        cursor = boundary;
    }

    Ok(bitmap)
}

fn scope_is_allowed(scope: &str, permissions: &[bool; 21]) -> bool {
    let has_all = permissions[Permission::All as usize];
    if has_all {
        return true;
    }

    let has_all_but_manage = permissions[Permission::AllButManageAuthority as usize];
    if has_all_but_manage {
        return !matches!(scope, "ManageAuthority" | "SubAccount");
    }

    match scope {
        "None" => true,
        "SolLimit" => permissions[Permission::SolLimit as usize],
        "SolRecurringLimit" => permissions[Permission::SolRecurringLimit as usize],
        "Program" => {
            permissions[Permission::Program as usize]
                || permissions[Permission::ProgramCurated as usize]
                || permissions[Permission::ProgramAll as usize]
        },
        "ProgramScope" => permissions[Permission::ProgramScope as usize],
        "TokenLimit" => permissions[Permission::TokenLimit as usize],
        "TokenRecurringLimit" => permissions[Permission::TokenRecurringLimit as usize],
        "All" => permissions[Permission::All as usize],
        "ManageAuthority" => permissions[Permission::ManageAuthority as usize],
        "SubAccount" => permissions[Permission::SubAccount as usize],
        "StakeLimit" => permissions[Permission::StakeLimit as usize],
        "StakeRecurringLimit" => permissions[Permission::StakeRecurringLimit as usize],
        "StakeAll" => permissions[Permission::StakeAll as usize],
        "ProgramAll" => permissions[Permission::ProgramAll as usize],
        "ProgramCurated" => {
            permissions[Permission::ProgramCurated as usize]
                || permissions[Permission::ProgramAll as usize]
        },
        "AllButManageAuthority" => permissions[Permission::AllButManageAuthority as usize],
        "SolDestinationLimit" => permissions[Permission::SolDestinationLimit as usize],
        "SolRecurringDestinationLimit" => {
            permissions[Permission::SolRecurringDestinationLimit as usize]
        },
        "TokenDestinationLimit" => permissions[Permission::TokenDestinationLimit as usize],
        "TokenRecurringDestinationLimit" => {
            permissions[Permission::TokenRecurringDestinationLimit as usize]
        },
        "CloseSwigAuthority" => permissions[Permission::CloseSwigAuthority as usize],
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_resources, scope_is_allowed};

    #[test]
    fn parses_swig_resource_context() {
        let resources = vec![
            "urn:swig:v1:swig:swig123",
            "urn:swig:v1:swig_wallet_address:wallet123",
            "urn:swig:v1:swig_program:program123",
            "urn:swig:v1:role_id:7",
            "urn:swig:v1:scope:TokenLimit",
        ];
        let parsed = match parse_resources(&resources) {
            Ok(parsed) => parsed,
            Err(error) => panic!("parse_resources should succeed: {error:?}"),
        };
        assert_eq!(parsed.swig, Some("swig123"));
        assert_eq!(parsed.swig_wallet_address, Some("wallet123"));
        assert_eq!(parsed.swig_program, Some("program123"));
        assert_eq!(parsed.role_id, Some(7));
        assert_eq!(parsed.scopes, vec!["TokenLimit"]);
    }

    #[test]
    fn all_but_manage_does_not_allow_manage_or_subaccount_scope() {
        let mut bitmap = [false; 21];
        bitmap[15] = true; // AllButManageAuthority
        assert!(scope_is_allowed("TokenLimit", &bitmap));
        assert!(!scope_is_allowed("ManageAuthority", &bitmap));
        assert!(!scope_is_allowed("SubAccount", &bitmap));
    }
}
