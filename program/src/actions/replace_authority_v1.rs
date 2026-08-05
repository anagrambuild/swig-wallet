//! Replace authority instruction.
//!
//! This instruction replaces one signer with another while preserving the
//! target role and permissions. Any authority may perform the replacement when
//! its role has the ReplaceAuthority action. ProgramExec authorities must also
//! prove that the configured external recovery program approved the exact
//! replacement.

use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::find_program_address,
    syscalls::sol_sha256,
    sysvars::{
        clock::Clock,
        instructions::{Instructions, INSTRUCTIONS_ID},
        Sysvar,
    },
    ProgramResult,
};
use swig_assertions::{check_self_owned, sol_assert_bytes_eq};
use swig_state::{
    action::replace_authority::ReplaceAuthority,
    authority::{
        ed25519::{ED25519Authority, Ed25519SessionAuthority},
        secp256k1::{Secp256k1Authority, Secp256k1SessionAuthority},
        secp256r1::{Secp256r1Authority, Secp256r1SessionAuthority},
        AuthorityType,
    },
    role::Position,
    swig::{swig_wallet_address_seeds, Swig},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, ReplaceAuthorityV1Accounts},
        SwigInstruction,
    },
};

const EXECUTE_RECOVERY_V1_DISCRIMINATOR: [u8; 8] = *b"execreV1";
const PENDING_RECOVERY_SEED: &[u8] = b"pending-recovery";
const PENDING_RECOVERY_V1_DISCRIMINATOR: [u8; 8] = *b"rpendV01";
const PENDING_RECOVERY_STATUS_EXECUTED: u8 = 2;
const PENDING_RECOVERY_V1_LEN: usize = 8 + 32 + 32 + 4 + 32 + 32 + 32 + 8 + 8 + 1 + 1 + 2 + 2 + 2;
const PENDING_SWIG_WALLET_OFFSET: usize = 40;
const PENDING_TARGET_ROLE_OFFSET: usize = 72;
const PENDING_OLD_AUTHORITY_HASH_OFFSET: usize = 108;
const PENDING_NEW_AUTHORITY_HASH_OFFSET: usize = 140;
const PENDING_STATUS_OFFSET: usize = 188;
const PENDING_AUTHORITY_TYPE_OFFSET: usize = 190;
const PENDING_OLD_AUTHORITY_LEN_OFFSET: usize = 192;
const PENDING_NEW_AUTHORITY_LEN_OFFSET: usize = 194;
const RECOVERY_SIGNER_DATA_HEADER_LEN: usize = 2 + 2 + 2;
const MAX_SIGNER_LEN: usize = 64;

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct ReplaceAuthorityV1Args {
    pub instruction: SwigInstruction,
    _padding: [u8; 2],
    /// Role authenticating and authorizing this replacement.
    pub acting_role_id: u32,
    /// Existing role whose signer will be replaced.
    pub target_role_id: u32,
    /// Length of the new authority bytes immediately following this header.
    pub new_authority_len: u16,
    _trailing_padding: [u8; 2],
}

impl Transmutable for ReplaceAuthorityV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for ReplaceAuthorityV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl ReplaceAuthorityV1Args {
    pub fn new(acting_role_id: u32, target_role_id: u32, new_authority_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::ReplaceAuthorityV1,
            _padding: [0; 2],
            acting_role_id,
            target_role_id,
            new_authority_len,
            _trailing_padding: [0; 2],
        }
    }
}

pub struct ReplaceAuthorityV1<'a> {
    pub args: &'a ReplaceAuthorityV1Args,
    data_payload: &'a [u8],
    authority_payload: &'a [u8],
    new_authority: &'a [u8],
}

impl<'a> ReplaceAuthorityV1<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < ReplaceAuthorityV1Args::LEN {
            return Err(SwigError::InvalidSwigReplaceAuthorityInstructionDataTooShort.into());
        }

        let (args_bytes, payload) = data.split_at(ReplaceAuthorityV1Args::LEN);
        let args = unsafe { ReplaceAuthorityV1Args::load_unchecked(args_bytes)? };
        if args._padding != [0; 2] || args._trailing_padding != [0; 2] {
            return Err(SwigError::ReplaceAuthorityInvalidPayload.into());
        }

        let new_authority_len = args.new_authority_len as usize;
        if !matches!(new_authority_len, 32 | 33) {
            return Err(SwigError::ReplaceAuthorityInvalidSignerLength.into());
        }

        if payload.len() < new_authority_len {
            return Err(SwigError::ReplaceAuthorityInvalidPayload.into());
        }

        let (new_authority, authority_payload) = payload.split_at(new_authority_len);
        let data_payload_len = ReplaceAuthorityV1Args::LEN
            .checked_add(new_authority_len)
            .ok_or(ProgramError::InvalidInstructionData)?;

        Ok(Self {
            args,
            data_payload: &data[..data_payload_len],
            authority_payload,
            new_authority,
        })
    }
}

#[inline(never)]
pub fn replace_authority_v1(
    ctx: Context<ReplaceAuthorityV1Accounts>,
    data: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;

    let replace = ReplaceAuthorityV1::from_instruction_bytes(data)?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if swig_account_data[0] != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    let parts = Swig::split_parts_mut(swig_account_data)?;
    let swig = parts.state;
    let swig_roles = parts.roles;

    let acting_authority_type = {
        let acting_role = Swig::get_mut_role(replace.args.acting_role_id, swig_roles)?
            .ok_or(SwigError::InvalidAuthorityNotFoundByRoleId)?;
        let acting_authority_type = acting_role.authority.authority_type();
        let slot = Clock::get()?.slot;
        if acting_role.authority.session_based() {
            acting_role.authority.authenticate_session(
                all_accounts,
                replace.authority_payload,
                replace.data_payload,
                slot,
            )?;
        } else {
            acting_role.authority.authenticate(
                all_accounts,
                replace.authority_payload,
                replace.data_payload,
                slot,
            )?;
        }

        if acting_role
            .get_action::<ReplaceAuthority>(&replace.args.target_role_id.to_le_bytes())?
            .is_none()
        {
            return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
        }
        acting_authority_type
    };

    let verified_recovery = if acting_authority_type == AuthorityType::ProgramExec {
        let swig_wallet_address = all_accounts
            .get(1)
            .ok_or(SwigAuthenticateError::InvalidAuthorityPayload)?;
        let pending_recovery = all_accounts
            .get(3)
            .ok_or(SwigAuthenticateError::InvalidAuthorityPayload)?;
        Some(load_verified_recovery_replacement(
            ctx.accounts.swig,
            swig_wallet_address,
            pending_recovery,
            all_accounts,
            replace.authority_payload,
        )?)
    } else {
        None
    };

    replace_target_signer(
        swig,
        swig_roles,
        replace.args.target_role_id,
        replace.new_authority,
        verified_recovery.as_ref(),
    )
}

struct SignerReplacement {
    target_role_id: u32,
    signer_type: u16,
    current_signer: [u8; MAX_SIGNER_LEN],
    current_signer_len: usize,
    new_signer: [u8; MAX_SIGNER_LEN],
    new_signer_len: usize,
}

impl SignerReplacement {
    fn current_signer(&self) -> &[u8] {
        &self.current_signer[..self.current_signer_len]
    }

    fn new_signer(&self) -> &[u8] {
        &self.new_signer[..self.new_signer_len]
    }
}

#[inline(never)]
fn replace_target_signer(
    swig: &Swig,
    swig_roles: &mut [u8],
    target_role_id: u32,
    new_authority: &[u8],
    verified_recovery: Option<&SignerReplacement>,
) -> ProgramResult {
    let mut cursor = 0;
    for _ in 0..swig.roles {
        let position =
            unsafe { Position::load_unchecked(&swig_roles[cursor..cursor + Position::LEN])? };
        if position.id() == target_role_id {
            let target_signer_type = position.authority_type()?;
            if let Some(recovery) = verified_recovery {
                if recovery.target_role_id != target_role_id
                    || recovery.new_signer() != new_authority
                {
                    return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
                }
                if recovery.signer_type != target_signer_type as u16 {
                    return Err(SwigError::ReplaceAuthorityTypeMismatch.into());
                }
            }

            if !matches!(
                target_signer_type,
                AuthorityType::Ed25519
                    | AuthorityType::Ed25519Session
                    | AuthorityType::Secp256k1
                    | AuthorityType::Secp256k1Session
                    | AuthorityType::Secp256r1
                    | AuthorityType::Secp256r1Session
            ) {
                return Err(SwigError::UnsupportedReplaceAuthorityType.into());
            }

            let expected_signer_len = match target_signer_type {
                AuthorityType::Ed25519 | AuthorityType::Ed25519Session => 32,
                AuthorityType::Secp256k1
                | AuthorityType::Secp256k1Session
                | AuthorityType::Secp256r1
                | AuthorityType::Secp256r1Session => 33,
                _ => unreachable!(),
            };
            if new_authority.len() != expected_signer_len {
                return Err(SwigError::ReplaceAuthorityInvalidSignerLength.into());
            }

            if let Some(recovery) = verified_recovery {
                if recovery.current_signer_len != expected_signer_len
                    || recovery.new_signer_len != expected_signer_len
                {
                    return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
                }
            }

            let authority_start = cursor + Position::LEN;
            match target_signer_type {
                AuthorityType::Ed25519 => {
                    let new_signer: [u8; 32] = new_authority
                        .try_into()
                        .map_err(|_| SwigError::ReplaceAuthorityInvalidSignerLength)?;
                    let authority_end = authority_start + ED25519Authority::LEN;
                    let authority = unsafe {
                        ED25519Authority::load_mut_unchecked(
                            &mut swig_roles[authority_start..authority_end],
                        )?
                    };
                    verify_recovery_current(verified_recovery, &authority.public_key)?;
                    authority.public_key = new_signer;
                },
                AuthorityType::Ed25519Session => {
                    let new_signer: [u8; 32] = new_authority
                        .try_into()
                        .map_err(|_| SwigError::ReplaceAuthorityInvalidSignerLength)?;
                    let authority_end = authority_start + Ed25519SessionAuthority::LEN;
                    let authority = unsafe {
                        Ed25519SessionAuthority::load_mut_unchecked(
                            &mut swig_roles[authority_start..authority_end],
                        )?
                    };
                    verify_recovery_current(verified_recovery, &authority.public_key)?;
                    authority.public_key = new_signer;
                    authority.session_key = [0; 32];
                    authority.current_session_expiration = 0;
                },
                AuthorityType::Secp256k1 => {
                    let new_signer: [u8; 33] = new_authority
                        .try_into()
                        .map_err(|_| SwigError::ReplaceAuthorityInvalidSignerLength)?;
                    let authority_end = authority_start + Secp256k1Authority::LEN;
                    let authority = unsafe {
                        Secp256k1Authority::load_mut_unchecked(
                            &mut swig_roles[authority_start..authority_end],
                        )?
                    };
                    verify_recovery_current(verified_recovery, &authority.public_key)?;
                    authority.public_key = new_signer;
                    authority.signature_odometer = 0;
                },
                AuthorityType::Secp256k1Session => {
                    let new_signer: [u8; 33] = new_authority
                        .try_into()
                        .map_err(|_| SwigError::ReplaceAuthorityInvalidSignerLength)?;
                    let authority_end = authority_start + Secp256k1SessionAuthority::LEN;
                    let authority = unsafe {
                        Secp256k1SessionAuthority::load_mut_unchecked(
                            &mut swig_roles[authority_start..authority_end],
                        )?
                    };
                    verify_recovery_current(verified_recovery, &authority.public_key)?;
                    authority.public_key = new_signer;
                    authority.signature_odometer = 0;
                    authority.session_key = [0; 32];
                    authority.current_session_expiration = 0;
                },
                AuthorityType::Secp256r1 => {
                    let new_signer: [u8; 33] = new_authority
                        .try_into()
                        .map_err(|_| SwigError::ReplaceAuthorityInvalidSignerLength)?;
                    let authority_end = authority_start + Secp256r1Authority::LEN;
                    let authority = unsafe {
                        Secp256r1Authority::load_mut_unchecked(
                            &mut swig_roles[authority_start..authority_end],
                        )?
                    };
                    verify_recovery_current(verified_recovery, &authority.public_key)?;
                    authority.public_key = new_signer;
                    authority.signature_odometer = 0;
                },
                AuthorityType::Secp256r1Session => {
                    let new_signer: [u8; 33] = new_authority
                        .try_into()
                        .map_err(|_| SwigError::ReplaceAuthorityInvalidSignerLength)?;
                    let authority_end = authority_start + Secp256r1SessionAuthority::LEN;
                    let authority = unsafe {
                        Secp256r1SessionAuthority::load_mut_unchecked(
                            &mut swig_roles[authority_start..authority_end],
                        )?
                    };
                    verify_recovery_current(verified_recovery, &authority.public_key)?;
                    authority.public_key = new_signer;
                    authority.signature_odometer = 0;
                    authority.session_key = [0; 32];
                    authority.current_session_expiration = 0;
                },
                _ => unreachable!(),
            }
            return Ok(());
        }

        cursor = position.boundary() as usize;
    }

    Err(SwigError::InvalidAuthorityNotFoundByRoleId.into())
}

fn verify_recovery_current(
    verified_recovery: Option<&SignerReplacement>,
    current_signer: &[u8],
) -> ProgramResult {
    if let Some(recovery) = verified_recovery {
        if recovery.current_signer() != current_signer {
            return Err(SwigError::ReplaceAuthorityCurrentSignerMismatch.into());
        }
    }
    Ok(())
}

#[inline(never)]
fn load_verified_recovery_replacement(
    swig: &AccountInfo,
    swig_wallet_address: &AccountInfo,
    pending_recovery: &AccountInfo,
    all_accounts: &[AccountInfo],
    authority_payload: &[u8],
) -> Result<SignerReplacement, ProgramError> {
    let (expected_swig_wallet_address, _) =
        find_program_address(&swig_wallet_address_seeds(swig.key().as_ref()), &crate::ID);
    if !sol_assert_bytes_eq(swig_wallet_address.key(), &expected_swig_wallet_address, 32) {
        return Err(SwigError::InvalidSeedSwigAccount.into());
    }

    let execute_ix =
        load_recovery_execute_ix(swig, swig_wallet_address, all_accounts, authority_payload)?;

    if !sol_assert_bytes_eq(
        pending_recovery.key(),
        execute_ix.pending_recovery.as_ref(),
        32,
    ) {
        return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
    }
    if !sol_assert_bytes_eq(pending_recovery.owner(), execute_ix.program_id.as_ref(), 32) {
        return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
    }

    let pending_data = unsafe { pending_recovery.borrow_data_unchecked() };
    if pending_data.len() < PENDING_RECOVERY_V1_LEN
        || pending_data[0..8] != PENDING_RECOVERY_V1_DISCRIMINATOR
    {
        return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
    }

    let pending_swig_wallet = read_hash(pending_data, PENDING_SWIG_WALLET_OFFSET)?;
    if !sol_assert_bytes_eq(&pending_swig_wallet, swig_wallet_address.key(), 32) {
        return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
    }

    let target_role_id = read_u32(pending_data, PENDING_TARGET_ROLE_OFFSET)?;
    let target_role_id_bytes = target_role_id.to_le_bytes();
    let (expected_pending, _) = find_program_address(
        &[
            PENDING_RECOVERY_SEED,
            swig_wallet_address.key().as_ref(),
            &target_role_id_bytes,
        ],
        &execute_ix.program_id,
    );
    if !sol_assert_bytes_eq(pending_recovery.key(), &expected_pending, 32) {
        return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
    }

    let pending_status = pending_data
        .get(PENDING_STATUS_OFFSET)
        .copied()
        .ok_or(SwigError::ReplaceAuthorityIntentMismatch)?;
    if pending_status != PENDING_RECOVERY_STATUS_EXECUTED {
        return Err(SwigError::ReplaceAuthorityPendingRecoveryNotExecuted.into());
    }

    let pending_authority_type = read_u16(pending_data, PENDING_AUTHORITY_TYPE_OFFSET)?;
    if execute_ix.authority_type != pending_authority_type {
        return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
    }
    let pending_current_signer_len = read_u16(pending_data, PENDING_OLD_AUTHORITY_LEN_OFFSET)?;
    if execute_ix.current_signer_len as u16 != pending_current_signer_len {
        return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
    }
    let pending_new_signer_len = read_u16(pending_data, PENDING_NEW_AUTHORITY_LEN_OFFSET)?;
    if execute_ix.new_signer_len as u16 != pending_new_signer_len {
        return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
    }

    let current_signer_hash = hash_signer(execute_ix.current_signer())?;
    let pending_current_signer_hash = read_hash(pending_data, PENDING_OLD_AUTHORITY_HASH_OFFSET)?;
    if current_signer_hash != pending_current_signer_hash {
        return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
    }

    let new_signer_hash = hash_signer(execute_ix.new_signer())?;
    let pending_new_signer_hash = read_hash(pending_data, PENDING_NEW_AUTHORITY_HASH_OFFSET)?;
    if new_signer_hash != pending_new_signer_hash {
        return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
    }

    Ok(SignerReplacement {
        target_role_id,
        signer_type: execute_ix.authority_type,
        current_signer: execute_ix.current_signer,
        current_signer_len: execute_ix.current_signer_len,
        new_signer: execute_ix.new_signer,
        new_signer_len: execute_ix.new_signer_len,
    })
}

struct RecoveryExecuteIx {
    program_id: [u8; 32],
    pending_recovery: [u8; 32],
    authority_type: u16,
    current_signer: [u8; MAX_SIGNER_LEN],
    current_signer_len: usize,
    new_signer: [u8; MAX_SIGNER_LEN],
    new_signer_len: usize,
}

impl RecoveryExecuteIx {
    fn current_signer(&self) -> &[u8] {
        &self.current_signer[..self.current_signer_len]
    }

    fn new_signer(&self) -> &[u8] {
        &self.new_signer[..self.new_signer_len]
    }
}

#[inline(never)]
fn load_recovery_execute_ix(
    swig: &AccountInfo,
    swig_wallet_address: &AccountInfo,
    all_accounts: &[AccountInfo],
    authority_payload: &[u8],
) -> Result<RecoveryExecuteIx, ProgramError> {
    if authority_payload.is_empty() || authority_payload.len() > 2 {
        return Err(SwigAuthenticateError::InvalidAuthorityPayload.into());
    }

    let instruction_sysvar_index = authority_payload[0] as usize;
    let target_ix_index = if authority_payload.len() == 2 {
        Some(authority_payload[1] as usize)
    } else {
        None
    };

    let sysvar_instructions = all_accounts
        .get(instruction_sysvar_index)
        .ok_or(SwigAuthenticateError::InvalidAuthorityPayload)?;
    if sysvar_instructions.key().as_ref() != &INSTRUCTIONS_ID {
        return Err(SwigAuthenticateError::PermissionDeniedProgramExecInvalidInstruction.into());
    }

    let sysvar_instructions_data = unsafe { sysvar_instructions.borrow_data_unchecked() };
    let ixs = unsafe { Instructions::new_unchecked(sysvar_instructions_data) };
    let current_index = ixs.load_current_index() as usize;
    let verify_ix_index = match target_ix_index {
        Some(index) => {
            if index >= current_index {
                return Err(
                    SwigAuthenticateError::PermissionDeniedProgramExecInvalidInstruction.into(),
                );
            }
            index
        },
        None => {
            if current_index == 0 {
                return Err(
                    SwigAuthenticateError::PermissionDeniedProgramExecInvalidInstruction.into(),
                );
            }
            current_index - 1
        },
    };

    let recovery_ix = unsafe { ixs.deserialize_instruction_unchecked(verify_ix_index) };
    let instruction_data = recovery_ix.get_instruction_data();
    if instruction_data.len() < 8 + RECOVERY_SIGNER_DATA_HEADER_LEN
        || instruction_data[0..8] != EXECUTE_RECOVERY_V1_DISCRIMINATOR
    {
        return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
    }
    let recovery_signers = parse_replace_authority_data(&instruction_data[8..])?;

    let swig_meta = recovery_ix.get_account_meta_at(0)?;
    let swig_wallet_meta = recovery_ix.get_account_meta_at(1)?;
    let pending_meta = recovery_ix.get_account_meta_at(2)?;
    if !sol_assert_bytes_eq(swig_meta.key.as_ref(), swig.key(), 32) {
        return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
    }
    if !sol_assert_bytes_eq(swig_wallet_meta.key.as_ref(), swig_wallet_address.key(), 32) {
        return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
    }

    Ok(RecoveryExecuteIx {
        program_id: *recovery_ix.get_program_id(),
        pending_recovery: pending_meta.key,
        authority_type: recovery_signers.authority_type,
        current_signer: recovery_signers.current_signer,
        current_signer_len: recovery_signers.current_signer_len,
        new_signer: recovery_signers.new_signer,
        new_signer_len: recovery_signers.new_signer_len,
    })
}

#[inline(never)]
fn hash_signer(signer: &[u8]) -> Result<[u8; 32], ProgramError> {
    let mut hash = [0u8; 32];

    #[cfg(target_os = "solana")]
    unsafe {
        let res = sol_sha256(
            [signer.as_ref()].as_ptr() as *const u8,
            1,
            hash.as_mut_ptr(),
        );
        if res != 0 {
            return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let _ = signer;
    }

    Ok(hash)
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, ProgramError> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or(SwigError::ReplaceAuthorityIntentMismatch)?
        .try_into()
        .map_err(|_| SwigError::ReplaceAuthorityIntentMismatch)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, ProgramError> {
    let bytes: [u8; 2] = data
        .get(offset..offset + 2)
        .ok_or(SwigError::ReplaceAuthorityIntentMismatch)?
        .try_into()
        .map_err(|_| SwigError::ReplaceAuthorityIntentMismatch)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_hash(data: &[u8], offset: usize) -> Result<[u8; 32], ProgramError> {
    data.get(offset..offset + 32)
        .ok_or(SwigError::ReplaceAuthorityIntentMismatch)?
        .try_into()
        .map_err(|_| SwigError::ReplaceAuthorityIntentMismatch.into())
}

struct ParsedReplaceAuthorityData {
    authority_type: u16,
    current_signer: [u8; MAX_SIGNER_LEN],
    current_signer_len: usize,
    new_signer: [u8; MAX_SIGNER_LEN],
    new_signer_len: usize,
}

fn parse_replace_authority_data(data: &[u8]) -> Result<ParsedReplaceAuthorityData, ProgramError> {
    if data.len() < RECOVERY_SIGNER_DATA_HEADER_LEN {
        return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
    }

    let authority_type = read_u16(data, 0)?;
    let current_signer_len = read_u16(data, 2)? as usize;
    let new_signer_len = read_u16(data, 4)? as usize;
    if current_signer_len == 0
        || current_signer_len > MAX_SIGNER_LEN
        || new_signer_len == 0
        || new_signer_len > MAX_SIGNER_LEN
    {
        return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
    }

    let old_start = RECOVERY_SIGNER_DATA_HEADER_LEN;
    let new_start = old_start
        .checked_add(current_signer_len)
        .ok_or(SwigError::ReplaceAuthorityIntentMismatch)?;
    let expected_len = new_start
        .checked_add(new_signer_len)
        .ok_or(SwigError::ReplaceAuthorityIntentMismatch)?;
    if data.len() != expected_len {
        return Err(SwigError::ReplaceAuthorityIntentMismatch.into());
    }

    let mut current_signer = [0u8; MAX_SIGNER_LEN];
    current_signer[..current_signer_len].copy_from_slice(
        data.get(old_start..new_start)
            .ok_or(SwigError::ReplaceAuthorityIntentMismatch)?,
    );
    let mut new_signer = [0u8; MAX_SIGNER_LEN];
    new_signer[..new_signer_len].copy_from_slice(
        data.get(new_start..expected_len)
            .ok_or(SwigError::ReplaceAuthorityIntentMismatch)?,
    );

    Ok(ParsedReplaceAuthorityData {
        authority_type,
        current_signer,
        current_signer_len,
        new_signer,
        new_signer_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_payload_is_actor_target_then_new_authority() {
        let args = ReplaceAuthorityV1Args::new(2, 7, 32);
        let new_authority = [9u8; 32];
        let authority_payload = [1u8];
        let data = [
            args.into_bytes().unwrap(),
            new_authority.as_slice(),
            authority_payload.as_slice(),
        ]
        .concat();

        let parsed = ReplaceAuthorityV1::from_instruction_bytes(&data).unwrap();

        assert_eq!(ReplaceAuthorityV1Args::LEN, 16);
        assert_eq!(parsed.args.acting_role_id, 2);
        assert_eq!(parsed.args.target_role_id, 7);
        assert_eq!(parsed.new_authority, new_authority);
        assert_eq!(parsed.authority_payload, authority_payload);
        assert_eq!(
            parsed.data_payload,
            &data[..ReplaceAuthorityV1Args::LEN + new_authority.len()]
        );
    }

    #[test]
    fn instruction_payload_rejects_noncanonical_key_length() {
        let args = ReplaceAuthorityV1Args::new(2, 7, 31);
        let data = [args.into_bytes().unwrap(), &[9u8; 31]].concat();

        assert!(ReplaceAuthorityV1::from_instruction_bytes(&data).is_err());
    }

    #[test]
    fn instruction_payload_rejects_nonzero_padding() {
        let args = ReplaceAuthorityV1Args::new(2, 7, 32);
        let mut data = [args.into_bytes().unwrap(), &[9u8; 32]].concat();
        data[2] = 1;

        assert!(ReplaceAuthorityV1::from_instruction_bytes(&data).is_err());
    }

    #[test]
    fn instruction_payload_rejects_truncated_new_authority() {
        let args = ReplaceAuthorityV1Args::new(2, 7, 32);
        let data = [args.into_bytes().unwrap(), &[9u8; 31]].concat();

        assert!(ReplaceAuthorityV1::from_instruction_bytes(&data).is_err());
    }
}
