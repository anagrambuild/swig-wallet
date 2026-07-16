//! Recovery authority instruction.
//!
//! This instruction rotates one signer authority to another while preserving
//! the target role and permissions. Authentication is delegated to the acting
//! role, which is expected to be a ProgramExec recovery role.

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
    action::recovery_authority::RecoveryAuthority,
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
        accounts::{Context, RecoverAuthorityV1Accounts},
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
const RECOVERY_AUTHORITY_DATA_HEADER_LEN: usize = 2 + 2 + 2;
const MAX_RECOVERY_AUTHORITY_LEN: usize = 64;

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct RecoverAuthorityV1Args {
    pub instruction: SwigInstruction,
    pub authority_payload_len: u16,
    pub acting_role_id: u32,
}

impl Transmutable for RecoverAuthorityV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for RecoverAuthorityV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl RecoverAuthorityV1Args {
    pub fn new(acting_role_id: u32, authority_payload_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::RecoverAuthorityV1,
            authority_payload_len,
            acting_role_id,
        }
    }
}

pub struct RecoverAuthorityV1<'a> {
    pub args: &'a RecoverAuthorityV1Args,
    data_payload: &'a [u8],
    authority_payload: &'a [u8],
}

impl<'a> RecoverAuthorityV1<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < RecoverAuthorityV1Args::LEN {
            return Err(SwigError::InvalidSwigRecoverAuthorityInstructionDataTooShort.into());
        }

        let (args_bytes, authority_payload) = data.split_at(RecoverAuthorityV1Args::LEN);
        let args = unsafe { RecoverAuthorityV1Args::load_unchecked(args_bytes)? };
        if authority_payload.len() != args.authority_payload_len as usize {
            return Err(ProgramError::InvalidInstructionData);
        }

        Ok(Self {
            args,
            data_payload: args_bytes,
            authority_payload,
        })
    }
}

#[inline(never)]
pub fn recover_authority_v1(
    ctx: Context<RecoverAuthorityV1Accounts>,
    data: &[u8],
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;

    let recover = RecoverAuthorityV1::from_instruction_bytes(data)?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if swig_account_data[0] != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    let parts = Swig::split_parts_mut(swig_account_data)?;
    let swig = parts.state;
    let swig_roles = parts.roles;

    {
        let acting_role = Swig::get_mut_role(recover.args.acting_role_id, swig_roles)?
            .ok_or(SwigError::InvalidAuthorityNotFoundByRoleId)?;
        let slot = Clock::get()?.slot;
        if acting_role.authority.session_based() {
            acting_role.authority.authenticate_session(
                all_accounts,
                recover.authority_payload,
                recover.data_payload,
                slot,
            )?;
        } else {
            acting_role.authority.authenticate(
                all_accounts,
                recover.authority_payload,
                recover.data_payload,
                slot,
            )?;
        }

        if acting_role.get_action::<RecoveryAuthority>(&[])?.is_none() {
            return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
        }
    }

    let binding = load_verified_recovery_binding(
        ctx.accounts.swig,
        ctx.accounts.swig_wallet_address,
        ctx.accounts.pending_recovery,
        all_accounts,
        recover.authority_payload,
    )?;

    rotate_target_authority(swig, swig_roles, binding)
}

struct RecoveryBinding {
    target_role_id: u32,
    authority_type: u16,
    old_authority: [u8; MAX_RECOVERY_AUTHORITY_LEN],
    old_authority_len: usize,
    new_authority: [u8; MAX_RECOVERY_AUTHORITY_LEN],
    new_authority_len: usize,
}

impl RecoveryBinding {
    fn old_authority(&self) -> &[u8] {
        &self.old_authority[..self.old_authority_len]
    }

    fn new_authority(&self) -> &[u8] {
        &self.new_authority[..self.new_authority_len]
    }
}

#[inline(never)]
fn rotate_target_authority(
    swig: &Swig,
    swig_roles: &mut [u8],
    binding: RecoveryBinding,
) -> ProgramResult {
    let mut cursor = 0;
    for _ in 0..swig.roles {
        let position =
            unsafe { Position::load_unchecked(&swig_roles[cursor..cursor + Position::LEN])? };
        if position.id() == binding.target_role_id {
            let target_authority_type = position.authority_type()?;
            if target_authority_type as u16 != binding.authority_type {
                return Err(SwigError::RecoveryAuthorityTypeMismatch.into());
            }

            let authority_start = cursor + Position::LEN;
            match target_authority_type {
                AuthorityType::Ed25519 => {
                    let (old_authority, new_authority) = fixed_authority_pair::<32>(&binding)?;
                    let authority_end = authority_start + ED25519Authority::LEN;
                    let authority = unsafe {
                        ED25519Authority::load_mut_unchecked(
                            &mut swig_roles[authority_start..authority_end],
                        )?
                    };
                    if authority.public_key != old_authority {
                        return Err(SwigError::RecoveryOldAuthorityMismatch.into());
                    }
                    authority.public_key = new_authority;
                },
                AuthorityType::Ed25519Session => {
                    let (old_authority, new_authority) = fixed_authority_pair::<32>(&binding)?;
                    let authority_end = authority_start + Ed25519SessionAuthority::LEN;
                    let authority = unsafe {
                        Ed25519SessionAuthority::load_mut_unchecked(
                            &mut swig_roles[authority_start..authority_end],
                        )?
                    };
                    if authority.public_key != old_authority {
                        return Err(SwigError::RecoveryOldAuthorityMismatch.into());
                    }
                    authority.public_key = new_authority;
                    authority.session_key = [0; 32];
                    authority.current_session_expiration = 0;
                },
                AuthorityType::Secp256k1 => {
                    let old_authority = normalize_secp256k1_authority(binding.old_authority())?;
                    let new_authority = normalize_secp256k1_authority(binding.new_authority())?;
                    let authority_end = authority_start + Secp256k1Authority::LEN;
                    let authority = unsafe {
                        Secp256k1Authority::load_mut_unchecked(
                            &mut swig_roles[authority_start..authority_end],
                        )?
                    };
                    if authority.public_key != old_authority {
                        return Err(SwigError::RecoveryOldAuthorityMismatch.into());
                    }
                    authority.public_key = new_authority;
                    authority.signature_odometer = 0;
                },
                AuthorityType::Secp256k1Session => {
                    let old_authority = normalize_secp256k1_authority(binding.old_authority())?;
                    let new_authority = normalize_secp256k1_authority(binding.new_authority())?;
                    let authority_end = authority_start + Secp256k1SessionAuthority::LEN;
                    let authority = unsafe {
                        Secp256k1SessionAuthority::load_mut_unchecked(
                            &mut swig_roles[authority_start..authority_end],
                        )?
                    };
                    if authority.public_key != old_authority {
                        return Err(SwigError::RecoveryOldAuthorityMismatch.into());
                    }
                    authority.public_key = new_authority;
                    authority.signature_odometer = 0;
                    authority.session_key = [0; 32];
                    authority.current_session_expiration = 0;
                },
                AuthorityType::Secp256r1 => {
                    let (old_authority, new_authority) = fixed_authority_pair::<33>(&binding)?;
                    let authority_end = authority_start + Secp256r1Authority::LEN;
                    let authority = unsafe {
                        Secp256r1Authority::load_mut_unchecked(
                            &mut swig_roles[authority_start..authority_end],
                        )?
                    };
                    if authority.public_key != old_authority {
                        return Err(SwigError::RecoveryOldAuthorityMismatch.into());
                    }
                    authority.public_key = new_authority;
                    authority.signature_odometer = 0;
                },
                AuthorityType::Secp256r1Session => {
                    let (old_authority, new_authority) = fixed_authority_pair::<33>(&binding)?;
                    let authority_end = authority_start + Secp256r1SessionAuthority::LEN;
                    let authority = unsafe {
                        Secp256r1SessionAuthority::load_mut_unchecked(
                            &mut swig_roles[authority_start..authority_end],
                        )?
                    };
                    if authority.public_key != old_authority {
                        return Err(SwigError::RecoveryOldAuthorityMismatch.into());
                    }
                    authority.public_key = new_authority;
                    authority.signature_odometer = 0;
                    authority.session_key = [0; 32];
                    authority.current_session_expiration = 0;
                },
                _ => {
                    return Err(SwigError::UnsupportedRecoveryAuthorityScheme.into());
                },
            }
            return Ok(());
        }

        cursor = position.boundary() as usize;
    }

    Err(SwigError::InvalidAuthorityNotFoundByRoleId.into())
}

fn fixed_authority_pair<const LEN: usize>(
    binding: &RecoveryBinding,
) -> Result<([u8; LEN], [u8; LEN]), ProgramError> {
    if binding.old_authority_len != LEN || binding.new_authority_len != LEN {
        return Err(SwigError::RecoveryInvalidAuthorityLength.into());
    }

    let old_authority = binding
        .old_authority()
        .try_into()
        .map_err(|_| SwigError::RecoveryInvalidAuthorityLength)?;
    let new_authority = binding
        .new_authority()
        .try_into()
        .map_err(|_| SwigError::RecoveryInvalidAuthorityLength)?;
    Ok((old_authority, new_authority))
}

fn normalize_secp256k1_authority(authority: &[u8]) -> Result<[u8; 33], ProgramError> {
    match authority.len() {
        33 => authority
            .try_into()
            .map_err(|_| SwigError::RecoveryInvalidAuthorityLength.into()),
        64 => {
            let uncompressed: &[u8; 64] = authority
                .try_into()
                .map_err(|_| SwigError::RecoveryInvalidAuthorityLength)?;
            Ok(compress_secp256k1_authority(uncompressed))
        },
        _ => Err(SwigError::RecoveryInvalidAuthorityLength.into()),
    }
}

fn compress_secp256k1_authority(key: &[u8; 64]) -> [u8; 33] {
    let mut compressed = [0u8; 33];
    compressed[0] = if key[63] & 1 == 0 { 0x02 } else { 0x03 };
    compressed[1..33].copy_from_slice(&key[..32]);
    compressed
}

#[inline(never)]
fn load_verified_recovery_binding(
    swig: &AccountInfo,
    swig_wallet_address: &AccountInfo,
    pending_recovery: &AccountInfo,
    all_accounts: &[AccountInfo],
    authority_payload: &[u8],
) -> Result<RecoveryBinding, ProgramError> {
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
        return Err(SwigError::RecoveryInstructionMismatch.into());
    }
    if !sol_assert_bytes_eq(pending_recovery.owner(), execute_ix.program_id.as_ref(), 32) {
        return Err(SwigError::RecoveryInstructionMismatch.into());
    }

    let pending_data = unsafe { pending_recovery.borrow_data_unchecked() };
    if pending_data.len() < PENDING_RECOVERY_V1_LEN
        || pending_data[0..8] != PENDING_RECOVERY_V1_DISCRIMINATOR
    {
        return Err(SwigError::RecoveryInstructionMismatch.into());
    }

    let pending_swig_wallet = read_hash(pending_data, PENDING_SWIG_WALLET_OFFSET)?;
    if !sol_assert_bytes_eq(&pending_swig_wallet, swig_wallet_address.key(), 32) {
        return Err(SwigError::RecoveryInstructionMismatch.into());
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
        return Err(SwigError::RecoveryInstructionMismatch.into());
    }

    let pending_status = pending_data
        .get(PENDING_STATUS_OFFSET)
        .copied()
        .ok_or(SwigError::RecoveryInstructionMismatch)?;
    if pending_status != PENDING_RECOVERY_STATUS_EXECUTED {
        return Err(SwigError::RecoveryPendingNotExecuted.into());
    }

    let pending_authority_type = read_u16(pending_data, PENDING_AUTHORITY_TYPE_OFFSET)?;
    if execute_ix.authority_type != pending_authority_type {
        return Err(SwigError::RecoveryInstructionMismatch.into());
    }
    let pending_old_authority_len = read_u16(pending_data, PENDING_OLD_AUTHORITY_LEN_OFFSET)?;
    if execute_ix.old_authority_len as u16 != pending_old_authority_len {
        return Err(SwigError::RecoveryInstructionMismatch.into());
    }
    let pending_new_authority_len = read_u16(pending_data, PENDING_NEW_AUTHORITY_LEN_OFFSET)?;
    if execute_ix.new_authority_len as u16 != pending_new_authority_len {
        return Err(SwigError::RecoveryInstructionMismatch.into());
    }

    let old_authority_hash = hash_authority(execute_ix.old_authority())?;
    let pending_old_authority_hash = read_hash(pending_data, PENDING_OLD_AUTHORITY_HASH_OFFSET)?;
    if old_authority_hash != pending_old_authority_hash {
        return Err(SwigError::RecoveryInstructionMismatch.into());
    }

    let new_authority_hash = hash_authority(execute_ix.new_authority())?;
    let pending_new_authority_hash = read_hash(pending_data, PENDING_NEW_AUTHORITY_HASH_OFFSET)?;
    if new_authority_hash != pending_new_authority_hash {
        return Err(SwigError::RecoveryInstructionMismatch.into());
    }

    Ok(RecoveryBinding {
        target_role_id,
        authority_type: execute_ix.authority_type,
        old_authority: execute_ix.old_authority,
        old_authority_len: execute_ix.old_authority_len,
        new_authority: execute_ix.new_authority,
        new_authority_len: execute_ix.new_authority_len,
    })
}

struct RecoveryExecuteIx {
    program_id: [u8; 32],
    pending_recovery: [u8; 32],
    authority_type: u16,
    old_authority: [u8; MAX_RECOVERY_AUTHORITY_LEN],
    old_authority_len: usize,
    new_authority: [u8; MAX_RECOVERY_AUTHORITY_LEN],
    new_authority_len: usize,
}

impl RecoveryExecuteIx {
    fn old_authority(&self) -> &[u8] {
        &self.old_authority[..self.old_authority_len]
    }

    fn new_authority(&self) -> &[u8] {
        &self.new_authority[..self.new_authority_len]
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
    if instruction_data.len() < 8 + RECOVERY_AUTHORITY_DATA_HEADER_LEN
        || instruction_data[0..8] != EXECUTE_RECOVERY_V1_DISCRIMINATOR
    {
        return Err(SwigError::RecoveryInstructionMismatch.into());
    }
    let recovery_authorities = parse_recovery_authority_data(&instruction_data[8..])?;

    let swig_meta = recovery_ix.get_account_meta_at(0)?;
    let swig_wallet_meta = recovery_ix.get_account_meta_at(1)?;
    let pending_meta = recovery_ix.get_account_meta_at(2)?;
    if !sol_assert_bytes_eq(swig_meta.key.as_ref(), swig.key(), 32) {
        return Err(SwigError::RecoveryInstructionMismatch.into());
    }
    if !sol_assert_bytes_eq(swig_wallet_meta.key.as_ref(), swig_wallet_address.key(), 32) {
        return Err(SwigError::RecoveryInstructionMismatch.into());
    }

    Ok(RecoveryExecuteIx {
        program_id: *recovery_ix.get_program_id(),
        pending_recovery: pending_meta.key,
        authority_type: recovery_authorities.authority_type,
        old_authority: recovery_authorities.old_authority,
        old_authority_len: recovery_authorities.old_authority_len,
        new_authority: recovery_authorities.new_authority,
        new_authority_len: recovery_authorities.new_authority_len,
    })
}

#[inline(never)]
fn hash_authority(authority: &[u8]) -> Result<[u8; 32], ProgramError> {
    let mut hash = [0u8; 32];

    #[cfg(target_os = "solana")]
    unsafe {
        let res = sol_sha256(
            [authority.as_ref()].as_ptr() as *const u8,
            1,
            hash.as_mut_ptr(),
        );
        if res != 0 {
            return Err(SwigError::RecoveryInstructionMismatch.into());
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let _ = authority;
    }

    Ok(hash)
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, ProgramError> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or(SwigError::RecoveryInstructionMismatch)?
        .try_into()
        .map_err(|_| SwigError::RecoveryInstructionMismatch)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, ProgramError> {
    let bytes: [u8; 2] = data
        .get(offset..offset + 2)
        .ok_or(SwigError::RecoveryInstructionMismatch)?
        .try_into()
        .map_err(|_| SwigError::RecoveryInstructionMismatch)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_hash(data: &[u8], offset: usize) -> Result<[u8; 32], ProgramError> {
    data.get(offset..offset + 32)
        .ok_or(SwigError::RecoveryInstructionMismatch)?
        .try_into()
        .map_err(|_| SwigError::RecoveryInstructionMismatch.into())
}

struct ParsedRecoveryAuthorityData {
    authority_type: u16,
    old_authority: [u8; MAX_RECOVERY_AUTHORITY_LEN],
    old_authority_len: usize,
    new_authority: [u8; MAX_RECOVERY_AUTHORITY_LEN],
    new_authority_len: usize,
}

fn parse_recovery_authority_data(data: &[u8]) -> Result<ParsedRecoveryAuthorityData, ProgramError> {
    if data.len() < RECOVERY_AUTHORITY_DATA_HEADER_LEN {
        return Err(SwigError::RecoveryInstructionMismatch.into());
    }

    let authority_type = read_u16(data, 0)?;
    let old_authority_len = read_u16(data, 2)? as usize;
    let new_authority_len = read_u16(data, 4)? as usize;
    if old_authority_len == 0
        || old_authority_len > MAX_RECOVERY_AUTHORITY_LEN
        || new_authority_len == 0
        || new_authority_len > MAX_RECOVERY_AUTHORITY_LEN
    {
        return Err(SwigError::RecoveryInstructionMismatch.into());
    }

    let old_start = RECOVERY_AUTHORITY_DATA_HEADER_LEN;
    let new_start = old_start
        .checked_add(old_authority_len)
        .ok_or(SwigError::RecoveryInstructionMismatch)?;
    let expected_len = new_start
        .checked_add(new_authority_len)
        .ok_or(SwigError::RecoveryInstructionMismatch)?;
    if data.len() != expected_len {
        return Err(SwigError::RecoveryInstructionMismatch.into());
    }

    let mut old_authority = [0u8; MAX_RECOVERY_AUTHORITY_LEN];
    old_authority[..old_authority_len].copy_from_slice(
        data.get(old_start..new_start)
            .ok_or(SwigError::RecoveryInstructionMismatch)?,
    );
    let mut new_authority = [0u8; MAX_RECOVERY_AUTHORITY_LEN];
    new_authority[..new_authority_len].copy_from_slice(
        data.get(new_start..expected_len)
            .ok_or(SwigError::RecoveryInstructionMismatch)?,
    );

    Ok(ParsedRecoveryAuthorityData {
        authority_type,
        old_authority,
        old_authority_len,
        new_authority,
        new_authority_len,
    })
}
