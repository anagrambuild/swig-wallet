//! Replace authority instruction.
//!
//! This instruction replaces one signer with another while preserving the
//! target role and permissions. Any authority may perform the replacement when
//! its role has All, ManageAuthority, or the target-scoped ReplaceAuthority
//! action. ProgramExec authorities must also prove that the configured external
//! policy program approved the exact replacement.

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
    action::{all::All, manage_authority::ManageAuthority, replace_authority::ReplaceAuthority},
    authority::{
        ed25519::{ED25519Authority, Ed25519SessionAuthority},
        secp256k1::{compress, Secp256k1Authority, Secp256k1SessionAuthority},
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

pub const REPLACE_AUTHORITY_PROOF_V1_DISCRIMINATOR: [u8; 8] = *b"rplauth1";
pub const REPLACE_AUTHORITY_PROOF_V1_DOMAIN: &[u8] = b"swig-replace-authority-v1";
const REPLACE_AUTHORITY_PROOF_V1_LEN: usize = 8 + 32;

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
        if !matches!(new_authority_len, 32 | 33 | 64) {
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
    let swig_key = *ctx.accounts.swig.key();
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

        let has_permission = acting_role.get_action::<All>(&[])?.is_some()
            || acting_role.get_action::<ManageAuthority>(&[])?.is_some()
            || acting_role
                .get_action::<ReplaceAuthority>(&replace.args.target_role_id.to_le_bytes())?
                .is_some();
        if !has_permission {
            return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
        }
        acting_authority_type
    };

    let program_exec_proof = if acting_authority_type == AuthorityType::ProgramExec {
        let swig_wallet_address = all_accounts
            .get(1)
            .ok_or(SwigAuthenticateError::InvalidAuthorityPayload)?;
        Some(load_program_exec_replacement_proof(
            ctx.accounts.swig,
            swig_wallet_address,
            all_accounts,
            replace.authority_payload,
        )?)
    } else {
        None
    };

    replace_target_signer(
        swig,
        swig_roles,
        &swig_key,
        replace.args.acting_role_id,
        replace.args.target_role_id,
        replace.new_authority,
        program_exec_proof.as_ref(),
    )
}

struct ProgramExecReplacementProof {
    swig_wallet_address: [u8; 32],
    replacement_hash: [u8; 32],
}

#[inline(never)]
fn replace_target_signer(
    swig: &Swig,
    swig_roles: &mut [u8],
    swig_key: &[u8; 32],
    acting_role_id: u32,
    target_role_id: u32,
    new_authority: &[u8],
    program_exec_proof: Option<&ProgramExecReplacementProof>,
) -> ProgramResult {
    let mut cursor = 0;
    for _ in 0..swig.roles {
        let position =
            unsafe { Position::load_unchecked(&swig_roles[cursor..cursor + Position::LEN])? };
        if position.id() == target_role_id {
            let target_signer_type = position.authority_type()?;

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

            let valid_signer_len = match target_signer_type {
                AuthorityType::Ed25519 | AuthorityType::Ed25519Session => new_authority.len() == 32,
                AuthorityType::Secp256k1 | AuthorityType::Secp256k1Session => {
                    matches!(new_authority.len(), 33 | 64)
                },
                AuthorityType::Secp256r1 | AuthorityType::Secp256r1Session => {
                    new_authority.len() == 33
                },
                _ => unreachable!(),
            };
            if !valid_signer_len {
                return Err(SwigError::ReplaceAuthorityInvalidSignerLength.into());
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
                    verify_program_exec_replacement_proof(
                        program_exec_proof,
                        swig_key,
                        acting_role_id,
                        target_role_id,
                        target_signer_type,
                        &authority.public_key,
                        &new_signer,
                    )?;
                    reject_same_signer(&authority.public_key, &new_signer)?;
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
                    verify_program_exec_replacement_proof(
                        program_exec_proof,
                        swig_key,
                        acting_role_id,
                        target_role_id,
                        target_signer_type,
                        &authority.public_key,
                        &new_signer,
                    )?;
                    reject_same_signer(&authority.public_key, &new_signer)?;
                    authority.public_key = new_signer;
                    authority.session_key = [0; 32];
                    authority.current_session_expiration = 0;
                },
                AuthorityType::Secp256k1 => {
                    let new_signer = normalize_secp256k1_authority(new_authority)?;
                    let authority_end = authority_start + Secp256k1Authority::LEN;
                    let authority = unsafe {
                        Secp256k1Authority::load_mut_unchecked(
                            &mut swig_roles[authority_start..authority_end],
                        )?
                    };
                    verify_program_exec_replacement_proof(
                        program_exec_proof,
                        swig_key,
                        acting_role_id,
                        target_role_id,
                        target_signer_type,
                        &authority.public_key,
                        &new_signer,
                    )?;
                    reject_same_signer(&authority.public_key, &new_signer)?;
                    authority.public_key = new_signer;
                    authority.signature_odometer = 0;
                },
                AuthorityType::Secp256k1Session => {
                    let new_signer = normalize_secp256k1_authority(new_authority)?;
                    let authority_end = authority_start + Secp256k1SessionAuthority::LEN;
                    let authority = unsafe {
                        Secp256k1SessionAuthority::load_mut_unchecked(
                            &mut swig_roles[authority_start..authority_end],
                        )?
                    };
                    verify_program_exec_replacement_proof(
                        program_exec_proof,
                        swig_key,
                        acting_role_id,
                        target_role_id,
                        target_signer_type,
                        &authority.public_key,
                        &new_signer,
                    )?;
                    reject_same_signer(&authority.public_key, &new_signer)?;
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
                    verify_program_exec_replacement_proof(
                        program_exec_proof,
                        swig_key,
                        acting_role_id,
                        target_role_id,
                        target_signer_type,
                        &authority.public_key,
                        &new_signer,
                    )?;
                    reject_same_signer(&authority.public_key, &new_signer)?;
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
                    verify_program_exec_replacement_proof(
                        program_exec_proof,
                        swig_key,
                        acting_role_id,
                        target_role_id,
                        target_signer_type,
                        &authority.public_key,
                        &new_signer,
                    )?;
                    reject_same_signer(&authority.public_key, &new_signer)?;
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

fn reject_same_signer(current_signer: &[u8], new_signer: &[u8]) -> ProgramResult {
    if current_signer == new_signer {
        return Err(SwigError::ReplaceAuthoritySameSigner.into());
    }
    Ok(())
}

fn normalize_secp256k1_authority(authority: &[u8]) -> Result<[u8; 33], ProgramError> {
    match authority.len() {
        33 => authority
            .try_into()
            .map_err(|_| SwigError::ReplaceAuthorityInvalidSignerLength.into()),
        64 => {
            let uncompressed: &[u8; 64] = authority
                .try_into()
                .map_err(|_| SwigError::ReplaceAuthorityInvalidSignerLength)?;
            Ok(compress(uncompressed))
        },
        _ => Err(SwigError::ReplaceAuthorityInvalidSignerLength.into()),
    }
}

fn verify_program_exec_replacement_proof(
    proof: Option<&ProgramExecReplacementProof>,
    swig_key: &[u8; 32],
    acting_role_id: u32,
    target_role_id: u32,
    target_signer_type: AuthorityType,
    current_signer: &[u8],
    new_signer: &[u8],
) -> ProgramResult {
    let Some(proof) = proof else {
        return Ok(());
    };
    let expected_hash = replacement_proof_hash(
        swig_key,
        &proof.swig_wallet_address,
        acting_role_id,
        target_role_id,
        target_signer_type,
        current_signer,
        new_signer,
    )?;
    if expected_hash != proof.replacement_hash {
        return Err(SwigError::ReplaceAuthorityProofMismatch.into());
    }
    Ok(())
}

#[inline(never)]
fn load_program_exec_replacement_proof(
    swig: &AccountInfo,
    swig_wallet_address: &AccountInfo,
    all_accounts: &[AccountInfo],
    authority_payload: &[u8],
) -> Result<ProgramExecReplacementProof, ProgramError> {
    let (expected_swig_wallet_address, _) =
        find_program_address(&swig_wallet_address_seeds(swig.key().as_ref()), &crate::ID);
    if !sol_assert_bytes_eq(swig_wallet_address.key(), &expected_swig_wallet_address, 32) {
        return Err(SwigError::InvalidSeedSwigAccount.into());
    }
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
    if sysvar_instructions.key().as_ref() != INSTRUCTIONS_ID {
        return Err(SwigAuthenticateError::PermissionDeniedProgramExecInvalidInstruction.into());
    }

    let sysvar_instructions_data = unsafe { sysvar_instructions.borrow_data_unchecked() };
    let ixs = unsafe { Instructions::new_unchecked(sysvar_instructions_data) };
    let current_index = ixs.load_current_index() as usize;
    let verify_ix_index = match target_ix_index {
        Some(index) => {
            if index >= current_index {
                return Err(SwigError::ReplaceAuthorityProofInvalidInstruction.into());
            }
            index
        },
        None => {
            if current_index == 0 {
                return Err(SwigError::ReplaceAuthorityProofInvalidInstruction.into());
            }
            current_index - 1
        },
    };

    let proof_ix = unsafe { ixs.deserialize_instruction_unchecked(verify_ix_index) };
    let instruction_data = proof_ix.get_instruction_data();
    if instruction_data.len() != REPLACE_AUTHORITY_PROOF_V1_LEN
        || instruction_data[0..8] != REPLACE_AUTHORITY_PROOF_V1_DISCRIMINATOR
    {
        return Err(SwigError::ReplaceAuthorityProofInvalidData.into());
    }
    let replacement_hash: [u8; 32] = instruction_data[8..]
        .try_into()
        .map_err(|_| SwigError::ReplaceAuthorityProofInvalidData)?;

    let swig_meta = proof_ix
        .get_account_meta_at(0)
        .map_err(|_| SwigError::ReplaceAuthorityProofInvalidAccounts)?;
    let swig_wallet_meta = proof_ix
        .get_account_meta_at(1)
        .map_err(|_| SwigError::ReplaceAuthorityProofInvalidAccounts)?;
    if !sol_assert_bytes_eq(swig_meta.key.as_ref(), swig.key(), 32) {
        return Err(SwigError::ReplaceAuthorityProofInvalidAccounts.into());
    }
    if !sol_assert_bytes_eq(swig_wallet_meta.key.as_ref(), swig_wallet_address.key(), 32) {
        return Err(SwigError::ReplaceAuthorityProofInvalidAccounts.into());
    }

    Ok(ProgramExecReplacementProof {
        swig_wallet_address: *swig_wallet_address.key(),
        replacement_hash,
    })
}

#[inline(never)]
fn replacement_proof_hash(
    swig_key: &[u8; 32],
    swig_wallet_address: &[u8; 32],
    acting_role_id: u32,
    target_role_id: u32,
    target_signer_type: AuthorityType,
    current_signer: &[u8],
    new_signer: &[u8],
) -> Result<[u8; 32], ProgramError> {
    let acting_role_id = acting_role_id.to_le_bytes();
    let target_role_id = target_role_id.to_le_bytes();
    let target_signer_type = (target_signer_type as u16).to_le_bytes();
    let values: [&[u8]; 8] = [
        REPLACE_AUTHORITY_PROOF_V1_DOMAIN,
        swig_key,
        swig_wallet_address,
        &acting_role_id,
        &target_role_id,
        &target_signer_type,
        current_signer,
        new_signer,
    ];
    let mut hash = [0u8; 32];

    #[cfg(target_os = "solana")]
    unsafe {
        let res = sol_sha256(
            values.as_ptr() as *const u8,
            values.len() as u64,
            hash.as_mut_ptr(),
        );
        if res != 0 {
            return Err(SwigError::ReplaceAuthorityProofMismatch.into());
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let _ = values;
    }

    Ok(hash)
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
    fn instruction_payload_accepts_uncompressed_secp256k1_length() {
        let args = ReplaceAuthorityV1Args::new(2, 7, 64);
        let new_authority = [9u8; 64];
        let data = [args.into_bytes().unwrap(), new_authority.as_slice()].concat();

        let parsed = ReplaceAuthorityV1::from_instruction_bytes(&data).unwrap();

        assert_eq!(parsed.new_authority, new_authority);
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

    #[test]
    fn same_signer_returns_the_dedicated_error() {
        let signer = [7u8; 33];
        let error = reject_same_signer(&signer, &signer).unwrap_err();

        assert!(matches!(
            error,
            ProgramError::Custom(code) if code == SwigError::ReplaceAuthoritySameSigner as u32
        ));
        assert!(reject_same_signer(&signer, &[8u8; 33]).is_ok());
    }

    #[test]
    fn uncompressed_secp256k1_normalizes_to_stored_format() {
        let mut uncompressed = [0u8; 64];
        uncompressed[..32].fill(7);
        uncompressed[63] = 3;

        let normalized = normalize_secp256k1_authority(&uncompressed).unwrap();

        assert_eq!(normalized[0], 0x03);
        assert_eq!(&normalized[1..], &uncompressed[..32]);
    }
}
