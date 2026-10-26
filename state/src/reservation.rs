use p256::elliptic_curve::sec1::ToEncodedPoint;
use pinocchio::program_error::ProgramError;
use solana_curve25519::{
    edwards::{multiply_edwards, PodEdwardsPoint},
    scalar::PodScalar,
};

use crate::authority::AuthorityType;

/// "Reserve": the commitment domain and config PDA prefix.
pub const DOMAIN: &[u8] = b"rsv";
pub const HEADER_LEN: usize = 67;

/// Both client import and activation accept exactly the same V1 wire format.
/// This decodes unaligned bytes without casting to a stored authority layout.
pub fn validate_package(
    bytes: &[u8],
    expected_program_id: &[u8; 32],
) -> Result<AuthorityType, ProgramError> {
    if !matches!(bytes.len(), 99 | 100) || bytes[0] != 1 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if &bytes[1..33] != expected_program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    let authority_type = AuthorityType::try_from(u16::from_le_bytes([bytes[65], bytes[66]]))?;
    let identity_len = match authority_type {
        AuthorityType::Ed25519 => 32,
        AuthorityType::Secp256k1 | AuthorityType::Secp256r1 => 33,
        _ => return Err(ProgramError::InvalidInstructionData),
    };
    if bytes.len() != HEADER_LEN + identity_len {
        return Err(ProgramError::InvalidInstructionData);
    }
    let public_key = &bytes[HEADER_LEN..];
    let canonical = canonical_public_key(authority_type, public_key)?;
    if public_key != &canonical[..identity_len] {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(authority_type)
}

/// Validates a direct owner and returns its canonical identity. Ed25519 uses
/// the first 32 bytes; secp identities use all 33 bytes. Runtime authority
/// storage (including odometers) remains owned by `Authority::set_into_bytes`.
/// A reservation's first authority must be a direct signing key, so unlike
/// CreateV1, Ed25519 PDA authorities are intentionally excluded here. Key
/// validation does not prove possession of the private key; activation only
/// requires the payer's signature.
pub fn canonical_public_key(
    authority_type: AuthorityType,
    public_key: &[u8],
) -> Result<[u8; 33], ProgramError> {
    let invalid = ProgramError::InvalidInstructionData;
    let mut canonical = [0; 33];
    match authority_type {
        AuthorityType::Ed25519 => {
            let key = <[u8; 32]>::try_from(public_key).map_err(|_| invalid.clone())?;
            let mut one = [0; 32];
            one[0] = 1;
            let point = PodEdwardsPoint(key);
            // Multiplication validates the point and returns its canonical
            // encoding. Solana uses native syscalls for these operations.
            let normalized = multiply_edwards(&PodScalar(one), &point).ok_or(invalid.clone())?;
            if normalized.0 != key {
                return Err(invalid);
            }
            let mut eight = [0; 32];
            eight[0] = 8;
            let cofactored = multiply_edwards(&PodScalar(eight), &point).ok_or(invalid.clone())?;
            if cofactored.0 == one {
                return Err(invalid);
            }
            canonical[..32].copy_from_slice(&key);
        },
        AuthorityType::Secp256k1 => {
            if !matches!(public_key, [2 | 3, ..] if public_key.len() == 33)
                && !matches!(public_key, [4, ..] if public_key.len() == 65)
                && public_key.len() != 64
            {
                return Err(invalid);
            }
            canonical = libsecp256k1::PublicKey::parse_slice(public_key, None)
                .map_err(|_| invalid)?
                .serialize_compressed();
        },
        AuthorityType::Secp256r1 => {
            if !matches!(public_key, [2 | 3, ..] if public_key.len() == 33)
                && !matches!(public_key, [4, ..] if public_key.len() == 65)
            {
                return Err(invalid);
            }
            let point = p256::PublicKey::from_sec1_bytes(public_key).map_err(|_| invalid)?;
            canonical.copy_from_slice(point.to_encoded_point(true).as_bytes());
        },
        _ => return Err(invalid),
    }
    Ok(canonical)
}
