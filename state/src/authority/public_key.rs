use p256::elliptic_curve::sec1::ToEncodedPoint;
use pinocchio::program_error::ProgramError;
use solana_curve25519::{
    edwards::{multiply_edwards, PodEdwardsPoint},
    scalar::PodScalar,
};

use super::AuthorityType;

/// Validates a direct owner and returns its canonical identity. Ed25519 uses
/// the first 32 bytes; secp identities use all 33 bytes. Runtime authority
/// storage (including odometers) remains owned by `Authority::set_into_bytes`.
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
