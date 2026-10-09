use pinocchio::program_error::ProgramError;

use crate::authority::{public_key::canonical_public_key, AuthorityType};

pub const DOMAIN: &[u8] = b"swig-reserved-v1";
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
