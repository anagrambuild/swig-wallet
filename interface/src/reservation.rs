//! Local address derivation for the proposed reservation V1 protocol.
//!
//! These packages require the future `CreateReservedV1` instruction to
//! activate. Deriving an address does not check deployment support or create an
//! account.

use curve25519_dalek::edwards::CompressedEdwardsY;
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    nid::Nid,
};
use solana_sdk::{hash::hashv, pubkey::Pubkey};
use swig_state::{authority::AuthorityType, swig::swig_wallet_address_seeds};

const DOMAIN: &[u8] = b"swig-reserved-v1";
const HEADER_LEN: usize = 67;

#[derive(Debug, thiserror::Error)]
pub enum ReservationError {
    #[error("reservation V1 requires a direct Ed25519, secp256k1, or secp256r1 owner")]
    UnsupportedAuthority,
    #[error("invalid public key for the reservation owner type")]
    InvalidPublicKey,
    #[error("invalid reservation V1 package")]
    InvalidPackage,
    #[error("reservation program ID differs from the expected program")]
    WrongProgram,
    #[error("could not derive a canonical reservation PDA")]
    AddressDerivationFailed,
    #[error("public key validation failed")]
    Cryptography(#[from] openssl::error::ErrorStack),
}

/// The default is index zero. An explicit salt and an index are mutually
/// exclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationAddressOptions {
    AccountIndex(u32),
    Salt([u8; 32]),
}

impl Default for ReservationAddressOptions {
    fn default() -> Self {
        Self::AccountIndex(0)
    }
}

/// A validated, canonically encoded activation package. Contains no private
/// keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationV1 {
    program_id: Pubkey,
    package_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservationAddresses {
    pub commitment: [u8; 32],
    pub swig_address: Pubkey,
    pub swig_bump: u8,
    pub wallet_address: Pubkey,
    pub wallet_bump: u8,
}

impl ReservationV1 {
    /// Creates a package without RPC, a transaction, or an implicit random
    /// salt.
    ///
    /// Ed25519 keys are canonical 32-byte points and must not have small order.
    /// SEC1 keys may be compressed (33 bytes) or
    /// uncompressed (65 bytes); k1 also accepts the existing SDK's raw 64-byte
    /// representation. Both curves are validated and encoded as compressed
    /// SEC1.
    pub fn new(
        program_id: Pubkey,
        authority_type: AuthorityType,
        public_key: &[u8],
        address_options: ReservationAddressOptions,
    ) -> Result<Self, ReservationError> {
        let public_key = normalize_public_key(authority_type, public_key)?;
        let salt = match address_options {
            ReservationAddressOptions::AccountIndex(index) => {
                let mut salt = [0; 32];
                salt[28..].copy_from_slice(&index.to_le_bytes());
                salt
            },
            ReservationAddressOptions::Salt(salt) => salt,
        };
        let mut package_bytes = Vec::with_capacity(HEADER_LEN + public_key.len());
        package_bytes.push(1);
        package_bytes.extend_from_slice(program_id.as_ref());
        package_bytes.extend_from_slice(&salt);
        package_bytes.extend_from_slice(&(authority_type as u16).to_le_bytes());
        package_bytes.extend_from_slice(&public_key);
        Ok(Self {
            program_id,
            package_bytes,
        })
    }

    /// Imports exactly one canonical package for a caller-selected program.
    /// Normalization is only for constructor input; serialized packages must
    /// already have the exact V1 lengths, authority tags, and compressed keys.
    /// Compare the derived wallet address with the originally verified address
    /// before accepting a restored package.
    pub fn from_bytes(bytes: &[u8], expected_program_id: Pubkey) -> Result<Self, ReservationError> {
        if !matches!(bytes.len(), 99 | 100) || bytes[0] != 1 {
            return Err(ReservationError::InvalidPackage);
        }
        if &bytes[1..33] != expected_program_id.as_ref() {
            return Err(ReservationError::WrongProgram);
        }
        let authority_type = match u16::from_le_bytes([bytes[65], bytes[66]]) {
            1 if bytes.len() == 99 => AuthorityType::Ed25519,
            3 if bytes.len() == 100 => AuthorityType::Secp256k1,
            5 if bytes.len() == 100 => AuthorityType::Secp256r1,
            _ => return Err(ReservationError::InvalidPackage),
        };
        let salt = bytes[33..65]
            .try_into()
            .map_err(|_| ReservationError::InvalidPackage)?;
        let package = Self::new(
            expected_program_id,
            authority_type,
            &bytes[HEADER_LEN..],
            ReservationAddressOptions::Salt(salt),
        )?;
        if package.as_bytes() != bytes {
            return Err(ReservationError::InvalidPackage);
        }
        Ok(package)
    }

    /// The immutable 99-byte Ed25519 or 100-byte k1/r1 activation package.
    pub fn as_bytes(&self) -> &[u8] {
        &self.package_bytes
    }

    /// Hashes the domain plus package and derives both PDAs with canonical
    /// bumps.
    pub fn addresses(&self) -> Result<ReservationAddresses, ReservationError> {
        let commitment = hashv(&[DOMAIN, &self.package_bytes]).to_bytes();
        let (swig_address, swig_bump) =
            Pubkey::try_find_program_address(&[DOMAIN, &commitment], &self.program_id)
                .ok_or(ReservationError::AddressDerivationFailed)?;
        let (wallet_address, wallet_bump) = Pubkey::try_find_program_address(
            &swig_wallet_address_seeds(swig_address.as_ref()),
            &self.program_id,
        )
        .ok_or(ReservationError::AddressDerivationFailed)?;
        Ok(ReservationAddresses {
            commitment,
            swig_address,
            swig_bump,
            wallet_address,
            wallet_bump,
        })
    }
}

fn normalize_public_key(
    authority_type: AuthorityType,
    public_key: &[u8],
) -> Result<Vec<u8>, ReservationError> {
    let curve = match authority_type {
        AuthorityType::Ed25519 => {
            let key: [u8; 32] = public_key
                .try_into()
                .map_err(|_| ReservationError::InvalidPublicKey)?;
            let point = CompressedEdwardsY(key)
                .decompress()
                .ok_or(ReservationError::InvalidPublicKey)?;
            if point.compress().to_bytes() != key || point.is_small_order() {
                return Err(ReservationError::InvalidPublicKey);
            }
            return Ok(key.to_vec());
        },
        AuthorityType::Secp256k1 => Nid::SECP256K1,
        AuthorityType::Secp256r1 => Nid::X9_62_PRIME256V1,
        _ => return Err(ReservationError::UnsupportedAuthority),
    };
    let sec1 = match public_key {
        [2 | 3, ..] if public_key.len() == 33 => public_key.to_vec(),
        [4, ..] if public_key.len() == 65 => public_key.to_vec(),
        _ if authority_type == AuthorityType::Secp256k1 && public_key.len() == 64 => {
            [&[4], public_key].concat()
        },
        _ => return Err(ReservationError::InvalidPublicKey),
    };
    let group = EcGroup::from_curve_name(curve)?;
    let mut context = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, &sec1, &mut context)
        .map_err(|_| ReservationError::InvalidPublicKey)?;
    EcKey::from_public_key(&group, &point)?
        .check_key()
        .map_err(|_| ReservationError::InvalidPublicKey)?;
    Ok(point.to_bytes(&group, PointConversionForm::COMPRESSED, &mut context)?)
}
