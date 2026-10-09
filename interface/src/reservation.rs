//! Local address reservation and permissionless wallet activation.

use solana_sdk::{
    hash::hashv,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
use swig_state::{
    authority::{public_key::canonical_public_key, AuthorityType},
    reservation::{validate_package, DOMAIN, HEADER_LEN},
    swig::swig_wallet_address_seeds,
};

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

/// Binary activation package. Consumers revalidate its public bytes before use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationV1 {
    pub package_bytes: Vec<u8>,
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
        let identity_len = match authority_type {
            AuthorityType::Ed25519 => 32,
            AuthorityType::Secp256k1 | AuthorityType::Secp256r1 => 33,
            _ => return Err(ReservationError::UnsupportedAuthority),
        };
        let canonical = canonical_public_key(authority_type, public_key)
            .map_err(|_| ReservationError::InvalidPublicKey)?;
        let public_key = &canonical[..identity_len];
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
        package_bytes.extend_from_slice(public_key);
        Ok(Self { package_bytes })
    }

    /// Imports exactly one canonical package for a caller-selected program.
    /// Normalization is only for constructor input; serialized packages must
    /// already have the exact V1 lengths, authority tags, and compressed keys.
    /// Compare the derived wallet address with the originally verified address
    /// before accepting a restored package.
    pub fn from_bytes(bytes: &[u8], expected_program_id: Pubkey) -> Result<Self, ReservationError> {
        validate_package(bytes, &expected_program_id.to_bytes()).map_err(|_| {
            if bytes
                .get(1..33)
                .is_some_and(|program| program != expected_program_id.as_ref())
            {
                ReservationError::WrongProgram
            } else {
                ReservationError::InvalidPackage
            }
        })?;
        Ok(Self {
            package_bytes: bytes.to_vec(),
        })
    }

    /// Hashes the domain plus package and derives both PDAs with canonical
    /// bumps.
    pub fn addresses(&self) -> Result<ReservationAddresses, ReservationError> {
        let program_bytes: [u8; 32] = self
            .package_bytes
            .get(1..33)
            .ok_or(ReservationError::InvalidPackage)?
            .try_into()
            .map_err(|_| ReservationError::InvalidPackage)?;
        validate_package(&self.package_bytes, &program_bytes)
            .map_err(|_| ReservationError::InvalidPackage)?;
        let program_id = Pubkey::new_from_array(program_bytes);
        let commitment = hashv(&[DOMAIN, &self.package_bytes]).to_bytes();
        let (swig_address, swig_bump) =
            Pubkey::try_find_program_address(&[DOMAIN, &commitment], &program_id)
                .ok_or(ReservationError::AddressDerivationFailed)?;
        let (wallet_address, wallet_bump) = Pubkey::try_find_program_address(
            &swig_wallet_address_seeds(swig_address.as_ref()),
            &program_id,
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

    /// Builds `CreateReservedV1` and returns its validated addresses so callers
    /// can open the wallet without repeating validation or PDA derivation.
    /// Only the external payer signs. The program
    /// fixes role zero to this owner with `All`; callers cannot inject actions.
    /// Set a transaction compute budget of 600,000 units for P-256 validation.
    pub fn create_instruction(
        &self,
        payer: Pubkey,
    ) -> Result<(Instruction, ReservationAddresses), ReservationError> {
        let addresses = self.addresses()?;
        let program_id = Pubkey::new_from_array(
            self.package_bytes[1..33]
                .try_into()
                .map_err(|_| ReservationError::InvalidPackage)?,
        );
        let mut data = (swig::instruction::SwigInstruction::CreateReservedV1 as u16)
            .to_le_bytes()
            .to_vec();
        data.extend_from_slice(&self.package_bytes);
        let instruction = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(addresses.swig_address, false),
                AccountMeta::new(payer, true),
                AccountMeta::new(addresses.wallet_address, false),
                AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            ],
            data,
        };
        Ok((instruction, addresses))
    }
}
