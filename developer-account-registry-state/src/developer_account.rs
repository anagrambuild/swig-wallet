use no_padding::NoPadding;
use pinocchio::{
    program_error::ProgramError,
    pubkey::{create_program_address, Pubkey},
};
use swig_state::{IntoBytes, Transmutable, TransmutableMut};

use crate::{seeds::developer_account_seeds_with_bump, ID};

pub const DEVELOPER_ACCOUNT_DISCRIMINATOR: u8 = 1;

pub const DEVELOPER_ACCOUNT_VERSION: u8 = 1;

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct DeveloperAccount {
    pub discriminator: u8,
    pub version: u8,
    pub bump: u8,
    pub tier: u8,
    pub _padding: [u8; 4],
    pub developer_account_id: [u8; 32],
    pub signer: [u8; 32],
    pub valid_until: i64,
}

impl Transmutable for DeveloperAccount {
    const LEN: usize = 80;
}

impl TransmutableMut for DeveloperAccount {}

impl IntoBytes for DeveloperAccount {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

const _: () = {
    assert!(core::mem::size_of::<DeveloperAccount>() == DeveloperAccount::LEN);
    assert!(core::mem::align_of::<DeveloperAccount>() == 8);
    assert!(core::mem::offset_of!(DeveloperAccount, developer_account_id) == 8);
    assert!(core::mem::offset_of!(DeveloperAccount, signer) == 40);
    assert!(core::mem::offset_of!(DeveloperAccount, valid_until) == 72);
};

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeveloperTier {
    Free = 0,
    Pro = 1,
    Ultra = 2,
    Enterprise = 3,
}

impl TryFrom<u8> for DeveloperTier {
    type Error = DeveloperAccountError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Free),
            1 => Ok(Self::Pro),
            2 => Ok(Self::Ultra),
            3 => Ok(Self::Enterprise),
            _ => Err(DeveloperAccountError::InvalidTier),
        }
    }
}

impl DeveloperTier {
    pub fn allows(self, required: DeveloperTier) -> bool {
        self >= required
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeveloperAccountError {
    InvalidLength,
    InvalidDiscriminator,
    UnsupportedVersion,
    InvalidPadding,
    InvalidTier,
    ZeroDeveloperAccountId,
    PdaMismatch,
}

impl DeveloperAccount {
    pub fn new(
        bump: u8,
        developer_account_id: [u8; 32],
        tier: DeveloperTier,
        valid_until: i64,
    ) -> Self {
        Self {
            discriminator: DEVELOPER_ACCOUNT_DISCRIMINATOR,
            version: DEVELOPER_ACCOUNT_VERSION,
            bump,
            tier: tier as u8,
            _padding: [0; 4],
            developer_account_id,
            signer: [0; 32],
            valid_until,
        }
    }

    /// The caller checks the account owner before borrowing its data.
    pub fn load(data: &[u8]) -> Result<&Self, DeveloperAccountError> {
        check_layout(data)?;
        // Length and alignment are checked; every field accepts any bit pattern.
        let account = unsafe { Self::load_unchecked(data) }
            .map_err(|_| DeveloperAccountError::InvalidLength)?;
        account.validate()?;
        Ok(account)
    }

    pub fn load_mut(data: &mut [u8]) -> Result<&mut Self, DeveloperAccountError> {
        check_layout(data)?;
        let account = unsafe { Self::load_mut_unchecked(data) }
            .map_err(|_| DeveloperAccountError::InvalidLength)?;
        account.validate()?;
        Ok(account)
    }

    /// Uses the `create_program_address` syscall, so it only runs on-chain.
    pub fn verify_pda(&self, key: &Pubkey) -> Result<(), DeveloperAccountError> {
        let bump = [self.bump];
        let address = create_program_address(
            &developer_account_seeds_with_bump(&self.developer_account_id, &bump),
            &ID,
        )
        .map_err(|_| DeveloperAccountError::PdaMismatch)?;
        if &address != key {
            return Err(DeveloperAccountError::PdaMismatch);
        }

        Ok(())
    }

    pub fn tier(&self) -> Result<DeveloperTier, DeveloperAccountError> {
        DeveloperTier::try_from(self.tier)
    }

    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.valid_until
    }

    pub fn signer_is_set(&self) -> bool {
        self.signer != [0; 32]
    }

    pub fn set_subscription(&mut self, tier: DeveloperTier, valid_until: i64) {
        self.tier = tier as u8;
        self.valid_until = valid_until;
    }

    fn validate(&self) -> Result<(), DeveloperAccountError> {
        if self.discriminator != DEVELOPER_ACCOUNT_DISCRIMINATOR {
            return Err(DeveloperAccountError::InvalidDiscriminator);
        }
        if self.version != DEVELOPER_ACCOUNT_VERSION {
            return Err(DeveloperAccountError::UnsupportedVersion);
        }
        if self._padding != [0; 4] {
            return Err(DeveloperAccountError::InvalidPadding);
        }
        self.tier()?;
        if self.developer_account_id == [0; 32] {
            return Err(DeveloperAccountError::ZeroDeveloperAccountId);
        }

        Ok(())
    }
}

fn check_layout(data: &[u8]) -> Result<(), DeveloperAccountError> {
    if data.len() != DeveloperAccount::LEN {
        return Err(DeveloperAccountError::InvalidLength);
    }
    // A misaligned slice cannot be cast safely; account data on-chain is always
    // aligned.
    let alignment = core::mem::align_of::<DeveloperAccount>();
    if data.as_ptr().align_offset(alignment) != 0 {
        return Err(DeveloperAccountError::InvalidLength);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(8))]
    struct AlignedBuffer([u8; 88]);

    fn sample_account() -> DeveloperAccount {
        DeveloperAccount::new(254, [7u8; 32], DeveloperTier::Pro, 1_000)
    }

    fn buffer_with(account: &DeveloperAccount) -> AlignedBuffer {
        let mut buffer = AlignedBuffer([0u8; 88]);
        buffer.0[..DeveloperAccount::LEN].copy_from_slice(account.into_bytes().unwrap());
        buffer
    }

    fn load_error(buffer: &AlignedBuffer) -> DeveloperAccountError {
        DeveloperAccount::load(&buffer.0[..DeveloperAccount::LEN]).unwrap_err()
    }

    #[test]
    fn test_developer_account_size() {
        assert_eq!(DeveloperAccount::LEN, 80);
        assert_eq!(core::mem::size_of::<DeveloperAccount>(), 80);
        assert_eq!(core::mem::align_of::<DeveloperAccount>(), 8);
    }

    #[test]
    fn test_developer_account_roundtrip() {
        let buffer = buffer_with(&sample_account());
        let loaded = DeveloperAccount::load(&buffer.0[..DeveloperAccount::LEN]).unwrap();

        assert_eq!(loaded.discriminator, DEVELOPER_ACCOUNT_DISCRIMINATOR);
        assert_eq!(loaded.version, DEVELOPER_ACCOUNT_VERSION);
        assert_eq!(loaded.bump, 254);
        assert_eq!(loaded.tier().unwrap(), DeveloperTier::Pro);
        assert_eq!(loaded._padding, [0; 4]);
        assert_eq!(loaded.developer_account_id, [7u8; 32]);
        assert_eq!(loaded.signer, [0u8; 32]);
        assert_eq!(loaded.valid_until, 1_000);
    }

    #[test]
    fn test_new_account_has_no_signer() {
        let mut account = sample_account();
        assert!(!account.signer_is_set());

        account.signer = [3u8; 32];
        assert!(account.signer_is_set());
    }

    #[test]
    fn test_load_mut_applies_the_same_checks() {
        let mut buffer = buffer_with(&sample_account());
        buffer.0[0] = 0;
        assert_eq!(
            DeveloperAccount::load_mut(&mut buffer.0[..DeveloperAccount::LEN]).unwrap_err(),
            DeveloperAccountError::InvalidDiscriminator
        );

        buffer.0[0] = DEVELOPER_ACCOUNT_DISCRIMINATOR;
        let account = DeveloperAccount::load_mut(&mut buffer.0[..DeveloperAccount::LEN]).unwrap();
        account.set_subscription(DeveloperTier::Ultra, 5);
        assert_eq!(buffer.0[3], DeveloperTier::Ultra as u8);
        assert_eq!(buffer.0[4..8], [0; 4]);
        assert_eq!(buffer.0[72..80], 5i64.to_le_bytes());
    }

    #[test]
    fn test_load_rejects_wrong_length() {
        let buffer = buffer_with(&sample_account());
        for len in [0, 1, 79, 81] {
            assert_eq!(
                DeveloperAccount::load(&buffer.0[..len]).unwrap_err(),
                DeveloperAccountError::InvalidLength
            );
        }
    }

    #[test]
    fn test_load_rejects_misaligned_data() {
        let mut buffer = AlignedBuffer([0u8; 88]);
        buffer.0[1..81].copy_from_slice(sample_account().into_bytes().unwrap());
        assert_eq!(
            DeveloperAccount::load(&buffer.0[1..81]).unwrap_err(),
            DeveloperAccountError::InvalidLength
        );
    }

    #[test]
    fn test_load_rejects_wrong_discriminator() {
        for value in [0, 2, 255] {
            let mut buffer = buffer_with(&sample_account());
            buffer.0[0] = value;
            assert_eq!(
                load_error(&buffer),
                DeveloperAccountError::InvalidDiscriminator
            );
        }
    }

    #[test]
    fn test_load_rejects_unsupported_version() {
        for value in [0, 2] {
            let mut buffer = buffer_with(&sample_account());
            buffer.0[1] = value;
            assert_eq!(
                load_error(&buffer),
                DeveloperAccountError::UnsupportedVersion
            );
        }
    }

    #[test]
    fn test_load_rejects_each_non_zero_padding_byte() {
        for offset in 4..8 {
            let mut buffer = buffer_with(&sample_account());
            buffer.0[offset] = 1;
            assert_eq!(load_error(&buffer), DeveloperAccountError::InvalidPadding);
        }
    }

    #[test]
    fn test_load_rejects_invalid_tier() {
        for value in [4, 255] {
            let mut buffer = buffer_with(&sample_account());
            buffer.0[3] = value;
            assert_eq!(load_error(&buffer), DeveloperAccountError::InvalidTier);
        }
    }

    #[test]
    fn test_load_rejects_zero_developer_account_id() {
        let mut buffer = buffer_with(&sample_account());
        buffer.0[8..40].fill(0);
        assert_eq!(
            load_error(&buffer),
            DeveloperAccountError::ZeroDeveloperAccountId
        );
    }

    #[test]
    fn test_is_expired_is_exclusive() {
        let account = sample_account();
        assert!(!account.is_expired(999));
        assert!(account.is_expired(1_000));
        assert!(account.is_expired(1_001));

        let expired = DeveloperAccount::new(254, [7u8; 32], DeveloperTier::Pro, 0);
        assert!(expired.is_expired(0));
        assert!(expired.is_expired(1_700_000_000));
    }

    #[test]
    fn test_tier_allows_matrix() {
        let tiers = [
            DeveloperTier::Free,
            DeveloperTier::Pro,
            DeveloperTier::Ultra,
            DeveloperTier::Enterprise,
        ];
        for (held_index, held) in tiers.iter().enumerate() {
            for (required_index, required) in tiers.iter().enumerate() {
                assert_eq!(held.allows(*required), held_index >= required_index);
            }
        }
    }

    #[test]
    fn test_enum_wire_values() {
        assert_eq!(DeveloperTier::Free as u8, 0);
        assert_eq!(DeveloperTier::Pro as u8, 1);
        assert_eq!(DeveloperTier::Ultra as u8, 2);
        assert_eq!(DeveloperTier::Enterprise as u8, 3);
    }
}
