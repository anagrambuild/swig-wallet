// V2 sub-account state account.
use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use crate::{Discriminator, IntoBytes, Transmutable, TransmutableMut};

/// On-chain state for a V2 sub-account.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct SubAccountV2 {
    /// Account type discriminator (`Discriminator::SwigSubAccountV2`)
    pub discriminator: u8,
    /// State PDA bump seed
    pub bump: u8,
    /// Asset PDA bump seed
    pub asset_bump: u8,
    /// Kill-switch for the whole sub-account
    pub enabled: bool,
    /// Sub-account identifier, drawn from the Swig header counter
    pub subacc_id: u32,
    /// ID of the parent Swig account
    pub swig_id: [u8; 32],
    /// Asset PDA pubkey (cached so it need not be re-derived on each op)
    pub sub_account: [u8; 32],
}

impl Transmutable for SubAccountV2 {
    /// 1 (discriminator) + 1 (bump) + 1 (asset_bump) + 1 (enabled) + 4
    /// (subacc_id) + 32 (swig_id) + 32 (sub_account) = 72
    const LEN: usize = 72;
}

impl TransmutableMut for SubAccountV2 {}

impl IntoBytes for SubAccountV2 {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl SubAccountV2 {
    /// Creates a new, enabled V2 sub-account state.
    pub fn new(
        bump: u8,
        asset_bump: u8,
        subacc_id: u32,
        swig_id: [u8; 32],
        sub_account: [u8; 32],
    ) -> Self {
        Self {
            discriminator: Discriminator::SwigSubAccountV2 as u8,
            bump,
            asset_bump,
            enabled: true,
            subacc_id,
            swig_id,
            sub_account,
        }
    }

    /// Validates the account discriminator, failing closed on anything that is
    /// not a V2 sub-account state account.
    pub fn check_discriminator(&self) -> Result<(), ProgramError> {
        match Discriminator::try_from(self.discriminator)? {
            Discriminator::SwigSubAccountV2 => Ok(()),
            _ => Err(ProgramError::InvalidAccountData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sub_account_v2_size() {
        assert_eq!(SubAccountV2::LEN, 72);
        assert_eq!(core::mem::size_of::<SubAccountV2>(), 72);
        assert_eq!(core::mem::align_of::<SubAccountV2>(), 8);
    }

    #[test]
    fn test_sub_account_v2_roundtrip() {
        let state = SubAccountV2::new(254, 253, 7, [3u8; 32], [4u8; 32]);
        assert_eq!(state.discriminator, Discriminator::SwigSubAccountV2 as u8);
        assert_eq!(state.enabled, true);
        assert_eq!(state.subacc_id, 7);

        let bytes = state.into_bytes().unwrap();
        assert_eq!(bytes.len(), 72);

        let loaded = unsafe { SubAccountV2::load_unchecked(bytes).unwrap() };
        assert_eq!(loaded.bump, 254);
        assert_eq!(loaded.asset_bump, 253);
        assert_eq!(loaded.subacc_id, 7);
        assert_eq!(loaded.swig_id, [3u8; 32]);
        assert_eq!(loaded.sub_account, [4u8; 32]);
        loaded.check_discriminator().unwrap();
    }

    #[test]
    fn test_check_discriminator_rejects_foreign() {
        let mut state = SubAccountV2::new(1, 1, 0, [0u8; 32], [0u8; 32]);
        state.discriminator = Discriminator::SwigConfigAccount as u8;
        assert!(state.check_discriminator().is_err());
        state.discriminator = 9; // not a valid discriminator at all
        assert!(state.check_discriminator().is_err());
    }
}
