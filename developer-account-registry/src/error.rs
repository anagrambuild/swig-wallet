use developer_account_registry_state::DeveloperAccountError;
use pinocchio::program_error::ProgramError;

// Codes are a public contract; append new variants only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DeveloperAccountRegistryError {
    InvalidRegistryAdmin = 0,
    MissingRegistryAdminSignature,
    PayerMustBeWritableSigner,
    InvalidSystemProgram,
    InvalidInstructionDataLength,
    InvalidInstructionPadding,
    InvalidDeveloperAccountId,
    InvalidSigner,
    InvalidTier,
    InvalidAccountState,
    InvalidDeveloperAccountPda,
    InvalidAccountOwner,
    AccountNotWritable,
    InvalidAccountLength,
    InvalidDiscriminator,
    UnsupportedVersion,
    InvalidAccountPadding,
}

impl From<DeveloperAccountError> for DeveloperAccountRegistryError {
    fn from(e: DeveloperAccountError) -> Self {
        match e {
            DeveloperAccountError::InvalidLength => Self::InvalidAccountLength,
            DeveloperAccountError::InvalidDiscriminator => Self::InvalidDiscriminator,
            DeveloperAccountError::UnsupportedVersion => Self::UnsupportedVersion,
            DeveloperAccountError::InvalidPadding => Self::InvalidAccountPadding,
            DeveloperAccountError::InvalidTier => Self::InvalidTier,
            DeveloperAccountError::ZeroDeveloperAccountId => Self::InvalidDeveloperAccountId,
            DeveloperAccountError::PdaMismatch => Self::InvalidDeveloperAccountPda,
        }
    }
}

impl From<DeveloperAccountRegistryError> for ProgramError {
    fn from(e: DeveloperAccountRegistryError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes_are_stable() {
        use DeveloperAccountRegistryError::*;
        let expected = [
            (InvalidRegistryAdmin, 0),
            (MissingRegistryAdminSignature, 1),
            (PayerMustBeWritableSigner, 2),
            (InvalidSystemProgram, 3),
            (InvalidInstructionDataLength, 4),
            (InvalidInstructionPadding, 5),
            (InvalidDeveloperAccountId, 6),
            (InvalidSigner, 7),
            (InvalidTier, 8),
            (InvalidAccountState, 9),
            (InvalidDeveloperAccountPda, 10),
            (InvalidAccountOwner, 11),
            (AccountNotWritable, 12),
            (InvalidAccountLength, 13),
            (InvalidDiscriminator, 14),
            (UnsupportedVersion, 15),
            (InvalidAccountPadding, 16),
        ];
        for (error, code) in expected {
            assert_eq!(error as u32, code, "{error:?}");
        }
    }
}
