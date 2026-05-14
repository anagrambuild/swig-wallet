use solana_program::program_error::ProgramError;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    InvalidInstruction = 6_000,
    InvalidAccount,
    InvalidPda,
    InvalidState,
    MissingRequiredSignature,
    GuardianMismatch,
    WalletMismatch,
    AlreadyPending,
    NotPending,
    TimelockNotElapsed,
    OldAuthorityMismatch,
    NewAuthorityMismatch,
}

impl From<RecoveryError> for ProgramError {
    fn from(error: RecoveryError) -> Self {
        ProgramError::Custom(error as u32)
    }
}
