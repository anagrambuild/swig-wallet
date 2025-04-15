use pinocchio::program_error::ProgramError;

#[derive(Debug)]
#[repr(u32)]
pub enum SwigError {
    // InvalidSwigAccount,
    InvalidSwigAccountDiscriminator = 0,
    // OwnerMismatch,
    OwnerMismatchSwigAccount,
    // AccountNotEmpty,
    AccountNotEmptySwigAccount,
    // NotOnCurve,
    NotOnCurveSwigAccount,
    // ExpectedSigner,
    ExpectedSignerSwigAccount,
    StateError,
    AccountBorrowFailed,
    InvalidAuthorityType,
    Cpi,
    // InvalidSeed,
    InvalidSeedSwigAccount,
    MissingInstructions,
    InvalidAuthorityPayload,
    // InvalidAuthority,
    InvalidAuthorityNotFoundByRoleId,
    InvalidAuthorityMustHaveAtLeastOneAction,
    // InstructionError,
    InstructionExecutionError,
    SerializationError,
    InvalidSwigSignInstructionDataTooShort,
    InvalidSwigRemoveAuthorityInstructionDataTooShort,
    InvalidSwigAddAuthorityInstructionDataTooShort,
    InvalidSwigCreateInstructionDataTooShort,
    InvalidSwigCreateSessionInstructionDataTooShort,
    // InvalidAccounts,
    InvalidAccountsLength,
    InvalidAccountsSwigMustBeFirst,

    InvalidSystemProgram,
    DuplicateAuthority,
    InvalidOperation,
    InvalidAlignment,
}

impl From<SwigError> for ProgramError {
    fn from(e: SwigError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
