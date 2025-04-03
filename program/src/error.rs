use pinocchio::{msg, program_error::ProgramError};
use swig_compact_instructions::InstructionError;

#[derive(Debug)]
#[repr(u32)]
pub enum SwigError {
    //InvalidSwigAccount,
    InvalidSwigAccountDiscriminator,
    //OwnerMismatch,
    OwnerMismatchSwigAccount,
    //AccountNotEmpty,
    AccountNotEmptySwigAccount,
    //NotOnCurve,
    NotOnCurveSwigAccount,
    //ExpectedSigner,
    ExpectedSignerSwigAccount,
    StateError,
    AccountBorrowFailed,
    InvalidAuthorityType,
    Cpi,
    //InvalidSeed,
    InvalidSeedSwigAccount,
    MissingInstructions,
    InvalidAuthorityPayload,
    //InvalidAuthority,
    InvalidAuthorityNotFoundByRoleId,
    //InstructionError,
    InstructionExecutionError,
    SerializationError,
    //InvalidAccounts,
    InvalidAccountsSwigMustBeFirst,
    // PermissionDenied,
    PermissionDeniedMissingPermission,
    PermissionDeniedTokenAccountPermissionFailure,
    PermissionDeniedTokenAccountDelegatePresent,
    PermissionDeniedTokenAccountNotInitialized,
    PermissionDeniedToManageAuthority,
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
