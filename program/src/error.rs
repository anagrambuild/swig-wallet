use pinocchio::{msg, program_error::ProgramError};
use swig_compact_instructions::InstructionError;
use swig_state::SwigStateError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SwigError {
    #[error("Account {0} Owner mismatch")]
    OwnerMismatch(&'static str),
    #[error("Account {0} is not empty")]
    AccountNotEmpty(&'static str),
    #[error("Account {0} must be on curve")]
    NotOnCurve(&'static str),
    #[error("Account {0} must be a signer")]
    ExpectedSigner(&'static str),
    #[error("State Error: {0:?}")]
    StateError(SwigStateError),
    #[error("Account {0} borrow failed")]
    AccountBorrowFailed(&'static str),
    #[error("Invalid Authority Type")]
    InvalidAuthorityType,
    #[error("Call from CPI not allowed")]
    Cpi,
    #[error("Account {0} Invalid Seeds")]
    InvalidSeed(&'static str),
    #[error("Missing Instructions")]
    MissingInstructions,
    #[error("Invalid Authority Payload")]
    InvalidAuthorityPayload,
    #[error("Invalid Authority")]
    InvalidAuthority,
    #[error("Instruction Error: {0}")]
    InstructionError(InstructionError),
    #[error("Serialization Error")]
    SerializationError,
    #[error("Invalid Accounts {0}")]
    InvalidAccounts(&'static str),
    #[error("Permission Denied {0}")]
    PermissionDenied(&'static str),
    #[error("Invalid System Program")]
    InvalidSystemProgram,
    #[error("Invalid Authority")]
    DuplicateAuthority,
    #[error("Invalid Operation {0}")]
    InvalidOperation(&'static str),
    #[error("Invalid account index")]
    InvalidAccountIndex,
    #[error("Invalid field offset")]
    InvalidFieldOffset,
    #[error("Stack underflow")]
    StackUnderflow,
    #[error("Stack overflow")]
    StackOverflow,
    #[error("Div by zero")]
    DivisionByZero,
    #[error("Invalid jump")]
    InvalidJump,
    #[error("No result")]
    NoResult,
    #[error("Invalid target program")]
    InvalidTargetProgram,
    #[error("Too many instructions")]
    TooManyInstructions,
    #[error("Invalid PDA")]
    InvalidPDA,
    #[error("Plugin rejected transaction")]
    PluginRejectedTransaction,
    #[error("Authority Type does not support sessiond")]
    AuthorityTypeDoesNotSupportSessions,
    #[error("Invalid Session Data")]
    InvalidSessionData,
    #[error("Config already initialized")]
    ConfigAlreadyInitialized,
    #[error("Admin signature required")]
    AdminSignatureRequired,
    #[error("Not the configured admin")]
    NotConfiguredAdmin,
}

impl From<InstructionError> for SwigError {
    fn from(e: InstructionError) -> Self {
        SwigError::InstructionError(e)
    }
}

impl From<SwigError> for u32 {
    fn from(val: SwigError) -> Self {
        match val {
            SwigError::OwnerMismatch { .. } => 0,
            SwigError::AccountNotEmpty { .. } => 1,
            SwigError::NotOnCurve { .. } => 2,
            SwigError::ExpectedSigner { .. } => 3,
            SwigError::StateError { .. } => 4,
            SwigError::AccountBorrowFailed { .. } => 5,
            SwigError::InvalidAuthorityType => 6,
            SwigError::Cpi => 7,
            SwigError::InvalidSeed(_) => 8,
            SwigError::MissingInstructions => 9,
            SwigError::InvalidAuthorityPayload => 10,
            SwigError::InvalidAuthority => 11,
            SwigError::InstructionError(_) => 12,
            SwigError::SerializationError => 13,
            SwigError::InvalidAccounts { .. } => 14,
            SwigError::PermissionDenied { .. } => 15,
            SwigError::InvalidSystemProgram => 16,
            SwigError::DuplicateAuthority => 17,
            SwigError::InvalidOperation { .. } => 18,
            SwigError::AuthorityTypeDoesNotSupportSessions => 19,
            SwigError::InvalidSessionData => 20,
            SwigError::InvalidAccountIndex => 21,
            SwigError::InvalidFieldOffset => 22,
            SwigError::StackUnderflow => 23,
            SwigError::StackOverflow => 24,
            SwigError::DivisionByZero => 25,
            SwigError::InvalidJump => 26,
            SwigError::NoResult => 27,
            SwigError::InvalidTargetProgram => 28,
            SwigError::TooManyInstructions => 29,
            SwigError::InvalidPDA => 30,
            SwigError::PluginRejectedTransaction => 31,
            SwigError::ConfigAlreadyInitialized => 32,
            SwigError::AdminSignatureRequired => 33,
            SwigError::NotConfiguredAdmin => 34,
        }
    }
}

impl From<SwigError> for ProgramError {
    fn from(e: SwigError) -> Self {
        msg!("Error: {:?}", e);
        ProgramError::Custom(e.into())
    }
}

impl From<SwigStateError> for SwigError {
    fn from(e: SwigStateError) -> Self {
        SwigError::StateError(e)
    }
}
