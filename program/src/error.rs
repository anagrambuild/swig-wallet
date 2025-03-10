use pinocchio::{account_info::AccountInfo, msg, program_error::ProgramError};
use swig_compact_instructions::InstructionError;
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
    #[error("State Error: {0}")]
    StateError(&'static str),
    #[error("Account {0} borrow failed")]
    AccountBorrowFailed(&'static str),
    #[error("Invalid Authority Type")]
    InvalidAuthorityType,
    #[error("Call from CPI not allowed")]
    CPI,
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
    #[error("Insufficient funds for rent exemption")]
    InsufficientFunds,
}

impl From<InstructionError> for SwigError {
    fn from(e: InstructionError) -> Self {
        SwigError::InstructionError(e)
    }
}

impl Into<u32> for SwigError {
    fn into(self) -> u32 {
        match self {
            SwigError::OwnerMismatch { .. } => 0,
            SwigError::AccountNotEmpty { .. } => 1,
            SwigError::NotOnCurve { .. } => 2,
            SwigError::ExpectedSigner { .. } => 3,
            SwigError::StateError { .. } => 4,
            SwigError::AccountBorrowFailed { .. } => 5,
            SwigError::InvalidAuthorityType => 6,
            SwigError::CPI => 7,
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
            SwigError::InsufficientFunds => 19,
        }
    }
}

impl From<SwigError> for ProgramError {
    fn from(e: SwigError) -> Self {
        msg!("Error: {:?}", e);
        ProgramError::Custom(e.into())
    }
}
