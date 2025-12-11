//! Error types for the Swig wallet program.
//!
//! This module defines all possible error conditions that can occur during
//! program execution. The errors are categorized into several groups:
//! - Account validation errors
//! - Authority-related errors
//! - Instruction processing errors
//! - Sub-account management errors
//! - Permission and security errors

use pinocchio::program_error::ProgramError;

/// Custom error types for the Swig wallet program.
///
/// Each error variant represents a specific failure condition that can occur
/// during program execution. The errors are assigned unique numeric codes
/// starting from 0.
#[derive(Debug)]
#[repr(u32)]
pub enum SwigError {
    /// Invalid discriminator in Swig account data
    InvalidSwigAccountDiscriminator = 0,
    /// Swig account owner does not match expected value
    OwnerMismatchSwigAccount,
    /// Swig account is not empty when it should be
    AccountNotEmptySwigAccount,
    /// Public key in Swig account is not on the curve
    NotOnCurveSwigAccount,
    /// Expected Swig account to be a signer but it isn't
    ExpectedSignerSwigAccount,
    /// General state error in program execution
    StateError,
    /// Failed to borrow account data
    AccountBorrowFailed,
    /// Invalid authority type specified
    InvalidAuthorityType,
    /// Error during cross-program invocation
    Cpi,
    /// Invalid seed used for Swig account derivation
    InvalidSeedSwigAccount,
    /// Required instructions are missing
    MissingInstructions,
    /// Invalid authority payload format
    InvalidAuthorityPayload,
    /// Authority not found for given role ID
    InvalidAuthorityNotFoundByRoleId,
    /// Authority must have at least one action
    InvalidAuthorityMustHaveAtLeastOneAction,
    /// Error during instruction execution
    InstructionExecutionError,
    /// Error during data serialization
    SerializationError,
    /// Sign instruction data is too short
    InvalidSwigSignInstructionDataTooShort,
    /// Remove authority instruction data is too short
    InvalidSwigRemoveAuthorityInstructionDataTooShort,
    /// Add authority instruction data is too short
    InvalidSwigAddAuthorityInstructionDataTooShort,
    /// Update authority instruction data is too short
    InvalidSwigUpdateAuthorityInstructionDataTooShort,
    /// Create instruction data is too short
    InvalidSwigCreateInstructionDataTooShort,
    /// Create session instruction data is too short
    InvalidSwigCreateSessionInstructionDataTooShort,
    /// Invalid number of accounts provided
    InvalidAccountsLength,
    /// Swig account must be the first account in the list
    InvalidAccountsSwigMustBeFirst,

    /// Invalid system program account
    InvalidSystemProgram,
    /// Authority already exists
    DuplicateAuthority,
    /// Invalid operation attempted
    InvalidOperation,
    /// Data alignment error
    InvalidAlignment,

    // Sub-account related errors
    /// Invalid seed used for sub-account derivation
    InvalidSeedSubAccount,
    /// Insufficient funds for operation
    InsufficientFunds,
    /// Token account owner mismatch
    OwnerMismatchTokenAccount,
    /// Permission denied for operation
    PermissionDenied,
    /// Invalid signature provided
    InvalidSignature,
    /// Instruction data is too short
    InvalidInstructionDataTooShort,
    /// Sub-account owner mismatch
    OwnerMismatchSubAccount,
    /// Sub-account already exists
    SubAccountAlreadyExists,
    /// Authority cannot create sub-account
    AuthorityCannotCreateSubAccount,
    /// Invalid discriminator in sub-account data
    InvalidSwigSubAccountDiscriminator,
    /// Sub-account is disabled
    InvalidSwigSubAccountDisabled,
    /// Sub-account Swig ID mismatch
    InvalidSwigSubAccountSwigIdMismatch,
    /// Sub-account role ID mismatch
    InvalidSwigSubAccountRoleIdMismatch,
    /// Invalid token account owner
    InvalidSwigTokenAccountOwner,
    /// Invalid program scope balance field configuration
    InvalidProgramScopeBalanceFields,
    /// Invalid sub-account index (must be 0-254)
    InvalidSubAccountIndex,
    /// Sub-account index mismatch between action and instruction
    SubAccountIndexMismatch,
    /// Sub-account indices must be sequential (missing previous index)
    SubAccountIndexNotSequential,
    /// Sub-account action not found for the specified index
    SubAccountActionNotFound,
    /// Account data was modified in unexpected ways during instruction
    /// execution
    AccountDataModifiedUnexpectedly,
    /// Cannot update root authority (ID 0)
    PermissionDeniedCannotUpdateRootAuthority,
    /// SignV1 instruction cannot be used with Swig v2 accounts
    SignV1CannotBeUsedWithSwigV2,
    /// SignV2 instruction cannot be used with Swig v1 accounts
    SignV2CannotBeUsedWithSwigV1,
}

/// Implements conversion from SwigError to ProgramError.
///
/// This allows SwigError variants to be used with the `?` operator in
/// functions that return `Result<T, ProgramError>`.
impl From<SwigError> for ProgramError {
    fn from(e: SwigError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
