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
    /// Account data was modified in unexpected ways during instruction
    /// execution
    AccountDataModifiedUnexpectedly,
    /// Cannot update root authority (ID 0)
    PermissionDeniedCannotUpdateRootAuthority,
    /// Reserved ID prefix, must use deterministic create ID
    ReservedIdPrefix,
    /// SignV1 instruction cannot be used with Swig v2 accounts
    SignV1CannotBeUsedWithSwigV2,
    /// SignV2 instruction cannot be used with Swig v1 accounts
    SignV2CannotBeUsedWithSwigV1,
    /// Token account still has a non-zero balance
    TokenAccountNotEmpty,
    /// Wallet has excess SOL balance (beyond rent-exempt minimum)
    WalletNotEmpty,
    /// Replace authority instruction data is too short
    InvalidSwigReplaceAuthorityInstructionDataTooShort,
    /// Replace authority instruction payload is malformed
    ReplaceAuthorityInvalidPayload,
    /// Existing signer does not match the external recovery proof
    ReplaceAuthorityCurrentSignerMismatch,
    /// Replacement instruction and external recovery state disagree
    ReplaceAuthorityIntentMismatch,
    /// External recovery pending state has not been executed
    ReplaceAuthorityPendingRecoveryNotExecuted,
    /// External recovery signer type does not match the target role
    ReplaceAuthorityTypeMismatch,
    /// Signer length is invalid for the target role
    ReplaceAuthorityInvalidSignerLength,
    /// Signer replacement does not support this signer type
    UnsupportedReplaceAuthorityType,
    /// Set rent claimer instruction data is too short
    InvalidSwigSetRentClaimerInstructionDataTooShort,
    /// Rent claimer can only be set once
    RentClaimerAlreadySet,
    /// Rent claimer pubkey is invalid
    InvalidRentClaimerValue,
    /// Destination does not match configured rent claimer
    InvalidRentClaimerDestination,
    /// V2 sub-account instruction data is too short
    InvalidSwigCreateSubAccountV2InstructionDataTooShort,
    /// Authority lacks the required V2 sub-account permission
    AuthorityCannotCreateSubAccountV2,
    /// Authority lacks a scoped V2 sub-account permission for this operation
    PermissionDeniedMissingSubAccountV2Permission,
    /// V2 sub-account state account owner mismatch
    OwnerMismatchSubAccountV2State,
    /// V2 sub-account Swig ID mismatch
    InvalidSwigSubAccountV2SwigIdMismatch,
    /// V2 sub-account id mismatch between state and instruction
    InvalidSwigSubAccountV2IdMismatch,
    /// V2 sub-account is disabled (kill-switch off)
    InvalidSwigSubAccountV2Disabled,
    /// Invalid seed used for V2 sub-account derivation
    InvalidSeedSubAccountV2,
    /// Replacement signer must differ from the target role's current signer
    ReplaceAuthoritySameSigner,
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
