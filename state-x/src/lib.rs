//! State-X is a crate that provides state management and authentication
//! functionality for the Swig wallet system. It includes account management,
//! role-based access control, and various authentication mechanisms.

//#![no_std]
use pinocchio::program_error::ProgramError;

pub mod action;
pub mod authority;
pub mod constants;
pub mod role;
pub mod swig;
pub mod util;

/// Represents the type discriminator for different account types in the system.
#[repr(u8)]
pub enum Discriminator {
    /// Represents a main Swig account
    SwigAccount,
    /// Represents a sub-account within a Swig account
    SwigSubAccount,
}

impl From<u8> for Discriminator {
    fn from(discriminator: u8) -> Self {
        match discriminator {
            0 => Discriminator::SwigAccount,
            1 => Discriminator::SwigSubAccount,
            _ => panic!("Invalid discriminator"),
        }
    }
}

/// Represents the possible states of a stake account in the system.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum StakeAccountState {
    /// Account has not been initialized
    Uninitialized,
    /// Account has been initialized but not yet staked
    Initialized,
    /// Account is actively staking
    Stake,
    /// Account is being used as a rewards pool
    RewardsPool,
}

/// Classifies different types of accounts within the system and their
/// associated data.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum AccountClassification {
    /// No specific classification
    None,
    /// A main Swig account with its lamport balance
    ThisSwig {
        /// The account's lamport balance
        lamports: u64,
    },
    /// A Swig token account with its token balance
    SwigTokenAccount {
        /// The token balance in the account
        balance: u64,
    },
    /// A Swig stake account with its state and balance
    SwigStakeAccount {
        /// The current state of the stake account
        state: StakeAccountState,
        /// The staked balance
        balance: u64,
    },
    /// A program scope account with role information
    ProgramScope {
        /// Index of the role associated with this scope
        role_index: u8,
        /// Balance in the program scope
        balance: u128,
    },
    /// A Swig sub-account with its lamport balance
    SwigSubAccount {
        /// The sub-account's lamport balance
        lamports: u64,
    },
}

/// Error types related to state management operations.
pub enum SwigStateError {
    /// Account data is invalid or corrupted
    InvalidAccountData = 1000,
    /// Action data is invalid or malformed
    InvalidActionData,
    /// Authority data is invalid or malformed
    InvalidAuthorityData,
    /// Role data is invalid or malformed
    InvalidRoleData,
    /// Swig account data is invalid or malformed
    InvalidSwigData,
    /// Specified role could not be found
    RoleNotFound,
    /// Error loading permissions
    PermissionLoadError,
}

/// Error types related to authentication operations.
pub enum SwigAuthenticateError {
    /// Invalid authority provided
    InvalidAuthority = 3000,
    /// Invalid authority payload format
    InvalidAuthorityPayload,
    /// Invalid data payload format
    InvalidDataPayload,
    /// Missing Ed25519 authority account
    InvalidAuthorityEd25519MissingAuthorityAccount,
    /// Authority does not support session-based authentication
    AuthorityDoesNotSupportSessionBasedAuth,
    /// Generic permission denied error
    PermissionDenied,
    /// Missing required permission
    PermissionDeniedMissingPermission,
    /// Token account permission check failed
    PermissionDeniedTokenAccountPermissionFailure,
    /// Token account has an active delegate
    PermissionDeniedTokenAccountDelegatePresent,
    /// Token account is not initialized
    PermissionDeniedTokenAccountNotInitialized,
    /// No permission to manage authority
    PermissionDeniedToManageAuthority,
    /// Insufficient balance for operation
    PermissionDeniedInsufficientBalance,
    /// Cannot remove root authority
    PermissionDeniedCannotRemoveRootAuthority,
    /// Session has expired
    PermissionDeniedSessionExpired,
    /// Invalid Secp256k1 signature
    PermissionDeniedSecp256k1InvalidSignature,
    /// Secp256k1 signature age is invalid
    PermissionDeniedSecp256k1InvalidSignatureAge,
    /// Secp256k1 signature has been reused
    PermissionDeniedSecp256k1SignatureReused,
    /// Invalid Secp256k1 hash
    PermissionDeniedSecp256k1InvalidHash,
    /// Stake account is in an invalid state
    PermissionDeniedStakeAccountInvalidState,
    /// Cannot reuse session key
    InvalidSessionKeyCannotReuseSessionKey,
    /// Invalid session duration
    InvalidSessionDuration,
    /// Authorization lock violation - transfer would reduce balance below locked amount
    PermissionDeniedAuthorizationLockViolation,
}

impl From<SwigStateError> for ProgramError {
    fn from(e: SwigStateError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

impl From<SwigAuthenticateError> for ProgramError {
    fn from(e: SwigAuthenticateError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

/// Marker trait for types that can be safely cast from a raw pointer.
///
/// Types implementing this trait must guarantee that the cast is safe,
/// ensuring proper field alignment and absence of padding bytes.
pub trait Transmutable: Sized {
    /// The length of the type in bytes.
    ///
    /// Must equal the total size of all fields in the type.
    const LEN: usize;

    /// Creates a reference to `Self` from a byte slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `bytes` contains a valid representation of
    /// the implementing type.
    #[inline(always)]
    unsafe fn load_unchecked(bytes: &[u8]) -> Result<&Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(&*(bytes.as_ptr() as *const Self))
    }
}

/// Marker trait for types that can be mutably cast from a raw pointer.
///
/// Types implementing this trait must guarantee that the mutable cast is safe,
/// ensuring proper field alignment and absence of padding bytes.
pub trait TransmutableMut: Transmutable {
    /// Creates a mutable reference to `Self` from a mutable byte slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `bytes` contains a valid representation of
    /// the implementing type.
    #[inline(always)]
    unsafe fn load_mut_unchecked(bytes: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(&mut *(bytes.as_mut_ptr() as *mut Self))
    }
}

/// Trait for types that can be converted into a byte slice representation.
pub trait IntoBytes {
    /// Converts the implementing type into a byte slice.
    fn into_bytes(&self) -> Result<&[u8], ProgramError>;
}
