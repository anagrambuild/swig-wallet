//! Program scope action type.
//!
//! This module defines the ProgramScope action type which manages
//! program-specific permissions and limits within the Swig wallet system. It
//! provides functionality for reading and validating program account data,
//! enforcing limits, and managing recurring limits with automatic resets.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{
    constants::PROGRAM_SCOPE_BYTE_SIZE, read_numeric_field, IntoBytes, SwigAuthenticateError,
    Transmutable, TransmutableMut,
};

/// Represents different types of program scope permissions.
#[repr(u8)]
pub enum ProgramScopeType {
    /// Basic program interaction without limits
    Basic = 0,
    /// Program interaction with fixed limits
    Limit = 1,
    /// Program interaction with recurring limits that reset
    RecurringLimit = 2,
}

/// Represents different numeric types that can be read from program data.
///
/// This enum is used to specify the size and type of numeric fields when
/// reading values from program account data.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NumericType {
    /// 8-bit unsigned integer
    U8 = 0,
    /// 32-bit unsigned integer
    U32 = 1,
    /// 64-bit unsigned integer
    U64 = 2,
    /// 128-bit unsigned integer
    U128 = 3,
}

impl NumericType {
    /// Creates a NumericType from a u8 value.
    ///
    /// # Arguments
    /// * `value` - The u8 value to convert
    ///
    /// # Returns
    /// * `Some(NumericType)` - If the value maps to a valid numeric type
    /// * `None` - If the value is invalid
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::U8),
            1 => Some(Self::U32),
            2 => Some(Self::U64),
            3 => Some(Self::U128),
            _ => None,
        }
    }

    /// Returns the maximum value for this numeric type.
    pub fn max_value(&self) -> u128 {
        match self {
            Self::U8 => u8::MAX as u128,
            Self::U32 => u32::MAX as u128,
            Self::U64 => u64::MAX as u128,
            Self::U128 => u128::MAX,
        }
    }
}

impl From<NumericType> for u8 {
    fn from(value: NumericType) -> Self {
        value as u8
    }
}

/// Represents program-specific permissions and limits.
///
/// This struct manages permissions and limits for interacting with specific
/// programs. It supports different types of limits (basic, fixed, recurring)
/// and can read and validate numeric values from program account data.
#[repr(C, align(8))]
#[derive(NoPadding)]
pub struct ProgramScope {
    /// Current amount used in limit tracking
    pub current_amount: u128, // 16 bytes
    /// Maximum limit allowed
    pub limit: u128, // 16 bytes
    /// Time window for recurring limits (in slots)
    pub window: u64, // 8 bytes
    /// Last slot when the limit was reset
    pub last_reset: u64, // 8 bytes
    /// Program ID this scope applies to
    pub program_id: [u8; 32], // 32 bytes
    /// Target account within the program
    pub target_account: [u8; 32], // 32 bytes
    /// Type of program scope (basic, limit, recurring)
    pub scope_type: u64, // 8 bytes
    /// Type of numeric values to read from account data
    pub numeric_type: u64, // 8 bytes
    /// Start index for reading balance field
    pub balance_field_start: u64, // 8 bytes - start index for reading balance
    /// End index for reading balance field
    pub balance_field_end: u64, // 8 bytes - end index for reading balance
}

impl ProgramScope {
    /// Creates a new basic program scope.
    ///
    /// # Arguments
    /// * `program_id` - The program ID this scope applies to
    /// * `target_account` - The target account within the program
    pub fn new_basic(program_id: [u8; 32], target_account: [u8; 32]) -> Self {
        Self {
            program_id,
            target_account,
            scope_type: ProgramScopeType::Basic as u64,
            numeric_type: NumericType::U64 as u64,
            current_amount: 0,
            limit: 0,
            window: 0,
            last_reset: 0,
            balance_field_start: 0,
            balance_field_end: 0,
        }
    }

    /// Creates a new program scope with fixed limits.
    ///
    /// # Arguments
    /// * `program_id` - The program ID this scope applies to
    /// * `target_account` - The target account within the program
    /// * `limit` - The maximum limit allowed
    /// * `numeric_type` - The type of numeric values to read
    pub fn new_limit<T: Into<u128>>(
        program_id: [u8; 32],
        target_account: [u8; 32],
        limit: T,
        numeric_type: NumericType,
    ) -> Self {
        let limit_u128 = limit.into();
        Self {
            program_id,
            target_account,
            scope_type: ProgramScopeType::Limit as u64,
            numeric_type: numeric_type as u64,
            current_amount: 0,
            limit: limit_u128,
            window: 0,
            last_reset: 0,
            balance_field_start: 0,
            balance_field_end: 0,
        }
    }

    /// Creates a new program scope with recurring limits.
    ///
    /// # Arguments
    /// * `program_id` - The program ID this scope applies to
    /// * `target_account` - The target account within the program
    /// * `limit` - The maximum limit allowed per window
    /// * `window` - The time window in slots
    /// * `numeric_type` - The type of numeric values to read
    pub fn new_recurring_limit<T: Into<u128>>(
        program_id: [u8; 32],
        target_account: [u8; 32],
        limit: T,
        window: u64,
        numeric_type: NumericType,
    ) -> Self {
        let limit_u128 = limit.into();
        Self {
            program_id,
            target_account,
            scope_type: ProgramScopeType::RecurringLimit as u64,
            numeric_type: numeric_type as u64,
            current_amount: 0,
            limit: limit_u128,
            window,
            last_reset: 0,
            balance_field_start: 0,
            balance_field_end: 0,
        }
    }

    /// Sets the indices for reading balance fields from account data.
    ///
    /// # Arguments
    /// * `start` - Starting index in the account data
    /// * `end` - Ending index in the account data
    ///
    /// # Returns
    /// * `Ok(())` - If the indices are valid
    /// * `Err(ProgramError)` - If the indices are invalid
    pub fn set_balance_field_indices(&mut self, start: u64, end: u64) -> Result<(), ProgramError> {
        if end <= start || end > 1024 {
            return Err(ProgramError::InvalidArgument);
        }
        self.balance_field_start = start;
        self.balance_field_end = end;
        Ok(())
    }

    /// Reads account balance from raw account data based on the configured
    /// field positions and type.
    ///
    /// This method reads a numeric balance value from the specified field range
    /// within account data according to the configured numeric type. It
    /// supports reading u8, u32, u64, and u128 values and handles their
    /// proper byte assembly.
    ///
    /// # Arguments
    /// * `account_data` - The raw account data bytes to read from
    ///
    /// # Returns
    /// * `Result<u128, ProgramError>` - The parsed balance as u128 or an error
    ///
    /// # Errors
    /// Returns `ProgramError::InvalidAccountData` if:
    /// * The account data isn't long enough for the specified field range
    /// * The field width doesn't match the required size for the numeric type
    pub fn read_account_balance(&self, account_data: &[u8]) -> Result<u128, ProgramError> {
        // Check if we have a valid balance field range
        if self.balance_field_start == 0 && self.balance_field_end == 0 {
            // No balance field configured - use account lamports instead (handled
            // elsewhere)
            return Ok(0);
        }

        // Check if account data is long enough
        if account_data.len() < self.balance_field_end as usize {
            return Err(ProgramError::InvalidAccountData);
        }

        let start = self.balance_field_start as usize;
        let end = self.balance_field_end as usize;

        // Handle Possible NumericType fields
        match NumericType::from_u8(self.numeric_type as u8).ok_or(ProgramError::InvalidArgument)? {
            NumericType::U8 => unsafe {
                read_numeric_field!(
                    account_data,
                    start,
                    end,
                    u8,
                    1,
                    ProgramError::InvalidAccountData
                )
            },
            NumericType::U32 => unsafe {
                read_numeric_field!(
                    account_data,
                    start,
                    end,
                    u32,
                    4,
                    ProgramError::InvalidAccountData
                )
            },
            NumericType::U64 => unsafe {
                read_numeric_field!(
                    account_data,
                    start,
                    end,
                    u64,
                    8,
                    ProgramError::InvalidAccountData
                )
            },
            NumericType::U128 => unsafe {
                read_numeric_field!(
                    account_data,
                    start,
                    end,
                    u128,
                    16,
                    ProgramError::InvalidAccountData
                )
            },
        }
    }

    /// Processes an operation and updates limits if applicable.
    ///
    /// # Arguments
    /// * `amount` - The amount to be used in the operation
    /// * `current_slot` - The current slot number (required for recurring
    ///   limits)
    ///
    /// # Returns
    /// * `Ok(())` - If the operation is allowed
    /// * `Err(ProgramError)` - If the operation would exceed limits
    pub fn run(&mut self, amount: u128, current_slot: Option<u64>) -> Result<(), ProgramError> {
        match self.scope_type as u8 {
            x if x == ProgramScopeType::Basic as u8 => Ok(()),
            x if x == ProgramScopeType::Limit as u8 => {
                // For Limit type, current_amount represents the total spent so far
                // We need to check if adding the new amount would exceed the limit
                if self.current_amount.saturating_add(amount) > self.limit {
                    return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
                }
                self.current_amount = self.current_amount.saturating_add(amount);
                Ok(())
            },
            x if x == ProgramScopeType::RecurringLimit as u8 => {
                let current_slot = current_slot.ok_or(ProgramError::InvalidArgument)?;

                // Check if window has passed and reset the spent amount if needed
                if current_slot - self.last_reset > self.window {
                    // Reset the spent amount to zero for the new window
                    self.current_amount = 0;
                    self.last_reset = current_slot;
                }

                // Check if the requested amount plus what's already spent would exceed the
                // limit
                if self.current_amount.saturating_add(amount) > self.limit {
                    return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
                }

                // Increase the spent amount
                self.current_amount = self.current_amount.saturating_add(amount);
                Ok(())
            },
            _ => Err(SwigAuthenticateError::InvalidDataPayload.into()),
        }
    }

    /// Gets the current amount as a specific numeric type.
    ///
    /// # Type Parameters
    /// * `T` - The target numeric type to convert to
    ///
    /// # Returns
    /// * `Ok(T)` - The current amount converted to type T
    /// * `Err(ProgramError)` - If the conversion fails
    pub fn get_current_amount<T>(&self) -> Result<T, ProgramError>
    where
        T: TryFrom<u128>,
        <T as TryFrom<u128>>::Error: std::fmt::Debug,
    {
        self.current_amount
            .try_into()
            .map_err(|_| ProgramError::InvalidArgument)
    }

    /// Sets the current amount from a numeric value.
    ///
    /// # Arguments
    /// * `amount` - The new amount to set
    ///
    /// # Returns
    /// * `Ok(())` - If the amount was set successfully
    /// * `Err(ProgramError)` - If the amount is invalid for the numeric type
    pub fn set_current_amount<T: Into<u128>>(&mut self, amount: T) -> Result<(), ProgramError> {
        let amount_u128 = amount.into();
        // Validate the amount based on the numeric type
        match NumericType::from_u8(self.numeric_type as u8).ok_or(ProgramError::InvalidArgument)? {
            NumericType::U8 if amount_u128 > u8::MAX as u128 => {
                return Err(ProgramError::InvalidArgument)
            },
            NumericType::U32 if amount_u128 > u32::MAX as u128 => {
                return Err(ProgramError::InvalidArgument)
            },
            NumericType::U64 if amount_u128 > u64::MAX as u128 => {
                return Err(ProgramError::InvalidArgument)
            },
            _ => (), // U128 can handle any value
        }
        self.current_amount = amount_u128;
        Ok(())
    }

    /// Validates that an amount is within the bounds of the configured numeric
    /// type.
    ///
    /// # Arguments
    /// * `amount` - The amount to validate
    ///
    /// # Returns
    /// * `Ok(())` - If the amount is valid
    /// * `Err(ProgramError)` - If the amount exceeds the numeric type's bounds
    pub fn validate_amount<T>(&self, amount: T) -> Result<(), ProgramError>
    where
        T: Into<u128>,
    {
        let amount_u128 = amount.into();
        match NumericType::from_u8(self.numeric_type as u8).ok_or(ProgramError::InvalidArgument)? {
            NumericType::U8 if amount_u128 > u8::MAX as u128 => {
                return Err(ProgramError::InvalidArgument)
            },
            NumericType::U32 if amount_u128 > u32::MAX as u128 => {
                return Err(ProgramError::InvalidArgument)
            },
            NumericType::U64 if amount_u128 > u64::MAX as u128 => {
                return Err(ProgramError::InvalidArgument)
            },
            _ => Ok(()), // U128 can handle any value
        }
    }
}

impl Transmutable for ProgramScope {
    /// Size of the ProgramScope struct in bytes
    const LEN: usize = PROGRAM_SCOPE_BYTE_SIZE;
}

impl TransmutableMut for ProgramScope {}

impl IntoBytes for ProgramScope {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> Actionable<'a> for ProgramScope {
    /// This action represents the ProgramScope permission type
    const TYPE: Permission = Permission::ProgramScope;
    /// Multiple program scopes can exist per role
    const REPEATABLE: bool = true;

    /// Checks if this program scope matches the provided program ID.
    ///
    /// # Arguments
    /// * `data` - The program ID to check against (first 32 bytes)
    fn match_data(&self, data: &[u8]) -> bool {
        data[0..32] == self.program_id
    }
}
