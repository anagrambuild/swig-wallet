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
///
/// Note: We use `[u8; 16]` instead of `u128` for `current_amount` and `limit`
/// to ensure the struct only requires 8-byte alignment (matching Solana's
/// account data alignment guarantee). Using `u128` would require 16-byte
/// alignment, which cannot be guaranteed when loading from arbitrary offsets
/// within account data on client side. The values are stored in little-endian
/// format and can be accessed via the accessor methods.
#[repr(C, align(8))]
#[derive(NoPadding)]
pub struct ProgramScope {
    /// Current amount used in limit tracking (stored as little-endian bytes)
    pub current_amount: [u8; 16], // 16 bytes
    /// Maximum limit allowed (stored as little-endian bytes)
    pub limit: [u8; 16], // 16 bytes
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
    /// Gets the current_amount field as a u128 value.
    #[inline(always)]
    pub fn get_current_amount_value(&self) -> u128 {
        u128::from_le_bytes(self.current_amount)
    }

    /// Sets the current_amount field from a u128 value.
    #[inline(always)]
    pub fn set_current_amount_value(&mut self, value: u128) {
        self.current_amount = value.to_le_bytes();
    }

    /// Gets the limit field as a u128 value.
    #[inline(always)]
    pub fn get_limit_value(&self) -> u128 {
        u128::from_le_bytes(self.limit)
    }

    /// Sets the limit field from a u128 value.
    #[inline(always)]
    pub fn set_limit_value(&mut self, value: u128) {
        self.limit = value.to_le_bytes();
    }

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
            current_amount: [0; 16],
            limit: [0; 16],
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
            current_amount: [0; 16],
            limit: limit_u128.to_le_bytes(),
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
            current_amount: [0; 16],
            limit: limit_u128.to_le_bytes(),
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
        let current_amount = self.get_current_amount_value();
        let limit = self.get_limit_value();

        match self.scope_type as u8 {
            x if x == ProgramScopeType::Basic as u8 => Ok(()),
            x if x == ProgramScopeType::Limit as u8 => {
                // For Limit type, current_amount represents the total spent so far
                // We need to check if adding the new amount would exceed the limit
                if current_amount.saturating_add(amount) > limit {
                    return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
                }
                self.set_current_amount_value(current_amount.saturating_add(amount));
                Ok(())
            },
            x if x == ProgramScopeType::RecurringLimit as u8 => {
                let current_slot = current_slot.ok_or(ProgramError::InvalidArgument)?;
                let mut current_amount = current_amount;

                // Check if window has passed and reset the spent amount if needed
                if current_slot.saturating_sub(self.last_reset) > self.window {
                    // Reset the spent amount to zero for the new window
                    current_amount = 0;
                    // reset the last reset to the start of the current window
                    self.last_reset = (current_slot / self.window) * self.window;
                }

                // Check if the requested amount plus what's already spent would exceed the
                // limit
                if current_amount.saturating_add(amount) > limit {
                    return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
                }

                // Increase the spent amount
                self.set_current_amount_value(current_amount.saturating_add(amount));
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
        self.get_current_amount_value()
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
        self.set_current_amount_value(amount_u128);
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

#[cfg(test)]
mod tests {
    use super::*;

    // Basic u128 <-> [u8; 16] Conversion Tests

    #[test]
    fn test_u128_zero_roundtrip() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);
        assert_eq!(scope.get_current_amount_value(), 0);
        assert_eq!(scope.get_limit_value(), 0);

        scope.set_current_amount_value(0);
        scope.set_limit_value(0);
        assert_eq!(scope.get_current_amount_value(), 0);
        assert_eq!(scope.get_limit_value(), 0);
    }

    #[test]
    fn test_u128_one_roundtrip() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);
        scope.set_current_amount_value(1);
        scope.set_limit_value(1);
        assert_eq!(scope.get_current_amount_value(), 1);
        assert_eq!(scope.get_limit_value(), 1);
    }

    #[test]
    fn test_u128_max_roundtrip() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);
        scope.set_current_amount_value(u128::MAX);
        scope.set_limit_value(u128::MAX);
        assert_eq!(scope.get_current_amount_value(), u128::MAX);
        assert_eq!(scope.get_limit_value(), u128::MAX);
    }

    #[test]
    fn test_u128_u64_max_roundtrip() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);
        let value = u64::MAX as u128;
        scope.set_current_amount_value(value);
        scope.set_limit_value(value);
        assert_eq!(scope.get_current_amount_value(), value);
        assert_eq!(scope.get_limit_value(), value);
    }

    #[test]
    fn test_u128_u64_max_plus_one_roundtrip() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);
        let value = (u64::MAX as u128) + 1;
        scope.set_current_amount_value(value);
        scope.set_limit_value(value);
        assert_eq!(scope.get_current_amount_value(), value);
        assert_eq!(scope.get_limit_value(), value);
    }

    #[test]
    fn test_u128_powers_of_two() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);
        for i in 0..128 {
            let value = 1u128 << i;
            scope.set_current_amount_value(value);
            scope.set_limit_value(value);
            assert_eq!(
                scope.get_current_amount_value(),
                value,
                "Failed for power of 2: 2^{}",
                i
            );
            assert_eq!(
                scope.get_limit_value(),
                value,
                "Failed for power of 2: 2^{}",
                i
            );
        }
    }

    #[test]
    fn test_u128_powers_of_two_minus_one() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);
        for i in 1..128 {
            let value = (1u128 << i) - 1;
            scope.set_current_amount_value(value);
            scope.set_limit_value(value);
            assert_eq!(
                scope.get_current_amount_value(),
                value,
                "Failed for 2^{} - 1",
                i
            );
            assert_eq!(scope.get_limit_value(), value, "Failed for 2^{} - 1", i);
        }
    }

    #[test]
    fn test_u128_boundary_values() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);

        // Test values around u64 boundary
        let boundary_values = [
            u64::MAX as u128 - 1,
            u64::MAX as u128,
            u64::MAX as u128 + 1,
            u64::MAX as u128 + 2,
            // Test values around u32 boundary
            u32::MAX as u128 - 1,
            u32::MAX as u128,
            u32::MAX as u128 + 1,
            // High bits only
            (u64::MAX as u128) << 64,
            ((u64::MAX as u128) << 64) + 1,
            ((u64::MAX as u128) << 64) + (u64::MAX as u128),
        ];

        for value in boundary_values {
            scope.set_current_amount_value(value);
            scope.set_limit_value(value);
            assert_eq!(
                scope.get_current_amount_value(),
                value,
                "Failed for boundary value: {}",
                value
            );
            assert_eq!(
                scope.get_limit_value(),
                value,
                "Failed for boundary value: {}",
                value
            );
        }
    }

    // Byte Layout Verification Tests

    #[test]
    fn test_byte_layout_little_endian() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);

        // Set a known value and verify byte layout
        scope.set_current_amount_value(0x0102030405060708090A0B0C0D0E0F10u128);

        // In little-endian, the least significant byte comes first
        assert_eq!(scope.current_amount[0], 0x10);
        assert_eq!(scope.current_amount[1], 0x0F);
        assert_eq!(scope.current_amount[2], 0x0E);
        assert_eq!(scope.current_amount[3], 0x0D);
        assert_eq!(scope.current_amount[4], 0x0C);
        assert_eq!(scope.current_amount[5], 0x0B);
        assert_eq!(scope.current_amount[6], 0x0A);
        assert_eq!(scope.current_amount[7], 0x09);
        assert_eq!(scope.current_amount[8], 0x08);
        assert_eq!(scope.current_amount[9], 0x07);
        assert_eq!(scope.current_amount[10], 0x06);
        assert_eq!(scope.current_amount[11], 0x05);
        assert_eq!(scope.current_amount[12], 0x04);
        assert_eq!(scope.current_amount[13], 0x03);
        assert_eq!(scope.current_amount[14], 0x02);
        assert_eq!(scope.current_amount[15], 0x01);
    }

    #[test]
    fn test_byte_layout_matches_native_u128() {
        let value = 0xDEADBEEFCAFEBABE1234567890ABCDEFu128;
        let native_bytes = value.to_le_bytes();

        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);
        scope.set_current_amount_value(value);

        assert_eq!(scope.current_amount, native_bytes);
    }

    #[test]
    fn test_direct_byte_manipulation_produces_correct_value() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);

        // Manually set bytes to represent a known value
        // Value: 0x0000000000000001_0000000000000000 (2^64)
        scope.current_amount = [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(scope.get_current_amount_value(), 1u128 << 64);

        // Value: 0x0000000000000000_FFFFFFFFFFFFFFFF (u64::MAX)
        scope.current_amount = [0xFF; 8]
            .into_iter()
            .chain([0; 8])
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        assert_eq!(scope.get_current_amount_value(), u64::MAX as u128);
    }

    // Struct Size and Alignment Tests

    #[test]
    fn test_struct_size_unchanged() {
        // ProgramScope should be exactly 144 bytes
        assert_eq!(
            core::mem::size_of::<ProgramScope>(),
            144,
            "ProgramScope size changed! This could break on-chain data compatibility."
        );
    }

    #[test]
    fn test_struct_alignment_is_8() {
        // With [u8; 16] instead of u128, alignment should be 8 (from u64 fields)
        assert_eq!(
            core::mem::align_of::<ProgramScope>(),
            8,
            "ProgramScope alignment should be 8 bytes"
        );
    }

    #[test]
    fn test_field_offsets_unchanged() {
        // Verify field offsets haven't changed
        let scope = ProgramScope::new_basic([0; 32], [0; 32]);
        let base_ptr = &scope as *const _ as usize;

        let current_amount_offset = &scope.current_amount as *const _ as usize - base_ptr;
        let limit_offset = &scope.limit as *const _ as usize - base_ptr;
        let window_offset = &scope.window as *const _ as usize - base_ptr;
        let last_reset_offset = &scope.last_reset as *const _ as usize - base_ptr;
        let program_id_offset = &scope.program_id as *const _ as usize - base_ptr;
        let target_account_offset = &scope.target_account as *const _ as usize - base_ptr;

        assert_eq!(current_amount_offset, 0, "current_amount offset changed");
        assert_eq!(limit_offset, 16, "limit offset changed");
        assert_eq!(window_offset, 32, "window offset changed");
        assert_eq!(last_reset_offset, 40, "last_reset offset changed");
        assert_eq!(program_id_offset, 48, "program_id offset changed");
        assert_eq!(target_account_offset, 80, "target_account offset changed");
    }

    // Transmutable / Serialization Tests

    #[test]
    fn test_transmutable_roundtrip() {
        let mut original = ProgramScope::new_limit([1; 32], [2; 32], 1000u64, NumericType::U64);
        original.set_current_amount_value(500);
        original.set_balance_field_indices(64, 72).unwrap();

        // Convert to bytes
        let bytes = original.into_bytes().unwrap();
        assert_eq!(bytes.len(), ProgramScope::LEN);

        // Load from bytes
        let loaded = unsafe { ProgramScope::load_unchecked(bytes).unwrap() };

        assert_eq!(loaded.get_current_amount_value(), 500);
        assert_eq!(loaded.get_limit_value(), 1000);
        assert_eq!(loaded.program_id, [1; 32]);
        assert_eq!(loaded.target_account, [2; 32]);
        assert_eq!(loaded.balance_field_start, 64);
        assert_eq!(loaded.balance_field_end, 72);
    }

    #[test]
    fn test_transmutable_with_max_values() {
        let mut original = ProgramScope::new_basic([0xFF; 32], [0xAA; 32]);
        original.set_current_amount_value(u128::MAX);
        original.set_limit_value(u128::MAX);
        original.window = u64::MAX;
        original.last_reset = u64::MAX;

        let bytes = original.into_bytes().unwrap();
        let loaded = unsafe { ProgramScope::load_unchecked(bytes).unwrap() };

        assert_eq!(loaded.get_current_amount_value(), u128::MAX);
        assert_eq!(loaded.get_limit_value(), u128::MAX);
        assert_eq!(loaded.window, u64::MAX);
        assert_eq!(loaded.last_reset, u64::MAX);
    }

    // Constructor Tests

    #[test]
    fn test_new_basic_initializes_to_zero() {
        let scope = ProgramScope::new_basic([0; 32], [0; 32]);
        assert_eq!(scope.get_current_amount_value(), 0);
        assert_eq!(scope.get_limit_value(), 0);
        assert_eq!(scope.current_amount, [0; 16]);
        assert_eq!(scope.limit, [0; 16]);
    }

    #[test]
    fn test_new_limit_sets_limit_correctly() {
        let scope = ProgramScope::new_limit([0; 32], [0; 32], u128::MAX, NumericType::U128);
        assert_eq!(scope.get_current_amount_value(), 0);
        assert_eq!(scope.get_limit_value(), u128::MAX);
    }

    #[test]
    fn test_new_recurring_limit_sets_values_correctly() {
        let scope = ProgramScope::new_recurring_limit(
            [0; 32],
            [0; 32],
            12345678901234567890u128,
            100,
            NumericType::U128,
        );
        assert_eq!(scope.get_current_amount_value(), 0);
        assert_eq!(scope.get_limit_value(), 12345678901234567890u128);
        assert_eq!(scope.window, 100);
    }

    // Run Method Tests (Limit Enforcement)

    #[test]
    fn test_run_basic_always_succeeds() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);
        assert!(scope.run(u128::MAX, None).is_ok());
        // Basic scope doesn't track amounts
        assert_eq!(scope.get_current_amount_value(), 0);
    }

    #[test]
    fn test_run_limit_accumulates_correctly() {
        let mut scope = ProgramScope::new_limit([0; 32], [0; 32], 1000u64, NumericType::U64);

        scope.run(100, None).unwrap();
        assert_eq!(scope.get_current_amount_value(), 100);

        scope.run(200, None).unwrap();
        assert_eq!(scope.get_current_amount_value(), 300);

        scope.run(700, None).unwrap();
        assert_eq!(scope.get_current_amount_value(), 1000);
    }

    #[test]
    fn test_run_limit_rejects_over_limit() {
        let mut scope = ProgramScope::new_limit([0; 32], [0; 32], 1000u64, NumericType::U64);

        scope.run(500, None).unwrap();
        assert!(scope.run(501, None).is_err());
        // Amount should not change on failure
        assert_eq!(scope.get_current_amount_value(), 500);
    }

    #[test]
    fn test_run_limit_with_large_u128_values() {
        let limit = u128::MAX / 2;
        let mut scope = ProgramScope::new_limit([0; 32], [0; 32], limit, NumericType::U128);

        let amount = limit / 4;
        scope.run(amount, None).unwrap();
        assert_eq!(scope.get_current_amount_value(), amount);

        scope.run(amount, None).unwrap();
        assert_eq!(scope.get_current_amount_value(), amount * 2);

        // This should fail (would exceed limit: amount*2 + amount + 1 > limit)
        // amount = limit/4, so amount*2 = limit/2
        // Adding amount again would give limit/2 + limit/4 = 3*limit/4 which is still <
        // limit So let's add more than (limit - amount*2) to trigger the error
        let remaining = limit - (amount * 2);
        assert!(scope.run(remaining + 1, None).is_err());
    }

    #[test]
    fn test_run_recurring_limit_resets_after_window() {
        let mut scope =
            ProgramScope::new_recurring_limit([0; 32], [0; 32], 1000u64, 100, NumericType::U64);

        // Use some of the limit
        scope.run(500, Some(50)).unwrap();
        assert_eq!(scope.get_current_amount_value(), 500);

        // Advance past window - should reset
        scope.run(800, Some(200)).unwrap();
        assert_eq!(scope.get_current_amount_value(), 800);
    }

    #[test]
    fn test_run_recurring_limit_no_reset_within_window() {
        let mut scope =
            ProgramScope::new_recurring_limit([0; 32], [0; 32], 1000u64, 100, NumericType::U64);

        scope.run(500, Some(50)).unwrap();
        // Still within window
        scope.run(400, Some(100)).unwrap();
        assert_eq!(scope.get_current_amount_value(), 900);

        // Should fail - still within window and would exceed limit
        assert!(scope.run(200, Some(100)).is_err());
    }

    // Overflow Protection Tests

    #[test]
    fn test_saturating_add_prevents_overflow() {
        let mut scope = ProgramScope::new_limit([0; 32], [0; 32], u128::MAX, NumericType::U128);

        // Set current amount close to max
        scope.set_current_amount_value(u128::MAX - 100);

        // This would overflow without saturating_add, but should fail due to limit
        // check The limit is u128::MAX, so adding 200 would overflow
        // But saturating_add should cap it at u128::MAX
        let result = scope.run(200, None);
        // This should succeed because saturating_add caps at MAX which equals limit
        assert!(result.is_ok());
        assert_eq!(scope.get_current_amount_value(), u128::MAX);
    }

    #[test]
    fn test_no_wraparound_on_large_values() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);

        // Set to max value
        scope.set_current_amount_value(u128::MAX);
        assert_eq!(scope.get_current_amount_value(), u128::MAX);

        // Set to 0 and verify no residual data
        scope.set_current_amount_value(0);
        assert_eq!(scope.get_current_amount_value(), 0);
        assert_eq!(scope.current_amount, [0; 16]);
    }

    // Edge Case and Security Tests

    #[test]
    fn test_independent_current_amount_and_limit() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);

        // Setting one should not affect the other
        scope.set_current_amount_value(0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAu128);
        scope.set_limit_value(0x55555555555555555555555555555555u128);

        assert_eq!(
            scope.get_current_amount_value(),
            0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAu128
        );
        assert_eq!(
            scope.get_limit_value(),
            0x55555555555555555555555555555555u128
        );

        // Verify bytes are distinct
        assert_ne!(scope.current_amount, scope.limit);
    }

    #[test]
    fn test_alternating_bit_patterns() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);

        // Test with alternating 1s and 0s
        let pattern1 = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAu128;
        let pattern2 = 0x55555555555555555555555555555555u128;

        scope.set_current_amount_value(pattern1);
        assert_eq!(scope.get_current_amount_value(), pattern1);

        scope.set_current_amount_value(pattern2);
        assert_eq!(scope.get_current_amount_value(), pattern2);

        // Verify all bits changed
        scope.set_limit_value(pattern1);
        scope.set_current_amount_value(pattern2);
        assert_eq!(scope.get_current_amount_value(), pattern2);
        assert_eq!(scope.get_limit_value(), pattern1);
    }

    #[test]
    fn test_sequential_byte_values() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);

        // Set bytes to sequential values and verify correct interpretation
        scope.current_amount = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let expected = u128::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        assert_eq!(scope.get_current_amount_value(), expected);
    }

    #[test]
    fn test_all_bytes_contribute_to_value() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);

        // Set each byte individually and verify it affects the result
        for i in 0..16 {
            scope.current_amount = [0; 16];
            scope.current_amount[i] = 0xFF;

            let value = scope.get_current_amount_value();
            let expected = 0xFFu128 << (i * 8);
            assert_eq!(
                value, expected,
                "Byte {} did not contribute correctly to value",
                i
            );
        }
    }

    // get_current_amount and set_current_amount API Tests

    #[test]
    fn test_get_current_amount_converts_to_u64() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);
        scope.set_current_amount_value(12345u128);

        let result: u64 = scope.get_current_amount().unwrap();
        assert_eq!(result, 12345u64);
    }

    #[test]
    fn test_get_current_amount_fails_for_overflow() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);
        scope.set_current_amount_value(u128::MAX);

        let result: Result<u64, _> = scope.get_current_amount();
        assert!(result.is_err());
    }

    #[test]
    fn test_set_current_amount_validates_numeric_type() {
        let mut scope = ProgramScope::new_limit([0; 32], [0; 32], 1000u64, NumericType::U8);

        // Should succeed for valid u8 value
        assert!(scope.set_current_amount(100u8).is_ok());
        assert_eq!(scope.get_current_amount_value(), 100);

        // Should fail for value exceeding u8 max
        assert!(scope.set_current_amount(256u64).is_err());
    }

    // Compatibility with Transmutable trait

    #[test]
    fn test_len_constant_matches_size() {
        assert_eq!(ProgramScope::LEN, core::mem::size_of::<ProgramScope>());
        assert_eq!(ProgramScope::LEN, 144);
    }

    #[test]
    fn test_load_unchecked_from_valid_buffer() {
        let mut buffer = [0u8; 144];

        // Set up a valid ProgramScope in the buffer
        // current_amount at offset 0
        buffer[0..16].copy_from_slice(&1000u128.to_le_bytes());
        // limit at offset 16
        buffer[16..32].copy_from_slice(&2000u128.to_le_bytes());

        let loaded = unsafe { ProgramScope::load_unchecked(&buffer).unwrap() };
        assert_eq!(loaded.get_current_amount_value(), 1000);
        assert_eq!(loaded.get_limit_value(), 2000);
    }

    #[test]
    fn test_load_unchecked_rejects_wrong_size() {
        let buffer = [0u8; 100]; // Wrong size
        let result = unsafe { ProgramScope::load_unchecked(&buffer) };
        assert!(result.is_err());
    }

    // Stress Tests

    #[test]
    fn test_many_roundtrips() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);

        // Perform many set/get cycles
        for i in 0..1000u128 {
            let value = i * 1234567890123456789u128;
            scope.set_current_amount_value(value);
            assert_eq!(scope.get_current_amount_value(), value);
        }
    }

    #[test]
    fn test_alternating_values() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);

        for _ in 0..100 {
            scope.set_current_amount_value(0);
            assert_eq!(scope.get_current_amount_value(), 0);

            scope.set_current_amount_value(u128::MAX);
            assert_eq!(scope.get_current_amount_value(), u128::MAX);

            scope.set_current_amount_value(1);
            assert_eq!(scope.get_current_amount_value(), 1);

            scope.set_current_amount_value(u128::MAX - 1);
            assert_eq!(scope.get_current_amount_value(), u128::MAX - 1);
        }
    }

    // Fuzzy-style Tests with Various Patterns

    #[test]
    fn test_fibonacci_values() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);
        let mut a = 1u128;
        let mut b = 1u128;

        for _ in 0..180 {
            // 180 iterations before u128 overflow
            scope.set_current_amount_value(a);
            assert_eq!(scope.get_current_amount_value(), a);

            let next = a.saturating_add(b);
            if next == u128::MAX {
                break;
            }
            a = b;
            b = next;
        }
    }

    #[test]
    fn test_prime_number_values() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);
        let primes: [u128; 20] = [
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
        ];

        for &prime in &primes {
            scope.set_current_amount_value(prime);
            assert_eq!(scope.get_current_amount_value(), prime);

            // Test with large multiples
            let large = prime * (u64::MAX as u128);
            scope.set_current_amount_value(large);
            assert_eq!(scope.get_current_amount_value(), large);
        }
    }

    #[test]
    fn test_random_looking_values() {
        let mut scope = ProgramScope::new_basic([0; 32], [0; 32]);

        // These are deterministic but look random
        let values: [u128; 10] = [
            0xDEADBEEFCAFEBABE1234567890ABCDEFu128,
            0x123456789ABCDEF0FEDCBA9876543210u128,
            0xFFFFFFFF00000000FFFFFFFF00000000u128,
            0x00000000FFFFFFFF00000000FFFFFFFFu128,
            0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0Fu128,
            0xF0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0u128,
            0x0123456789ABCDEF0123456789ABCDEFu128,
            0xFEDCBA9876543210FEDCBA9876543210u128,
            0x8000000000000000_0000000000000001u128,
            0x7FFFFFFFFFFFFFFF_FFFFFFFFFFFFFFFEu128,
        ];

        for &value in &values {
            scope.set_current_amount_value(value);
            assert_eq!(
                scope.get_current_amount_value(),
                value,
                "Failed for value: 0x{:032X}",
                value
            );
        }
    }
}
