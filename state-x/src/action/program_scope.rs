use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::constants::PROGRAM_SCOPE_BYTE_SIZE;
use crate::read_numeric_field;
use crate::{IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut};

#[repr(u8)]
pub enum ProgramScopeType {
    Basic = 0,
    Limit = 1,
    RecurringLimit = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NumericType {
    U8 = 0,
    U32 = 1,
    U64 = 2,
    U128 = 3,
}

impl NumericType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::U8),
            1 => Some(Self::U32),
            2 => Some(Self::U64),
            3 => Some(Self::U128),
            _ => None,
        }
    }

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

#[repr(C, align(8))]
#[derive(NoPadding)]
pub struct ProgramScope {
    pub current_amount: u128,     // 16 bytes
    pub limit: u128,              // 16 bytes
    pub window: u64,              // 8 bytes
    pub last_reset: u64,          // 8 bytes
    pub program_id: [u8; 32],     // 32 bytes
    pub target_account: [u8; 32], // 32 bytes
    pub scope_type: u64,          // 8 bytes
    pub numeric_type: u64,        // 8 bytes
    pub balance_field_start: u64, // 8 bytes - start index for reading balance
    pub balance_field_end: u64,   // 8 bytes - end index for reading balance
}

impl ProgramScope {
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

    pub fn set_balance_field_indices(&mut self, start: u64, end: u64) -> Result<(), ProgramError> {
        if end <= start || end > 1024 {
            return Err(ProgramError::InvalidArgument);
        }
        self.balance_field_start = start;
        self.balance_field_end = end;
        Ok(())
    }

    /// Reads account balance from raw account data based on the configured field positions and type.
    ///
    /// This method reads a numeric balance value from the specified field range within account data
    /// according to the configured numeric type. It supports reading u8, u32, u64, and u128 values
    /// and handles their proper byte assembly.
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
            // No balance field configured - use account lamports instead (handled elsewhere)
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

                // Check if the requested amount plus what's already spent would exceed the limit
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

    pub fn get_current_amount<T>(&self) -> Result<T, ProgramError>
    where
        T: TryFrom<u128>,
        <T as TryFrom<u128>>::Error: std::fmt::Debug,
    {
        self.current_amount
            .try_into()
            .map_err(|_| ProgramError::InvalidArgument)
    }

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
    const LEN: usize = PROGRAM_SCOPE_BYTE_SIZE;
}

impl TransmutableMut for ProgramScope {}

impl IntoBytes for ProgramScope {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> Actionable<'a> for ProgramScope {
    const TYPE: Permission = Permission::ProgramScope;
    const REPEATABLE: bool = true;

    fn match_data(&self, data: &[u8]) -> bool {
        data[0..32] == self.program_id
    }
}
