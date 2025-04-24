use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
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
    pub scope_type: u8,           // 1 byte
    pub numeric_type: u8,         // 1 byte
    pub _padding: [u8; 14],       // 14 bytes padding to reach total size of 128 bytes
}

impl ProgramScope {
    pub fn new_basic(program_id: [u8; 32], target_account: [u8; 32]) -> Self {
        Self {
            program_id,
            target_account,
            scope_type: ProgramScopeType::Basic as u8,
            numeric_type: NumericType::U64 as u8,
            current_amount: 0,
            limit: 0,
            window: 0,
            last_reset: 0,
            _padding: [0; 14],
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
            scope_type: ProgramScopeType::Limit as u8,
            numeric_type: numeric_type as u8,
            current_amount: limit_u128,
            limit: limit_u128,
            window: 0,
            last_reset: 0,
            _padding: [0; 14],
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
            scope_type: ProgramScopeType::RecurringLimit as u8,
            numeric_type: numeric_type as u8,
            current_amount: limit_u128,
            limit: limit_u128,
            window,
            last_reset: 0,
            _padding: [0; 14],
        }
    }

    pub fn run(&mut self, amount: u64, current_slot: Option<u64>) -> Result<(), ProgramError> {
        let amount_u128 = u128::from(amount);
        match self.scope_type {
            x if x == ProgramScopeType::Basic as u8 => Ok(()),
            x if x == ProgramScopeType::Limit as u8 => {
                if amount_u128 > self.current_amount {
                    return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
                }
                self.current_amount = self.current_amount.saturating_sub(amount_u128);
                Ok(())
            },
            x if x == ProgramScopeType::RecurringLimit as u8 => {
                let current_slot = current_slot.ok_or(ProgramError::InvalidArgument)?;

                if current_slot - self.last_reset > self.window && amount_u128 <= self.limit {
                    self.current_amount = self.limit;
                    self.last_reset = current_slot;
                }

                if amount_u128 > self.current_amount {
                    return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
                }

                self.current_amount = self.current_amount.saturating_sub(amount_u128);
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
        match NumericType::from_u8(self.numeric_type).ok_or(ProgramError::InvalidArgument)? {
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
        match NumericType::from_u8(self.numeric_type).ok_or(ProgramError::InvalidArgument)? {
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
    const LEN: usize = 128; // Updated to match total size
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
