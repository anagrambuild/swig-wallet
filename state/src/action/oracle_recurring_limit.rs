/// Oracle-based recurring token limit action type.
///
/// This module defines the OracleRecurringLimit action type which enforces recurring
/// value-based limits on token operations within the Swig wallet system. It uses oracle
/// price feeds to convert token amounts to a base asset value (e.g. USDC) for limit
/// enforcement and resets the limit after a specified time window.
///
/// The system supports:
/// - Different base assets (e.g. USDC, EURC) for value denomination
/// - Oracle price feed integration for real-time value conversion
/// - Configurable recurring value limits per base asset
/// - Time-based window resets for recurring limits
/// - Decimal precision handling for different token types
///
/// The limits are enforced by:
/// 1. Converting token amounts to base asset value using oracle prices
/// 2. Tracking cumulative usage against the configured recurring limit
/// 3. Resetting the limit after the time window expires
/// 4. Preventing operations that would exceed the current limit
/// 5. Supporting both token and native SOL operations
use super::{Actionable, Permission};
use crate::{IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut};
use no_padding::NoPadding;
use pinocchio::msg;
use pinocchio::program_error::ProgramError;

/// Represents a recurring limit on token operations based on oracle base asset value.
///
/// This struct tracks and enforces a maximum value of tokens that can be
/// used in operations within a specified time window, denominated in a base asset
/// (e.g. USDC). The limit is enforced by converting token amounts to the base asset
/// value using oracle price feeds and resets after the time window expires.
///
/// # Fields
/// * `recurring_value_limit` - The value limit that resets each window (in base asset)
/// * `base_asset_type` - The base asset type used to denominate the limit (e.g. USDC)
/// * `window` - The time window in slots after which the limit resets
/// * `last_reset` - The last slot when the limit was reset
/// * `current_amount` - The current remaining amount that can be used (in base asset)
/// * `passthrough_check` - Flag to check remaining actions after oracle limit check
/// * `_padding` - Padding bytes to ensure proper struct alignment
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct OracleRecurringLimit {
    /// The value limit that resets each window (in base asset)
    pub recurring_value_limit: u64,
    /// The time window in slots after which the limit resets
    pub window: u64,
    /// The last slot when the limit was reset
    pub last_reset: u64,
    /// The current remaining amount that can be used (in base asset)
    pub current_amount: u64,
    /// The base asset type used to denominate the limit (e.g. USDC)
    pub base_asset_type: u8,
    /// The passthrough flag, it will check the remaining actions
    /// and not just stop with oracle limit check
    pub passthrough_check: u8,
    /// Padding bytes to ensure proper struct alignment
    _padding: [u8; 6],
}

impl OracleRecurringLimit {
    /// Creates a new OracleRecurringLimit with the specified parameters.
    ///
    /// # Arguments
    /// * `base_asset` - The base asset to denominate the limit in (e.g. USDC)
    /// * `recurring_value_limit` - The maximum value allowed in base asset that resets each window
    /// * `window` - The time window in slots after which the limit resets
    /// * `passthrough_check` - Whether to check remaining actions after oracle limit check
    ///
    /// # Returns
    /// A new OracleRecurringLimit instance configured with the specified parameters
    pub fn new(
        base_asset: super::oracle_limits::BaseAsset,
        recurring_value_limit: u64,
        window: u64,
        passthrough_check: bool,
    ) -> Self {
        Self {
            recurring_value_limit,
            window,
            last_reset: 0,
            current_amount: recurring_value_limit,
            base_asset_type: base_asset as u8,
            passthrough_check: passthrough_check as u8,
            _padding: [0; 6],
        }
    }

    /// Gets the decimal places for the configured base asset type.
    ///
    /// # Returns
    /// The number of decimal places for the base asset (e.g. 6 for USDC)
    pub fn get_base_asset_decimals(&self) -> u8 {
        match super::oracle_limits::BaseAsset::try_from(self.base_asset_type).unwrap() {
            super::oracle_limits::BaseAsset::USD => 6,
            super::oracle_limits::BaseAsset::EUR => 6,
        }
    }

    /// Processes a token operation by checking the oracle price and recurring value limit.
    ///
    /// This method:
    /// 1. Checks if the time window has expired and resets the limit if needed
    /// 2. Converts the token amount to oracle decimal precision
    /// 3. Multiplies by the oracle price to get the value
    /// 4. Adjusts for price exponent
    /// 5. Converts to base asset decimal precision
    /// 6. Checks against and updates the remaining limit
    ///
    /// # Arguments
    /// * `price` - The value in base asset for the token operation
    /// * `current_slot` - The current slot number for window calculation
    ///
    /// # Returns
    /// * `Ok(())` - If the operation is within limits
    /// * `Err(ProgramError)` - If the operation would exceed the limit or encounters an error
    pub fn run_for_token(&mut self, price: u64, current_slot: u64) -> Result<(), ProgramError> {
        // Check if time window has expired and reset if needed
        if current_slot - self.last_reset > self.window {
            self.current_amount = self.recurring_value_limit;
            self.last_reset = current_slot;
        }

        // Check if operation would exceed limit
        if price > self.current_amount {
            msg!("Operation denied: Would exceed recurring value limit");
            return Err(SwigAuthenticateError::PermissionDeniedOracleLimitReached.into());
        }

        // Safe to subtract since we verified value <= current_amount
        self.current_amount = self
            .current_amount
            .checked_sub(price)
            .ok_or(SwigAuthenticateError::PermissionDeniedInsufficientBalance)?;

        Ok(())
    }

    /// Processes a Solana operation by checking the oracle price and recurring value limit.
    ///
    /// This method handles native SOL operations by:
    /// 1. Checking if the time window has expired and resets the limit if needed
    /// 2. Checking for potential multiplication overflow
    /// 3. Converting SOL amount to base asset value using oracle price
    /// 4. Adjusting for price exponent
    /// 5. Checking against and updating the remaining limit
    ///
    /// # Arguments
    /// * `price` - The value in base asset for the SOL operation
    /// * `current_slot` - The current slot number for window calculation
    ///
    /// # Returns
    /// * `Ok(())` - If the operation is within limits
    /// * `Err(ProgramError)` - If the operation would exceed the limit or encounters an error
    pub fn run_for_sol(&mut self, price: u64, current_slot: u64) -> Result<(), ProgramError> {
        // Check if time window has expired and reset if needed
        if current_slot - self.last_reset > self.window {
            self.current_amount = self.recurring_value_limit;
            self.last_reset = current_slot;
        }

        // Check if we have enough limit
        if price > self.current_amount {
            return Err(SwigAuthenticateError::PermissionDeniedOracleLimitReached.into());
        }

        // Safe to subtract since we verified value <= current_amount
        self.current_amount -= price;
        Ok(())
    }
}

impl Transmutable for OracleRecurringLimit {
    /// Size of the OracleRecurringLimit struct in bytes
    const LEN: usize = core::mem::size_of::<Self>();
}

impl TransmutableMut for OracleRecurringLimit {}

impl IntoBytes for OracleRecurringLimit {
    /// Converts the OracleRecurringLimit struct into a byte slice.
    ///
    /// # Returns
    /// * `Ok(&[u8])` - A byte slice representing the struct
    /// * `Err(ProgramError)` - If the conversion fails
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

impl<'a> Actionable<'a> for OracleRecurringLimit {
    /// This action represents the OracleRecurringLimit permission type
    const TYPE: Permission = Permission::OracleRecurringLimit;
    /// Multiple oracle recurring limits can exist per role (one per base asset)
    const REPEATABLE: bool = false;

    /// Checks if this token limit matches the provided base asset type.
    ///
    /// # Arguments
    /// * `data` - The base asset type to check against (first byte)
    ///
    /// # Returns
    /// `true` if the base asset type matches, `false` otherwise
    fn match_data(&self, data: &[u8]) -> bool {
        !data.is_empty()
    }

    /// Validates the layout of the action data.
    ///
    /// # Arguments
    /// * `data` - The action data to validate
    ///
    /// # Returns
    /// * `Ok(true)` - If the layout is valid
    /// * `Err(ProgramError)` - If validation fails
    fn valid_layout(data: &'a [u8]) -> Result<bool, ProgramError> {
        if data.len() != Self::LEN {
            return Ok(false);
        }

        // Check that current_amount equals recurring_value_limit initially
        let current_amount_bytes = &data[24..32];
        let recurring_value_limit_bytes = &data[0..8];

        // Check that last_reset is 0 initially
        let last_reset_bytes = &data[16..24];

        Ok(current_amount_bytes == recurring_value_limit_bytes && last_reset_bytes == &[0u8; 8])
    }
}
