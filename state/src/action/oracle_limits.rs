/// Oracle-based token limit action type.
///
/// This module defines the OracleTokenLimit action type which enforces value-based limits on
/// token operations within the Swig wallet system. It uses oracle price feeds to convert token
/// amounts to a base asset value (e.g. USDC) for limit enforcement.
///
/// The system supports:
/// - Different base assets (e.g. USDC, EURC) for value denomination
/// - Oracle price feed integration for real-time value conversion
/// - Configurable value limits per base asset
/// - Decimal precision handling for different token types
///
/// The limits are enforced by:
/// 1. Converting token amounts to base asset value using oracle prices
/// 2. Tracking cumulative usage against the configured limit
/// 3. Preventing operations that would exceed the limit
/// 4. Supporting both token and native SOL operations
use super::{Actionable, Permission};
use crate::{IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut};
use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;
use pinocchio_pubkey::pubkey;

pub const ORACLE_MAPPING_ACCOUNT: [u8; 32] =
    pubkey!("FbeuRDWwLvZWEU3HNtaLoYKagw9rH1NvmjpRMpjMwhDw");
pub const SCOPE_ACCOUNT: [u8; 32] = pubkey!("HFn8GnPADiny6XqUoWE8uRPPxb29ikn4yTuPa9MF2fWJ");
pub const ORACLE_MAPPING_OWNER: [u8; 32] = pubkey!("9WM51wrB9xpRzFgYJHocYNnx4DF6G6ee2eB44ZGoZ8vg");
pub const SCOPE_OWNER: [u8; 32] = pubkey!("HFn8GnPADiny6XqUoWE8uRPPxb29ikn4yTuPa9MF2fWJ");
pub const SOL_MINT: [u8; 32] = pubkey!("So11111111111111111111111111111111111111112");

/// Represents the base asset type for value denomination.
///
/// This enum defines the supported base assets that can be used to denominate
/// token value limits. Each base asset has a specific decimal precision that
/// is used in value calculations.
#[repr(u8)]
pub enum BaseAsset {
    /// USDC stablecoin with 6 decimal places precision
    USD = 0,
    /// EURC stablecoin with 6 decimal places precision
    EUR = 1,
}

impl TryFrom<u8> for BaseAsset {
    type Error = ProgramError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(BaseAsset::USD),
            1 => Ok(BaseAsset::EUR),
            _ => Err(SwigAuthenticateError::InvalidDataPayload.into()),
        }
    }
}

impl BaseAsset {
    pub fn get_scope_index(&self) -> Option<u16> {
        match self {
            BaseAsset::USD => None,
            BaseAsset::EUR => Some(173),
        }
    }
}

/// Represents a limit on token operations based on oracle base asset value.
///
/// This struct tracks and enforces a maximum value of tokens that can be
/// used in operations, denominated in a base asset (e.g. USDC). The limit is enforced
/// by converting token amounts to the base asset value using oracle price feeds.
///
/// # Fields
/// * `value_limit` - The current remaining amount that can be used (in base asset)
/// * `base_asset_type` - The base asset type used to denominate the limit (e.g. USDC)
/// * `passthrough_check` - Flag to check remaining actions after oracle limit check
/// * `_padding` - Padding bytes to ensure proper struct alignment
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct OracleTokenLimit {
    /// The current remaining amount that can be used (in base asset)
    pub value_limit: u64,
    /// The base asset type used to denominate the limit (e.g. USDC)
    pub base_asset_type: u8,
    /// The passthrough flag, it will check the remaining actions
    /// and not just stop with oracle limit check
    pub passthrough_check: bool,
    /// Padding bytes to ensure proper struct alignment
    _padding: [u8; 6],
}

impl OracleTokenLimit {
    /// Creates a new OracleTokenLimit with the specified parameters.
    ///
    /// # Arguments
    /// * `base_asset` - The base asset to denominate the limit in (e.g. USDC)
    /// * `value_limit` - The maximum value allowed in base asset
    /// * `passthrough_check` - Whether to check remaining actions after oracle limit check
    ///
    /// # Returns
    /// A new OracleTokenLimit instance configured with the specified parameters
    pub fn new(base_asset: BaseAsset, value_limit: u64, passthrough_check: bool) -> Self {
        Self {
            base_asset_type: base_asset as u8,
            value_limit,
            passthrough_check,
            _padding: [0; 6],
        }
    }

    /// Gets the decimal places for the configured base asset type.
    ///
    /// # Returns
    /// The number of decimal places for the base asset (e.g. 6 for USDC)
    pub fn get_base_asset_decimals(&self) -> u8 {
        match BaseAsset::try_from(self.base_asset_type).unwrap() {
            BaseAsset::USD => 6,
            BaseAsset::EUR => 6,
        }
    }

    /// Processes a token operation by checking the oracle price and value limit.
    ///
    /// This method:
    /// 1. Converts the token amount to oracle decimal precision
    /// 2. Multiplies by the oracle price to get the value
    /// 3. Adjusts for price exponent
    /// 4. Converts to base asset decimal precision
    /// 5. Checks against and updates the remaining limit
    ///
    /// # Arguments
    /// * `amount` - The amount of tokens to be used (in token decimals)
    /// * `oracle_price` - The current oracle price for the token
    /// * `_confidence` - The confidence interval for the oracle price (unused)
    /// * `exponent` - The exponent for price calculation
    /// * `token_decimals` - The number of decimal places for the token
    ///
    /// # Returns
    /// * `Ok(())` - If the operation is within limits
    /// * `Err(ProgramError)` - If the operation would exceed the limit or encounters an error
    pub fn run_for_token(&mut self, price: u64) -> Result<(), ProgramError> {
        // Check if operation would exceed limit
        if price > self.value_limit {
            return Err(SwigAuthenticateError::PermissionDeniedOracleLimitReached.into());
        }

        // Safe to subtract since we verified value <= value_limit
        self.value_limit = self
            .value_limit
            .checked_sub(price)
            .ok_or(SwigAuthenticateError::PermissionDeniedInsufficientBalance)?;

        Ok(())
    }

    /// Processes a Solana operation by checking the oracle price and value limit.
    ///
    /// This method handles native SOL operations by:
    /// 1. Checking for potential multiplication overflow
    /// 2. Converting SOL amount to base asset value using oracle price
    /// 3. Adjusting for price exponent
    /// 4. Checking against and updating the remaining limit
    ///
    /// # Arguments
    /// * `amount` - The amount of SOL lamports to be used
    /// * `oracle_price` - The current oracle price for SOL
    /// * `_confidence` - The confidence interval for the oracle price (unused)
    /// * `exponent` - The exponent for price calculation
    ///
    /// # Returns
    /// * `Ok(())` - If the operation is within limits
    /// * `Err(ProgramError)` - If the operation would exceed the limit or encounters an error
    pub fn run_for_sol(&mut self, price: u64) -> Result<(), ProgramError> {
        // Check if we have enough limit
        if price > self.value_limit {
            return Err(SwigAuthenticateError::PermissionDeniedOracleLimitReached.into());
        }

        // Safe to subtract since we verified value <= value_limit
        self.value_limit -= price;
        Ok(())
    }
}

impl Transmutable for OracleTokenLimit {
    /// Size of the OracleTokenLimit struct in bytes
    const LEN: usize = core::mem::size_of::<Self>();
}

impl TransmutableMut for OracleTokenLimit {}

impl IntoBytes for OracleTokenLimit {
    /// Converts the OracleTokenLimit struct into a byte slice.
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

impl<'a> Actionable<'a> for OracleTokenLimit {
    /// This action represents the OracleTokenLimit permission type
    const TYPE: Permission = Permission::OracleTokenLimit;
    /// Multiple oracle token limits can exist per role (one per base asset)
    const REPEATABLE: bool = false;
}
