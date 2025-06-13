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
use crate::{IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable, TransmutableMut};
use no_padding::NoPadding;
use pinocchio::msg;
use pinocchio::program_error::ProgramError;

/// Represents the base asset type for value denomination.
///
/// This enum defines the supported base assets that can be used to denominate
/// token value limits. Each base asset has a specific decimal precision that
/// is used in value calculations.
#[repr(u8)]
pub enum BaseAsset {
    /// USDC stablecoin with 6 decimal places precision
    USDC = 0,
    /// EURC stablecoin with 6 decimal places precision
    EURC = 1,
}

impl TryFrom<u8> for BaseAsset {
    type Error = ProgramError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(BaseAsset::USDC),
            // 1 => Ok(BaseAsset::EURC),
            _ => Err(SwigAuthenticateError::InvalidDataPayload.into()),
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
/// * `value_limit` - The current remaining amount that can be used (in base asset lamports)
/// * `base_asset_type` - The base asset type used to denominate the limit (e.g. USDC)
/// * `passthrough_check` - Flag to check remaining actions after oracle limit check
/// * `_padding` - Padding bytes to ensure proper struct alignment

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct OracleTokenLimit {
    /// The current remaining amount that can be used (in base asset lamports)
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
    /// * `value_limit` - The maximum value allowed in base asset lamports
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
    fn get_base_asset_decimals(&self) -> u8 {
        match BaseAsset::try_from(self.base_asset_type).unwrap() {
            BaseAsset::USDC => 6,
            BaseAsset::EURC => 6,
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
    pub fn run_for_token(
        &mut self,
        amount: u64,
        oracle_price: u64,
        _confidence: u64,
        exponent: i32,
        token_decimals: u8,
    ) -> Result<(), ProgramError> {
        // Early return if amount is 0
        if amount == 0 {
            return Ok(());
        }

        // Get base asset decimals
        let base_decimals = self.get_base_asset_decimals();

        // Convert to u128 for intermediate calculations to prevent overflow
        let amount = amount as u128;
        let oracle_price = oracle_price as u128;

        // Calculate value with proper decimal handling
        let value = if exponent >= 0 {
            // For positive exponent:
            // (amount * price * 10^exponent) / 10^token_decimals
            amount
                .checked_mul(oracle_price)
                .and_then(|v| v.checked_mul(10u128.pow(exponent as u32)))
                .and_then(|v| v.checked_div(10u128.pow(token_decimals as u32)))
                .ok_or(SwigAuthenticateError::PermissionDeniedInsufficientBalance)?
        } else {
            // For negative exponent:
            // (amount * price) / (10^|exponent| * 10^token_decimals)
            // First multiply by 10^base_decimals to preserve precision
            amount
                .checked_mul(oracle_price)
                .and_then(|v| v.checked_mul(10u128.pow(base_decimals as u32)))
                .and_then(|v| v.checked_div(10u128.pow((-exponent) as u32)))
                .and_then(|v| v.checked_div(10u128.pow(token_decimals as u32)))
                .ok_or(SwigAuthenticateError::PermissionDeniedInsufficientBalance)?
        };

        // No need for additional decimal conversion since we already handled it above
        let value = value
            .try_into()
            .map_err(|_| SwigAuthenticateError::PermissionDeniedInsufficientBalance)?;

        // Check if operation would exceed limit
        if value > self.value_limit {
            msg!("Operation denied: Would exceed value limit");
            return Err(SwigAuthenticateError::PermissionDeniedOracleLimitReached.into());
        }

        // Safe to subtract since we verified value <= value_limit
        self.value_limit = self
            .value_limit
            .checked_sub(value)
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
    pub fn run_for_sol(
        &mut self,
        amount: u64,
        oracle_price: u64,
        _confidence: u64,
        exponent: i32,
    ) -> Result<(), ProgramError> {
        // First check if amount * oracle_price would overflow u64
        if amount != 0 && oracle_price as u128 > u128::MAX / amount as u128 {
            return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
        }

        let value = if exponent >= 0 {
            amount * oracle_price * 10u64.pow(exponent as u32) / 1000
        } else {
            amount * oracle_price / (1000 * 10u64.pow((-exponent) as u32))
        };

        // Check if we have enough limit
        if value > self.value_limit {
            return Err(SwigAuthenticateError::PermissionDeniedOracleLimitReached.into());
        }

        // Safe to subtract since we verified value <= value_limit
        self.value_limit -= value;
        Ok(())
    }

    /// Get the token feed ID and decimal from the token mint address.
    ///
    /// This function maps token mint addresses to their corresponding oracle feed IDs and mint decimals.
    /// Each token has a unique feed ID for price lookups and a specific decimal precision.
    ///
    /// # Arguments
    /// * `token_mint` - The 32-byte array representing the token's mint address
    ///
    /// # Returns
    /// * `Ok(([u8; 32], u8))` - A tuple containing:
    ///   - The oracle feed ID as a 32-byte array
    ///   - The token's mint decimal precision
    /// * `Err(SwigStateError)` - If the token mint is not recognized
    pub fn get_feed_id_and_decimal_from_mint(
        token_mint: &[u8],
    ) -> Result<([u8; 32], u8), SwigStateError> {
        match token_mint {
            // "SOL/USD"
            [252, 209, 65, 233, 131, 44, 175, 16, 173, 145, 116, 149, 202, 15, 39, 27, 91, 41, 60, 212, 112, 39, 234, 115, 112, 7, 237, 64, 235, 57, 160, 189] => {
                Ok((
                    [
                        103, 190, 159, 81, 155, 149, 207, 36, 51, 136, 1, 5, 31, 154, 128, 142,
                        255, 10, 87, 140, 203, 56, 141, 183, 59, 127, 111, 225, 222, 1, 159, 251,
                    ],
                    9,
                ))
            }, // "JITOSOL/USD"
            [11, 98, 186, 7, 79, 114, 44, 157, 65, 20, 242, 216, 247, 10, 0, 198, 96, 2, 51, 123, 155, 249, 12, 135, 54, 87, 166, 210, 1, 219, 76, 128] => {
                Ok((
                    [
                        194, 40, 154, 106, 67, 210, 206, 145, 198, 245, 92, 174, 195, 112, 244,
                        172, 195, 138, 46, 212, 119, 245, 136, 19, 51, 76, 109, 3, 116, 159, 242,
                        164,
                    ],
                    9,
                ))
            }, // "MSOL/USD"
            [8, 210, 233, 112, 249, 60, 123, 61, 80, 25, 30, 97, 26, 205, 147, 170, 128, 165, 70, 180, 94, 201, 101, 225, 139, 5, 135, 21, 86, 153, 200, 172] => {
                Ok((
                    [
                        137, 135, 83, 121, 231, 15, 143, 186, 220, 23, 174, 243, 21, 173, 243, 168,
                        213, 209, 96, 184, 17, 67, 85, 55, 224, 60, 151, 232, 170, 201, 125, 156,
                    ],
                    9,
                ))
            }, // "BSOL/USD"
            [95, 12, 68, 99, 24, 171, 16, 201, 95, 64, 148, 149, 133, 112, 205, 5, 116, 101, 165, 77, 171, 20, 217, 221, 227, 72, 26, 134, 254, 213, 252, 203] => {
                Ok((
                    [
                        173, 214, 73, 154, 66, 15, 128, 155, 190, 188, 11, 34, 251, 246, 138, 203,
                        140, 17, 144, 35, 137, 127, 110, 168, 1, 104, 142, 13, 110, 57, 26, 244,
                    ],
                    9,
                ))
            }, // "SSOL/SOL"
            [188, 7, 197, 110, 96, 173, 61, 63, 23, 115, 130, 234, 198, 84, 143, 186, 31, 211, 44, 253, 144, 202, 2, 179, 231, 207, 161, 133, 253, 206, 115, 152] => {
                Ok((
                    [
                        114, 176, 33, 33, 124, 163, 254, 104, 146, 42, 25, 170, 249, 144, 16, 156,
                        185, 216, 78, 154, 208, 4, 180, 210, 2, 90, 214, 245, 41, 49, 68, 25,
                    ],
                    9,
                ))
            }, // "BONK/USD"
            [105, 39, 253, 192, 30, 169, 6, 249, 109, 113, 55, 135, 76, 221, 122, 218, 208, 12, 163, 87, 100, 97, 147, 16, 229, 65, 150, 199, 129, 216, 77, 91] => {
                Ok((
                    [
                        239, 247, 68, 100, 117, 226, 24, 81, 117, 102, 234, 153, 231, 42, 74, 190,
                        194, 225, 189, 132, 152, 180, 59, 125, 131, 49, 226, 157, 203, 5, 147, 137,
                    ],
                    9,
                ))
            }, // "W/USD"
            [4, 179, 126, 86, 185, 201, 53, 133, 88, 74, 255, 68, 184, 205, 28, 157, 252, 69, 100, 248, 157, 220, 77, 89, 124, 115, 211, 178, 15, 234, 98, 85] => {
                Ok((
                    [
                        177, 126, 91, 197, 222, 116, 42, 138, 55, 139, 84, 201, 199, 84, 66, 183,
                        213, 30, 48, 173, 166, 63, 40, 217, 189, 40, 211, 192, 226, 101, 17, 160,
                    ],
                    9,
                ))
            }, // "KMNO/USD"
            [5, 46, 225, 131, 56, 150, 150, 159, 140, 209, 205, 70, 131, 24, 197, 152, 204, 19, 238, 217, 56, 6, 199, 171, 139, 221, 15, 180, 202, 218, 176, 234] => {
                Ok((
                    [
                        81, 74, 237, 82, 202, 82, 148, 23, 127, 32, 24, 122, 232, 131, 206, 196,
                        160, 24, 97, 151, 114, 221, 206, 65, 239, 204, 54, 166, 68, 143, 93, 93,
                    ],
                    9,
                ))
            }, // "MEW/USD"
            [6, 193, 87, 113, 84, 101, 116, 159, 7, 10, 48, 14, 109, 244, 176, 212, 201, 240, 134, 253, 228, 39, 238, 32, 46, 4, 113, 31, 230, 32, 135, 75] => {
                Ok((
                    [
                        5, 236, 212, 89, 124, 212, 143, 225, 61, 108, 195, 89, 108, 98, 175, 79,
                        150, 117, 174, 224, 110, 46, 11, 148, 192, 109, 139, 238, 43, 101, 158, 5,
                    ],
                    9,
                ))
            }, // "TNSR/USD"
            [198, 250, 122, 243, 190, 219, 173, 58, 61, 101, 243, 106, 171, 201, 116, 49, 177, 187, 228, 194, 210, 246, 224, 228, 124, 166, 2, 3, 69, 47, 93, 97] => {
                Ok((
                    [
                        234, 160, 32, 198, 28, 196, 121, 113, 40, 19, 70, 28, 225, 83, 137, 74,
                        150, 166, 192, 11, 33, 237, 12, 252, 39, 152, 209, 249, 169, 233, 201, 74,
                    ],
                    9,
                ))
            }, // "USDC/USD"
            [10, 252, 248, 150, 139, 141, 171, 136, 72, 30, 45, 42, 230, 137, 201, 82, 199, 87, 174, 186, 100, 62, 57, 25, 232, 159, 46, 85, 121, 92, 118, 193] => {
                Ok((
                    [
                        180, 54, 96, 165, 247, 144, 198, 147, 84, 176, 114, 154, 94, 249, 213, 13,
                        104, 241, 223, 146, 16, 117, 64, 33, 11, 156, 204, 186, 31, 148, 124, 194,
                    ],
                    9,
                ))
            }, // "JTO/USD"
            [206, 1, 14, 96, 175, 237, 178, 39, 23, 189, 99, 25, 47, 84, 20, 90, 63, 150, 90, 51, 187, 130, 210, 199, 2, 158, 178, 206, 30, 32, 130, 100] => {
                Ok((
                    [
                        43, 137, 185, 220, 143, 223, 159, 52, 112, 154, 91, 16, 107, 71, 47, 15,
                        57, 187, 108, 169, 206, 4, 176, 253, 127, 46, 151, 22, 136, 226, 229, 59,
                    ],
                    9,
                ))
            }, // "USDT/USD"
            [4, 121, 217, 199, 204, 16, 53, 222, 114, 17, 249, 158, 180, 140, 9, 215, 11, 43, 223, 91, 223, 158, 46, 86, 184, 161, 251, 181, 162, 234, 51, 39] => {
                Ok((
                    [
                        10, 4, 8, 214, 25, 233, 56, 10, 186, 211, 80, 96, 249, 25, 32, 57, 237, 80,
                        66, 250, 111, 130, 48, 29, 14, 72, 187, 82, 190, 131, 9, 150,
                    ],
                    9,
                ))
            }, // "JUP/USD"
            [245, 237, 236, 132, 113, 199, 86, 36, 235, 196, 7, 154, 99, 67, 38, 217, 106, 104, 158, 97, 87, 215, 154, 190, 143, 90, 111, 148, 71, 40, 83, 188] => {
                Ok((
                    [
                        11, 191, 40, 233, 168, 65, 161, 204, 120, 143, 106, 54, 27, 23, 202, 7, 45,
                        14, 163, 9, 138, 30, 93, 241, 195, 146, 45, 6, 113, 149, 121, 255,
                    ],
                    9,
                ))
            }, // "PYTH/USD"
            [10, 115, 32, 147, 145, 133, 97, 247, 221, 127, 203, 236, 74, 189, 133, 19, 222, 202, 26, 150, 127, 122, 215, 163, 157, 99, 180, 30, 216, 147, 128, 139] => {
                Ok((
                    [
                        100, 159, 221, 126, 192, 142, 142, 42, 32, 244, 37, 114, 152, 84, 233, 2,
                        147, 220, 190, 35, 118, 171, 196, 113, 151, 161, 77, 166, 255, 51, 151, 86,
                    ],
                    9,
                ))
            }, // "HNT/USD"
            [12, 193, 15, 81, 106, 170, 233, 193, 75, 169, 71, 31, 96, 171, 211, 146, 220, 215, 134, 213, 115, 84, 171, 237, 238, 231, 40, 157, 212, 10, 10, 10] => {
                Ok((
                    [
                        61, 74, 43, 217, 83, 91, 230, 206, 128, 89, 215, 94, 173, 235, 165, 7, 176,
                        67, 37, 115, 33, 170, 84, 71, 23, 197, 111, 161, 155, 73, 227, 93,
                    ],
                    9,
                ))
            }, // "RENDER/USD"
            [12, 0, 208, 175, 235, 134, 20, 218, 127, 25, 171, 160, 45, 64, 241, 140, 105, 37, 133, 246, 80, 32, 223, 206, 211, 213, 229, 249, 169, 192, 196, 225] => {
                Ok((
                    [
                        55, 80, 82, 97, 229, 87, 226, 81, 41, 11, 140, 136, 153, 69, 48, 100, 232,
                        215, 96, 237, 92, 101, 167, 121, 114, 111, 36, 144, 152, 13, 167, 76,
                    ],
                    9,
                ))
            }, // "ORCA/USD"
            [103, 82, 5, 92, 32, 179, 233, 216, 116, 102, 86, 221, 247, 56, 85, 80, 127, 135, 171, 109, 135, 82, 62, 76, 118, 167, 250, 54, 9, 106, 153, 235] => {
                Ok((
                    [
                        73, 96, 22, 37, 225, 163, 66, 193, 249, 12, 63, 230, 160, 58, 224, 37, 25,
                        145, 161, 215, 110, 72, 13, 39, 65, 82, 76, 41, 3, 123, 226, 138,
                    ],
                    9,
                ))
            }, // "SAMO/USD"
            [197, 249, 251, 50, 244, 145, 17, 171, 32, 195, 63, 37, 152, 252, 131, 108, 17, 62, 41, 24, 129, 172, 33, 238, 41, 22, 147, 148, 1, 18, 68, 228] => {
                Ok((
                    [
                        76, 164, 190, 236, 168, 111, 13, 22, 65, 96, 50, 56, 23, 164, 228, 43, 16,
                        1, 10, 114, 76, 34, 23, 198, 238, 65, 181, 76, 212, 204, 97, 252,
                    ],
                    9,
                ))
            }, // "WIF/USD"
            [4, 250, 212, 33, 200, 243, 118, 190, 252, 227, 205, 105, 72, 205, 99, 182, 190, 197, 184, 163, 111, 54, 77, 235, 131, 163, 147, 215, 33, 183, 215, 239] => {
                Ok((
                    [
                        18, 251, 103, 78, 228, 150, 4, 91, 29, 156, 247, 213, 230, 83, 121, 172,
                        176, 38, 19, 60, 42, 214, 159, 62, 217, 150, 251, 159, 230, 142, 58, 55,
                    ],
                    9,
                ))
            }, // "LST/USD"
            [5, 190, 108, 135, 238, 194, 212, 10, 46, 38, 225, 252, 10, 132, 35, 163, 121, 130, 12, 164, 84, 152, 35, 72, 173, 252, 149, 99, 181, 21, 119, 37] => {
                Ok((
                    [
                        91, 189, 28, 230, 23, 121, 43, 71, 108, 85, 153, 28, 39, 205, 253, 137,
                        121, 79, 159, 19, 53, 107, 171, 201, 201, 36, 5, 245, 240, 7, 150, 131,
                    ],
                    9,
                ))
            }, // "PRCL/USD"
            [55, 153, 140, 203, 242, 208, 69, 139, 97, 92, 188, 198, 177, 163, 103, 196, 116, 158, 159, 239, 115, 6, 98, 46, 27, 27, 88, 145, 1, 32, 188, 154] => {
                Ok((
                    [
                        145, 86, 139, 170, 139, 235, 83, 219, 35, 235, 63, 183, 242, 44, 110, 139,
                        211, 3, 209, 3, 145, 158, 25, 115, 63, 43, 182, 66, 211, 231, 152, 122,
                    ],
                    9,
                ))
            }, // "RAY/USD"
            [202, 77, 57, 150, 76, 156, 181, 249, 121, 13, 10, 18, 150, 159, 96, 253, 151, 36, 147, 98, 132, 234, 74, 18, 218, 222, 212, 45, 223, 166, 156, 93] => {
                Ok((
                    [
                        200, 6, 87, 183, 246, 243, 234, 194, 114, 24, 208, 157, 90, 78, 84, 228,
                        123, 37, 118, 141, 159, 94, 16, 172, 21, 254, 44, 249, 0, 136, 20, 0,
                    ],
                    9,
                ))
            }, // "FIDA/USD"
            [5, 55, 153, 111, 38, 153, 103, 79, 183, 8, 110, 70, 143, 179, 59, 79, 222, 20, 73, 244, 122, 139, 239, 216, 179, 66, 191, 107, 51, 207, 243, 114] => {
                Ok((
                    [
                        54, 7, 191, 77, 123, 120, 102, 107, 211, 115, 108, 122, 172, 175, 47, 210,
                        188, 86, 202, 168, 102, 125, 50, 36, 151, 30, 190, 60, 6, 35, 41, 42,
                    ],
                    9,
                ))
            }, // "MNDE/USD"
            [10, 181, 211, 6, 27, 91, 3, 60, 216, 75, 230, 110, 96, 172, 193, 172, 117, 104, 244, 97, 251, 57, 116, 211, 165, 182, 170, 47, 213, 36, 1, 236] => {
                Ok((
                    [
                        107, 112, 30, 41, 46, 8, 54, 209, 138, 89, 4, 160, 143, 233, 69, 52, 249,
                        171, 92, 61, 79, 243, 125, 192, 44, 116, 221, 15, 73, 1, 148, 77,
                    ],
                    9,
                ))
            }, // "IOT/USD"
            [5, 139, 241, 240, 13, 22, 125, 61, 243, 20, 145, 218, 226, 4, 214, 0, 107, 157, 89, 104, 112, 238, 207, 93, 48, 80, 53, 223, 138, 63, 150, 221] => {
                Ok((
                    [
                        216, 33, 131, 221, 72, 123, 239, 50, 8, 162, 39, 187, 37, 215, 72, 147, 13,
                        181, 136, 98, 197, 18, 17, 152, 231, 35, 237, 9, 118, 235, 146, 183,
                    ],
                    9,
                ))
            }, // "NEON/USD"
            [6, 125, 106, 212, 16, 32, 240, 79, 186, 125, 168, 221, 6, 118, 211, 153, 210, 108, 65, 64, 99, 134, 240, 3, 156, 160, 6, 51, 3, 180, 197, 43] => {
                Ok((
                    [
                        248, 208, 48, 228, 239, 70, 11, 145, 173, 35, 234, 187, 187, 39, 174, 196,
                        99, 227, 195, 14, 204, 141, 92, 75, 113, 233, 47, 84, 163, 108, 205, 189,
                    ],
                    9,
                ))
            }, // "SLND/USD"
            [7, 124, 246, 58, 86, 255, 10, 251, 18, 79, 111, 104, 135, 90, 2, 173, 206, 78, 50, 11, 191, 204, 16, 114, 230, 122, 10, 79, 250, 70, 194, 149] => {
                Ok((
                    [
                        81, 105, 73, 28, 215, 226, 164, 76, 152, 53, 59, 119, 157, 94, 182, 18,
                        228, 172, 50, 224, 115, 245, 204, 83, 67, 3, 216, 99, 7, 194, 241, 188,
                    ],
                    9,
                ))
            }, // "WEN/USD"
            [2, 165, 235, 116, 118, 180, 121, 40, 190, 178, 71, 91, 8, 236, 221, 201, 92, 161, 103, 151, 248, 20, 31, 178, 53, 51, 32, 59, 232, 202, 10, 216] => {
                Ok((
                    [
                        147, 195, 222, 249, 177, 105, 244, 158, 237, 20, 201, 215, 62, 208, 233,
                        66, 198, 102, 207, 14, 18, 144, 101, 126, 200, 32, 56, 235, 183, 146, 194,
                        168,
                    ],
                    9,
                ))
            }, // "BLZE/USD"
            [4, 112, 205, 245, 179, 146, 37, 47, 78, 87, 169, 38, 218, 227, 61, 44, 134, 117, 164, 143, 153, 230, 88, 88, 111, 60, 234, 245, 11, 146, 156, 197] => {
                Ok((
                    [
                        200, 17, 171, 200, 43, 75, 173, 31, 155, 215, 17, 162, 119, 60, 202, 169,
                        53, 176, 62, 206, 249, 116, 35, 105, 66, 206, 197, 224, 235, 132, 90, 58,
                    ],
                    9,
                ))
            }, // "JLP/USD"
            [130, 104, 233, 169, 161, 68, 76, 43, 165, 199, 122, 81, 147, 104, 86, 176, 114, 228, 63, 239, 207, 245, 228, 176, 30, 153, 98, 60, 142, 187, 119, 73] => {
                Ok((
                    [
                        201, 216, 176, 117, 165, 198, 147, 3, 54, 90, 226, 54, 51, 212, 224, 133,
                        25, 155, 245, 197, 32, 163, 185, 15, 237, 19, 34, 160, 52, 47, 252, 51,
                    ],
                    9,
                ))
            }, // "WBTC/USD"
            [5, 177, 228, 60, 41, 26, 113, 5, 254, 186, 15, 12, 26, 38, 66, 134, 238, 175, 255, 173, 23, 245, 56, 125, 81, 88, 20, 163, 244, 172, 5, 225] => {
                Ok((
                    [
                        190, 211, 9, 112, 8, 185, 181, 227, 201, 59, 236, 32, 190, 121, 203, 67,
                        152, 107, 133, 169, 150, 71, 85, 137, 53, 26, 33, 230, 123, 174, 155, 97,
                    ],
                    9,
                ))
            }, // "PENGU/USD"
            [24, 29, 235, 32, 16, 221, 196, 241, 239, 94, 210, 58, 247, 238, 26, 204, 106, 112, 232, 16, 16, 98, 42, 12, 37, 151, 20, 247, 8, 78, 170, 162] => {
                Ok((
                    [
                        135, 149, 81, 2, 24, 83, 238, 199, 167, 220, 130, 117, 120, 232, 230, 157,
                        167, 228, 250, 129, 72, 51, 154, 160, 211, 213, 41, 100, 5, 190, 75, 26,
                    ],
                    9,
                ))
            }, // "TRUMP/USD"
            [27, 244, 244, 37, 186, 186, 98, 141, 221, 94, 58, 7, 123, 70, 117, 100, 51, 136, 195, 179, 169, 244, 17, 142, 11, 133, 89, 11, 12, 238, 167, 113] => {
                Ok((
                    [
                        88, 205, 41, 239, 14, 113, 76, 90, 255, 196, 79, 38, 155, 44, 24, 153, 165,
                        45, 164, 22, 157, 122, 204, 20, 123, 157, 166, 146, 230, 149, 54, 8,
                    ],
                    9,
                ))
            }, // "FARTCOIN/USD"
            [84, 135, 218, 189, 206, 53, 75, 193, 66, 144, 224, 68, 246, 34, 246, 92, 211, 247, 125, 106, 65, 166, 49, 188, 130, 202, 221, 250, 200, 23, 198, 214] => {
                Ok((
                    [
                        64, 172, 51, 41, 147, 58, 107, 91, 101, 207, 49, 73, 96, 24, 197, 118, 74,
                        192, 86, 115, 22, 20, 111, 125, 13, 224, 0, 149, 136, 107, 72, 13,
                    ],
                    9,
                ))
            }, // "TESTTOKEN/USD"
            [247, 169, 151, 255, 215, 241, 92, 175, 239, 134, 208, 37, 97, 234, 209, 161, 53, 165, 40, 34, 193, 65, 166, 81, 164, 72, 62, 60, 149, 224, 228, 83] => {
                Ok((
                    [
                        239, 13, 139, 111, 218, 44, 235, 164, 29, 161, 93, 64, 149, 209, 218, 57,
                        42, 13, 47, 142, 208, 198, 199, 188, 15, 76, 250, 200, 194, 128, 181, 109,
                    ],
                    9,
                ))
            },
            _ => Err(SwigStateError::InvalidOracleTokenMint),
        }
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
    const REPEATABLE: bool = true;

    /// Checks if this token limit matches the provided base asset type.
    ///
    /// # Arguments
    /// * `data` - The base asset type to check against (first byte)
    ///
    /// # Returns
    /// `true` if the base asset type matches, `false` otherwise
    fn match_data(&self, data: &[u8]) -> bool {
        !data.is_empty() && data[0] == self.base_asset_type
    }
}
