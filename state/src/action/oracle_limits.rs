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
use pinocchio_pubkey::pubkey;

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
    pub fn run_for_token(&mut self, price: u64) -> Result<(), ProgramError> {
        // Check if operation would exceed limit
        if price > self.value_limit {
            msg!("Operation denied: Would exceed value limit");
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

    /// Gets the token feed ID and decimal from the token mint address.
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
        TOKEN_CONFIGS
            .iter()
            .find(|(mint, _)| mint.as_ref() == token_mint)
            .map(|(_, config)| {
                let feed_id = get_feed_id_from_hex(config.feed_id)?;
                Ok((feed_id, config.decimals))
            })
            .unwrap_or(Err(SwigStateError::FeedIdMustBe32Bytes))
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

/// Converts a hex string to a 32-byte array.
///
/// # Arguments
/// * `input` - A hex string representing the feed ID (with or without "0x" prefix)
///
/// # Returns
/// * `Ok([u8; 32])` - The feed ID as a 32-byte array
/// * `Err(SwigStateError)` - If the input is invalid
fn get_feed_id_from_hex(input: &str) -> Result<[u8; 32], SwigStateError> {
    let mut feed_id = [0; 32];
    match input.len() {
        66 => feed_id.copy_from_slice(
            &hex::decode(&input[2..]).map_err(|_| SwigStateError::FeedIdNonHexCharacter)?,
        ),
        64 => feed_id.copy_from_slice(
            &hex::decode(input).map_err(|_| SwigStateError::FeedIdNonHexCharacter)?,
        ),
        _ => return Err(SwigStateError::FeedIdMustBe32Bytes),
    }
    Ok(feed_id)
}

/// Represents a token mint configuration with its feed ID and decimals
struct TokenConfig {
    /// The hex string representation of the oracle feed ID
    feed_id: &'static str,
    /// The number of decimal places for the token
    decimals: u8,
}

/// Static lookup table mapping mint addresses to their configurations.
///
/// Each entry contains:
/// - A 32-byte mint address
/// - A TokenConfig with the feed ID and decimals
const TOKEN_CONFIGS: &[(&[u8; 32], TokenConfig)] = &[
    // JitoSOL / USD
    (
        &pubkey!("J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn"),
        TokenConfig {
            feed_id: "67be9f519b95cf24338801051f9a808eff0a578ccb388db73b7f6fe1de019ffb",
            decimals: 9,
        },
    ),
    // mSOL / USD
    (
        &pubkey!("mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So"),
        TokenConfig {
            feed_id: "c2289a6a43d2ce91c6f55caec370f4acc38a2ed477f58813334c6d03749ff2a4",
            decimals: 9,
        },
    ),
    // bSOL / USD
    (
        &pubkey!("bSo13r4TkiE4KumL71LsHTPpL2euBYLFx6h9HP3piy1"),
        TokenConfig {
            feed_id: "89875379e70f8fbadc17aef315adf3a8d5d160b811435537e03c97e8aac97d9c",
            decimals: 9,
        },
    ),
    // BONK / USD
    (
        &pubkey!("DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"),
        TokenConfig {
            feed_id: "72b021217ca3fe68922a19aaf990109cb9d84e9ad004b4d2025ad6f529314419",
            decimals: 5,
        },
    ),
    // W / USD
    (
        &pubkey!("85VBFQZC9TZkfaptBWjvUw7YbZjy52A6mjtPGjstQAmQ"),
        TokenConfig {
            feed_id: "eff7446475e218517566ea99e72a4abec2e1bd8498b43b7d8331e29dcb059389",
            decimals: 9,
        },
    ),
    // KMNO / USD
    (
        &pubkey!("KMNo4fXk3qpr8HTnKydyHqWXyUz1eWQNv6i6gY6A7hN"),
        TokenConfig {
            feed_id: "b17e5bc5de742a8a378b54c9c75442b7d51e30ada63f28d9bd28d3c0e26511a0",
            decimals: 9,
        },
    ),
    // MEW / USD
    (
        &pubkey!("MEW1gQWJ3nEXg2qgERiKu7mFZqun83UZpZUWxT5CakH"),
        TokenConfig {
            feed_id: "514aed52ca5294177f20187ae883cec4a018619772ddce41efcc36a6448f5d5d",
            decimals: 9,
        },
    ),
    // TNSR / USD
    (
        &pubkey!("TNSRxcUxoT9xBG3de7PiJyTDYu7kskLqcpddxnEJAS6"),
        TokenConfig {
            feed_id: "05ecd4597cd48fe13d6cc3596c62af4f9675aee06e2e0b94c06d8bee2b659e05",
            decimals: 9,
        },
    ),
    // USDC / USD
    (
        &pubkey!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
        TokenConfig {
            feed_id: "eaa020c61cc479712813461ce153894a96a6c00b21ed0cfc2798d1f9a9e9c94a",
            decimals: 6,
        },
    ),
    // JTO / USD
    (
        &pubkey!("jtojtomepa8beP8AuQc6eXt5FriJwfFMwQx2v2f9mCL"),
        TokenConfig {
            feed_id: "b43660a5f790c69354b0729a5ef9d50d68f1df92107540210b9cccba1f947cc2",
            decimals: 9,
        },
    ),
    // USDT / USD
    (
        &pubkey!("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"),
        TokenConfig {
            feed_id: "2b89b9dc8fdf9f34709a5b106b472f0f39bb6ca9ce04b0fd7f2e971688e2e53b",
            decimals: 6,
        },
    ),
    // JUP / USD
    (
        &pubkey!("JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN"),
        TokenConfig {
            feed_id: "0a0408d619e9380abad35060f9192039ed5042fa6f82301d0e48bb52be830996",
            decimals: 6,
        },
    ),
    // PYTH / USD
    (
        &pubkey!("HZ1JovNiVvGrGNiiYvEozEVgZ58xaU3RKwX8eACQBCt3"),
        TokenConfig {
            feed_id: "0bbf28e9a841a1cc788f6a361b17ca072d0ea3098a1e5df1c3922d06719579ff",
            decimals: 6,
        },
    ),
    // HNT / USD
    (
        &pubkey!("hntyVP6YFm1Hg25TN9WGLqM12b8TQmcknKrdu1oxWux"),
        TokenConfig {
            feed_id: "649fdd7ec08e8e2a20f425729854e90293dcbe2376abc47197a14da6ff339756",
            decimals: 8,
        },
    ),
    // RENDER / USD
    (
        &pubkey!("rndrizKT3MK1iimdxRdWabcF7Zg7AR5T4nud4EkHBof"),
        TokenConfig {
            feed_id: "3d4a2bd9535be6ce8059d75eadeba507b043257321aa544717c56fa19b49e35d",
            decimals: 9,
        },
    ),
    // ORCA / USD
    (
        &pubkey!("orcaEKTdK7LKz57vaAYr9QeNsVEPfiu6QeMU1kektZE"),
        TokenConfig {
            feed_id: "37505261e557e251290b8c8899453064e8d760ed5c65a779726f2490980da74c",
            decimals: 6,
        },
    ),
    // SAMO / USD
    (
        &pubkey!("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"),
        TokenConfig {
            feed_id: "49601625e1a342c1f90c3fe6a03ae0251991a1d76e480d2741524c29037be28a",
            decimals: 9,
        },
    ),
    // WIF / USD
    (
        &pubkey!("EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm"),
        TokenConfig {
            feed_id: "4ca4beeca86f0d164160323817a4e42b10010a724c2217c6ee41b54cd4cc61fc",
            decimals: 9,
        },
    ),
    // LST / USD
    (
        &pubkey!("LSTxxxnJzKDFSLr4dUkPcmCf5VyryEqzPLz5j4bpxFp"),
        TokenConfig {
            feed_id: "12fb674ee496045b1d9cf7d5e65379acb026133c2ad69f3ed996fb9fe68e3a37",
            decimals: 9,
        },
    ),
    // PRCL / USD
    (
        &pubkey!("PRT88RkA4Kg5z7pKnezeNH4mafTvtQdfFgpQTGRjz44"),
        TokenConfig {
            feed_id: "5bbd1ce617792b476c55991c27cdfd89794f9f13356babc9c92405f5f0079683",
            decimals: 9,
        },
    ),
    // RAY / USD
    (
        &pubkey!("4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R"),
        TokenConfig {
            feed_id: "91568baa8beb53db23eb3fb7f22c6e8bd303d103919e19733f2bb642d3e7987a",
            decimals: 6,
        },
    ),
    // FIDA / USD
    (
        &pubkey!("EchesyfXePKdLtoiZSL8pBe8Myagyy8ZRqsACNCFGnvp"),
        TokenConfig {
            feed_id: "c80657b7f6f3eac27218d09d5a4e54e47b25768d9f5e10ac15fe2cf900881400",
            decimals: 6,
        },
    ),
    // MNDE / USD
    (
        &pubkey!("MNDEFzGvMt87ueuHvVU9VcTqsAP5b3fTGPsHuuPA5ey"),
        TokenConfig {
            feed_id: "3607bf4d7b78666bd3736c7aacaf2fd2bc56caa8667d3224971ebe3c0623292a",
            decimals: 9,
        },
    ),
    // IOT / USD
    (
        &pubkey!("iotEVVZLEywoTn1QdwNPddxPWszn3zFhEot3MfL9fns"),
        TokenConfig {
            feed_id: "6b701e292e0836d18a5904a08fe94534f9ab5c3d4ff37dc02c74dd0f4901944d",
            decimals: 9,
        },
    ),
    // NEON / USD
    (
        &pubkey!("NeonTjSjsuo3rexg9o6vHuMXw62f9V7zvmu8M8Zut44"),
        TokenConfig {
            feed_id: "d82183dd487bef3208a227bb25d748930db58862c5121198e723ed0976eb92b7",
            decimals: 9,
        },
    ),
    // SLND / USD
    (
        &pubkey!("SLNDpmoWTVADgEdndyvWzroNL7zSi1dF9PC3xHGtPwp"),
        TokenConfig {
            feed_id: "f8d030e4ef460b91ad23eabbbb27aec463e3c30ecc8d5c4b71e92f54a36ccdbd",
            decimals: 6,
        },
    ),
    // WEN / USD
    (
        &pubkey!("WENWENvqqNya429ubCdR81ZmD69brwQaaBYY6p3LCpk"),
        TokenConfig {
            feed_id: "5169491cd7e2a44c98353b779d5eb612e4ac32e073f5cc534303d86307c2f1bc",
            decimals: 9,
        },
    ),
    // BLZE / USD
    (
        &pubkey!("BLZEEuZUBV2FNLJ5h5UKxBg2u8mKYbf5Zo6W8PE7d9y"),
        TokenConfig {
            feed_id: "93c3def9b169f49eed14c9d73ed0e942c666cf0e1290657ec82038ebb792c2a8",
            decimals: 9,
        },
    ),
    // JLP / USD
    (
        &pubkey!("JLPx6n7WC1Y3yQ4q8GkARyMHVZ5noqYjF8qyWY5y2P6"),
        TokenConfig {
            feed_id: "c811abc82b4bad1f9bd711a2773ccaa935b03ecef974236942cec5e0eb845a3a",
            decimals: 9,
        },
    ),
    // WBTC / USD
    (
        &pubkey!("9n4nbM75f5Ui33ZbPYXn59EwSgE8CGsHtAeTH5YFeJ9E"),
        TokenConfig {
            feed_id: "c9d8b075a5c69303365ae23633d4e085199bf5c520a3b90fed1322a0342ffc33",
            decimals: 8,
        },
    ),
    // PENGU / USD
    (
        &pubkey!("PENGUxLhrQwB1QJ2kQ3Y1F5Sq8UdVFQo5Xvg4Z5AxAt"),
        TokenConfig {
            feed_id: "bed3097008b9b5e3c93bec20be79cb43986b85a996475589351a21e67bae9b61",
            decimals: 9,
        },
    ),
    // TRUMP / USD
    (
        &pubkey!("2d9FCSx5QYAJs3YQeS2WATx3W98v3QH1N2k2ZkF5XQ5F"),
        TokenConfig {
            feed_id: "879551021853eec7a7dc827578e8e69da7e4fa8148339aa0d3d5296405be4b1a",
            decimals: 9,
        },
    ),
    // FARTCOIN / USD
    (
        &pubkey!("2t8eUbYKjidMs3uSeYM9jXM9uudYZwGkSeTB4TKjmvnC"),
        TokenConfig {
            feed_id: "58cd29ef0e714c5affc44f269b2c1899a52da4169d7acc147b9da692e6953608",
            decimals: 9,
        },
    ),
    // ACRED / USD
    (
        &pubkey!("6gyQ2TKvvV1JB5oWDobndv6BLRWcJzeBNk9PLQ5uPQms"),
        TokenConfig {
            feed_id: "40ac3329933a6b5b65cf31496018c5764ac0567316146f7d0de00095886b480d",
            decimals: 9,
        },
    ),
    // TEST / USD
    (
        &pubkey!("Hfmh5FEBkR17ame7dhjMFjaFLtP1Mbp6mgT1Cv86YhLW"),
        TokenConfig {
            feed_id: "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d",
            decimals: 9,
        },
    ),
];
