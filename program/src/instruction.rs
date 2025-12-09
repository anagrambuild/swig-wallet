//! Instruction definitions for the Swig wallet program.
//!
//! This module defines all instructions that can be processed by the Swig
//! wallet program. Each instruction variant specifies its required accounts and
//! their properties (writable, signer, etc.). The instructions support wallet
//! creation, authority management, session management, and sub-account
//! operations.

use num_enum::{FromPrimitive, IntoPrimitive};
use pinocchio::{account_info::AccountInfo, program_error::ProgramError};
use shank::{ShankContext, ShankInstruction};

/// Instructions supported by the Swig wallet program.
///
/// Each variant represents a different operation that can be performed. The
/// accounts required for each instruction are specified using the `account`
/// attribute. The instruction data format is documented in the variant
/// description.
#[derive(Clone, Copy, Debug, ShankContext, ShankInstruction, FromPrimitive, IntoPrimitive)]
#[rustfmt::skip]
#[repr(u16)]
pub enum SwigInstruction {
    /// Creates a new Swig wallet.
    ///
    /// Required accounts:
    /// 1. `[writable]` Swig wallet account to create
    /// 2. `[writable, signer]` Payer account for rent
    /// 3. `[writable]` Swig wallet address account to create
    /// 4. `[writable]` System program account
    #[account(0, writable, name="swig", desc="the swig smart wallet")]
    #[account(1, writable, signer, name="payer", desc="the payer")]
    #[account(2, writable, name="swig_wallet_address", desc="the swig wallet address account")]
    #[account(3, name="system_program", desc="the system program")]
    #[num_enum(default)]
    CreateV1 = 0,

    /// Adds a new authority to the wallet.
    ///
    /// Required accounts:
    /// 1. `[writable, signer]` Swig wallet account
    /// 2. `[writable, signer]` Payer account
    /// 3. System program account
    #[account(0, writable, signer, name="swig", desc="the swig smart wallet")]
    #[account(1, writable, signer, name="payer", desc="the payer")]
    #[account(2, name="system_program", desc="the system program")]
    AddAuthorityV1 = 1,

    /// Removes an authority from the wallet.
    ///
    /// Required accounts:
    /// 1. `[writable, signer]` Swig wallet account
    /// 2. `[writable, signer]` Payer account
    /// 3. System program account
    #[account(0, writable, signer, name="swig", desc="the swig smart wallet")]
    #[account(1, writable, signer, name="payer", desc="the payer")]
    #[account(2, name="system_program", desc="the system program")]
    RemoveAuthorityV1 = 2,

    /// Updates an existing authority in the wallet.
    ///
    /// Required accounts:
    /// 1. `[writable, signer]` Swig wallet account
    /// 2. `[writable, signer]` Payer account
    /// 3. System program account
    #[account(0, writable, signer, name="swig", desc="the swig smart wallet")]
    #[account(1, writable, signer, name="payer", desc="the payer")]
    #[account(2, name="system_program", desc="the system program")]
    UpdateAuthorityV1 = 3,

    /// DEPRECATED: Signs and executes a transaction (V1 accounts only).
    ///
    /// This instruction is no longer supported. Use SignV2 instead.
    /// The discriminator value 4 is reserved to maintain backwards compatibility.
    #[doc(hidden)]
    #[account(0, name="deprecated", desc="deprecated instruction")]
    DeprecatedSignV1 = 4,

    /// Creates a new session for temporary authority.
    ///
    /// Required accounts:
    /// 1. `[writable, signer]` Swig wallet account
    /// 2. `[writable, signer]` Payer account
    /// 3. System program account
    #[account(0, writable, signer, name="swig", desc="the swig smart wallet")]
    #[account(1, writable, signer, name="payer", desc="the payer")]
    #[account(2, name="system_program", desc="the system program")]
    CreateSessionV1 = 5,

    /// Creates a new sub-account.
    ///
    /// Required accounts:
    /// 1. `[writable]` Swig wallet account
    /// 2. `[writable, signer]` Payer account
    /// 3. `[writable]` Sub-account to create
    /// 4. System program account
    #[account(0, writable, name="swig", desc="the swig smart wallet")]
    #[account(1, writable, signer, name="payer", desc="the payer")]
    #[account(2, writable, name="sub_account", desc="the sub account to be created")]
    #[account(3, name="system_program", desc="the system program")]
    CreateSubAccountV1 = 6,

    /// Withdraws funds from a sub-account.
    ///
    /// Required accounts:
    /// 1. `[writable]` Swig wallet account
    /// 2. `[writable, signer]` Payer account
    /// 3. `[writable]` Sub-account to withdraw from
    /// 4. `[writable]` Swig wallet address account (destination)
    /// 5. System program account
    #[account(0, writable, name="swig", desc="the swig smart wallet")]
    #[account(1, writable, signer, name="payer", desc="the payer")]
    #[account(2, writable, name="sub_account", desc="the sub account to withdraw from")]
    #[account(3, writable, signer, name="authority", desc="the swig authority")]
    #[account(4, writable, name="swig_wallet_address", desc="the swig wallet address (destination)")]
    #[account(5, name="system_program", desc="the system program")]
    WithdrawFromSubAccountV1 = 7,

    /// Signs and executes a transaction from a sub-account.
    ///
    /// Required accounts:
    /// 1. Swig wallet account
    /// 2. `[writable]` Sub-account
    /// 3. System program account
    #[account(0, name="swig", desc="the swig smart wallet")]
    #[account(1, writable, name="sub_account", desc="the sub account")]
    #[account(2, name="system_program", desc="the system program")]
    SubAccountSignV1 = 9,

    /// Toggles the enabled state of a sub-account.
    ///
    /// Required accounts:
    /// 1. `[writable]` Swig wallet account
    /// 2. `[signer]` Payer account
    /// 3. `[writable]` Sub-account to toggle
    #[account(0, writable, name="swig", desc="the swig smart wallet")]
    #[account(1, signer, name="payer", desc="the payer")]
    #[account(2, writable, name="sub_account", desc="the sub account to toggle enabled state")]
    ToggleSubAccountV1 = 10,

    /// Signs and executes a transaction (V2 accounts).
    ///
    /// The instruction data includes:
    /// - Instruction payload with offset and length
    /// - Authority payload with offset and length
    /// Additional accounts may be required for CPI calls.
    ///
    /// Required accounts:
    /// 1. `[writable]` Swig wallet account
    /// 2. `[writable, signer]` Swig wallet address account
    /// 3. System program account
    #[account(0, writable, name="swig", desc="the swig smart wallet")]
    #[account(1, writable, signer, name="swig_wallet_address", desc="the swig smart wallet address")]
    #[account(2, name="system_program", desc="the system program")]
    SignV2 = 11,

    /// Migrates a Swig account to support wallet address feature.
    ///
    /// This instruction updates the Swig account structure from the old format
    /// (with reserved_lamports) to the new format (with wallet_bump + padding)
    /// and creates the associated wallet address account.
    ///
    /// Required accounts:
    /// 1. `[writable]` Swig wallet account to migrate
    /// 2. `[writable, signer]` Authority with ManageAuthority permission or hardcoded admin
    /// 3. `[writable, signer]` Payer account for rent
    /// 4. `[writable]` Swig wallet address account to create
    /// 5. System program account
    #[account(0, writable, name="swig", desc="the swig smart wallet to migrate")]
    #[account(1, writable, signer, name="authority", desc="authority with manage authority permission or admin")]
    #[account(2, writable, signer, name="payer", desc="the payer")]
    #[account(3, writable, name="swig_wallet_address", desc="the swig wallet address account to create")]
    #[account(4, name="system_program", desc="the system program")]
    MigrateToWalletAddressV1 = 12,

    /// Transfers assets from the swig account to the swig wallet address.
    ///
    /// This instruction transfers all assets (SOL and SPL tokens) held by the
    /// swig account to the swig wallet address account. This is useful after
    /// migration where assets need to be moved from the old swig account to
    /// the new wallet address structure.
    ///
    /// Required accounts:
    /// 1. `[writable]` Swig wallet account (source)
    /// 2. `[writable]` Swig wallet address account (destination)
    /// 3. `[writable, signer]` Payer account
    /// 4. System program account
    #[account(0, writable, name="swig", desc="the swig smart wallet (source)")]
    #[account(1, writable, name="swig_wallet_address", desc="the swig wallet address (destination)")]
    #[account(2, writable, signer, name="payer", desc="the payer")]
    #[account(3, name="system_program", desc="the system program")]
    TransferAssetsV1 = 13,

    /// Closes a single token account owned by the swig wallet.
    ///
    /// The token account must have zero balance. Rent is returned to destination.
    /// This instruction handles both V1 (swig as authority) and V2 (swig_wallet_address
    /// as authority) token accounts automatically.
    ///
    /// Required accounts:
    /// 1. `[writable]` Swig wallet account
    /// 2. `[writable]` Swig wallet address PDA
    /// 3. `[writable]` Destination for rent
    /// 4. `[writable]` Token account to close
    /// 5. Token program (SPL Token or Token-2022)
    #[account(0, writable, name="swig", desc="the swig smart wallet")]
    #[account(1, writable, name="swig_wallet_address", desc="the swig wallet address PDA")]
    #[account(2, writable, name="destination", desc="rent destination")]
    #[account(3, writable, name="token_account", desc="the token account to close")]
    #[account(4, name="token_program", desc="the token program")]
    CloseTokenAccountV1 = 14,

    /// Closes the swig account and returns all lamports to destination.
    ///
    /// This instruction should only be called after all token accounts
    /// and sub-accounts have been closed. It handles both V1 and V2 accounts:
    /// - Transfers all lamports from swig_wallet_address to destination (if any)
    /// - Transfers all lamports from swig to destination
    /// - Closes the swig account
    ///
    /// Required accounts:
    /// 1. `[writable]` Swig wallet account to close
    /// 2. `[writable]` Swig wallet address PDA
    /// 3. `[writable]` Destination for all SOL and rent
    /// 4. System program
    #[account(0, writable, name="swig", desc="the swig smart wallet to close")]
    #[account(1, writable, name="swig_wallet_address", desc="the swig wallet address PDA")]
    #[account(2, writable, name="destination", desc="destination for SOL and rent")]
    #[account(3, name="system_program", desc="the system program")]
    CloseSwigV1 = 15,
}
