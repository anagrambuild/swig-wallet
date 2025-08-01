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
    /// 3. `[writable]` System program account
    #[account(0, writable, name="swig", desc="the swig smart wallet")]
    #[account(1, writable, signer, name="payer", desc="the payer")]
    #[account(2, name="system_program", desc="the system program")]
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

    /// Signs and executes a transaction.
    ///
    /// The instruction data includes:
    /// - Instruction payload with offset and length
    /// - Authority payload with offset and length
    /// Additional accounts may be required for CPI calls.
    ///
    /// Required accounts:
    /// 1. `[writable, signer]` Swig wallet account
    /// 2. `[writable, signer]` Payer account
    /// 3. System program account
    #[account(0, writable, signer, name="swig", desc="the swig smart wallet")]
    #[account(1, writable, signer, name="payer", desc="the payer")]
    #[account(2, name="system_program", desc="the system program")]
    SignV1 = 4,

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
    #[account(0, writable, name="swig", desc="the swig smart wallet")]
    #[account(1, writable, signer, name="payer", desc="the payer")]
    #[account(2, writable, name="sub_account", desc="the sub account to withdraw from")]
    WithdrawFromSubAccountV1 = 7,

    /// Signs and executes a transaction from a sub-account.
    ///
    /// Required accounts:
    /// 1. Swig wallet account
    /// 2. `[writable, signer]` Payer account
    /// 3. `[writable]` Sub-account
    /// 4. System program account
    #[account(0, name="swig", desc="the swig smart wallet")]
    #[account(1, writable, signer, name="payer", desc="the payer")]
    #[account(2, writable, name="sub_account", desc="the sub account")]
    #[account(3, name="system_program", desc="the system program")]
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
}
