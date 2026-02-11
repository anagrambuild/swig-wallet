// Public modules
pub mod client_role;
pub mod error;
pub mod instruction_builder;
pub mod multi_wallet_manager;
pub mod types;
pub mod utils;
pub mod wallet;

// Re-exports for convenient public API
pub use client_role::{
    ClientRole, Ed25519ClientRole, Ed25519SessionClientRole, Secp256k1ClientRole,
    Secp256k1SessionClientRole,
};
pub use error::SwigError;
pub use instruction_builder::SwigInstructionBuilder;
pub use multi_wallet_manager::{
    BatchConfig, BatchExecutionResult, BatchStrategy, FailedInstruction, MultiWalletManager,
    SuccessfulBatch,
};
pub use swig_state::{authority, swig};
pub use types::{Permission, RecurringConfig};
pub use utils::*;
pub use wallet::SwigWallet;

#[cfg(all(feature = "rust_sdk_test", test))]
mod tests;
