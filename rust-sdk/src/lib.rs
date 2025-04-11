// Public modules
mod error;
mod instruction_builder;
mod types;
mod wallet;

// Re-exports for convenient public API
pub use error::SwigError;
pub use instruction_builder::SwigInstructionBuilder;
pub use types::{Permission, WalletAuthority};
pub use wallet::SwigWallet;
