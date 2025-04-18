// Public modules
mod error;
mod instruction_builder;
mod types;
mod wallet;

// Re-exports for convenient public API
pub use error::SwigError;
pub use instruction_builder::{AuthorityManager, SwigInstructionBuilder};
pub use types::{Permission, RecurringConfig};
pub use wallet::SwigWallet;
