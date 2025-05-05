// Public modules
pub mod error;
pub mod instruction_builder;
pub mod types;
pub mod wallet;

// Re-exports for convenient public API
pub use error::SwigError;
pub use instruction_builder::{AuthorityManager, SwigInstructionBuilder};

pub use swig_state_x::authority;
pub use types::{Permission, RecurringConfig};
pub use wallet::SwigWallet;

#[cfg(all(feature = "rust_sdk_test", test))]
mod tests;
