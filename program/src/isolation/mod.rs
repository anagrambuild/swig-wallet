//! Protect outer signers' personal assets across Swig-authorized CPIs.
//!
//! Construct an empty `IsolationGuard`, call `capture_signers` after authentication,
//! and add the relevant account snapshots before the first CPI. Pass the guard by
//! reference and call `validate` after execution.
//! The guard retains its account list so validation uses the captured accounts.
//! Snapshots are bounded local scratch; they add no serialized state, instruction
//! fields, or heap allocations.

mod frozen;
mod funding;
mod snapshot;
mod token;

#[cfg(test)]
mod tests;

pub use snapshot::IsolationGuard;

use pinocchio::ProgramResult;

const MAX_PROTECTED_TOKENS: usize = 4;
const MAX_PROTECTED_SIGNERS: usize = 64;
const MAX_FROZEN: usize = 4;
const MAX_CREATIONS: usize = 8;

impl IsolationGuard<'_> {
    /// Validate personal balances and control against the pre-CPI snapshots.
    /// Credits are allowed. Signer SOL decreases are bounded by newly allocated
    /// accounts' rent deficits; existing token/SOL accounts cannot absorb spend.
    #[inline(always)]
    pub fn validate(&self) -> ProgramResult {
        self.validate_signer_accounts()?;
        self.validate_token_accounts()?;
        self.validate_frozen_accounts()
    }
}
