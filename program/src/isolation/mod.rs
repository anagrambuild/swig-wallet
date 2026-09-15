//! Protect outer signers' personal assets across Swig-authorized CPIs.
//!
//! Construct an `IsolationGuard`, add the relevant account snapshots before the
//! first CPI, then pass the guard by reference and call `validate` after execution.
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

use pinocchio::{account_info::AccountInfo, ProgramResult};

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
        let all_accounts = self.accounts;
        funding::validate_signer_balances(self, all_accounts)?;
        if !self.tokens.as_slice().is_empty() || !self.frozen.as_slice().is_empty() {
            self.validate_account_data(all_accounts)?;
        }
        Ok(())
    }

    #[inline(never)]
    fn validate_account_data(&self, all_accounts: &[AccountInfo]) -> ProgramResult {
        token::validate_token_accounts(self, all_accounts)?;
        frozen::validate_frozen_accounts(self, all_accounts)
    }
}
