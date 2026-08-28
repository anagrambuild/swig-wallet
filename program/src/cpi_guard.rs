//! Inbound CPI policy for Swig instructions.
//!
//! Signing instructions own their existing top-level checks because they are
//! latency-sensitive execution paths. Every non-sign instruction is
//! direct-only unless an exact compile-time allowlisted signer is forwarded to
//! the CPI.

use pinocchio::{account_info::AccountInfo, ProgramResult};
use swig_assertions::{get_stack_height, sol_assert_bytes_eq};

use crate::error::SwigError;

// The only production exception is the signer observed on Dexter's inbound
// non-sign Swig CPIs. This key must remain on-curve: an arbitrary caller must
// not be able to manufacture its signer privilege with invoke_signed.
const DEXTER_CPI_SIGNER: [u8; 32] =
    pinocchio_pubkey::pubkey!("X4o2kSLzqEQjnAzhq3L3BW92aawMV2n2F37EXd2GMpy");
const NON_SIGN_CPI_SIGNER_ALLOWLIST: &[[u8; 32]] = &[DEXTER_CPI_SIGNER];

/// Enforces the inbound-CPI policy before dispatching a non-sign instruction.
///
/// Direct calls remain account- and wire-compatible. An inbound CPI must
/// forward an exact allowlisted public key with signer privilege. The exception
/// applies to every non-sign instruction; it authenticates the signer, not the
/// immediate caller program, which Solana does not expose to the callee.
#[inline(always)]
pub(crate) fn enforce_non_sign_cpi_policy(accounts: &[AccountInfo]) -> ProgramResult {
    if get_stack_height(1) {
        return Ok(());
    }

    let allowed = accounts.iter().any(|account| {
        account.is_signer()
            && NON_SIGN_CPI_SIGNER_ALLOWLIST
                .iter()
                .any(|signer| sol_assert_bytes_eq(account.key(), signer, 32))
    });

    if allowed {
        Ok(())
    } else {
        Err(SwigError::Cpi.into())
    }
}
