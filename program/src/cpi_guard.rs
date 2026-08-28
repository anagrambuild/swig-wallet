//! Inbound CPI policy for Swig instructions.
//!
//! Signing instructions own their existing top-level checks because they are
//! latency-sensitive execution paths. Every non-sign instruction is
//! direct-only unless the current top-level transaction instruction matches
//! one exact compile-time allowlist entry.

use pinocchio::{
    account_info::AccountInfo,
    sysvars::instructions::{Instructions, INSTRUCTIONS_ID},
    ProgramResult,
};
use swig_assertions::{get_stack_height, sol_assert_bytes_eq};

use crate::error::SwigError;

struct NonSignCpiAllowlistEntry {
    outer_program_id: [u8; 32],
    outer_instruction_prefix: &'static [u8],
}

// Dexter Vault's SetSwigAtomic instruction creates and configures a Swig wallet
// through CPI as one atomic onboarding operation.
const NON_SIGN_CPI_ALLOWLIST: &[NonSignCpiAllowlistEntry] = &[NonSignCpiAllowlistEntry {
    outer_program_id: pinocchio_pubkey::pubkey!("Hg3wRaydFtJhYrdvYrKECacpJYDsC9Px7yKmpncj2fhc"),
    outer_instruction_prefix: &[0x77, 0x6f, 0xf7, 0xd7, 0xbe, 0x03, 0xaa, 0x17],
}];

/// Enforces the inbound-CPI policy before dispatching a non-sign instruction.
///
/// Direct calls remain account- and wire-compatible. An allowlisted CPI must
/// forward the real instructions sysvar in any account position so the guard
/// can verify the current top-level program and instruction data. Solana does
/// not expose the immediate CPI caller, so this policy deliberately binds the
/// top-level transaction instruction that owns the invocation tree.
#[inline(always)]
pub(crate) fn enforce_non_sign_cpi_policy(accounts: &[AccountInfo]) -> ProgramResult {
    if get_stack_height(1) {
        return Ok(());
    }

    let instructions_sysvar = accounts
        .iter()
        .find(|account| account.key() == &INSTRUCTIONS_ID)
        .ok_or(SwigError::Cpi)?;
    let instructions = Instructions::try_from(instructions_sysvar).map_err(|_| SwigError::Cpi)?;
    let outer_instruction = instructions
        .load_instruction_at(instructions.load_current_index() as usize)
        .map_err(|_| SwigError::Cpi)?;

    let outer_program_id = outer_instruction.get_program_id();
    let outer_instruction_data = outer_instruction.get_instruction_data();
    let allowed = NON_SIGN_CPI_ALLOWLIST.iter().any(|entry| {
        let prefix_len = entry.outer_instruction_prefix.len();
        prefix_len > 0
            && outer_instruction_data.len() >= prefix_len
            && sol_assert_bytes_eq(outer_program_id, &entry.outer_program_id, 32)
            && sol_assert_bytes_eq(
                &outer_instruction_data[..prefix_len],
                entry.outer_instruction_prefix,
                prefix_len,
            )
    });

    if allowed {
        Ok(())
    } else {
        Err(SwigError::Cpi.into())
    }
}
