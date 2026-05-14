//! Swig guardian recovery program.
//!
//! This program owns recovery policy state. It does not mutate Swig wallet
//! roles directly; instead, its execute instruction is used by a Swig
//! `ProgramExec` recovery role that is limited to `RecoveryAuthority`.

pub mod error;
pub mod instruction;
pub mod processor;
pub mod state;

#[cfg(not(feature = "no-entrypoint"))]
use solana_program::entrypoint;
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

solana_program::declare_id!("49JZPWhDRM9er4xrQxxSVEgYqHZqh5MFZGFgFdguhVTk");

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    processor::process_instruction(program_id, accounts, instruction_data)
}
