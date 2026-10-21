pub mod actions;
pub mod error;
pub mod instruction;

use actions::process_action;
#[cfg(not(feature = "no-entrypoint"))]
use pinocchio::program_entrypoint;
use pinocchio::{account_info::AccountInfo, pubkey::Pubkey, ProgramResult};
use pinocchio_pubkey::pubkey;

pub use developer_account_registry_state::ID;

// Temporary devnet key. Replace it before the first mainnet deployment.
pub const REGISTRY_ADMIN: Pubkey = pubkey!("BMsQBYvQoNTsU91Bi4GztEogWCmVwLm2FfRebp5kNyQq");

pinocchio::default_allocator!();
pinocchio::default_panic_handler!();

#[cfg(not(feature = "no-entrypoint"))]
program_entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    process_action(accounts, data)
}
