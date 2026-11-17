#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    use pinocchio::{
        account_info::AccountInfo, entrypoint, pubkey::Pubkey,
        ProgramResult,
    };

    use crate::processor;

    entrypoint!(process_instruction);

    pub fn process_instruction(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        data: &[u8],
    ) -> ProgramResult {
        processor::process_instruction(program_id, accounts, data)
    }
}

pub mod error;
pub mod processor;

pinocchio_pubkey::declare_id!("EQ2rR75Y9nzQVSVBC4Fb8p7p8xVdRsaAxdNYBLiGTZjp");
