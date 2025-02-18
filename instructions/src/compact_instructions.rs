#[cfg(feature = "client")]
mod inner {
    use solana_program::{instruction::{AccountMeta, Instruction}, pubkey::Pubkey};

    use super::{CompactInstruction, CompactInstructions};
    pub fn compact_instructions(
        swig_account: Pubkey,
        mut accounts: Vec<AccountMeta>,
        inner_instructions: Vec<Instruction>,
    ) -> (Vec<AccountMeta>, CompactInstructions) {
        let mut compact_ix = Vec::with_capacity(inner_instructions.len());
        let hash_set = accounts.iter().map(|x| x.pubkey).collect::<std::collections::HashSet<Pubkey>>();
        for ix in inner_instructions.into_iter() {
            let program_id_index = accounts.len();
            accounts.push(AccountMeta::new_readonly(ix.program_id, false));
            let mut accts = Vec::with_capacity(ix.accounts.len());
            for mut ix_account in ix.accounts.into_iter() {
                if ix_account.pubkey == swig_account {
                    ix_account.is_signer = false;
                }
                let account_index = accounts.len() as u8;
                if !hash_set.contains(&ix_account.pubkey) {
                    accounts.push(ix_account);
                }
                accts.push(account_index);
            }
            compact_ix.push(CompactInstruction {
                program_id_index: program_id_index as u8,
                accounts: accts,
                data: ix.data,
            });
        }

        (accounts, CompactInstructions { inner_instructions: compact_ix })
    }
}
#[cfg(feature = "client")]
pub use inner::compact_instructions;
pub struct CompactInstructions {
    pub inner_instructions: Vec<CompactInstruction>,
}

pub struct CompactInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

pub struct CompactInstructionRef<'a> {
    pub program_id_index: u8,
    pub accounts: &'a [u8],
    pub data: &'a [u8],
}


impl CompactInstructions {
    pub fn into_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.inner_instructions.len() as u8];
        for ix in self.inner_instructions.iter() {
            bytes.push(ix.program_id_index);
            bytes.push(ix.accounts.len() as u8);
            bytes.extend(ix.accounts.iter());
            bytes.extend((ix.data.len() as u16).to_le_bytes());
            bytes.extend(ix.data.iter());
        }
        bytes
    }
}
