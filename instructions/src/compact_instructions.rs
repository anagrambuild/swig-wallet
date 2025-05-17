/// Module for handling compact instruction formats.
///
/// This module provides functionality to convert between standard Solana
/// instructions and a compact format optimized for the Swig wallet. The compact
/// format reduces instruction size by deduplicating account references and
/// using indexes instead of full public keys.

#[cfg(feature = "client")]
mod inner {
    use std::collections::HashMap;

    use solana_program::{
        instruction::{AccountMeta, Instruction},
        pubkey::Pubkey,
    };

    use super::{CompactInstruction, CompactInstructions};

    /// Converts a set of instructions into a compact format for a Swig wallet.
    ///
    /// This function optimizes instruction data by:
    /// 1. Deduplicating account references
    /// 2. Converting public keys to indexes
    /// 3. Handling signer privileges for the Swig account
    ///
    /// # Arguments
    /// * `swig_account` - Public key of the Swig wallet
    /// * `accounts` - Initial set of account metadata
    /// * `inner_instructions` - Instructions to compact
    ///
    /// # Returns
    /// * `(Vec<AccountMeta>, CompactInstructions)` - Optimized accounts and
    ///   instructions
    pub fn compact_instructions(
        swig_account: Pubkey,
        mut accounts: Vec<AccountMeta>,
        inner_instructions: Vec<Instruction>,
    ) -> (Vec<AccountMeta>, CompactInstructions) {
        let mut compact_ix = Vec::with_capacity(inner_instructions.len());
        let mut hashmap = accounts
            .iter()
            .enumerate()
            .map(|(i, x)| (x.pubkey, i))
            .collect::<HashMap<Pubkey, usize>>();
        for ix in inner_instructions.into_iter() {
            let program_id_index = accounts.len();
            accounts.push(AccountMeta::new_readonly(ix.program_id, false));
            let mut accts = Vec::with_capacity(ix.accounts.len());
            for mut ix_account in ix.accounts.into_iter() {
                if ix_account.pubkey == swig_account {
                    ix_account.is_signer = false;
                }
                let account_index = hashmap.get(&ix_account.pubkey);
                if let Some(index) = account_index {
                    accts.push(*index as u8);
                } else {
                    let idx = accounts.len();
                    hashmap.insert(ix_account.pubkey, idx);
                    accounts.push(ix_account);
                    accts.push(idx as u8);
                }
            }
            compact_ix.push(CompactInstruction {
                program_id_index: program_id_index as u8,
                accounts: accts,
                data: ix.data,
            });
        }

        (
            accounts,
            CompactInstructions {
                inner_instructions: compact_ix,
            },
        )
    }

    /// Converts a set of instructions into a compact format for a Swig
    /// sub-account.
    ///
    /// Similar to `compact_instructions`, but handles both the main Swig
    /// account and a sub-account's signing privileges.
    ///
    /// # Arguments
    /// * `swig_account` - Public key of the main Swig wallet
    /// * `sub_account` - Public key of the sub-account
    /// * `accounts` - Initial set of account metadata
    /// * `inner_instructions` - Instructions to compact
    ///
    /// # Returns
    /// * `(Vec<AccountMeta>, CompactInstructions)` - Optimized accounts and
    ///   instructions
    pub fn compact_instructions_sub_account(
        swig_account: Pubkey,
        sub_account: Pubkey,
        mut accounts: Vec<AccountMeta>,
        inner_instructions: Vec<Instruction>,
    ) -> (Vec<AccountMeta>, CompactInstructions) {
        let mut compact_ix = Vec::with_capacity(inner_instructions.len());
        let mut hashmap = accounts
            .iter()
            .enumerate()
            .map(|(i, x)| (x.pubkey, i))
            .collect::<HashMap<Pubkey, usize>>();
        for ix in inner_instructions.into_iter() {
            let program_id_index = accounts.len();
            accounts.push(AccountMeta::new_readonly(ix.program_id, false));
            let mut accts = Vec::with_capacity(ix.accounts.len());
            for mut ix_account in ix.accounts.into_iter() {
                if ix_account.pubkey == swig_account {
                    ix_account.is_signer = false;
                }
                if ix_account.pubkey == sub_account {
                    ix_account.is_signer = false;
                }
                let account_index = hashmap.get(&ix_account.pubkey);
                if let Some(index) = account_index {
                    accts.push(*index as u8);
                } else {
                    let idx = accounts.len();
                    hashmap.insert(ix_account.pubkey, idx);
                    accounts.push(ix_account);
                    accts.push(idx as u8);
                }
            }
            compact_ix.push(CompactInstruction {
                program_id_index: program_id_index as u8,
                accounts: accts,
                data: ix.data,
            });
        }

        (
            accounts,
            CompactInstructions {
                inner_instructions: compact_ix,
            },
        )
    }
}
#[cfg(feature = "client")]
pub use inner::{compact_instructions, compact_instructions_sub_account};

/// Container for a set of compact instructions.
///
/// This struct holds multiple compact instructions and provides
/// functionality to serialize them into a byte format.
pub struct CompactInstructions {
    /// Vector of individual compact instructions
    pub inner_instructions: Vec<CompactInstruction>,
}

/// Represents a single instruction in compact format.
///
/// Instead of storing full public keys, this format uses indexes
/// into a shared account list to reduce data size.
///
/// # Fields
/// * `program_id_index` - Index of the program ID in the account list
/// * `accounts` - Indexes of accounts used by this instruction
/// * `data` - Raw instruction data
pub struct CompactInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

/// Reference version of CompactInstruction that borrows its data.
///
/// # Fields
/// * `program_id_index` - Index of the program ID in the account list
/// * `accounts` - Slice of account indexes
/// * `data` - Slice of instruction data
pub struct CompactInstructionRef<'a> {
    pub program_id_index: u8,
    pub accounts: &'a [u8],
    pub data: &'a [u8],
}

impl CompactInstructions {
    /// Serializes the compact instructions into bytes.
    ///
    /// The byte format is:
    /// 1. Number of instructions (u8)
    /// 2. For each instruction:
    ///    - Program ID index (u8)
    ///    - Number of accounts (u8)
    ///    - Account indexes (u8 array)
    ///    - Data length (u16 LE)
    ///    - Instruction data (bytes)
    ///
    /// # Returns
    /// * `Vec<u8>` - Serialized instruction data
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
