/// Module for handling compact instruction formats.
///
/// This module provides functionality to convert between standard Solana
/// instructions and a compact format optimized for the Swig wallet. The compact
/// format reduces instruction size by deduplicating account references and
/// using indexes instead of full public keys.
use core::fmt;

use crate::MAX_ACCOUNTS;

/// Errors returned when compact instructions exceed their wire limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactInstructionError {
    TooManyAccounts,
    TooManyInstructions,
    InstructionDataTooLarge,
    AccountIndexOutOfBounds,
}

impl fmt::Display for CompactInstructionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyAccounts => f.write_str("compact instruction account limit exceeded"),
            Self::TooManyInstructions => f.write_str("compact instruction count limit exceeded"),
            Self::InstructionDataTooLarge => {
                f.write_str("compact instruction data length limit exceeded")
            },
            Self::AccountIndexOutOfBounds => {
                f.write_str("compact instruction account index out of bounds")
            },
        }
    }
}

impl std::error::Error for CompactInstructionError {}

#[cfg(feature = "client")]
mod inner {
    use std::collections::HashMap;

    use solana_program::{
        instruction::{AccountMeta, Instruction},
        pubkey::Pubkey,
    };

    use super::{CompactInstruction, CompactInstructionError, CompactInstructions};
    use crate::MAX_ACCOUNTS;

    /// Converts a set of instructions into a compact format for a Swig wallet.
    ///
    /// This function optimizes instruction data by:
    /// 1. Deduplicating account references
    /// 2. Converting public keys to indexes
    /// 3. Handling signer privileges for the Swig account
    ///
    /// # Arguments
    /// * `swig_signer` - Public key of the Swig-controlled CPI signer
    /// * `accounts` - Initial set of account metadata
    /// * `inner_instructions` - Instructions to compact
    ///
    /// # Returns
    /// * `Result<(Vec<AccountMeta>, CompactInstructions),
    ///   CompactInstructionError>`
    ///   - Optimized accounts and instructions, or a wire-limit error
    pub fn compact_instructions(
        swig_signer: Pubkey,
        mut accounts: Vec<AccountMeta>,
        inner_instructions: Vec<Instruction>,
    ) -> Result<(Vec<AccountMeta>, CompactInstructions), CompactInstructionError> {
        if accounts.len() > MAX_ACCOUNTS {
            return Err(CompactInstructionError::TooManyAccounts);
        }
        u8::try_from(inner_instructions.len())
            .map_err(|_| CompactInstructionError::TooManyInstructions)?;

        let mut compact_ix = Vec::with_capacity(inner_instructions.len());
        let mut hashmap = accounts
            .iter()
            .enumerate()
            .map(|(i, x)| (x.pubkey, i))
            .collect::<HashMap<Pubkey, usize>>();
        for ix in inner_instructions.into_iter() {
            if ix.accounts.len() > MAX_ACCOUNTS {
                return Err(CompactInstructionError::TooManyAccounts);
            }
            u16::try_from(ix.data.len())
                .map_err(|_| CompactInstructionError::InstructionDataTooLarge)?;
            if accounts.len() >= MAX_ACCOUNTS {
                return Err(CompactInstructionError::TooManyAccounts);
            }
            let program_id_index = u8::try_from(accounts.len())
                .map_err(|_| CompactInstructionError::TooManyAccounts)?;
            accounts.push(AccountMeta::new_readonly(ix.program_id, false));
            let mut accts = Vec::with_capacity(ix.accounts.len());
            for mut ix_account in ix.accounts.into_iter() {
                if ix_account.pubkey == swig_signer {
                    ix_account.is_signer = false;
                }
                let account_index = hashmap.get(&ix_account.pubkey);
                if let Some(index) = account_index {
                    let account = &mut accounts[*index];
                    account.is_signer |= ix_account.is_signer;
                    account.is_writable |= ix_account.is_writable;
                    accts.push(
                        u8::try_from(*index)
                            .map_err(|_| CompactInstructionError::TooManyAccounts)?,
                    );
                } else {
                    if accounts.len() >= MAX_ACCOUNTS {
                        return Err(CompactInstructionError::TooManyAccounts);
                    }
                    let idx = accounts.len();
                    let compact_idx =
                        u8::try_from(idx).map_err(|_| CompactInstructionError::TooManyAccounts)?;
                    hashmap.insert(ix_account.pubkey, idx);
                    accounts.push(ix_account);
                    accts.push(compact_idx);
                }
            }
            compact_ix.push(CompactInstruction {
                program_id_index,
                accounts: accts,
                data: ix.data,
            });
        }

        Ok((
            accounts,
            CompactInstructions {
                inner_instructions: compact_ix,
            },
        ))
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
    /// * `Result<(Vec<AccountMeta>, CompactInstructions),
    ///   CompactInstructionError>`
    ///   - Optimized accounts and instructions, or a wire-limit error
    pub fn compact_instructions_sub_account(
        swig_account: Pubkey,
        sub_account: Pubkey,
        mut accounts: Vec<AccountMeta>,
        inner_instructions: Vec<Instruction>,
    ) -> Result<(Vec<AccountMeta>, CompactInstructions), CompactInstructionError> {
        if accounts.len() > MAX_ACCOUNTS {
            return Err(CompactInstructionError::TooManyAccounts);
        }
        u8::try_from(inner_instructions.len())
            .map_err(|_| CompactInstructionError::TooManyInstructions)?;

        let mut compact_ix = Vec::with_capacity(inner_instructions.len());
        let mut hashmap = accounts
            .iter()
            .enumerate()
            .map(|(i, x)| (x.pubkey, i))
            .collect::<HashMap<Pubkey, usize>>();
        for ix in inner_instructions.into_iter() {
            if ix.accounts.len() > MAX_ACCOUNTS {
                return Err(CompactInstructionError::TooManyAccounts);
            }
            u16::try_from(ix.data.len())
                .map_err(|_| CompactInstructionError::InstructionDataTooLarge)?;
            if accounts.len() >= MAX_ACCOUNTS {
                return Err(CompactInstructionError::TooManyAccounts);
            }
            let program_id_index = u8::try_from(accounts.len())
                .map_err(|_| CompactInstructionError::TooManyAccounts)?;
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
                    let account = &mut accounts[*index];
                    account.is_signer |= ix_account.is_signer;
                    account.is_writable |= ix_account.is_writable;
                    accts.push(
                        u8::try_from(*index)
                            .map_err(|_| CompactInstructionError::TooManyAccounts)?,
                    );
                } else {
                    if accounts.len() >= MAX_ACCOUNTS {
                        return Err(CompactInstructionError::TooManyAccounts);
                    }
                    let idx = accounts.len();
                    let compact_idx =
                        u8::try_from(idx).map_err(|_| CompactInstructionError::TooManyAccounts)?;
                    hashmap.insert(ix_account.pubkey, idx);
                    accounts.push(ix_account);
                    accts.push(compact_idx);
                }
            }
            compact_ix.push(CompactInstruction {
                program_id_index,
                accounts: accts,
                data: ix.data,
            });
        }

        Ok((
            accounts,
            CompactInstructions {
                inner_instructions: compact_ix,
            },
        ))
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
    /// * `Result<Vec<u8>, CompactInstructionError>` - Serialized instruction
    ///   data, or a wire-limit error
    pub fn into_bytes(&self) -> Result<Vec<u8>, CompactInstructionError> {
        let instruction_count = u8::try_from(self.inner_instructions.len())
            .map_err(|_| CompactInstructionError::TooManyInstructions)?;
        let mut bytes = vec![instruction_count];
        for ix in self.inner_instructions.iter() {
            if usize::from(ix.program_id_index) >= MAX_ACCOUNTS
                || ix
                    .accounts
                    .iter()
                    .any(|index| usize::from(*index) >= MAX_ACCOUNTS)
            {
                return Err(CompactInstructionError::AccountIndexOutOfBounds);
            }
            if ix.accounts.len() > MAX_ACCOUNTS {
                return Err(CompactInstructionError::TooManyAccounts);
            }
            let account_count = u8::try_from(ix.accounts.len())
                .map_err(|_| CompactInstructionError::TooManyAccounts)?;
            let data_len = u16::try_from(ix.data.len())
                .map_err(|_| CompactInstructionError::InstructionDataTooLarge)?;
            bytes.push(ix.program_id_index);
            bytes.push(account_count);
            bytes.extend(ix.accounts.iter());
            bytes.extend(data_len.to_le_bytes());
            bytes.extend(ix.data.iter());
        }
        Ok(bytes)
    }
}
