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
}

impl fmt::Display for CompactInstructionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyAccounts => f.write_str("compact instruction account limit exceeded"),
            Self::TooManyInstructions => f.write_str("compact instruction count limit exceeded"),
            Self::InstructionDataTooLarge => {
                f.write_str("compact instruction data length limit exceeded")
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
    /// * `Result<(Vec<AccountMeta>, CompactInstructions), CompactInstructionError>`
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
    /// * `Result<(Vec<AccountMeta>, CompactInstructions), CompactInstructionError>`
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

#[cfg(all(test, feature = "client"))]
mod tests {
    use solana_program::{
        instruction::{AccountMeta, Instruction},
        pubkey::Pubkey,
    };

    use super::*;

    fn instruction(accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
        Instruction {
            program_id: Pubkey::new_unique(),
            accounts,
            data,
        }
    }

    fn compact_instruction(account_count: usize, data_len: usize) -> CompactInstruction {
        CompactInstruction {
            program_id_index: 0,
            accounts: vec![0; account_count],
            data: vec![0; data_len],
        }
    }

    #[test]
    fn merges_duplicate_account_privileges() {
        let swig = Pubkey::new_unique();
        let shared = Pubkey::new_unique();
        let instructions = vec![
            instruction(vec![AccountMeta::new_readonly(shared, false)], Vec::new()),
            instruction(vec![AccountMeta::new(shared, true)], Vec::new()),
        ];

        let (accounts, _) = compact_instructions(swig, Vec::new(), instructions).unwrap();
        let shared_meta = accounts
            .iter()
            .find(|account| account.pubkey == shared)
            .unwrap();

        assert!(shared_meta.is_signer);
        assert!(shared_meta.is_writable);
    }

    #[test]
    fn keeps_swig_and_subaccount_pdas_non_signers() {
        let swig = Pubkey::new_unique();
        let sub_account = Pubkey::new_unique();
        let accounts = vec![
            AccountMeta::new_readonly(swig, false),
            AccountMeta::new_readonly(sub_account, false),
        ];
        let inner = instruction(
            vec![
                AccountMeta::new_readonly(swig, true),
                AccountMeta::new_readonly(sub_account, true),
            ],
            Vec::new(),
        );

        let (accounts, _) =
            compact_instructions_sub_account(swig, sub_account, accounts, vec![inner]).unwrap();

        assert!(
            !accounts
                .iter()
                .find(|meta| meta.pubkey == swig)
                .unwrap()
                .is_signer
        );
        assert!(
            !accounts
                .iter()
                .find(|meta| meta.pubkey == sub_account)
                .unwrap()
                .is_signer
        );
    }

    #[test]
    fn compaction_enforces_account_limit() {
        let swig = Pubkey::new_unique();
        let accounts = (0..MAX_ACCOUNTS - 1)
            .map(|_| AccountMeta::new_readonly(Pubkey::new_unique(), false))
            .collect();
        let (accounts, _) =
            compact_instructions(swig, accounts, vec![instruction(Vec::new(), Vec::new())])
                .unwrap();
        assert_eq!(accounts.len(), MAX_ACCOUNTS);

        let full_accounts = (0..MAX_ACCOUNTS)
            .map(|_| AccountMeta::new_readonly(Pubkey::new_unique(), false))
            .collect();
        assert!(matches!(
            compact_instructions(
                swig,
                full_accounts,
                vec![instruction(Vec::new(), Vec::new())]
            ),
            Err(CompactInstructionError::TooManyAccounts)
        ));

        let repeated = AccountMeta::new_readonly(Pubkey::new_unique(), false);
        assert!(matches!(
            compact_instructions(
                swig,
                Vec::new(),
                vec![instruction(vec![repeated; MAX_ACCOUNTS + 1], Vec::new())]
            ),
            Err(CompactInstructionError::TooManyAccounts)
        ));
    }

    #[test]
    fn compaction_rejects_unencodable_instruction_and_data_counts() {
        let swig = Pubkey::new_unique();
        let empty_instruction = instruction(Vec::new(), Vec::new());
        assert!(matches!(
            compact_instructions(
                swig,
                Vec::new(),
                vec![empty_instruction; usize::from(u8::MAX) + 1]
            ),
            Err(CompactInstructionError::TooManyInstructions)
        ));

        assert!(compact_instructions(
            swig,
            Vec::new(),
            vec![instruction(Vec::new(), vec![0; usize::from(u16::MAX)])]
        )
        .is_ok());
        assert!(matches!(
            compact_instructions(
                swig,
                Vec::new(),
                vec![instruction(Vec::new(), vec![0; usize::from(u16::MAX) + 1])]
            ),
            Err(CompactInstructionError::InstructionDataTooLarge)
        ));
    }

    #[test]
    fn serialization_enforces_wire_limits() {
        let max_instructions = CompactInstructions {
            inner_instructions: (0..usize::from(u8::MAX))
                .map(|_| compact_instruction(0, 0))
                .collect(),
        };
        assert!(max_instructions.into_bytes().is_ok());

        let too_many_instructions = CompactInstructions {
            inner_instructions: (0..usize::from(u8::MAX) + 1)
                .map(|_| compact_instruction(0, 0))
                .collect(),
        };
        assert_eq!(
            too_many_instructions.into_bytes().unwrap_err(),
            CompactInstructionError::TooManyInstructions
        );

        let max_accounts = CompactInstructions {
            inner_instructions: vec![compact_instruction(MAX_ACCOUNTS, 0)],
        };
        assert!(max_accounts.into_bytes().is_ok());
        let too_many_accounts = CompactInstructions {
            inner_instructions: vec![compact_instruction(MAX_ACCOUNTS + 1, 0)],
        };
        assert_eq!(
            too_many_accounts.into_bytes().unwrap_err(),
            CompactInstructionError::TooManyAccounts
        );

        let max_data = CompactInstructions {
            inner_instructions: vec![compact_instruction(0, usize::from(u16::MAX))],
        };
        assert!(max_data.into_bytes().is_ok());
        let too_much_data = CompactInstructions {
            inner_instructions: vec![compact_instruction(0, usize::from(u16::MAX) + 1)],
        };
        assert_eq!(
            too_much_data.into_bytes().unwrap_err(),
            CompactInstructionError::InstructionDataTooLarge
        );
    }
}
