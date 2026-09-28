/// Instruction processing and execution module for the Swig wallet program.
///
/// This crate provides functionality for parsing, validating, and executing
/// instructions in a compact format. It includes support for:
/// - Instruction iteration and parsing
/// - Account validation and lookup
/// - Cross-program invocation (CPI)
/// - Restricted key handling
/// - Memory-efficient instruction processing
mod compact_instructions;
use core::{cell::RefCell, marker::PhantomData, mem};
use std::rc::Rc;

pub use compact_instructions::*;
use pinocchio::{
    account_info::AccountInfo,
    instruction::{Account, AccountMeta, Instruction, Signer},
    program::invoke_signed_unchecked,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

pub const MAX_ACCOUNTS: usize = 254;
/// Errors that can occur during instruction processing.
#[repr(u32)]
pub enum InstructionError {
    /// No instructions found in the instruction data
    MissingInstructions = 2000,
    /// Required account info not found at specified index
    MissingAccountInfo,
    /// Instruction data is incomplete or invalid
    MissingData,
}

impl From<InstructionError> for ProgramError {
    fn from(e: InstructionError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

/// Holds parsed instruction data and associated accounts.
///
/// # Fields
/// * `program_id` - The program that will execute this instruction
/// * `cpi_accounts` - Accounts required for cross-program invocation
/// * `indexes` - Original indexes of accounts in the instruction
/// * `accounts` - Account metadata for the instruction
/// * `data` - Raw instruction data
pub struct InstructionHolder<'a> {
    pub program_id: &'a Pubkey,
    cpi_accounts: Vec<Account<'a>>,
    indexes: Vec<usize>,
    accounts: Vec<AccountMeta<'a>>,
    pub data: &'a [u8],
    pub uses_swig_signer: bool,
    scratch: Rc<RefCell<InstructionScratch<'a>>>,
}

struct InstructionScratch<'a> {
    accounts: Vec<AccountMeta<'a>>,
    cpi_accounts: Vec<Account<'a>>,
    indexes: Vec<usize>,
}

impl<'a> Drop for InstructionHolder<'a> {
    fn drop(&mut self) {
        let mut scratch = self.scratch.borrow_mut();
        scratch.accounts = mem::take(&mut self.accounts);
        scratch.cpi_accounts = mem::take(&mut self.cpi_accounts);
        scratch.indexes = mem::take(&mut self.indexes);
    }
}

impl<'a> InstructionHolder<'a> {
    pub fn accounts(&self) -> &[AccountMeta<'a>] {
        &self.accounts
    }

    pub fn execute(
        &self,
        all_accounts: &[AccountInfo],
        swig_key: &Pubkey,
        swig_signer: &[Signer],
    ) -> ProgramResult {
        if self.program_id == &pinocchio_system::ID
            && self.data.len() >= 12
            && self.accounts.len() >= 2
            && unsafe { self.data.get_unchecked(0..4) == [2, 0, 0, 0] }
            && unsafe { self.accounts.get_unchecked(0).pubkey == swig_key }
        {
            // Check if the "from" account (swig_key) is system-owned or program-owned
            let from_account_index = *self
                .indexes
                .first()
                .ok_or(ProgramError::NotEnoughAccountKeys)?;
            let from_account = all_accounts
                .get(from_account_index)
                .ok_or(ProgramError::NotEnoughAccountKeys)?;

            if from_account.owner() == &pinocchio_system::ID {
                // For system-owned PDAs (new swig_wallet_address accounts),
                // use proper CPI with signer seeds
                unsafe {
                    invoke_signed_unchecked(
                        &self.borrow(),
                        self.cpi_accounts.as_slice(),
                        swig_signer,
                    )
                }
            } else {
                // For program-owned accounts (old swig accounts),
                // use direct lamport manipulation for backwards compatibility
                let amount = u64::from_le_bytes(
                    unsafe { self.data.get_unchecked(4..12) }
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                let account2 = all_accounts
                    .get(
                        *self
                            .indexes
                            .get(1)
                            .ok_or(ProgramError::NotEnoughAccountKeys)?,
                    )
                    .ok_or(ProgramError::NotEnoughAccountKeys)?;
                unsafe {
                    *from_account.borrow_mut_lamports_unchecked() -= amount;
                    *account2.borrow_mut_lamports_unchecked() += amount;
                }
            }
        } else {
            unsafe {
                invoke_signed_unchecked(&self.borrow(), self.cpi_accounts.as_slice(), swig_signer)
            }
        }
        Ok(())
    }
}

/// Interface for accessing account information.
///
/// This trait provides methods to query basic account properties
/// and convert account types into a common format.
pub trait AccountProxy<'a> {
    /// Returns whether the account is a signer
    fn signer(&self) -> bool;
    /// Returns whether the account is writable
    fn writable(&self) -> bool;
    /// Returns the account's public key
    fn pubkey(&self) -> &'a Pubkey;
    /// Converts the account into a common Account format
    fn into_account(self) -> Account<'a>;
}

/// Interface for looking up accounts by index.
///
/// This trait provides methods to safely access accounts from
/// a collection or storage structure.
pub trait AccountLookup<'a, T>
where
    T: AccountProxy<'a>,
{
    /// Retrieves an account at the specified index
    fn get_account(&self, index: usize) -> Result<T, InstructionError>;
    /// Returns the total number of accounts available
    fn size(&self) -> usize;
}

/// Interface for checking restricted keys.
///
/// This trait provides functionality to determine if a public key
/// is in a restricted set, which affects signing capabilities.
pub trait RestrictedKeys {
    /// Returns true if the public key is restricted
    fn is_restricted(&self, pubkey: &Pubkey) -> bool;
}

impl<'a> InstructionHolder<'a> {
    pub fn borrow(&self) -> Instruction<'a, '_, 'a, 'a> {
        Instruction {
            program_id: self.program_id,
            accounts: &self.accounts,
            data: self.data,
        }
    }
}

/// Iterator for processing compact instructions.
///
/// This struct provides functionality to iterate over a series of
/// compact instructions, parsing each one into a full instruction
/// with resolved accounts and program IDs.
///
/// # Type Parameters
/// * `AL` - Account lookup implementation
/// * `RK` - Restricted keys implementation
/// * `P` - Account proxy implementation
pub struct InstructionIterator<'a, AL, RK, P>
where
    AL: AccountLookup<'a, P>,
    RK: RestrictedKeys,
    P: AccountProxy<'a>,
{
    accounts: AL,
    data: &'a [u8],
    cursor: usize,
    remaining: usize,
    restricted_keys: RK,
    signer: &'a Pubkey,
    scratch: Rc<RefCell<InstructionScratch<'a>>>,
    _phantom: PhantomData<P>,
}

impl<'a> RestrictedKeys for &'a [&'a Pubkey] {
    fn is_restricted(&self, pubkey: &Pubkey) -> bool {
        self.contains(&pubkey)
    }
}

impl<'a> AccountProxy<'a> for &'a AccountInfo {
    #[inline(always)]
    fn signer(&self) -> bool {
        self.is_signer()
    }
    #[inline(always)]
    fn writable(&self) -> bool {
        self.is_writable()
    }
    #[inline(always)]
    fn pubkey(&self) -> &'a Pubkey {
        self.key()
    }
    #[inline(always)]
    fn into_account(self) -> Account<'a> {
        self.into()
    }
}

impl<'a> AccountLookup<'a, &'a AccountInfo> for &'a [AccountInfo] {
    fn get_account(&self, index: usize) -> Result<&'a AccountInfo, InstructionError> {
        self.get(index).ok_or(InstructionError::MissingAccountInfo)
    }

    fn size(&self) -> usize {
        self.len()
    }
}

impl<'a> InstructionIterator<'a, &'a [AccountInfo], &'a [&'a Pubkey], &'a AccountInfo> {
    pub fn new(
        accounts: &'a [AccountInfo],
        data: &'a [u8],
        signer: &'a Pubkey,
        restricted_keys: &'a [&'a Pubkey],
    ) -> Result<Self, InstructionError> {
        if data.is_empty() {
            return Err(InstructionError::MissingInstructions);
        }

        let max_accounts = max_accounts_in_payload(data)?;
        let scratch = InstructionScratch {
            accounts: Vec::with_capacity(max_accounts),
            cpi_accounts: Vec::with_capacity(max_accounts),
            indexes: Vec::with_capacity(max_accounts),
        };

        Ok(Self {
            accounts,
            data,
            cursor: 1, // Start after the number of instructions
            remaining: unsafe { *data.get_unchecked(0) } as usize,
            restricted_keys,
            signer,
            scratch: Rc::new(RefCell::new(scratch)),
            _phantom: PhantomData,
        })
    }
}

fn max_accounts_in_payload(data: &[u8]) -> Result<usize, InstructionError> {
    let mut cursor = 1usize;
    let mut max_accounts = 0;
    for _ in 0..data[0] {
        let header = data
            .get(cursor..cursor + 2)
            .ok_or(InstructionError::MissingData)?;
        let account_count = header[1] as usize;
        if account_count > MAX_ACCOUNTS {
            return Err(InstructionError::MissingAccountInfo);
        }
        max_accounts = max_accounts.max(account_count);
        cursor += 2 + account_count;
        let data_length = data
            .get(cursor..cursor + 2)
            .ok_or(InstructionError::MissingData)?;
        let data_length = u16::from_le_bytes([data_length[0], data_length[1]]) as usize;
        cursor += 2 + data_length;
        if cursor > data.len() {
            return Err(InstructionError::MissingData);
        }
    }
    Ok(max_accounts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_transfer_rejects_short_execution_accounts() {
        let swig_key = [1; 32];
        let program_id = pinocchio_system::ID;
        let scratch = Rc::new(RefCell::new(InstructionScratch {
            accounts: Vec::new(),
            cpi_accounts: Vec::new(),
            indexes: Vec::new(),
        }));
        let holder = InstructionHolder {
            program_id: &program_id,
            cpi_accounts: Vec::new(),
            indexes: vec![0, 1],
            accounts: vec![
                AccountMeta {
                    pubkey: &swig_key,
                    is_signer: false,
                    is_writable: true,
                },
                AccountMeta {
                    pubkey: &swig_key,
                    is_signer: false,
                    is_writable: true,
                },
            ],
            data: &[2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
            uses_swig_signer: false,
            scratch,
        };
        assert!(matches!(
            holder.execute(&[], &swig_key, &[]),
            Err(ProgramError::NotEnoughAccountKeys)
        ));
    }

    #[test]
    fn compact_payload_accepts_101_account_entries_and_rejects_255() {
        let mut payload = vec![1, 0, 101];
        payload.extend(vec![0; 101]);
        payload.extend([0, 0]);
        assert!(matches!(max_accounts_in_payload(&payload), Ok(101)));

        let mut payload = vec![1, 0, 255];
        payload.extend(vec![0; 255]);
        payload.extend([0, 0]);
        assert!(matches!(
            max_accounts_in_payload(&payload),
            Err(InstructionError::MissingAccountInfo)
        ));
    }
}

impl<'a, AL, RK, P> Iterator for InstructionIterator<'a, AL, RK, P>
where
    AL: AccountLookup<'a, P>,
    RK: RestrictedKeys,
    P: AccountProxy<'a>,
{
    type Item = Result<InstructionHolder<'a>, InstructionError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        if Rc::strong_count(&self.scratch) != 1 {
            self.remaining = 0;
            return Some(Err(InstructionError::MissingAccountInfo));
        }
        self.remaining -= 1;
        let instruction = self.parse_next_instruction();
        if instruction.is_err() {
            self.remaining = 0;
        }
        Some(instruction)
    }
}

impl<'a, AL, RK, P> InstructionIterator<'a, AL, RK, P>
where
    AL: AccountLookup<'a, P>,
    RK: RestrictedKeys,
    P: AccountProxy<'a>,
{
    /// Parses the next instruction from the compact format.
    ///
    /// This method handles the parsing of:
    /// 1. Program ID
    /// 2. Account metadata
    /// 3. Instruction data
    ///
    /// # Returns
    /// * `Result<InstructionHolder<'a>, InstructionError>` - Parsed instruction
    ///   or error
    fn parse_next_instruction(&mut self) -> Result<InstructionHolder<'a>, InstructionError> {
        // Parse program_id
        let (program_id_index, cursor) = self.read_u8()?;
        self.cursor = cursor;
        let program_id = self
            .accounts
            .get_account(program_id_index as usize)?
            .pubkey();
        // Parse accounts
        let (num_accounts, cursor) = self.read_u8()?;
        self.cursor = cursor;
        let num_accounts = num_accounts as usize;
        if num_accounts > MAX_ACCOUNTS {
            return Err(InstructionError::MissingAccountInfo);
        }
        let mut scratch = self.scratch.borrow_mut();
        let mut accounts = mem::take(&mut scratch.accounts);
        let mut infos = mem::take(&mut scratch.cpi_accounts);
        let mut indexes = mem::take(&mut scratch.indexes);
        drop(scratch);
        accounts.clear();
        infos.clear();
        indexes.clear();
        let mut uses_swig_signer = false;
        for _ in 0..num_accounts {
            let (pubkey_index, cursor) = self.read_u8()?;
            self.cursor = cursor;
            let account = self.accounts.get_account(pubkey_index as usize)?;
            indexes.push(pubkey_index as usize);
            let pubkey = account.pubkey();
            let is_signer = (pubkey == self.signer || account.signer())
                && !self.restricted_keys.is_restricted(pubkey);
            if is_signer && pubkey == self.signer {
                uses_swig_signer = true;
            }
            accounts.push(AccountMeta {
                pubkey,
                is_signer,
                is_writable: account.writable(),
            });
            infos.push(account.into_account());
        }

        // Parse data
        let (data_len, cursor) = self.read_u16()?;
        self.cursor = cursor;
        let (data, cursor) = self.read_slice(data_len as usize)?;
        self.cursor = cursor;

        Ok(InstructionHolder {
            program_id,
            cpi_accounts: infos,
            accounts,
            indexes,
            data,
            uses_swig_signer,
            scratch: Rc::clone(&self.scratch),
        })
    }

    /// Reads a u8 value from the current cursor position.
    ///
    /// # Returns
    /// * `Result<(u8, usize), InstructionError>` - Value and new cursor
    ///   position
    #[inline(always)]
    fn read_u8(&self) -> Result<(u8, usize), InstructionError> {
        if self.cursor >= self.data.len() {
            return Err(InstructionError::MissingData);
        }
        let value = unsafe { self.data.get_unchecked(self.cursor) };
        Ok((*value, self.cursor + 1))
    }

    /// Reads a u16 value from the current cursor position.
    ///
    /// # Returns
    /// * `Result<(u16, usize), InstructionError>` - Value and new cursor
    ///   position
    #[inline(always)]
    fn read_u16(&self) -> Result<(u16, usize), InstructionError> {
        let end = self.cursor + 2;
        if end > self.data.len() {
            return Err(InstructionError::MissingData);
        }
        let value_bytes = unsafe { self.data.get_unchecked(self.cursor..end) };
        let value = u16::from_le_bytes([value_bytes[0], value_bytes[1]]);
        Ok((value, end))
    }

    /// Reads a slice of bytes from the current cursor position.
    ///
    /// # Arguments
    /// * `len` - Number of bytes to read
    ///
    /// # Returns
    /// * `Result<(&'a [u8], usize), InstructionError>` - Byte slice and new
    ///   cursor position
    #[inline(always)]
    fn read_slice(&self, len: usize) -> Result<(&'a [u8], usize), InstructionError> {
        let end = self.cursor + len;
        if end > self.data.len() {
            return Err(InstructionError::MissingData);
        }

        let slice = unsafe { self.data.get_unchecked(self.cursor..end) };
        Ok((slice, end))
    }
}
