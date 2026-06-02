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
use core::{marker::PhantomData, mem::MaybeUninit};

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

#[inline(always)]
fn uninit_array<T>() -> [MaybeUninit<T>; MAX_ACCOUNTS] {
    unsafe { MaybeUninit::<[MaybeUninit<T>; MAX_ACCOUNTS]>::uninit().assume_init() }
}

/// Reusable fixed storage for one parsed compact instruction.
pub struct InstructionScratch<'a> {
    account_metas: [MaybeUninit<AccountMeta<'a>>; MAX_ACCOUNTS],
    indexes: [MaybeUninit<usize>; MAX_ACCOUNTS],
    cpi_accounts: [MaybeUninit<Account<'a>>; MAX_ACCOUNTS],
}

impl<'a> InstructionScratch<'a> {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            account_metas: uninit_array(),
            indexes: uninit_array(),
            cpi_accounts: uninit_array(),
        }
    }

    #[inline(always)]
    unsafe fn account_metas(&self, len: usize) -> &[AccountMeta<'a>] {
        core::slice::from_raw_parts(self.account_metas.as_ptr() as *const AccountMeta<'a>, len)
    }

    #[inline(always)]
    unsafe fn indexes(&self, len: usize) -> &[usize] {
        core::slice::from_raw_parts(self.indexes.as_ptr() as *const usize, len)
    }

    #[inline(always)]
    unsafe fn cpi_accounts(&self, len: usize) -> &[Account<'a>] {
        core::slice::from_raw_parts(self.cpi_accounts.as_ptr() as *const Account<'a>, len)
    }
}

impl<'a> Default for InstructionScratch<'a> {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

/// Holds a borrowed view over parsed instruction data and associated accounts.
///
/// # Fields
/// * `program_id` - The program that will execute this instruction
/// * `cpi_accounts` - Accounts required for cross-program invocation
/// * `indexes` - Original indexes of accounts in the instruction
/// * `accounts` - Account metadata for the instruction
/// * `data` - Raw instruction data
pub struct InstructionHolder<'scratch, 'a> {
    pub program_id: &'a Pubkey,
    pub cpi_accounts: &'scratch [Account<'a>],
    pub indexes: &'scratch [usize],
    pub accounts: &'scratch [AccountMeta<'a>],
    pub data: &'a [u8],
    pub uses_swig_signer: bool,
}

impl<'scratch, 'a> InstructionHolder<'scratch, 'a>
where
    'a: 'scratch,
{
    pub fn execute(
        &self,
        all_accounts: &'a [AccountInfo],
        swig_key: &'a Pubkey,
        swig_signer: &[Signer],
    ) -> ProgramResult {
        if self.program_id == &pinocchio_system::ID
            && self.accounts.len() >= 2
            && self.data.len() >= 12
            && unsafe { self.data.get_unchecked(0..4) == [2, 0, 0, 0] }
            && unsafe { self.accounts.get_unchecked(0).pubkey == swig_key }
        {
            // Check if the "from" account (swig_key) is system-owned or program-owned
            let from_account_index = unsafe { *self.indexes.get_unchecked(0) };
            let from_account = unsafe { all_accounts.get_unchecked(from_account_index) };

            if from_account.owner() == &pinocchio_system::ID {
                // For system-owned PDAs (new swig_wallet_address accounts),
                // use proper CPI with signer seeds
                unsafe { invoke_signed_unchecked(&self.borrow(), self.cpi_accounts, swig_signer) }
            } else {
                // For program-owned accounts (old swig accounts),
                // use direct lamport manipulation for backwards compatibility
                let amount = u64::from_le_bytes(
                    unsafe { self.data.get_unchecked(4..12) }
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                unsafe {
                    let index = self.indexes.get_unchecked(0);
                    let index2 = self.indexes.get_unchecked(1);
                    let account1 = all_accounts.get_unchecked(*index);
                    let account2 = all_accounts.get_unchecked(*index2);

                    *account1.borrow_mut_lamports_unchecked() -= amount;
                    *account2.borrow_mut_lamports_unchecked() += amount;
                }
            }
        } else {
            unsafe { invoke_signed_unchecked(&self.borrow(), self.cpi_accounts, swig_signer) }
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

impl<'scratch, 'a> InstructionHolder<'scratch, 'a>
where
    'a: 'scratch,
{
    pub fn borrow(&self) -> Instruction<'a, 'scratch, 'a, 'a> {
        Instruction {
            program_id: self.program_id,
            accounts: self.accounts,
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

        Ok(Self {
            accounts,
            data,
            cursor: 1, // Start after the number of instructions
            remaining: unsafe { *data.get_unchecked(0) } as usize,
            restricted_keys,
            signer,
            _phantom: PhantomData,
        })
    }
}

impl<'a, AL, RK, P> InstructionIterator<'a, AL, RK, P>
where
    AL: AccountLookup<'a, P>,
    RK: RestrictedKeys,
    P: AccountProxy<'a>,
{
    /// Parses the next compact instruction into fixed scratch storage and calls
    /// `handler` while the parsed slices are still valid.
    #[inline(always)]
    pub fn process_next<'scratch, E, F>(
        &mut self,
        scratch: &'scratch mut InstructionScratch<'a>,
        handler: F,
    ) -> Result<Option<Result<(), E>>, InstructionError>
    where
        'a: 'scratch,
        F: FnOnce(InstructionHolder<'scratch, 'a>) -> Result<(), E>,
    {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        self.parse_next_instruction(scratch, handler).map(Some)
    }

    /// Parses the next instruction from the compact format.
    ///
    /// This method handles the parsing of:
    /// 1. Program ID
    /// 2. Account metadata
    /// 3. Instruction data
    ///
    /// # Returns
    /// * `Result<(), E>` - Callback success or parser/callback error
    fn parse_next_instruction<'scratch, E, F>(
        &mut self,
        scratch: &'scratch mut InstructionScratch<'a>,
        handler: F,
    ) -> Result<Result<(), E>, InstructionError>
    where
        'a: 'scratch,
        F: FnOnce(InstructionHolder<'scratch, 'a>) -> Result<(), E>,
    {
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

        let mut uses_swig_signer = false;
        for i in 0..num_accounts {
            let (pubkey_index, cursor) = self.read_u8()?;
            self.cursor = cursor;
            let account = self.accounts.get_account(pubkey_index as usize)?;
            scratch.indexes[i].write(pubkey_index as usize);
            let pubkey = account.pubkey();
            let is_signer = (pubkey == self.signer || account.signer())
                && !self.restricted_keys.is_restricted(pubkey);
            if is_signer && pubkey == self.signer {
                uses_swig_signer = true;
            }
            scratch.account_metas[i].write(AccountMeta {
                pubkey,
                is_signer,
                is_writable: account.writable(),
            });
            scratch.cpi_accounts[i].write(account.into_account());
        }

        // Parse data
        let (data_len, cursor) = self.read_u16()?;
        self.cursor = cursor;
        let (data, cursor) = self.read_slice(data_len as usize)?;
        self.cursor = cursor;

        let instruction = InstructionHolder {
            program_id,
            cpi_accounts: unsafe { scratch.cpi_accounts(num_accounts) },
            accounts: unsafe { scratch.account_metas(num_accounts) },
            indexes: unsafe { scratch.indexes(num_accounts) },
            data,
            uses_swig_signer,
        };

        Ok(handler(instruction))
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
        let value = unsafe { *(value_bytes.as_ptr() as *const u16) };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_holder_borrows_scratch_account_metadata() {
        let program_id: Pubkey = [1; 32];
        let account_key: Pubkey = [2; 32];
        let data = [3, 4, 5];
        let account_metas = [AccountMeta {
            pubkey: &account_key,
            is_writable: true,
            is_signer: false,
        }];
        let indexes = [7usize];
        let holder = InstructionHolder {
            program_id: &program_id,
            cpi_accounts: &[],
            indexes: &indexes,
            accounts: &account_metas,
            data: &data,
            uses_swig_signer: false,
        };

        let instruction = holder.borrow();

        assert_eq!(instruction.program_id, &program_id);
        assert_eq!(instruction.data, data.as_slice());
        assert_eq!(instruction.accounts.len(), 1);
        assert_eq!(instruction.accounts[0].pubkey, &account_key);
        assert!(instruction.accounts[0].is_writable);
        assert!(!instruction.accounts[0].is_signer);
        assert_eq!(holder.indexes, &[7]);
    }
}
