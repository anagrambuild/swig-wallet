mod compact_instructions;
pub use compact_instructions::*;
use pinocchio::{
    account_info::AccountInfo,
    instruction::{Account, AccountMeta, Instruction, Signer},
    msg,
    program::invoke_signed_unchecked,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};
use std::marker::PhantomData;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum InstructionError {
    #[error("Missing instructions")]
    MissingInstructions,
    #[error("Missing AccountInfo")]
    MissingAccountInfo,
    #[error("Missing Data")]
    MissingData,
}

pub struct InstructionHolder<'a> {
    pub program_id: &'a Pubkey,
    pub cpi_accounts: Vec<Account<'a>>,
    pub indexes: Vec<usize>,
    pub accounts: Vec<AccountMeta<'a>>,
    pub data: &'a [u8],
}

impl<'a> InstructionHolder<'a> {
    pub fn execute(
        &'a self,
        all_accounts: &'a [AccountInfo],
        swig_key: &'a Pubkey,
        swig_signer: &[Signer],
    ) -> ProgramResult {
        if self.program_id == &pinocchio_system::ID
            && self.data[0..4] == [2, 0, 0, 0]
            && self.accounts[0].pubkey == swig_key
        {
            let amount = u64::from_le_bytes(
                self.data[4..12]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            );
            unsafe {
                *all_accounts[self.indexes[0]].borrow_mut_lamports_unchecked() -= amount;
                *all_accounts[self.indexes[1]].borrow_mut_lamports_unchecked() += amount;
            }
        } else {
            unsafe {
                invoke_signed_unchecked(&self.borrow(), self.cpi_accounts.as_slice(), swig_signer)
            }
        }
        Ok(())
    }
}
pub trait AccountProxy<'a> {
    fn signer(&self) -> bool;
    fn writable(&self) -> bool;
    fn pubkey(&self) -> &'a Pubkey;
    fn into_account(self) -> Account<'a>;
}
pub trait AccountLookup<'a, T>
where
    T: AccountProxy<'a>,
{
    fn get_account(&self, index: usize) -> Result<T, InstructionError>;
    fn size(&self) -> usize;
}

pub trait RestrictedKeys {
    fn is_restricted(&self, pubkey: &Pubkey) -> bool;
}

impl<'a, 'b> InstructionHolder<'a> {
    pub fn borrow(&'a self) -> Instruction<'a, 'a, 'a, 'a> {
        Instruction {
            program_id: self.program_id,
            accounts: &self.accounts,
            data: self.data,
        }
    }
}

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
            remaining: data[0] as usize,
            restricted_keys,
            signer,
            _phantom: PhantomData,
        })
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
        self.remaining -= 1;
        Some(self.parse_next_instruction())
    }
}

impl<'a, AL, RK, P> InstructionIterator<'a, AL, RK, P>
where
    AL: AccountLookup<'a, P>,
    RK: RestrictedKeys,
    P: AccountProxy<'a>,
{
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
        let mut accounts = Vec::with_capacity(num_accounts);
        let mut infos = Vec::with_capacity(num_accounts);
        let mut indexes = Vec::with_capacity(num_accounts);
        for _ in 0..num_accounts {
            let (pubkey_index, cursor) = self.read_u8()?;
            self.cursor = cursor;
            let account = self.accounts.get_account(pubkey_index as usize)?;
            indexes.push(pubkey_index as usize);
            let pubkey = account.pubkey();
            accounts.push(AccountMeta {
                pubkey,
                is_signer: (pubkey == self.signer || account.signer())
                    && !self.restricted_keys.is_restricted(pubkey),
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
        })
    }

    #[inline(always)]
    fn read_u8(&self) -> Result<(u8, usize), InstructionError> {
        if self.cursor >= self.data.len() {
            return Err(InstructionError::MissingData);
        }
        let value = self.data[self.cursor];
        Ok((value, self.cursor + 1))
    }

    #[inline(always)]
    fn read_u16(&self) -> Result<(u16, usize), InstructionError> {
        if self.cursor + 2 > self.data.len() {
            return Err(InstructionError::MissingData);
        }
        let value = u16::from_le_bytes(self.data[self.cursor..self.cursor + 2].try_into().unwrap());
        Ok((value, self.cursor + 2))
    }

    #[inline(always)]
    fn read_slice(&self, len: usize) -> Result<(&'a [u8], usize), InstructionError> {
        if self.cursor + len > self.data.len() {
            return Err(InstructionError::MissingData);
        }
        let slice = &self.data[self.cursor..self.cursor + len];
        Ok((slice, self.cursor + len))
    }
}
