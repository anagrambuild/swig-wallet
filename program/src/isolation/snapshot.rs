//! Select protected accounts and capture pre-CPI metadata and balances.

use std::mem::MaybeUninit;

use pinocchio::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey, ProgramResult,
};

use super::{
    frozen::any_signer_controls_frozen,
    token::{
        is_token_account, is_token_program, token_owner_is_any_signer_or_multisig,
        TOKEN_ACCOUNT_BASE_DATA_LEN, TOKEN_AMOUNT_OFF, TOKEN_AUTHORITY_OFF,
    },
    MAX_CREATIONS, MAX_FROZEN, MAX_PROTECTED_SIGNERS, MAX_PROTECTED_TOKENS,
};
use crate::{error::SwigError, util::hash_except};

/// Bounded, transaction-local scratch; this is not serialized account state.
pub struct IsolationGuard<'a> {
    pub(super) accounts: &'a [AccountInfo],
    pub(super) signers: Snapshots<SignerSnapshot, MAX_PROTECTED_SIGNERS>,
    pub(super) creations: Snapshots<CreationSnapshot, MAX_CREATIONS>,
    pub(super) creation_overflow: bool,
    pub(super) tokens: Snapshots<TokenSnapshot, MAX_PROTECTED_TOKENS>,
    pub(super) frozen: Snapshots<FrozenSnapshot, MAX_FROZEN>,
}

#[derive(Clone, Copy)]
pub(super) struct SignerSnapshot {
    pub index: u8,
    pub lamports: u64,
    pub system_account: bool,
}

#[derive(Clone, Copy)]
pub(super) struct CreationSnapshot {
    pub index: u8,
    pub lamports: u64,
}

#[derive(Clone, Copy)]
pub(super) struct TokenSnapshot {
    pub index: u8,
    pub is_legacy: bool,
    pub amount: u64,
    pub lamports: u64,
    pub data_len: u16,
    pub rest: [u8; 157],
    pub tail_hash: Option<[u8; 32]>,
}

#[derive(Clone, Copy)]
pub(super) struct FrozenSnapshot {
    pub index: u8,
    pub lamports: u64,
    pub hash: [u8; 32],
}

/// Initialize only captured entries. Zeroing unused capacity is costly on SBF.
/// `push` is the only writer; `as_slice` exposes exactly the initialized prefix.
pub(super) struct Snapshots<T: Copy, const N: usize> {
    entries: [MaybeUninit<T>; N],
    len: usize,
}

impl<T: Copy, const N: usize> Snapshots<T, N> {
    const fn new() -> Self {
        Self {
            entries: [const { MaybeUninit::uninit() }; N],
            len: 0,
        }
    }

    #[inline(always)]
    fn push(&mut self, entry: T) -> ProgramResult {
        if self.len == N {
            return Err(SwigError::InvalidAccountsLength.into());
        }
        self.entries[self.len].write(entry);
        self.len += 1;
        Ok(())
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: only push advances len, after writing the entry. The backing
        // array has T's alignment and remains borrowed for the slice lifetime.
        unsafe { core::slice::from_raw_parts(self.entries.as_ptr().cast::<T>(), self.len) }
    }
}

impl<'a> IsolationGuard<'a> {
    /// Capture outer signers before execution. The wallet PDA is covered by
    /// Swig's permission checks, not personal-asset isolation.
    #[inline(never)]
    pub fn new(all_accounts: &'a [AccountInfo], pda: &Pubkey) -> Result<Self, ProgramError> {
        let mut guard = Self {
            accounts: all_accounts,
            signers: Snapshots::new(),
            creations: Snapshots::new(),
            creation_overflow: false,
            tokens: Snapshots::new(),
            frozen: Snapshots::new(),
        };
        for (index, account) in all_accounts.iter().enumerate() {
            if !account.is_signer() || account.key() == pda {
                continue;
            }
            if index > u8::MAX as usize {
                return Err(SwigError::InvalidAccountsLength.into());
            }
            if guard
                .signers
                .as_slice()
                .iter()
                .any(|previous| all_accounts[previous.index as usize].key() == account.key())
            {
                continue;
            }
            guard.signers.push(SignerSnapshot {
                index: index as u8,
                lamports: account.lamports(),
                // Existing SOL accounts retain their program owner and shape;
                // a fresh keypair may become a new account.
                system_account: account.lamports() != 0
                    && account.is_owned_by(&crate::SYSTEM_PROGRAM_ID)
                    && account.data_len() == 0,
            })?;
        }
        Ok(guard)
    }

    /// Snapshot one writable account before any CPI. Call once per account,
    /// omitting accounts already covered by the wallet's permission checks.
    /// Read-only and unrelated accounts need no snapshot.
    #[inline(always)]
    pub fn snapshot(&mut self, index: usize) -> ProgramResult {
        let all_accounts = self.accounts;
        let guard = self;
        let account = all_accounts
            .get(index)
            .ok_or(SwigError::InvalidAccountsLength)?;
        if !account.is_writable() || guard.signers.as_slice().is_empty() {
            return Ok(());
        }
        if index > u8::MAX as usize {
            return Err(SwigError::InvalidAccountsLength.into());
        }
        // Only an empty System account can become a creation-rent destination.
        // Remember prefunding so it cannot be counted again as signer spending.
        if account.is_owned_by(&crate::SYSTEM_PROGRAM_ID) && account.data_len() == 0 {
            // Existing signer SOL accounts cannot be reassigned; they are not
            // rent destinations. Duplicate account metas count only once.
            if account.is_signer() && account.lamports() != 0 {
                return Ok(());
            }
            if guard
                .creations
                .as_slice()
                .iter()
                .any(|previous| all_accounts[previous.index as usize].key() == account.key())
            {
                return Ok(());
            }
            // A System account may only receive SOL, so exhausting rent scratch
            // is relevant only if validation needs a personal spending allowance.
            if guard.creations.as_slice().len() == MAX_CREATIONS {
                guard.creation_overflow = true;
                return Ok(());
            }
            return guard.creations.push(CreationSnapshot {
                index: index as u8,
                lamports: account.lamports(),
            });
        }
        let owner = account.owner();
        let data = unsafe { account.borrow_data_unchecked() };
        let signed_existing = account.is_signer() && account.lamports() != 0;
        if !is_token_program(owner) || !is_token_account(data) {
            // Signed accounts and known authority-bearing layouts retain their
            // complete data/control. Token accounts use balance-aware checks.
            if signed_existing
                || any_signer_controls_frozen(account, all_accounts, guard.signers.as_slice())
            {
                return guard.snapshot_frozen(index, account, data);
            }
            return Ok(());
        }
        if !signed_existing
            && !token_owner_is_any_signer_or_multisig(
                &data[TOKEN_AUTHORITY_OFF..TOKEN_AUTHORITY_OFF + 32],
                all_accounts,
                guard.signers.as_slice(),
            )
        {
            return Ok(());
        }
        guard.snapshot_token(index, account, data)
    }

    #[inline(never)]
    fn snapshot_frozen(
        &mut self,
        index: usize,
        account: &AccountInfo,
        data: &[u8],
    ) -> ProgramResult {
        self.frozen.push(FrozenSnapshot {
            index: index as u8,
            lamports: account.lamports(),
            hash: hash_except(data, account.owner(), &[]),
        })
    }

    // Parsing/hash scratch is only needed for accounts selected by snapshot.
    #[inline(never)]
    fn snapshot_token(
        &mut self,
        index: usize,
        account: &AccountInfo,
        data: &[u8],
    ) -> ProgramResult {
        let guard = self;
        let owner = account.owner();
        let mut amount = [0u8; 8];
        amount.copy_from_slice(&data[TOKEN_AMOUNT_OFF..TOKEN_AMOUNT_OFF + 8]);
        let mut rest = [0u8; 157];
        rest[..64].copy_from_slice(&data[..64]);
        rest[64..].copy_from_slice(&data[72..165]);
        let data_len = u16::try_from(data.len()).map_err(|_| SwigError::InvalidAccountsLength)?;
        let tail_hash = if data.len() > TOKEN_ACCOUNT_BASE_DATA_LEN {
            Some(hash_except(
                &data[TOKEN_ACCOUNT_BASE_DATA_LEN..],
                owner,
                &[],
            ))
        } else {
            None
        };
        guard.tokens.push(TokenSnapshot {
            index: index as u8,
            is_legacy: owner == &crate::SPL_TOKEN_ID,
            amount: u64::from_le_bytes(amount),
            lamports: account.lamports(),
            data_len,
            rest,
            tail_hash,
        })
    }
}
