use super::*;
use crate::{error::SwigError, SYSTEM_PROGRAM_ID};
use litesvm_token::spl_token::state::{Account as TokenAccount, AccountState, Multisig};
use pinocchio::entrypoint::deserialize;
use solana_sdk::{account::Account, program_option::COption, program_pack::Pack, pubkey::Pubkey};
use spl_token_2022_interface::{
    extension::{
        transfer_fee::TransferFeeConfig, BaseStateWithExtensionsMut, ExtensionType,
        StateWithExtensionsMut,
    },
    state::Mint,
};
use std::mem::MaybeUninit;

// Build ordinary account states using the pinned loader layout. The backing
// storage outlives every AccountInfo and preserves its required alignment.
fn with_accounts(states: &[(Pubkey, Account, bool)], check: impl FnOnce(&[AccountInfo])) {
    let mut backing = vec![0u64; states.len() * 2_000 + 16];
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), backing.len() * 8)
    };
    bytes[..8].copy_from_slice(&(states.len() as u64).to_le_bytes());
    let mut offset = 8;
    for (key, account, signer) in states {
        bytes[offset] = u8::MAX;
        bytes[offset + 1] = u8::from(*signer);
        bytes[offset + 2] = 1;
        bytes[offset + 8..offset + 40].copy_from_slice(key.as_ref());
        bytes[offset + 40..offset + 72].copy_from_slice(account.owner.as_ref());
        bytes[offset + 72..offset + 80].copy_from_slice(&account.lamports.to_le_bytes());
        bytes[offset + 80..offset + 88].copy_from_slice(&(account.data.len() as u64).to_le_bytes());
        bytes[offset + 88..offset + 88 + account.data.len()].copy_from_slice(&account.data);
        offset = (offset + 88 + account.data.len() + 10_240 + 8).next_multiple_of(8);
    }
    assert!(offset + 40 < bytes.len());
    let mut uninit = [const { MaybeUninit::uninit() }; 16];
    let (_, count, _) = unsafe { deserialize(bytes.as_mut_ptr(), &mut uninit) };
    assert_eq!(count, states.len());
    let accounts =
        unsafe { core::slice::from_raw_parts(uninit.as_ptr().cast::<AccountInfo>(), count) };
    check(accounts);
}

fn account(owner: [u8; 32], data: Vec<u8>) -> Account {
    Account {
        lamports: 10_000_000,
        data,
        owner: Pubkey::new_from_array(owner),
        executable: false,
        rent_epoch: 0,
    }
}

#[test]
fn snapshots_cover_extended_mints_and_multisig_token_owners() {
    let signer = Pubkey::new_unique();
    let multisig_key = Pubkey::new_unique();
    let mut mint_data =
        vec![
            0;
            ExtensionType::try_calculate_account_len::<Mint>(&[ExtensionType::TransferFeeConfig])
                .unwrap()
        ];
    let mut mint = StateWithExtensionsMut::<Mint>::unpack_uninitialized(&mut mint_data).unwrap();
    mint.init_extension::<TransferFeeConfig>(false).unwrap();
    mint.base = Mint {
        mint_authority: COption::Some(signer),
        is_initialized: true,
        ..Default::default()
    };
    mint.pack_base();
    mint.init_account_type().unwrap();
    // The real layout pads the base mint to 165 before the account-type byte.
    assert_eq!(mint_data[82], 0);
    assert_eq!(mint_data[165], 1);
    let mut multisig_data = vec![0; Multisig::LEN];
    Multisig::pack(
        Multisig {
            m: 1,
            n: 1,
            is_initialized: true,
            signers: [signer; 11],
        },
        &mut multisig_data,
    )
    .unwrap();
    let mut token_data = vec![0; TokenAccount::LEN];
    TokenAccount::pack(
        TokenAccount {
            mint: Pubkey::new_unique(),
            owner: multisig_key,
            amount: 100,
            state: AccountState::Initialized,
            ..Default::default()
        },
        &mut token_data,
    )
    .unwrap();
    with_accounts(
        &[
            (signer, account(SYSTEM_PROGRAM_ID, vec![]), true),
            (
                Pubkey::new_unique(),
                account(crate::SPL_TOKEN_2022_ID, mint_data),
                false,
            ),
            (
                multisig_key,
                account(crate::SPL_TOKEN_ID, multisig_data),
                false,
            ),
            (
                Pubkey::new_unique(),
                account(crate::SPL_TOKEN_ID, token_data),
                false,
            ),
        ],
        |accounts| {
            let mut guard = IsolationGuard::new(accounts, &[9; 32]).unwrap();
            for index in 0..accounts.len() {
                guard.snapshot(index).unwrap();
            }
            assert_eq!(guard.frozen.as_slice().len(), 2);
            assert_eq!(guard.tokens.as_slice().len(), 1);
            // The snapshot can move to another function without losing its baseline.
            assert_eq!(guard.validate(), Ok(()));
            accounts[3].try_borrow_mut_data().unwrap()[64..72]
                .copy_from_slice(&101u64.to_le_bytes());
            assert_eq!(guard.validate(), Ok(()), "incoming tokens remain allowed");
            accounts[3].try_borrow_mut_data().unwrap()[64..72]
                .copy_from_slice(&99u64.to_le_bytes());
            assert_eq!(
                guard.validate(),
                Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into())
            );
        },
    );
}

#[test]
fn existing_signer_keeps_system_ownership_while_receiving_sol() {
    with_accounts(
        &[(
            Pubkey::new_unique(),
            account(SYSTEM_PROGRAM_ID, vec![]),
            true,
        )],
        |accounts| {
            let mut guard = IsolationGuard::new(accounts, &[9; 32]).unwrap();
            guard.snapshot(0).unwrap();
            *accounts[0].try_borrow_mut_lamports().unwrap() += 1;
            assert_eq!(guard.validate(), Ok(()));
            unsafe { accounts[0].assign(&crate::SPL_TOKEN_ID) };
            assert_eq!(
                guard.validate(),
                Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into())
            );
        },
    );
}

#[test]
fn zero_signers_need_no_asset_snapshots_and_limits_fail_closed() {
    let states: Vec<_> = (0..MAX_PROTECTED_TOKENS + 1)
        .map(|_| {
            let mut data = vec![0; TokenAccount::LEN];
            TokenAccount::pack(
                TokenAccount {
                    owner: Pubkey::new_from_array([1; 32]),
                    state: AccountState::Initialized,
                    ..Default::default()
                },
                &mut data,
            )
            .unwrap();
            (
                Pubkey::new_unique(),
                account(crate::SPL_TOKEN_ID, data),
                false,
            )
        })
        .collect();
    with_accounts(&states, |accounts| {
        let mut guard = IsolationGuard::new(accounts, &[9; 32]).unwrap();
        for index in 0..accounts.len() {
            guard.snapshot(index).unwrap();
        }
        assert!(guard.tokens.as_slice().is_empty());
        assert!(guard.frozen.as_slice().is_empty());
        assert!(guard.creations.as_slice().is_empty());
        assert_eq!(guard.validate(), Ok(()));
    });
    let mut states = states;
    states.insert(
        0,
        (
            Pubkey::new_from_array([1; 32]),
            account(SYSTEM_PROGRAM_ID, vec![]),
            true,
        ),
    );
    with_accounts(&states, |accounts| {
        let mut guard = IsolationGuard::new(accounts, &[9; 32]).unwrap();
        for index in 0..accounts.len() - 1 {
            guard.snapshot(index).unwrap();
        }
        assert_eq!(
            guard.snapshot(accounts.len() - 1),
            Err(SwigError::InvalidAccountsLength.into())
        );
    });
}
