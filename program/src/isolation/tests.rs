use super::*;
use crate::{error::SwigError, SYSTEM_PROGRAM_ID};
use litesvm_token::spl_token::state::{Account as TokenAccount, AccountState, Multisig};
use pinocchio::{account_info::AccountInfo, entrypoint::deserialize};
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
fn signing_account_postcondition_rejects_reassignment_and_allocation() {
    use crate::util::assert_system_account_invariants;

    with_accounts(
        &[(
            Pubkey::new_unique(),
            account(SYSTEM_PROGRAM_ID, vec![]),
            false,
        )],
        |accounts| {
            let asset = &accounts[0];
            assert_eq!(assert_system_account_invariants(asset), Ok(()));
            *asset.try_borrow_mut_lamports().unwrap() -= 1;
            assert_eq!(
                assert_system_account_invariants(asset),
                Ok(()),
                "normal spending remains allowed"
            );
            unsafe { asset.assign(&Pubkey::new_unique().to_bytes()) };
            assert_eq!(
                assert_system_account_invariants(asset),
                Err(SwigError::WalletAddressInvariantViolation.into()),
                "assigned ownership must not survive the batch"
            );
            unsafe { asset.assign(&SYSTEM_PROGRAM_ID) };
            asset.resize(80).unwrap();
            assert_eq!(
                assert_system_account_invariants(asset),
                Err(SwigError::WalletAddressInvariantViolation.into()),
                "System-owned nonce data must not survive the batch"
            );
            asset.resize(0).unwrap();
            assert_eq!(assert_system_account_invariants(asset), Ok(()));
        },
    );
}

#[test]
fn seeded_vote_authorities_preserve_control_and_sol() {
    use solana_vote_interface::{
        instruction::{authorize_checked_with_seed, authorize_with_seed},
        state::{VoteAuthorize, VoteStateV3, VoteStateVersions},
    };
    use swig_compact_instructions::compact_instructions;

    let base = Pubkey::new_unique();
    let wallet = Pubkey::new_unique();
    let vote_key = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    let replacement = Pubkey::new_unique();
    let authority = Pubkey::create_with_seed(&base, "vote", &owner).unwrap();
    let original = bincode::serialize(&VoteStateVersions::new_v3(VoteStateV3 {
        authorized_withdrawer: authority,
        ..Default::default()
    }))
    .unwrap();
    for checked in [false, true] {
        let build = if checked {
            authorize_checked_with_seed
        } else {
            authorize_with_seed
        };
        let instruction = build(
            &vote_key,
            &base,
            &owner,
            "vote",
            &replacement,
            VoteAuthorize::Withdrawer,
        );
        let (metas, compact) = compact_instructions(wallet, vec![], vec![instruction]).unwrap();
        let payload = compact.into_bytes().unwrap();
        let vote_index = metas
            .iter()
            .position(|meta| meta.pubkey == vote_key)
            .unwrap();
        for (signed, excluded) in [(true, wallet), (false, wallet), (true, base)] {
            let states: Vec<_> = metas
                .iter()
                .map(|meta| {
                    let state = if meta.pubkey == vote_key {
                        account(crate::VOTE_PROGRAM_ID, original.clone())
                    } else {
                        account(SYSTEM_PROGRAM_ID, vec![])
                    };
                    (meta.pubkey, state, signed && meta.is_signer)
                })
                .collect();
            with_accounts(&states, |accounts| {
                let mut guard = IsolationGuard::new(accounts);
                guard.capture_signers(&excluded.to_bytes()).unwrap();
                guard.capture_seeded_accounts(&payload).unwrap();
                guard.snapshot(vote_index).unwrap();
                let protected = signed && excluded != base;
                assert_eq!(guard.frozen.as_slice().len(), usize::from(protected));
                assert_eq!(guard.validate(), Ok(()));
                if protected {
                    let vote = &accounts[vote_index];
                    vote.try_borrow_mut_data().unwrap()[36..68]
                        .copy_from_slice(replacement.as_ref());
                    assert_eq!(
                        guard.validate(),
                        Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into())
                    );
                    vote.try_borrow_mut_data()
                        .unwrap()
                        .copy_from_slice(&original);
                    *vote.try_borrow_mut_lamports().unwrap() += 1;
                    assert_eq!(guard.validate(), Ok(()));
                    *vote.try_borrow_mut_lamports().unwrap() -= 2;
                    assert_eq!(
                        guard.validate(),
                        Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into())
                    );
                    // Vote's base is account 2, after the clock sysvar.
                    let mut malformed = payload.clone();
                    malformed[5] = u8::MAX;
                    assert_eq!(
                        guard.capture_seeded_accounts(&malformed),
                        Err(SwigError::InstructionExecutionError.into())
                    );
                }
            });
        }
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
            let mut guard = IsolationGuard::new(accounts);
            guard.capture_signers(&[9; 32]).unwrap();
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
            // Restore the token balance, then check the frozen-account phase.
            accounts[3].try_borrow_mut_data().unwrap()[64..72]
                .copy_from_slice(&100u64.to_le_bytes());
            *accounts[1].try_borrow_mut_lamports().unwrap() -= 1;
            assert_eq!(
                guard.validate(),
                Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into()),
                "mint account lamports cannot decrease"
            );
        },
    );
}

#[test]
fn signer_baseline_is_captured_after_guard_allocation() {
    let mut signer = account(SYSTEM_PROGRAM_ID, vec![]);
    signer.lamports = 0;
    with_accounts(&[(Pubkey::new_unique(), signer, true)], |accounts| {
        let mut guard = IsolationGuard::new(accounts);
        // Allocation may precede authentication; the baseline must not.
        *accounts[0].try_borrow_mut_lamports().unwrap() = 10_000_000;
        guard.capture_signers(&[9; 32]).unwrap();
        guard.snapshot(0).unwrap();
        assert_eq!(guard.validate(), Ok(()));

        // This is an existing funded signer at capture time, so its System
        // ownership must remain protected even though it was empty at new().
        unsafe { accounts[0].assign(&crate::SPL_TOKEN_ID) };
        assert_eq!(
            guard.validate(),
            Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into())
        );
    });
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
            let mut guard = IsolationGuard::new(accounts);
            guard.capture_signers(&[9; 32]).unwrap();
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
        let mut guard = IsolationGuard::new(accounts);
        guard.capture_signers(&[9; 32]).unwrap();
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
        let mut guard = IsolationGuard::new(accounts);
        guard.capture_signers(&[9; 32]).unwrap();
        for index in 0..accounts.len() - 1 {
            guard.snapshot(index).unwrap();
        }
        assert_eq!(
            guard.snapshot(accounts.len() - 1),
            Err(SwigError::InvalidAccountsLength.into())
        );
    });
}

#[test]
fn seeded_stake_authorities_keep_their_pre_cpi_control_and_balance() {
    use solana_stake_interface::{
        instruction::{authorize_checked_with_seed, authorize_with_seed},
        stake_flags::StakeFlags,
        state::{Authorized, Meta, Stake, StakeAuthorize, StakeStateV2},
    };
    use swig_compact_instructions::compact_instructions;

    let base = Pubkey::new_unique();
    let stake_key = Pubkey::new_unique();
    let wallet = Pubkey::new_unique();
    let replacement = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    for checked in [false, true] {
        for delegated in [false, true] {
            for kind in [StakeAuthorize::Staker, StakeAuthorize::Withdrawer] {
                let seed = "s".repeat(32);
                let authority = Pubkey::create_with_seed(&base, &seed, &owner).unwrap();
                let meta = Meta {
                    authorized: Authorized::auto(&authority),
                    ..Meta::default()
                };
                let state = if delegated {
                    StakeStateV2::Stake(meta, Stake::default(), StakeFlags::empty())
                } else {
                    StakeStateV2::Initialized(meta)
                };
                let original_data = bincode::serialize(&state).unwrap();
                let instruction = if checked {
                    authorize_checked_with_seed(
                        &stake_key,
                        &base,
                        seed,
                        &owner,
                        &replacement,
                        kind,
                        None,
                    )
                } else {
                    authorize_with_seed(&stake_key, &base, seed, &owner, &replacement, kind, None)
                };
                // Repeated uses of the same account must keep one original baseline.
                let (metas, compact) =
                    compact_instructions(wallet, vec![], vec![instruction.clone(), instruction])
                        .unwrap();
                let states: Vec<_> = metas
                    .iter()
                    .map(|meta| {
                        let state = if meta.pubkey == stake_key {
                            account(crate::STAKING_ID, original_data.clone())
                        } else {
                            account(SYSTEM_PROGRAM_ID, vec![])
                        };
                        (meta.pubkey, state, meta.is_signer)
                    })
                    .collect();
                let payload = compact.into_bytes().unwrap();
                let stake_index = metas
                    .iter()
                    .position(|meta| meta.pubkey == stake_key)
                    .unwrap();
                with_accounts(&states, |accounts| {
                    let mut guard = IsolationGuard::new(accounts);
                    guard.capture_signers(&wallet.to_bytes()).unwrap();
                    guard.capture_seeded_accounts(&payload).unwrap();
                    for index in 0..accounts.len() {
                        guard.snapshot(index).unwrap();
                    }
                    assert_eq!(guard.frozen.as_slice().len(), 1);
                    assert_eq!(guard.validate(), Ok(()), "no-op remains allowed");
                    let stake = &accounts[stake_index];
                    let offset = match kind {
                        StakeAuthorize::Staker => 12,
                        StakeAuthorize::Withdrawer => 44,
                    };
                    stake.try_borrow_mut_data().unwrap()[offset..offset + 32]
                        .copy_from_slice(replacement.as_ref());
                    assert_eq!(
                        guard.validate(),
                        Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into()),
                        "authority changes must be rejected without any balance decrease"
                    );
                    stake
                        .try_borrow_mut_data()
                        .unwrap()
                        .copy_from_slice(&original_data);
                    *stake.try_borrow_mut_lamports().unwrap() += 1;
                    assert_eq!(guard.validate(), Ok(()), "credits remain allowed");
                    *stake.try_borrow_mut_lamports().unwrap() -= 2;
                    assert_eq!(
                        guard.validate(),
                        Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into()),
                        "the derived account cannot lose SOL while the base is unchanged"
                    );
                });
            }
        }
    }
}

#[test]
fn seeded_stake_selection_excludes_wallet_and_unsigned_bases_and_rejects_truncation() {
    use solana_stake_interface::instruction::authorize_with_seed;
    use solana_stake_interface::state::StakeAuthorize;
    use swig_compact_instructions::compact_instructions;

    let base = Pubkey::new_unique();
    let wallet = Pubkey::new_unique();
    let stake_key = Pubkey::new_unique();
    let instruction = authorize_with_seed(
        &stake_key,
        &base,
        String::new(),
        &Pubkey::new_unique(),
        &Pubkey::new_unique(),
        StakeAuthorize::Withdrawer,
        None,
    );
    let (metas, compact) = compact_instructions(wallet, vec![], vec![instruction]).unwrap();
    let payload = compact.into_bytes().unwrap();
    let stake_index = metas
        .iter()
        .position(|meta| meta.pubkey == stake_key)
        .unwrap();
    for (signer, pda) in [(false, wallet), (true, base), (true, wallet)] {
        let states: Vec<_> = metas
            .iter()
            .map(|meta| {
                let state = if meta.pubkey == stake_key {
                    account(crate::STAKING_ID, vec![0; 200])
                } else {
                    account(SYSTEM_PROGRAM_ID, vec![])
                };
                (meta.pubkey, state, signer && meta.pubkey == base)
            })
            .collect();
        with_accounts(&states, |accounts| {
            let mut guard = IsolationGuard::new(accounts);
            guard.capture_signers(&pda.to_bytes()).unwrap();
            guard.capture_seeded_accounts(&payload).unwrap();
            guard.snapshot(stake_index).unwrap();
            assert_eq!(
                guard.frozen.as_slice().len(),
                usize::from(signer && pda != base)
            );
            if signer && pda != base {
                for end in 0..payload.len() {
                    let mut guard = IsolationGuard::new(accounts);
                    guard.capture_signers(&pda.to_bytes()).unwrap();
                    assert_eq!(
                        guard.capture_seeded_accounts(&payload[..end]),
                        Err(SwigError::InstructionExecutionError.into())
                    );
                }
                // Corrupt only an index in the production compact encoding.
                for offset in [1, 3, 4] {
                    let mut malformed = payload.clone();
                    malformed[offset] = u8::MAX;
                    let mut guard = IsolationGuard::new(accounts);
                    guard.capture_signers(&pda.to_bytes()).unwrap();
                    assert_eq!(
                        guard.capture_seeded_accounts(&malformed),
                        Err(SwigError::InstructionExecutionError.into())
                    );
                }
            }
        });
    }
}

#[test]
fn seeded_system_source_keeps_sol_and_control_without_charging_the_base() {
    use solana_system_interface::instruction::transfer_with_seed;
    use swig_compact_instructions::compact_instructions;

    let base = Pubkey::new_unique();
    let wallet = Pubkey::new_unique();
    let recipient = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    let seed = "s".repeat(32);
    let source = Pubkey::create_with_seed(&base, &seed, &owner).unwrap();
    let instruction = transfer_with_seed(&source, &base, seed, &owner, &recipient, 1);
    let (metas, compact) = compact_instructions(wallet, vec![], vec![instruction]).unwrap();
    let payload = compact.into_bytes().unwrap();
    let states: Vec<_> = metas
        .iter()
        .map(|meta| {
            (
                meta.pubkey,
                account(SYSTEM_PROGRAM_ID, vec![]),
                meta.is_signer,
            )
        })
        .collect();
    let source_index = metas.iter().position(|meta| meta.pubkey == source).unwrap();
    let recipient_index = metas
        .iter()
        .position(|meta| meta.pubkey == recipient)
        .unwrap();
    with_accounts(&states, |accounts| {
        let mut guard = IsolationGuard::new(accounts);
        guard.capture_signers(&wallet.to_bytes()).unwrap();
        guard.capture_seeded_accounts(&payload).unwrap();
        for index in 0..accounts.len() {
            guard.snapshot(index).unwrap();
        }
        assert_eq!(guard.frozen.as_slice().len(), 1);
        assert_eq!(guard.validate(), Ok(()), "no-op remains allowed");
        let source = &accounts[source_index];
        *source.try_borrow_mut_lamports().unwrap() += 1;
        assert_eq!(guard.validate(), Ok(()), "credits remain allowed");
        *source.try_borrow_mut_lamports().unwrap() -= 2;
        assert_eq!(
            guard.validate(),
            Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into()),
            "a seeded source cannot lose SOL even when the base is unchanged"
        );
        *source.try_borrow_mut_lamports().unwrap() += 1;
        unsafe { source.assign(&owner.to_bytes()) };
        assert_eq!(
            guard.validate(),
            Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into()),
            "reassignment must not bypass protection of the funded source"
        );
        unsafe { source.assign(&SYSTEM_PROGRAM_ID) };
        *accounts[recipient_index].try_borrow_mut_lamports().unwrap() -= 1;
        assert_eq!(
            guard.validate(),
            Ok(()),
            "unrelated accounts remain unprotected"
        );
    });
}

#[test]
fn seeded_system_selection_covers_native_variants_and_preserves_creation_and_pda_exclusions() {
    use solana_system_interface::instruction::{
        allocate_with_seed, assign_with_seed, create_account_with_seed, transfer_with_seed,
    };
    use swig_compact_instructions::compact_instructions;

    let base = Pubkey::new_unique();
    let wallet = Pubkey::new_unique();
    let funder = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    let target = Pubkey::create_with_seed(&base, "", &owner).unwrap();
    let mut instructions = vec![
        transfer_with_seed(&target, &base, String::new(), &owner, &funder, 1),
        assign_with_seed(&target, &base, "", &owner),
        allocate_with_seed(&target, &base, "", 8, &owner),
        create_account_with_seed(&funder, &target, &base, "", 1, 8, &owner),
        create_account_with_seed(&base, &target, &base, "", 1, 8, &owner),
    ];
    // These variants find their base in instruction data and accept its signer
    // anywhere in the account list, not just the SDK builder's usual position.
    for mut instruction in instructions.clone().into_iter().skip(1) {
        let position = if instruction.data[0] == 3 { 2 } else { 1 };
        instruction.accounts.insert(
            position,
            solana_sdk::instruction::AccountMeta::new_readonly(Pubkey::new_unique(), false),
        );
        instructions.push(instruction);
    }
    for instruction in instructions {
        let (metas, compact) = compact_instructions(wallet, vec![], vec![instruction]).unwrap();
        let payload = compact.into_bytes().unwrap();
        let target_index = metas.iter().position(|meta| meta.pubkey == target).unwrap();
        for (funded, signer, pda) in [
            (true, true, wallet),
            (false, true, wallet),
            (true, false, wallet),
            (true, true, base),
        ] {
            let states: Vec<_> = metas
                .iter()
                .map(|meta| {
                    let mut state = account(SYSTEM_PROGRAM_ID, vec![]);
                    if meta.pubkey == target && !funded {
                        state.lamports = 0;
                    }
                    (meta.pubkey, state, signer && meta.pubkey == base)
                })
                .collect();
            with_accounts(&states, |accounts| {
                let mut guard = IsolationGuard::new(accounts);
                guard.capture_signers(&pda.to_bytes()).unwrap();
                guard.capture_seeded_accounts(&payload).unwrap();
                guard.snapshot(target_index).unwrap();
                assert_eq!(
                    guard.frozen.as_slice().len(),
                    usize::from(funded && signer && pda != base)
                );
                if !funded && signer && pda != base {
                    assert_eq!(
                        guard.creations.as_slice().len(),
                        1,
                        "new accounts can still receive rent"
                    );
                }
                assert_eq!(guard.validate(), Ok(()));
            });
        }
    }
}

#[test]
fn seeded_system_snapshot_capacity_fails_closed() {
    use solana_system_interface::instruction::transfer_with_seed;
    use swig_compact_instructions::compact_instructions;

    let base = Pubkey::new_unique();
    let wallet = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    let recipient = Pubkey::new_unique();
    let sources: Vec<_> = (0..=MAX_FROZEN)
        .map(|index| Pubkey::create_with_seed(&base, &index.to_string(), &owner).unwrap())
        .collect();
    let instructions = sources
        .iter()
        .enumerate()
        .map(|(index, source)| {
            transfer_with_seed(source, &base, index.to_string(), &owner, &recipient, 1)
        })
        .collect();
    let (metas, compact) = compact_instructions(wallet, vec![], instructions).unwrap();
    let payload = compact.into_bytes().unwrap();
    let states: Vec<_> = metas
        .iter()
        .map(|meta| {
            (
                meta.pubkey,
                account(SYSTEM_PROGRAM_ID, vec![]),
                meta.is_signer,
            )
        })
        .collect();
    with_accounts(&states, |accounts| {
        let mut guard = IsolationGuard::new(accounts);
        guard.capture_signers(&wallet.to_bytes()).unwrap();
        guard.capture_seeded_accounts(&payload).unwrap();
        for (count, source) in sources.iter().enumerate() {
            let index = metas
                .iter()
                .position(|meta| meta.pubkey == *source)
                .unwrap();
            if count < MAX_FROZEN {
                guard.snapshot(index).unwrap();
            } else {
                assert_eq!(
                    guard.snapshot(index),
                    Err(SwigError::InvalidAccountsLength.into())
                );
            }
        }
        assert_eq!(guard.frozen.as_slice().len(), MAX_FROZEN);
    });
}
