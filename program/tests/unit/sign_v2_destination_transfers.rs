use super::*;
use std::mem::MaybeUninit;
use swig_compact_instructions::{CompactInstruction, CompactInstructions};

fn preflight_destination_limits(
    actions: &mut [u8],
    slot: u64,
    instruction_payload: &[u8],
    all_accounts: &[AccountInfo],
    signer: &Pubkey,
    classifiers: &[AccountClassification],
) -> Result<[bool; MAX_ACCOUNTS], ProgramError> {
    let flags = super::preflight_destination_limits(
        actions,
        slot,
        instruction_payload,
        all_accounts,
        signer,
        classifiers,
    )?;
    Ok(std::array::from_fn(|index| {
        account_has_destination_limit(&flags, index)
    }))
}

// Match the aligned loader fixture used by isolation unit tests. Only account
// keys and flags are needed to exercise the production accounting helpers.
fn with_accounts(keys: &[Pubkey], check: impl FnOnce(&[AccountInfo])) {
    let mut backing = vec![0u64; keys.len() * 2_000 + 16];
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), backing.len() * 8)
    };
    bytes[..8].copy_from_slice(&(keys.len() as u64).to_le_bytes());
    let mut offset = 8;
    for key in keys {
        bytes[offset] = u8::MAX;
        bytes[offset + 2] = 1;
        bytes[offset + 8..offset + 40].copy_from_slice(key);
        offset = (offset + 88 + 10_240 + 8).next_multiple_of(8);
    }
    assert!(offset + 40 < bytes.len());
    let mut uninit = [const { MaybeUninit::uninit() }; 16];
    let (_, count, _) =
        unsafe { pinocchio::entrypoint::deserialize(bytes.as_mut_ptr(), &mut uninit) };
    assert_eq!(count, keys.len());
    let accounts =
        unsafe { core::slice::from_raw_parts(uninit.as_ptr().cast::<AccountInfo>(), count) };
    check(accounts);
}

const EDWARD: Pubkey = [1; 32];
const ALICE: Pubkey = [2; 32];
const BOB: Pubkey = [3; 32];
const MINT: Pubkey = [4; 32];
const CONFIG: Pubkey = [5; 32];

fn with_actions(entries: &[(Permission, &[u8])], check: impl FnOnce(&mut [u8])) {
    let len: usize = entries
        .iter()
        .map(|(_, data)| Action::LEN + data.len())
        .sum();
    let mut aligned = vec![0u64; len.div_ceil(8)];
    let bytes = unsafe { core::slice::from_raw_parts_mut(aligned.as_mut_ptr().cast::<u8>(), len) };
    let mut offset = 0;
    for (permission, data) in entries {
        let end = offset + Action::LEN + data.len();
        let header = Action::new(*permission, data.len() as u16, end as u32);
        bytes[offset..offset + Action::LEN].copy_from_slice(header.into_bytes().unwrap());
        bytes[offset + Action::LEN..end].copy_from_slice(data);
        offset = end;
    }
    check(bytes);
}

fn classifiers(program: Pubkey) -> [AccountClassification; 6] {
    let mut classifiers = [AccountClassification::None; 6];
    classifiers[0] = AccountClassification::ThisSwigV2 { lamports: 0 };
    classifiers[1] = if program == SYSTEM_PROGRAM_ID {
        AccountClassification::SwigWalletAddress
    } else {
        AccountClassification::SwigTokenAccount {
            mint: MINT,
            balance: 1_000,
            native_reserve: None,
            spent: 0,
        }
    };
    classifiers
}

fn transfer(
    program: Pubkey,
    checked: bool,
    source: u8,
    destination: u8,
    amount: u64,
) -> CompactInstruction {
    let (mut data, accounts) = if program == SYSTEM_PROGRAM_ID {
        (
            SYSTEM_TRANSFER_DISCRIMINATOR.to_le_bytes().to_vec(),
            vec![source, destination],
        )
    } else if checked {
        (
            vec![TOKEN_TRANSFER_CHECKED_DISCRIMINATOR],
            vec![source, 4, destination, 1],
        )
    } else {
        (
            vec![TOKEN_TRANSFER_DISCRIMINATOR],
            vec![source, destination, 1],
        )
    };
    data.extend_from_slice(&amount.to_le_bytes());
    if program != SYSTEM_PROGRAM_ID && checked {
        data.push(6);
    }
    CompactInstruction {
        program_id_index: 5,
        accounts,
        data,
    }
}

fn payload(instructions: Vec<CompactInstruction>) -> Vec<u8> {
    CompactInstructions {
        inner_instructions: instructions,
    }
    .into_bytes()
    .unwrap()
}

#[test]
fn destination_flags_cover_word_boundaries_and_reject_excess_accounts() {
    for program in [SPL_TOKEN_ID, SPL_TOKEN_2022_ID] {
        with_accounts(&[CONFIG, EDWARD, ALICE, BOB, MINT, program], |initial| {
            let mut accounts = initial.to_vec();
            accounts.resize(MAX_ACCOUNTS, accounts[1].clone());
            for index in [
                0,
                DESTINATION_LIMIT_BITS_PER_WORD - 1,
                DESTINATION_LIMIT_BITS_PER_WORD,
                2 * DESTINATION_LIMIT_BITS_PER_WORD - 1,
                2 * DESTINATION_LIMIT_BITS_PER_WORD,
                3 * DESTINATION_LIMIT_BITS_PER_WORD - 1,
                3 * DESTINATION_LIMIT_BITS_PER_WORD,
                MAX_ACCOUNTS - 1,
            ] {
                let mut classified = vec![AccountClassification::None; MAX_ACCOUNTS];
                classified[index] = classifiers(program)[1];
                let limit = TokenDestinationLimit {
                    token_mint: MINT,
                    destination: ALICE,
                    amount: 100,
                };
                with_actions(
                    &[(
                        Permission::TokenDestinationLimit,
                        limit.into_bytes().unwrap(),
                    )],
                    |actions| {
                        let data = payload(vec![transfer(program, false, index as u8, 2, 100)]);
                        let mut excessive = classified.clone();
                        excessive.push(AccountClassification::None);
                        for (classes, supplied) in [
                            (excessive.as_slice(), accounts.as_slice()),
                            (classified.as_slice(), &accounts[..MAX_ACCOUNTS - 1]),
                        ] {
                            assert_eq!(
                                preflight_destination_limits(
                                    actions, 0, &data, supplied, &EDWARD, classes
                                ),
                                Err(SwigError::InvalidAccountsLength.into())
                            );
                        }
                        let flags = preflight_destination_limits(
                            actions,
                            0,
                            &data,
                            &accounts,
                            &EDWARD,
                            &classified,
                        )
                        .unwrap();
                        for (flag_index, flag) in flags.iter().enumerate() {
                            assert_eq!(*flag, flag_index == index);
                        }
                        let key = [MINT, ALICE].concat();
                        assert_eq!(
                            RoleMut::get_action_mut::<TokenDestinationLimit>(actions, &key)
                                .unwrap()
                                .unwrap()
                                .amount,
                            0
                        );
                    },
                );
            }
        });
    }
}

#[test]
fn extra_account_positions_preserve_general_and_destination_allowances() {
    with_accounts(
        &[CONFIG, EDWARD, ALICE, BOB, MINT, SYSTEM_PROGRAM_ID],
        |initial| {
            for count in [MAX_ACCOUNT_SNAPSHOTS + 1, MAX_ACCOUNTS] {
                let mut accounts = initial.to_vec();
                accounts.resize(count, initial[5].clone());
                let mut classified = classifiers(SYSTEM_PROGRAM_ID).to_vec();
                classified.resize(count, AccountClassification::None);
                let data = payload(vec![transfer(SYSTEM_PROGRAM_ID, false, 1, 3, 20)]);
                for with_destination in [false, true] {
                    let general = SolLimit { amount: 100 };
                    let destination = SolDestinationLimit {
                        destination: BOB,
                        amount: 100,
                    };
                    let mut entries = vec![(Permission::SolLimit, general.into_bytes().unwrap())];
                    if with_destination {
                        entries.push((
                            Permission::SolDestinationLimit,
                            destination.into_bytes().unwrap(),
                        ));
                    }
                    with_actions(&entries, |actions| {
                        let flags = preflight_destination_limits(
                            actions,
                            0,
                            &data,
                            &accounts,
                            &EDWARD,
                            &classified,
                        )
                        .unwrap();
                        for (index, flag) in flags.iter().enumerate() {
                            assert_eq!(*flag, with_destination && index == 0);
                        }
                        assert_eq!(
                            RoleMut::get_action_mut::<SolLimit>(actions, &[])
                                .unwrap()
                                .unwrap()
                                .amount,
                            100,
                        );
                        consume_general_sol_limit(actions, 20, 0, flags[0]).unwrap();
                        assert_eq!(
                            RoleMut::get_action_mut::<SolLimit>(actions, &[])
                                .unwrap()
                                .unwrap()
                                .amount,
                            80,
                        );
                        if with_destination {
                            assert_eq!(
                                RoleMut::get_action_mut::<SolDestinationLimit>(actions, &BOB)
                                    .unwrap()
                                    .unwrap()
                                    .amount,
                                80,
                            );
                        }
                    });
                }
            }
        },
    );
}

#[test]
fn self_transfers_consume_destination_quota_but_cannot_cover_another_cpi() {
    for program in [SYSTEM_PROGRAM_ID, SPL_TOKEN_ID, SPL_TOKEN_2022_ID] {
        for checked in [false, true] {
            with_accounts(&[CONFIG, EDWARD, ALICE, BOB, MINT, program], |initial| {
                let mut accounts = initial.to_vec();
                accounts.push(accounts[1].clone());
                for destination in [1, 6] {
                    for amount in [0, 100] {
                        // CreateAccount or an unsupported token instruction debits the
                        // source. A later self-transfer must not cover that debit.
                        let unknown = CompactInstruction {
                            program_id_index: 5,
                            accounts: vec![1, 3, 4],
                            data: if program == SYSTEM_PROGRAM_ID {
                                let mut data = 0u32.to_le_bytes().to_vec();
                                data.extend_from_slice(&100u64.to_le_bytes());
                                data.extend_from_slice(&0u64.to_le_bytes());
                                data.extend_from_slice(&SYSTEM_PROGRAM_ID);
                                data
                            } else {
                                vec![26, 1, 100, 0, 0, 0, 0, 0, 0, 0, 6, 1, 0, 0, 0, 0, 0, 0, 0]
                            },
                        };
                        let data = payload(vec![
                            unknown,
                            transfer(program, checked, 1, destination, amount),
                        ]);
                        let mut decoded = Vec::new();
                        let mut check = |destination: &Pubkey, amount| {
                            decoded.push((*destination, amount));
                            Ok(())
                        };
                        if program == SYSTEM_PROGRAM_ID {
                            process_sol_transfers(&data, &EDWARD, &accounts, &EDWARD, &mut check)
                                .unwrap();
                        } else {
                            process_token_destinations(
                                &data, &EDWARD, &accounts, &EDWARD, &mut check,
                            )
                            .unwrap();
                        }
                        assert_eq!(decoded, vec![(EDWARD, amount)]);
                        for (index, instruction) in
                            InstructionIterator::new(&accounts, &data, &EDWARD, &[])
                                .map_err(ProgramError::from)
                                .unwrap()
                                .enumerate()
                        {
                            let instruction = instruction.map_err(ProgramError::from).unwrap();
                            let transfer = if program == SYSTEM_PROGRAM_ID {
                                sol_transfer(&instruction, &EDWARD)
                            } else {
                                token_transfer(&instruction, &EDWARD)
                            };
                            assert_eq!(require_destination_debit(transfer, &EDWARD, 0), Ok(()));
                            assert_eq!(
                                require_destination_debit(transfer, &EDWARD, 100),
                                Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into()),
                                "instruction {index}"
                            );
                        }
                    }
                }
            });
        }
    }
}

#[test]
fn each_debit_requires_its_own_source_and_exact_transfer_amount() {
    for program in [SYSTEM_PROGRAM_ID, SPL_TOKEN_ID, SPL_TOKEN_2022_ID] {
        for checked in [false, true] {
            with_accounts(&[CONFIG, EDWARD, ALICE, BOB, MINT, program], |accounts| {
                let data = payload(vec![transfer(program, checked, 1, 2, 100)]);
                let instruction = InstructionIterator::new(accounts, &data, &EDWARD, &[])
                    .map_err(ProgramError::from)
                    .unwrap()
                    .next()
                    .unwrap()
                    .map_err(ProgramError::from)
                    .unwrap();
                let decoded = if program == SYSTEM_PROGRAM_ID {
                    sol_transfer(&instruction, &EDWARD)
                } else {
                    token_transfer(&instruction, &EDWARD)
                };
                assert_eq!(decoded, Some((&ALICE, 100)));
                assert_eq!(require_destination_debit(decoded, &EDWARD, 100), Ok(()));
                for debit in [1, 99, 101, u64::MAX] {
                    assert_eq!(
                        require_destination_debit(decoded, &EDWARD, debit),
                        Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into())
                    );
                }
                let wrong_source = if program == SYSTEM_PROGRAM_ID {
                    sol_transfer(&instruction, &BOB)
                } else {
                    token_transfer(&instruction, &BOB)
                };
                assert_eq!(wrong_source, None);
                assert!(require_destination_debit(wrong_source, &BOB, 100).is_err());
            });
        }
    }
}

#[test]
fn sol_preflight_charges_self_and_external_transfers_independently_of_general_spend() {
    with_accounts(
        &[CONFIG, EDWARD, ALICE, BOB, MINT, SYSTEM_PROGRAM_ID],
        |accounts| {
            let general = SolLimit { amount: 100 };
            let self_limit = SolDestinationLimit {
                destination: EDWARD,
                amount: 300,
            };
            let alice = SolDestinationLimit {
                destination: ALICE,
                amount: 100,
            };
            let data = payload(vec![
                transfer(SYSTEM_PROGRAM_ID, false, 1, 1, 300),
                transfer(SYSTEM_PROGRAM_ID, false, 1, 2, 100),
            ]);
            with_actions(
                &[
                    (Permission::SolLimit, general.into_bytes().unwrap()),
                    (
                        Permission::SolDestinationLimit,
                        self_limit.into_bytes().unwrap(),
                    ),
                    (Permission::SolDestinationLimit, alice.into_bytes().unwrap()),
                ],
                |actions| {
                    let flags = preflight_destination_limits(
                        actions,
                        0,
                        &data,
                        accounts,
                        &EDWARD,
                        &classifiers(SYSTEM_PROGRAM_ID),
                    )
                    .unwrap();
                    assert!(flags[0]);
                    assert_eq!(
                        RoleMut::get_action_mut::<SolDestinationLimit>(actions, &EDWARD)
                            .unwrap()
                            .unwrap()
                            .amount,
                        0
                    );
                    assert_eq!(
                        RoleMut::get_action_mut::<SolDestinationLimit>(actions, &ALICE)
                            .unwrap()
                            .unwrap()
                            .amount,
                        0
                    );
                    assert_eq!(
                        RoleMut::get_action_mut::<SolLimit>(actions, &[])
                            .unwrap()
                            .unwrap()
                            .amount,
                        100
                    );
                    consume_general_sol_limit(actions, 100, 0, flags[0]).unwrap();
                    assert_eq!(
                        RoleMut::get_action_mut::<SolLimit>(actions, &[])
                            .unwrap()
                            .unwrap()
                            .amount,
                        0
                    );
                },
            );
        },
    );
}

#[test]
fn sol_destination_checks_run_even_without_balance_loss() {
    with_accounts(
        &[CONFIG, EDWARD, ALICE, BOB, MINT, SYSTEM_PROGRAM_ID],
        |accounts| {
            for destination in [EDWARD, ALICE, BOB] {
                for allowance in [0, 99, 100] {
                    let limit = SolDestinationLimit {
                        destination,
                        amount: allowance,
                    };
                    let general = SolLimit { amount: 0 };
                    let data = payload(vec![transfer(SYSTEM_PROGRAM_ID, false, 1, 1, 100)]);
                    with_actions(
                        &[
                            (Permission::SolLimit, general.into_bytes().unwrap()),
                            (Permission::SolDestinationLimit, limit.into_bytes().unwrap()),
                        ],
                        |actions| {
                            let result = preflight_destination_limits(
                                actions,
                                0,
                                &data,
                                accounts,
                                &EDWARD,
                                &classifiers(SYSTEM_PROGRAM_ID),
                            );
                            if destination != EDWARD {
                                assert_eq!(
                                    result.unwrap_err(),
                                    SwigAuthenticateError::PermissionDeniedMissingPermission.into()
                                );
                            } else if allowance < 100 {
                                assert_eq!(result.unwrap_err(), SwigAuthenticateError::PermissionDeniedSolDestinationLimitExceeded.into());
                            } else {
                                assert!(result.unwrap()[0]);
                                consume_general_sol_limit(actions, 0, 0, true).unwrap();
                                assert_eq!(
                                    RoleMut::get_action_mut::<SolLimit>(actions, &[])
                                        .unwrap()
                                        .unwrap()
                                        .amount,
                                    0
                                );
                            }
                        },
                    );
                }
            }
        },
    );
}

#[test]
fn alice_permission_does_not_authorize_bob_even_with_general_allowance() {
    with_accounts(
        &[CONFIG, EDWARD, ALICE, BOB, MINT, SYSTEM_PROGRAM_ID],
        |accounts| {
            let general = SolLimit { amount: 1_000 };
            let alice = SolDestinationLimit {
                destination: ALICE,
                amount: 1_000,
            };
            let data = payload(vec![transfer(SYSTEM_PROGRAM_ID, false, 1, 3, 300)]);
            with_actions(
                &[
                    (Permission::SolLimit, general.into_bytes().unwrap()),
                    (Permission::SolDestinationLimit, alice.into_bytes().unwrap()),
                ],
                |actions| {
                    assert_eq!(
                        preflight_destination_limits(
                            actions,
                            0,
                            &data,
                            accounts,
                            &EDWARD,
                            &classifiers(SYSTEM_PROGRAM_ID)
                        )
                        .unwrap_err(),
                        SwigAuthenticateError::PermissionDeniedMissingPermission.into()
                    );
                    assert_eq!(
                        RoleMut::get_action_mut::<SolLimit>(actions, &[])
                            .unwrap()
                            .unwrap()
                            .amount,
                        1_000
                    );
                },
            );
            with_actions(
                &[(Permission::SolLimit, general.into_bytes().unwrap())],
                |actions| {
                    let flags = preflight_destination_limits(
                        actions,
                        0,
                        &data,
                        accounts,
                        &EDWARD,
                        &classifiers(SYSTEM_PROGRAM_ID),
                    )
                    .unwrap();
                    assert!(!flags[0]);
                    consume_general_sol_limit(actions, 300, 0, flags[0]).unwrap();
                    assert_eq!(
                        RoleMut::get_action_mut::<SolLimit>(actions, &[])
                            .unwrap()
                            .unwrap()
                            .amount,
                        700
                    );
                },
            );
        },
    );
}

#[test]
fn token_destination_limits_check_mint_recipient_and_amount_before_execution() {
    for program in [SPL_TOKEN_ID, SPL_TOKEN_2022_ID] {
        for checked in [false, true] {
            for destination in [EDWARD, ALICE, BOB] {
                for allowance in [0, 99, 100] {
                    with_accounts(&[CONFIG, EDWARD, ALICE, BOB, MINT, program], |accounts| {
                        let limit = TokenDestinationLimit {
                            token_mint: MINT,
                            destination,
                            amount: allowance,
                        };
                        for to in [1, 2] {
                            let expected = if to == 1 { EDWARD } else { ALICE };
                            let data = payload(vec![transfer(program, checked, 1, to, 100)]);
                            with_actions(
                                &[(
                                    Permission::TokenDestinationLimit,
                                    limit.into_bytes().unwrap(),
                                )],
                                |actions| {
                                    let result = preflight_destination_limits(
                                        actions,
                                        0,
                                        &data,
                                        accounts,
                                        &EDWARD,
                                        &classifiers(program),
                                    );
                                    if destination != expected {
                                        assert_eq!(result.unwrap_err(), SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                                    } else if allowance < 100 {
                                        assert_eq!(result.unwrap_err(), SwigAuthenticateError::PermissionDeniedTokenDestinationLimitExceeded.into());
                                    } else {
                                        assert!(result.unwrap()[1]);
                                        let key = [MINT, expected].concat();
                                        assert_eq!(
                                            RoleMut::get_action_mut::<TokenDestinationLimit>(
                                                actions, &key
                                            )
                                            .unwrap()
                                            .unwrap()
                                            .amount,
                                            0
                                        );
                                        consume_general_token_limit(
                                            actions,
                                            &MINT,
                                            if to == 1 { 0 } else { 100 },
                                            0,
                                            true,
                                        )
                                        .unwrap();
                                    }
                                },
                            );
                        }
                        let other_mint = TokenDestinationLimit {
                            token_mint: BOB,
                            destination,
                            amount: allowance,
                        };
                        with_actions(
                            &[(
                                Permission::TokenDestinationLimit,
                                other_mint.into_bytes().unwrap(),
                            )],
                            |actions| {
                                let data = payload(vec![transfer(program, checked, 1, 2, 100)]);
                                assert!(
                                    !preflight_destination_limits(
                                        actions,
                                        0,
                                        &data,
                                        accounts,
                                        &EDWARD,
                                        &classifiers(program)
                                    )
                                    .unwrap()[1]
                                );
                                assert!(consume_general_token_limit(actions, &MINT, 100, 0, false)
                                    .is_err());
                            },
                        );
                    });
                }
            }
        }
    }
}

#[test]
fn paired_destination_limits_charge_both_and_preserve_recurring_reset() {
    for program in [SYSTEM_PROGRAM_ID, SPL_TOKEN_ID, SPL_TOKEN_2022_ID] {
        with_accounts(&[CONFIG, EDWARD, ALICE, BOB, MINT, program], |accounts| {
            let sol_fixed = SolDestinationLimit {
                destination: ALICE,
                amount: 999,
            };
            let sol_recurring = SolRecurringDestinationLimit {
                destination: ALICE,
                recurring_amount: 100,
                window: 10,
                last_reset: 0,
                current_amount: 0,
            };
            let token_fixed = TokenDestinationLimit {
                token_mint: MINT,
                destination: ALICE,
                amount: 999,
            };
            let token_recurring = TokenRecurringDestinationLimit {
                token_mint: MINT,
                destination: ALICE,
                recurring_amount: 100,
                window: 10,
                last_reset: 0,
                current_amount: 0,
            };
            let entries = if program == SYSTEM_PROGRAM_ID {
                [
                    (
                        Permission::SolDestinationLimit,
                        sol_fixed.into_bytes().unwrap(),
                    ),
                    (
                        Permission::SolRecurringDestinationLimit,
                        sol_recurring.into_bytes().unwrap(),
                    ),
                ]
            } else {
                [
                    (
                        Permission::TokenDestinationLimit,
                        token_fixed.into_bytes().unwrap(),
                    ),
                    (
                        Permission::TokenRecurringDestinationLimit,
                        token_recurring.into_bytes().unwrap(),
                    ),
                ]
            };
            with_actions(&entries, |actions| {
                let data = payload(vec![transfer(program, true, 1, 2, 100)]);
                assert!(preflight_destination_limits(
                    actions,
                    10,
                    &data,
                    accounts,
                    &EDWARD,
                    &classifiers(program)
                )
                .is_err());
                preflight_destination_limits(
                    actions,
                    11,
                    &data,
                    accounts,
                    &EDWARD,
                    &classifiers(program),
                )
                .unwrap();
                if program == SYSTEM_PROGRAM_ID {
                    let recurring =
                        RoleMut::get_action_mut::<SolRecurringDestinationLimit>(actions, &ALICE)
                            .unwrap()
                            .unwrap();
                    assert_eq!((recurring.current_amount, recurring.last_reset), (0, 11));
                    assert_eq!(
                        RoleMut::get_action_mut::<SolDestinationLimit>(actions, &ALICE)
                            .unwrap()
                            .unwrap()
                            .amount,
                        899
                    );
                } else {
                    let key = [MINT, ALICE].concat();
                    let recurring =
                        RoleMut::get_action_mut::<TokenRecurringDestinationLimit>(actions, &key)
                            .unwrap()
                            .unwrap();
                    assert_eq!((recurring.current_amount, recurring.last_reset), (0, 11));
                    assert_eq!(
                        RoleMut::get_action_mut::<TokenDestinationLimit>(actions, &key)
                            .unwrap()
                            .unwrap()
                            .amount,
                        899
                    );
                }
                assert!(preflight_destination_limits(
                    actions,
                    11,
                    &data,
                    accounts,
                    &EDWARD,
                    &classifiers(program)
                )
                .is_err());
            });
        });
    }
}

#[test]
fn general_allowance_rejects_overspend_even_with_destination_permission() {
    let general = SolLimit { amount: 99 };
    with_actions(
        &[(Permission::SolLimit, general.into_bytes().unwrap())],
        |actions| {
            assert_eq!(
                consume_general_sol_limit(actions, 100, 0, true),
                Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into())
            );
            assert_eq!(
                RoleMut::get_action_mut::<SolLimit>(actions, &[])
                    .unwrap()
                    .unwrap()
                    .amount,
                99
            );
        },
    );
    let general = TokenLimit {
        token_mint: MINT,
        current_amount: 99,
    };
    with_actions(
        &[(Permission::TokenLimit, general.into_bytes().unwrap())],
        |actions| {
            assert_eq!(
                consume_general_token_limit(actions, &MINT, 100, 0, true),
                Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into())
            );
            assert_eq!(
                RoleMut::get_action_mut::<TokenLimit>(actions, &MINT)
                    .unwrap()
                    .unwrap()
                    .current_amount,
                99
            );
        },
    );
}

#[test]
fn unrecognized_or_truncated_instructions_never_authorize_a_debit() {
    for program in [SYSTEM_PROGRAM_ID, SPL_TOKEN_ID, SPL_TOKEN_2022_ID, BOB] {
        with_accounts(&[CONFIG, EDWARD, ALICE, BOB, MINT, program], |accounts| {
            let valid = transfer(program, true, 1, 2, 100);
            for length in 0..valid.data.len() {
                let data = payload(vec![CompactInstruction {
                    program_id_index: 5,
                    accounts: valid.accounts.clone(),
                    data: valid.data[..length].to_vec(),
                }]);
                let instruction = InstructionIterator::new(accounts, &data, &EDWARD, &[])
                    .map_err(ProgramError::from)
                    .unwrap()
                    .next()
                    .unwrap()
                    .map_err(ProgramError::from)
                    .unwrap();
                assert!(sol_transfer(&instruction, &EDWARD).is_none());
                assert!(token_transfer(&instruction, &EDWARD).is_none());
                assert_eq!(
                    require_destination_debit(None, &EDWARD, 100),
                    Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into())
                );
            }
            let data = payload(vec![CompactInstruction {
                program_id_index: 5,
                accounts: vec![1],
                data: valid.data,
            }]);
            let instruction = InstructionIterator::new(accounts, &data, &EDWARD, &[])
                .map_err(ProgramError::from)
                .unwrap()
                .next()
                .unwrap()
                .map_err(ProgramError::from)
                .unwrap();
            assert!(sol_transfer(&instruction, &EDWARD).is_none());
            assert!(token_transfer(&instruction, &EDWARD).is_none());
        });
    }
}
