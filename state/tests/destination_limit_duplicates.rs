use pinocchio::program_error::ProgramError;
use swig_state::{
    action::{
        sol_destination_limit::SolDestinationLimit, sol_limit::SolLimit,
        sol_recurring_destination_limit::SolRecurringDestinationLimit,
        token_destination_limit::TokenDestinationLimit,
        token_recurring_destination_limit::TokenRecurringDestinationLimit, Action, ActionLoader,
        Permission,
    },
    IntoBytes, SwigStateError, Transmutable,
};

fn action_bytes<T: Transmutable + IntoBytes>(permission: Permission, action: &T) -> Vec<u8> {
    let mut bytes = Action::new(permission, T::LEN as u16, (Action::LEN + T::LEN) as u32)
        .into_bytes()
        .unwrap()
        .to_vec();
    bytes.extend_from_slice(action.into_bytes().unwrap());
    bytes
}

fn sol_destination_limit(destination: [u8; 32], amount: u64) -> Vec<u8> {
    action_bytes(
        Permission::SolDestinationLimit,
        &SolDestinationLimit {
            destination,
            amount,
        },
    )
}

fn sol_recurring_destination_limit(destination: [u8; 32]) -> Vec<u8> {
    action_bytes(
        Permission::SolRecurringDestinationLimit,
        &SolRecurringDestinationLimit {
            destination,
            recurring_amount: 100,
            window: 100,
            last_reset: 0,
            current_amount: 100,
        },
    )
}

fn token_destination_limit(mint: [u8; 32], destination: [u8; 32]) -> Vec<u8> {
    action_bytes(
        Permission::TokenDestinationLimit,
        &TokenDestinationLimit {
            token_mint: mint,
            destination,
            amount: 100,
        },
    )
}

fn token_recurring_destination_limit(mint: [u8; 32], destination: [u8; 32]) -> Vec<u8> {
    action_bytes(
        Permission::TokenRecurringDestinationLimit,
        &TokenRecurringDestinationLimit {
            token_mint: mint,
            destination,
            recurring_amount: 100,
            window: 100,
            last_reset: 0,
            current_amount: 100,
        },
    )
}

#[test]
fn rejects_duplicate_sol_destination_limits_of_the_same_type() {
    let dest = [7u8; 32];
    let mut actions = sol_destination_limit(dest, 100);
    actions.extend(sol_destination_limit(dest, 200));
    assert_eq!(
        ActionLoader::validate_destination_limit_duplicates(&actions),
        Err(ProgramError::Custom(
            SwigStateError::DuplicateDestinationLimit as u32
        )),
        "two one-shot limits for the same destination must be rejected"
    );
}

#[test]
fn rejects_non_adjacent_duplicate_sol_destination_limits() {
    let dest = [7u8; 32];
    let other = [8u8; 32];
    let mut actions = sol_destination_limit(dest, 100);
    actions.extend(sol_destination_limit(other, 1));
    actions.extend(sol_destination_limit(other, 2));
    actions.extend(sol_destination_limit(dest, 300));
    assert_eq!(
        ActionLoader::validate_destination_limit_duplicates(&actions),
        Err(ProgramError::Custom(
            SwigStateError::DuplicateDestinationLimit as u32
        ))
    );
}

#[test]
fn rejects_duplicate_sol_recurring_destination_limits() {
    let dest = [7u8; 32];
    let mut actions = sol_recurring_destination_limit(dest);
    actions.extend(sol_recurring_destination_limit(dest));
    assert_eq!(
        ActionLoader::validate_destination_limit_duplicates(&actions),
        Err(ProgramError::Custom(
            SwigStateError::DuplicateDestinationLimit as u32
        ))
    );
}

#[test]
fn allows_a_one_shot_and_recurring_pair_for_the_same_destination() {
    let dest = [7u8; 32];
    let mut actions = sol_destination_limit(dest, 4_000_000_000);
    actions.extend(sol_recurring_destination_limit(dest));
    assert_eq!(
        ActionLoader::validate_destination_limit_duplicates(&actions),
        Ok(()),
        "the intended smoothing pair must stay allowed"
    );
}

#[test]
fn allows_different_destinations_of_the_same_type() {
    let first = [7u8; 32];
    let second = [8u8; 32];
    let mut actions = sol_destination_limit(first, 100);
    actions.extend(sol_destination_limit(second, 100));
    actions.extend(sol_recurring_destination_limit(first));
    actions.extend(sol_recurring_destination_limit(second));
    assert_eq!(
        ActionLoader::validate_destination_limit_duplicates(&actions),
        Ok(())
    );
}

#[test]
fn rejects_duplicate_token_destination_limits_of_the_same_type() {
    let mint = [1u8; 32];
    let dest = [2u8; 32];
    let mut actions = token_destination_limit(mint, dest);
    actions.extend(token_destination_limit(mint, dest));
    assert_eq!(
        ActionLoader::validate_destination_limit_duplicates(&actions),
        Err(ProgramError::Custom(
            SwigStateError::DuplicateDestinationLimit as u32
        ))
    );
}

#[test]
fn rejects_duplicate_token_recurring_destination_limits() {
    let mint = [1u8; 32];
    let dest = [2u8; 32];
    let mut actions = token_recurring_destination_limit(mint, dest);
    actions.extend(token_recurring_destination_limit(mint, dest));
    assert_eq!(
        ActionLoader::validate_destination_limit_duplicates(&actions),
        Err(ProgramError::Custom(
            SwigStateError::DuplicateDestinationLimit as u32
        ))
    );
}

#[test]
fn allows_a_token_one_shot_and_recurring_pair() {
    let mint = [1u8; 32];
    let dest = [2u8; 32];
    let mut actions = token_destination_limit(mint, dest);
    actions.extend(token_recurring_destination_limit(mint, dest));
    assert_eq!(
        ActionLoader::validate_destination_limit_duplicates(&actions),
        Ok(())
    );
}

#[test]
fn allows_the_same_destination_across_mints_and_across_types() {
    let mint_a = [1u8; 32];
    let mint_b = [3u8; 32];
    let dest = [2u8; 32];
    let mut actions = token_destination_limit(mint_a, dest);
    actions.extend(token_destination_limit(mint_b, dest));
    actions.extend(token_recurring_destination_limit(mint_a, dest));
    // SOL and token limits never collide even on identical destination bytes.
    actions.extend(sol_destination_limit(dest, 100));
    actions.extend(sol_recurring_destination_limit(dest));
    assert_eq!(
        ActionLoader::validate_destination_limit_duplicates(&actions),
        Ok(())
    );
}

#[test]
fn mixed_other_actions_do_not_confuse_the_scan() {
    let dest = [7u8; 32];
    let limit = action_bytes(
        Permission::SolLimit,
        &SolLimit {
            amount: 1_000_000_000,
        },
    );
    let mut actions = limit;
    actions.extend(sol_destination_limit(dest, 100));
    actions.extend(sol_recurring_destination_limit(dest));
    assert_eq!(
        ActionLoader::validate_destination_limit_duplicates(&actions),
        Ok(())
    );
}

fn token_limit(mint: [u8; 32], amount: u64) -> Vec<u8> {
    action_bytes(
        Permission::TokenLimit,
        &swig_state::action::token_limit::TokenLimit {
            token_mint: mint,
            current_amount: amount,
        },
    )
}

fn token_recurring_limit(mint: [u8; 32]) -> Vec<u8> {
    action_bytes(
        Permission::TokenRecurringLimit,
        &swig_state::action::token_recurring_limit::TokenRecurringLimit {
            token_mint: mint,
            window: 100,
            limit: 100,
            current: 100,
            last_reset: 0,
        },
    )
}

fn duplicate_token_limit() -> Result<(), ProgramError> {
    Err(SwigStateError::DuplicateTokenLimit.into())
}

#[test]
fn rejects_duplicate_general_token_limits_for_the_same_mint() {
    let mint = [3u8; 32];
    let mut actions = token_limit(mint, 10);
    actions.extend(token_limit(mint, 20));
    assert_eq!(
        ActionLoader::validate_destination_limit_duplicates(&actions),
        duplicate_token_limit()
    );

    let mut actions = token_recurring_limit(mint);
    actions.extend(token_recurring_limit(mint));
    assert_eq!(
        ActionLoader::validate_destination_limit_duplicates(&actions),
        duplicate_token_limit()
    );
}

#[test]
fn allows_general_token_pairs_and_distinct_mints() {
    let mut actions = token_limit([3u8; 32], 10);
    actions.extend(token_recurring_limit([3u8; 32]));
    actions.extend(token_limit([4u8; 32], 10));
    assert_eq!(
        ActionLoader::validate_destination_limit_duplicates(&actions),
        Ok(())
    );
}

#[test]
fn added_actions_are_checked_against_existing_ones() {
    let dest = [7u8; 32];
    let existing = sol_destination_limit(dest, 100);
    assert_eq!(
        ActionLoader::validate_added_limit_duplicates(&existing, &sol_destination_limit(dest, 5)),
        Err(SwigStateError::DuplicateDestinationLimit.into())
    );
    assert_eq!(
        ActionLoader::validate_added_limit_duplicates(
            &existing,
            &sol_recurring_destination_limit(dest)
        ),
        Ok(())
    );
}

#[test]
fn existing_duplicates_do_not_block_unrelated_additions() {
    // Roles created before duplicates were rejected keep them and stay
    // updatable; only the added actions are checked.
    let dest = [7u8; 32];
    let mut existing = sol_destination_limit(dest, 100);
    existing.extend(sol_destination_limit(dest, 200));
    existing.extend(token_limit([3u8; 32], 10));
    existing.extend(token_limit([3u8; 32], 20));
    assert_eq!(
        ActionLoader::validate_added_limit_duplicates(&existing, &token_limit([4u8; 32], 1)),
        Ok(())
    );
    assert_eq!(
        ActionLoader::validate_added_limit_duplicates(&existing, &[]),
        Ok(())
    );
    assert_eq!(
        ActionLoader::validate_added_limit_duplicates(&existing, &token_limit([3u8; 32], 1)),
        duplicate_token_limit()
    );
}
