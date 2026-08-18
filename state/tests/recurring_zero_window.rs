use pinocchio::program_error::ProgramError;
use swig_state::{
    action::{
        program_scope::{NumericType, ProgramScope, ProgramScopeType},
        sol_recurring_limit::SolRecurringLimit,
        stake_recurring_limit::StakeRecurringLimit,
        token_recurring_limit::TokenRecurringLimit,
        Actionable,
    },
    IntoBytes,
};

#[test]
fn stored_zero_window_recurring_actions_fail_without_mutating_state() {
    let mut sol = SolRecurringLimit {
        recurring_amount: 10,
        window: 0,
        last_reset: 0,
        current_amount: 5,
    };
    assert!(matches!(sol.run(1, 1), Err(ProgramError::InvalidArgument)));
    assert_eq!(sol.current_amount, 5);
    assert_eq!(sol.last_reset, 0);

    let mut token = TokenRecurringLimit {
        token_mint: [1; 32],
        window: 0,
        limit: 10,
        current: 5,
        last_reset: 0,
    };
    assert!(matches!(
        token.run(1, 1),
        Err(ProgramError::InvalidArgument)
    ));
    assert_eq!(token.current, 5);
    assert_eq!(token.last_reset, 0);

    let mut stake = StakeRecurringLimit {
        recurring_amount: 10,
        window: 0,
        last_reset: 0,
        current_amount: 5,
    };
    assert!(matches!(
        stake.run(1, 1),
        Err(ProgramError::InvalidArgument)
    ));
    assert_eq!(stake.current_amount, 5);
    assert_eq!(stake.last_reset, 0);

    let mut program_scope = ProgramScope {
        current_amount: 5,
        limit: 10,
        window: 0,
        last_reset: 0,
        program_id: [2; 32],
        target_account: [3; 32],
        scope_type: ProgramScopeType::RecurringLimit as u64,
        numeric_type: NumericType::U64 as u64,
        balance_field_start: 0,
        balance_field_end: 0,
    };
    assert!(matches!(
        program_scope.run(1, Some(1)),
        Err(ProgramError::InvalidArgument)
    ));
    assert_eq!(program_scope.current_amount, 5);
    assert_eq!(program_scope.last_reset, 0);
}

#[test]
fn program_scope_layout_uses_the_runtime_scope_type_representation() {
    let mut program_scope = ProgramScope {
        current_amount: 0,
        limit: 10,
        window: 0,
        last_reset: 0,
        program_id: [2; 32],
        target_account: [3; 32],
        scope_type: 0x102,
        numeric_type: NumericType::U64 as u64,
        balance_field_start: 0,
        balance_field_end: 0,
    };

    let zero_window_layout = program_scope
        .into_bytes()
        .and_then(<ProgramScope as Actionable>::valid_layout);
    assert!(matches!(zero_window_layout, Ok(false)));

    program_scope.window = 1;
    let nonzero_window_layout = program_scope
        .into_bytes()
        .and_then(<ProgramScope as Actionable>::valid_layout);
    assert!(matches!(nonzero_window_layout, Ok(true)));
}
