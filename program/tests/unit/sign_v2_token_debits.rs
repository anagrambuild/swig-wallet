#[test]
fn erased_token_data_charges_the_remaining_balance_once() {
    let (mut balance, mut spent) = (100, 0);
    super::record_token_debit(&mut balance, &mut spent, 0).unwrap();
    assert_eq!((balance, spent), (0, 100));
    super::record_token_debit(&mut balance, &mut spent, 0).unwrap();
    assert_eq!((balance, spent), (0, 100));
}

#[test]
fn closure_preserves_debits_observed_before_the_close() {
    let (mut balance, mut spent) = (100, 0);
    super::record_token_debit(&mut balance, &mut spent, 40).unwrap();
    assert_eq!((balance, spent), (40, 60));
    super::record_token_debit(&mut balance, &mut spent, 0).unwrap();
    assert_eq!((balance, spent), (0, 100));
}

#[test]
fn token_credits_do_not_cancel_spending_and_overflow_rejects_before_mutation() {
    let (mut balance, mut spent) = (100, 0);
    super::record_token_debit(&mut balance, &mut spent, 40).unwrap();
    super::record_token_debit(&mut balance, &mut spent, 100).unwrap();
    assert_eq!((balance, spent), (100, 60));
    let (mut balance, mut spent) = (1, u64::MAX);
    let error = super::record_token_debit(&mut balance, &mut spent, 0).unwrap_err();
    assert_eq!(
        error,
        pinocchio::program_error::ProgramError::from(
            crate::error::SwigError::AccountDataModifiedUnexpectedly
        )
    );
    assert_eq!((balance, spent), (1, u64::MAX));
}
