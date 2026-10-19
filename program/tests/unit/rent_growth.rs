#[test]
#[allow(deprecated)]
fn growing_rent_does_not_use_surplus_and_repairs_existing_deficit() {
    let rent = Rent {
        lamports_per_byte_year: pinocchio::sysvars::rent::DEFAULT_LAMPORTS_PER_BYTE_YEAR,
        exemption_threshold: pinocchio::sysvars::rent::DEFAULT_EXEMPTION_THRESHOLD,
        burn_percent: pinocchio::sysvars::rent::DEFAULT_BURN_PERCENT,
    };
    let old_reserve = rent.minimum_balance(64);
    let new_reserve = rent.minimum_balance(96);
    let increase = new_reserve - old_reserve;
    assert_eq!(growth_cost(&rent, old_reserve, 64, 96), increase);
    assert_eq!(
        growth_cost(&rent, old_reserve + 1_000_000_000, 64, 96),
        increase
    );
    assert_eq!(growth_cost(&rent, old_reserve - 1, 64, 96), increase + 1);
    assert_eq!(growth_cost(&rent, 0, 64, 96), new_reserve);
}
