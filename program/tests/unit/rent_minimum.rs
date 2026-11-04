#[test]
fn minimum_balance_preserves_rent_parameters_and_rounding() {
    for threshold in [0.0f64, 1.0, 1.5, 2.0, 2.5, f64::INFINITY, f64::NAN] {
        for rate in [0, 3_480, 5_080, 6_960, 1_000_000_000] {
            let rent = Rent {
                lamports_per_byte_year: rate,
                exemption_threshold: threshold,
                burn_percent: 50,
            };
            for len in [0, 165, 200, 8_192, 10_485_760] {
                assert_eq!(minimum_balance(&rent, len), rent.minimum_balance(len));
            }
        }
    }

    // Rate 1 makes the amount exactly 128 + data_len. Odd integers above
    // 2^53 expose the legacy floating-point rounding that must be preserved.
    let rent = Rent {
        lamports_per_byte_year: 1,
        exemption_threshold: 1.0,
        burn_percent: 50,
    };
    for amount in [
        (1u64 << 53) - 1,
        1u64 << 53,
        (1u64 << 53) + 1,
        (1u64 << 53) + 3,
    ] {
        let len = (amount - ACCOUNT_STORAGE_OVERHEAD) as usize;
        assert_eq!(minimum_balance(&rent, len), rent.minimum_balance(len));
    }
    assert_eq!(
        minimum_balance(&rent, ((1u64 << 53) + 1 - 128) as usize),
        1u64 << 53
    );
}
