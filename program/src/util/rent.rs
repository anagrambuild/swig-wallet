use pinocchio::sysvars::rent::Rent;

/// Fund growth from the payer, preserving SOL above the prior rent reserve.
pub(crate) fn growth_cost(rent: &Rent, balance: u64, old_len: usize, new_len: usize) -> u64 {
    let available_reserve = balance.min(rent.minimum_balance(old_len));
    rent.minimum_balance(new_len)
        .saturating_sub(available_reserve)
}

#[cfg(test)]
include!("../../tests/unit/rent_growth.rs");
