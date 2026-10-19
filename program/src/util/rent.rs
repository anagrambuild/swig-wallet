use pinocchio::{account_info::AccountInfo, program_error::ProgramError, sysvars::rent::Rent};
use swig_state::swig::swig_wallet_address_seeds;

use crate::error::SwigError;

pub(crate) fn refund_destination<'a>(
    configured_claimer: Option<&[u8; 32]>,
    swig: &AccountInfo,
    payer: &'a AccountInfo,
    accounts: &'a [AccountInfo],
) -> Result<&'a AccountInfo, ProgramError> {
    let Some(claimer) = configured_claimer else {
        return Ok(payer);
    };
    let (wallet_address, _) =
        pinocchio::pubkey::find_program_address(&swig_wallet_address_seeds(swig.key()), &crate::ID);
    if claimer == &[0; 32] || claimer == swig.key() || claimer == &wallet_address {
        return Err(SwigError::InvalidRentClaimerDestination.into());
    }
    accounts
        .iter()
        .find(|account| account.key() == claimer && account.is_writable())
        .ok_or_else(|| SwigError::InvalidRentClaimerDestination.into())
}

/// Fund growth from the payer, preserving SOL above the prior rent reserve.
pub(crate) fn growth_cost(rent: &Rent, balance: u64, old_len: usize, new_len: usize) -> u64 {
    let available_reserve = balance.min(rent.minimum_balance(old_len));
    rent.minimum_balance(new_len)
        .saturating_sub(available_reserve)
}

#[cfg(test)]
include!("../../tests/unit/rent_growth.rs");
