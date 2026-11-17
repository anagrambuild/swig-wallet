//! Token capacity mirrors SignV2's restrictive exact/wildcard charging.
//! Wildcard mints authorize unlimited spend; exact-mint budgets back locks.

extern crate alloc;
use alloc::{vec, vec::Vec};
use pinocchio::program_error::ProgramError;
use swig_state::{
    action::{
        token_destination_limit::TokenDestinationLimit,
        token_limit::TokenLimit,
        token_recurring_destination_limit::TokenRecurringDestinationLimit,
        token_recurring_limit::TokenRecurringLimit,
        wildcard::{covers_field, WILDCARD},
        Action, Permission,
    },
    Transmutable,
};

struct Budget {
    mint: [u8; 32],
    destination: Option<[u8; 32]>,
    one_shot: Option<u64>,
    recurring: Option<u64>,
}

impl Budget {
    fn capacity(&self) -> u64 {
        self.one_shot
            .unwrap_or(u64::MAX)
            .min(self.recurring.unwrap_or(u64::MAX))
    }
}

pub(crate) struct TokenCapacity {
    budgets: Vec<Budget>,
}

impl TokenCapacity {
    pub(crate) fn read(actions: &[u8], slot: u64) -> Result<Self, ProgramError> {
        let mut budgets: Vec<Budget> = Vec::new();
        let mut cursor = 0;
        while cursor < actions.len() {
            let header_end = cursor + Action::LEN;
            let header = actions
                .get(cursor..header_end)
                .ok_or(ProgramError::InvalidAccountData)?;
            let header = unsafe { Action::load_unchecked(header)? };
            let end = header_end + header.length() as usize;
            if header.boundary() as usize != end {
                return Err(ProgramError::InvalidAccountData);
            }
            let data = actions
                .get(header_end..end)
                .ok_or(ProgramError::InvalidAccountData)?;
            let (mint, destination, recurring, amount) = match header.permission()? {
                Permission::TokenLimit => {
                    let a = unsafe { TokenLimit::load_unchecked(data)? };
                    (a.token_mint, None, false, a.current_amount)
                },
                Permission::TokenRecurringLimit => {
                    let a = unsafe { TokenRecurringLimit::load_unchecked(data)? };
                    (
                        a.token_mint,
                        None,
                        true,
                        super::authorization_lock::recurring_remaining(
                            a.window,
                            a.last_reset,
                            a.limit,
                            a.current,
                            slot,
                        ),
                    )
                },
                Permission::TokenDestinationLimit => {
                    let a = unsafe { TokenDestinationLimit::load_unchecked(data)? };
                    (a.token_mint, Some(a.destination), false, a.amount)
                },
                Permission::TokenRecurringDestinationLimit => {
                    let a = unsafe { TokenRecurringDestinationLimit::load_unchecked(data)? };
                    (
                        a.token_mint,
                        Some(a.destination),
                        true,
                        super::authorization_lock::recurring_remaining(
                            a.window,
                            a.last_reset,
                            a.recurring_amount,
                            a.current_amount,
                            slot,
                        ),
                    )
                },
                _ => {
                    cursor = end;
                    continue;
                },
            };
            let amount = if mint == WILDCARD { u64::MAX } else { amount };
            let index = if let Some(index) = budgets
                .iter()
                .position(|b| b.mint == mint && b.destination == destination)
            {
                index
            } else {
                budgets.push(Budget {
                    mint,
                    destination,
                    one_shot: None,
                    recurring: None,
                });
                budgets.len() - 1
            };
            // Preserve first-match behavior for legacy same-type duplicate keys.
            let b = &mut budgets[index];
            if recurring {
                b.recurring.get_or_insert(amount);
            } else {
                b.one_shot.get_or_insert(amount);
            }
            cursor = end;
        }
        Ok(Self { budgets })
    }

    /// General limits and any-destination limits bound the aggregate debit.
    fn aggregate_bound(&self, mint: &[u8; 32]) -> u64 {
        self.budgets
            .iter()
            .filter(|b| {
                covers_field(&b.mint, mint)
                    && (b.destination.is_none() || b.destination == Some(WILDCARD))
            })
            .map(Budget::capacity)
            .min()
            .unwrap_or(u64::MAX)
    }

    fn open_destinations(&self, mint: &[u8; 32]) -> bool {
        let mut restricted = false;
        for b in self.budgets.iter().filter(|b| covers_field(&b.mint, mint)) {
            if b.destination == Some(WILDCARD) {
                return true;
            }
            restricted |= b.destination.is_some();
        }
        !restricted
    }

    fn edge_bound(&self, mint: &[u8; 32], destination: Option<[u8; 32]>) -> u64 {
        let bound = destination.and_then(|d| {
            self.budgets
                .iter()
                .filter(|b| covers_field(&b.mint, mint) && b.destination == Some(d))
                .map(Budget::capacity)
                .min()
        });
        bound.unwrap_or_else(|| {
            if self.open_destinations(mint) {
                u64::MAX
            } else {
                0
            }
        })
    }

    pub(crate) fn remaining(&self, mint: &[u8; 32]) -> u64 {
        if !self.budgets.iter().any(|b| covers_field(&b.mint, mint)) {
            return 0;
        }
        let destination = if self.open_destinations(mint) {
            u64::MAX
        } else {
            self.budgets
                .iter()
                .enumerate()
                .filter_map(|(index, b)| {
                    let d = b.destination?;
                    if d == WILDCARD
                        || !covers_field(&b.mint, mint)
                        || self.budgets[..index].iter().any(|earlier| {
                            earlier.destination == Some(d) && covers_field(&earlier.mint, mint)
                        })
                    {
                        return None;
                    }
                    Some(self.edge_bound(mint, Some(d)))
                })
                .fold(0u64, u64::saturating_add)
        };
        self.aggregate_bound(mint).min(destination)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(mint: [u8; 32], dest: Option<[u8; 32]>, one: u64, recurring: u64) -> Budget {
        Budget {
            mint,
            destination: dest,
            one_shot: Some(one),
            recurring: Some(recurring),
        }
    }
    #[test]
    fn exact_and_wildcard_pairs_take_minima_without_double_counting_destinations() {
        let m = [1; 32];
        let d = [2; 32];
        let caps = TokenCapacity {
            budgets: vec![
                budget(WILDCARD, None, 100, 10),
                budget(m, None, 80, 8),
                budget(WILDCARD, Some(d), 50, 5),
                budget(m, Some(d), 40, 4),
            ],
        };
        assert_eq!(caps.remaining(&m), 4);
        assert_eq!(caps.remaining(&[3; 32]), 5);
        // A destination-wide budget also covers unnamed recipients: its
        // capacity is not artificially reduced to the named destination sum.
        let caps = TokenCapacity {
            budgets: vec![budget(m, Some(WILDCARD), 20, 10), budget(m, Some(d), 1, 1)],
        };
        assert_eq!(caps.remaining(&m), 10);
    }
}
