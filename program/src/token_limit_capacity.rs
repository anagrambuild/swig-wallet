//! Token capacity mirrors SignV2's restrictive exact/wildcard charging.
//! Shared wildcard-mint budgets must back all the creator's token locks,
//! rather than being counted afresh for every locked mint.

extern crate alloc;
use crate::error::SwigError;
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
    tail::authorization_locks::{AuthorizationLock, NATIVE_SOL_MINT},
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

    fn destinations(&self) -> Vec<Option<[u8; 32]>> {
        let mut result = Vec::new();
        for b in &self.budgets {
            if let Some(d) = b.destination {
                if d != WILDCARD && !result.contains(&Some(d)) {
                    result.push(Some(d));
                }
            }
        }
        // All destinations not named by an exact key share this unrestricted
        // alternative, available only when there is no destination restriction
        // or an applicable wildcard-destination scope.
        result.push(None);
        result
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

    /// Checks simultaneous backing, including overlapping destination pools.
    /// This is a small bipartite max-flow: mint reservations feed destination
    /// budgets, with wildcard-mint keys shared across every mint. Sparse flow
    /// records avoid allocating a dense mint-by-destination capacity matrix.
    pub(crate) fn check_reservations(
        &self,
        locks: impl Iterator<Item = AuthorizationLock>,
    ) -> Result<(), ProgramError> {
        let mut mints: Vec<([u8; 32], u64)> = Vec::new();
        let mut total = 0u64;
        for lock in locks.filter(|l| l.mint != NATIVE_SOL_MINT) {
            total = total
                .checked_add(lock.amount)
                .ok_or(ProgramError::ArithmeticOverflow)?;
            if let Some((_, reserved)) = mints.iter_mut().find(|(m, _)| m == &lock.mint) {
                *reserved = reserved
                    .checked_add(lock.amount)
                    .ok_or(ProgramError::ArithmeticOverflow)?;
            } else {
                mints.push((lock.mint, lock.amount));
            }
        }
        let denied = || ProgramError::from(SwigError::AuthorizationLockExceedsSpendLimit);
        if mints
            .iter()
            .any(|(m, reserved)| *reserved > self.remaining(m))
        {
            return Err(denied());
        }
        if mints.len() < 2 || !self.budgets.iter().any(|b| b.mint == WILDCARD) {
            return Ok(());
        }
        if total > self.aggregate_bound(&WILDCARD) {
            return Err(denied());
        }
        // Shared general/any-destination caps need only the aggregate check.
        // Allocation is necessary only for shared named-destination pools.
        if !self
            .budgets
            .iter()
            .any(|b| b.mint == WILDCARD && b.destination.is_some_and(|d| d != WILDCARD))
        {
            return Ok(());
        }

        let destinations = self.destinations();
        let count = mints.len();
        let nodes = count + destinations.len();
        let mut used_mint = vec![0u64; count];
        let mut used_dest = vec![0u64; destinations.len()];
        let dest_bounds: Vec<u64> = destinations
            .iter()
            .map(|d| {
                d.and_then(|d| {
                    self.budgets
                        .iter()
                        .filter(|b| b.mint == WILDCARD && b.destination == Some(d))
                        .map(Budget::capacity)
                        .min()
                })
                .unwrap_or(u64::MAX)
            })
            .collect();
        let mut flows: Vec<(usize, usize, u64)> = Vec::new();
        let mut sent = 0u64;
        let mut parent = vec![usize::MAX; nodes];
        let mut queue = Vec::with_capacity(nodes);
        while sent < total {
            parent.fill(usize::MAX);
            queue.clear();
            for (i, (_, reserved)) in mints.iter().enumerate() {
                if used_mint[i] < *reserved {
                    parent[i] = nodes;
                    queue.push(i);
                }
            }
            let mut terminal = None;
            let mut cursor = 0;
            while cursor < queue.len() {
                let node = queue[cursor];
                cursor += 1;
                if node < count {
                    for (j, d) in destinations.iter().enumerate() {
                        let next = count + j;
                        if parent[next] == usize::MAX
                            && self.edge_bound(&mints[node].0, *d) > flow(&flows, node, j)
                        {
                            parent[next] = node;
                            queue.push(next);
                        }
                    }
                } else {
                    let j = node - count;
                    if used_dest[j] < dest_bounds[j] {
                        terminal = Some(j);
                        break;
                    }
                    for &(i, dest, amount) in &flows {
                        if dest == j && amount != 0 && parent[i] == usize::MAX {
                            parent[i] = node;
                            queue.push(i);
                        }
                    }
                }
            }
            let j = terminal.ok_or_else(denied)?;
            let mut amount = dest_bounds[j] - used_dest[j];
            let mut node = count + j;
            while parent[node] != nodes {
                let previous = parent[node];
                amount = amount.min(if node >= count {
                    self.edge_bound(&mints[previous].0, destinations[node - count])
                        - flow(&flows, previous, node - count)
                } else {
                    flow(&flows, node, previous - count)
                });
                node = previous;
            }
            amount = amount.min(mints[node].1 - used_mint[node]);
            used_mint[node] += amount;
            used_dest[j] += amount;
            sent += amount;
            node = count + j;
            while parent[node] != nodes {
                let previous = parent[node];
                let (i, d, add) = if node >= count {
                    (previous, node - count, true)
                } else {
                    (node, previous - count, false)
                };
                if let Some(index) = flows.iter().position(|&(m, dest, _)| m == i && dest == d) {
                    if add {
                        flows[index].2 += amount;
                    } else {
                        flows[index].2 -= amount;
                    }
                    if flows[index].2 == 0 {
                        flows.swap_remove(index);
                    }
                } else {
                    flows.push((i, d, amount));
                }
                node = previous;
            }
        }
        Ok(())
    }
}

fn flow(flows: &[(usize, usize, u64)], mint: usize, destination: usize) -> u64 {
    flows
        .iter()
        .find(|&&(m, d, _)| m == mint && d == destination)
        .map(|x| x.2)
        .unwrap_or(0)
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
    fn lock(mint: [u8; 32], amount: u64) -> AuthorizationLock {
        AuthorizationLock {
            mint,
            amount,
            asset_account: mint,
            expiry_slot: 100,
            role_id: 1,
            lock_id: 0,
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

    #[test]
    fn shared_destination_pools_cannot_be_overbooked_by_subsets_of_mints() {
        let a = [1; 32];
        let b = [2; 32];
        let c = [3; 32];
        let x = [4; 32];
        let y = [5; 32];
        let caps = TokenCapacity {
            budgets: vec![
                budget(WILDCARD, Some(x), 5, 5),
                budget(WILDCARD, Some(y), 5, 5),
                budget(a, Some(y), 0, 0),
                budget(b, Some(y), 0, 0),
            ],
        };
        // Per-mint checks (4 <= 5) and total checks (9 <= 10) alone pass,
        // but A+B both depend on X, whose shared capacity is only 5.
        assert_eq!(caps.remaining(&a), 5);
        assert!(caps
            .check_reservations([lock(a, 4), lock(b, 4), lock(c, 1)].into_iter())
            .is_err());
        assert!(caps
            .check_reservations([lock(a, 2), lock(b, 3), lock(c, 5)].into_iter())
            .is_ok());
    }

    #[test]
    fn residual_paths_reassign_earlier_reservations_to_fit_a_constrained_mint() {
        let a = [1; 32];
        let b = [2; 32];
        let x = [3; 32];
        let y = [4; 32];
        let caps = TokenCapacity {
            budgets: vec![
                budget(WILDCARD, Some(x), 5, 5),
                budget(WILDCARD, Some(y), 5, 5),
                budget(b, Some(y), 0, 0),
            ],
        };
        // A initially takes X. The residual path must move A to Y so B fits X.
        assert!(caps
            .check_reservations([lock(a, 5), lock(b, 5)].into_iter())
            .is_ok());
    }

    #[test]
    fn capacity_flow_matches_exhaustive_small_allocation_search() {
        let a = [1; 32];
        let b = [2; 32];
        let x = [3; 32];
        let y = [4; 32];
        for ax in 0..=2 {
            for ay in 0..=2 {
                for bx in 0..=2 {
                    for by in 0..=2 {
                        let caps = TokenCapacity {
                            budgets: vec![
                                budget(WILDCARD, Some(x), 2, 2),
                                budget(WILDCARD, Some(y), 2, 2),
                                budget(a, Some(x), ax, ax),
                                budget(a, Some(y), ay, ay),
                                budget(b, Some(x), bx, bx),
                                budget(b, Some(y), by, by),
                            ],
                        };
                        for ra in 0u64..=3 {
                            for rb in 0u64..=3 {
                                let possible = (0..=ra).any(|a_x| {
                                    (0..=rb).any(|b_x| {
                                        a_x <= ax
                                            && ra - a_x <= ay
                                            && b_x <= bx
                                            && rb - b_x <= by
                                            && a_x + b_x <= 2
                                            && (ra - a_x) + (rb - b_x) <= 2
                                    })
                                });
                                let actual = caps
                                    .check_reservations([lock(a, ra), lock(b, rb)].into_iter())
                                    .is_ok();
                                assert_eq!(
                                    actual, possible,
                                    "edges {ax}/{ay}/{bx}/{by}, locks {ra}/{rb}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
