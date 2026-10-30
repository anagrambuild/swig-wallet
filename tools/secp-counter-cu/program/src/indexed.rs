//! Benchmark-only alternatives: collect replay metadata during the account-layout walk.
use std::collections::BTreeMap;

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
};
use swig_state::{
    authority::counter::SecpCounter, role::Position, swig::Swig, SwigAuthenticateError,
    Transmutable,
};

#[derive(Default)]
struct Group {
    highest: u32,
    positions: Vec<u32>,
}

struct CounterPosition {
    position: u32,
    curve: u16,
}

fn curve(kind: u16) -> Option<u16> {
    match kind {
        3 | 4 => Some(3),
        5 | 6 => Some(5),
        _ => None,
    }
}

pub fn authenticate_indexed<const GROUPED: bool>(
    data: &mut [u8],
    role_id: u32,
    accounts: &[AccountInfo],
    authority_payload: &[u8],
    create_session: bool,
) -> Result<(), ProgramError> {
    if data.len() < Swig::LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let count = u16::from_le_bytes(data[34..36].try_into().unwrap()) as usize;
    let roles_and_tail = &mut data[Swig::LEN..];
    let mut groups: BTreeMap<(u16, [u8; 33]), Group> = BTreeMap::new();
    let mut entries: Vec<CounterPosition> = Vec::new();
    let mut selected = None;
    let mut cursor = 0;

    // One full role walk: find the selected role, locate the tail, and collect counters.
    for _ in 0..count {
        let pos_end = cursor + Position::LEN;
        let bytes = roles_and_tail
            .get(cursor..pos_end)
            .ok_or(ProgramError::InvalidAccountData)?;
        let position = unsafe { (bytes.as_ptr() as *const Position).read_unaligned() };
        let boundary = position.boundary as usize;
        if boundary < pos_end || boundary > roles_and_tail.len() {
            return Err(ProgramError::InvalidAccountData);
        }
        if position.id == role_id && selected.is_none() {
            selected = Some(cursor);
        }
        if let Some(curve) = curve(position.authority_type) {
            let len = position.authority_length as usize;
            if len < 40 || pos_end + len > boundary {
                return Err(ProgramError::InvalidAccountData);
            }
            if GROUPED {
                let key: [u8; 33] = roles_and_tail[pos_end..pos_end + 33].try_into().unwrap();
                let counter = u32::from_le_bytes(
                    roles_and_tail[pos_end + 36..pos_end + 40]
                        .try_into()
                        .unwrap(),
                );
                let group = groups.entry((curve, key)).or_default();
                group.highest = group.highest.max(counter);
                group.positions.push(cursor as u32);
            } else {
                // Allocate once; the bump allocator cannot reclaim Vec growth allocations.
                if entries.capacity() == 0 {
                    entries.reserve_exact(count);
                }
                entries.push(CounterPosition {
                    position: cursor as u32,
                    curve,
                });
            }
        }
        cursor = boundary;
    }

    let selected = selected.ok_or(ProgramError::InvalidAccountData)?;
    let roles = &mut roles_and_tail[..cursor];
    let slot = Clock::get()?.slot;
    let consumed = {
        let role = Swig::get_mut_role_at(selected, roles)?;
        if create_session && !role.authority.session_based() {
            return Err(SwigAuthenticateError::AuthorityDoesNotSupportSessionBasedAuth.into());
        }
        if role.authority.session_based() && !create_session {
            role.authority.authenticate_session(
                accounts,
                authority_payload,
                b"counter-cu",
                slot,
            )?;
            None
        } else {
            role.authority
                .authenticate(accounts, authority_payload, b"counter-cu", slot)?;
            SecpCounter::from_role(&role)?
        }
    };

    if let Some(counter) = consumed {
        let selected_curve = curve(counter.authority_type as u16).unwrap();
        if GROUPED {
            let group = groups.get(&(selected_curve, counter.public_key)).unwrap();
            let next = group.highest.wrapping_add(1).to_le_bytes();
            for position in &group.positions {
                let start = *position as usize + Position::LEN + 36;
                roles[start..start + 4].copy_from_slice(&next);
            }
        } else {
            let mut highest = counter.counter.wrapping_sub(1);
            entries.retain(|entry| {
                if entry.curve != selected_curve {
                    return false;
                }
                let start = entry.position as usize + Position::LEN;
                let key = &roles[start..start + 33];
                if key[1..9] != counter.public_key[1..9] || key != counter.public_key {
                    return false;
                }
                if entry.position as usize != selected {
                    highest = highest.max(u32::from_le_bytes(
                        roles[start + 36..start + 40].try_into().unwrap(),
                    ));
                }
                true
            });
            let next = highest.wrapping_add(1).to_le_bytes();
            for entry in &entries {
                let start = entry.position as usize + Position::LEN + 36;
                roles[start..start + 4].copy_from_slice(&next);
            }
        }
    }
    // Match the production helper's final role reload.
    Swig::get_mut_role_at(selected, roles)?;
    Ok(())
}
