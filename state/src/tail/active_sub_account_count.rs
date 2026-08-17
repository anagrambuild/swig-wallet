//! Active sub-account count tail entry.
//!
//! The Swig header's `sub_account_counter` remains a monotonic V2 ID allocator.
//! This independent count tracks live V1 and V2 children so the parent cannot
//! be tombstoned while a child still depends on it.

use core::convert::TryInto;

use pinocchio::program_error::ProgramError;

use crate::{
    action::{sub_account::SubAccount, Action, Permission},
    role::Position,
    swig::Swig,
    tail::{read_first_of, TailDescriptor, TailHeader, TailKind, TailReadError, TAIL_HEADER_LEN},
    Transmutable,
};

pub const VERSION: u8 = 1;
// Keep the value and the complete entry 8-byte aligned. The second word is
// reserved for future use and must remain zero.
pub const VALUE_LEN: usize = 8;
pub const ENTRY_LEN: usize = TAIL_HEADER_LEN + VALUE_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveSubAccountCountEntry<'a> {
    pub header: TailHeader,
    value: &'a [u8; VALUE_LEN],
}

impl ActiveSubAccountCountEntry<'_> {
    pub fn count(&self) -> u32 {
        u32::from_le_bytes(self.value[..4].try_into().expect("fixed-size count"))
    }

    pub fn reserved_is_zero(&self) -> bool {
        self.value[4..] == [0u8; 4]
    }
}

impl<'a> TailDescriptor<'a> for ActiveSubAccountCountEntry<'a> {
    const KIND: TailKind = TailKind::ActiveSubAccountCount;

    fn from_parts(header: TailHeader, value: &'a [u8]) -> Result<Self, TailReadError> {
        let value = value
            .try_into()
            .map_err(|_| TailReadError::InvalidValueLen {
                expected: VALUE_LEN,
                found: value.len(),
            })?;
        Ok(Self { header, value })
    }
}

pub fn read(tail_data: &[u8]) -> Result<Option<u32>, ProgramError> {
    Ok(read_first_of::<ActiveSubAccountCountEntry<'_>>(tail_data)?.map(|entry| entry.count()))
}

pub fn write(tail_data: &mut [u8], count: u32) -> Result<bool, ProgramError> {
    let mut offset = 0usize;
    while offset < tail_data.len() {
        let header = TailHeader::parse(&tail_data[offset..])?;
        let entry_len = header.total_len()?;
        let end = offset
            .checked_add(entry_len)
            .ok_or(ProgramError::InvalidAccountData)?;
        if end > tail_data.len() {
            return Err(ProgramError::InvalidAccountData);
        }
        if header.kind == TailKind::ActiveSubAccountCount.as_u8() {
            tail_data[offset + TAIL_HEADER_LEN..offset + TAIL_HEADER_LEN + 4]
                .copy_from_slice(&count.to_le_bytes());
            return Ok(true);
        }
        offset = end;
    }
    Ok(false)
}

pub fn entry(count: u32) -> [u8; ENTRY_LEN] {
    let mut buf = [0u8; ENTRY_LEN];
    buf[0] = TailKind::ActiveSubAccountCount.as_u8();
    buf[1] = VERSION;
    buf[2..4].copy_from_slice(&(VALUE_LEN as u16).to_le_bytes());
    buf[TAIL_HEADER_LEN..TAIL_HEADER_LEN + 4].copy_from_slice(&count.to_le_bytes());
    buf
}

/// Computes the active-child count for a wallet created before the count tail
/// existed. The program layer supplies the number of allocated V2 ids only
/// after it has established that the parent uses the V2 header. V1 children
/// are represented by populated, non-tombstoned actions in either generation.
pub fn legacy_count(
    swig: &Swig,
    roles: &[u8],
    allocated_v2_count: u32,
) -> Result<u32, ProgramError> {
    let mut count = allocated_v2_count;
    let mut role_cursor = 0usize;

    for _ in 0..swig.roles {
        let position_end = role_cursor
            .checked_add(Position::LEN)
            .ok_or(ProgramError::InvalidAccountData)?;
        if position_end > roles.len() {
            return Err(ProgramError::InvalidAccountData);
        }
        let position = unsafe { Position::load_unchecked(&roles[role_cursor..position_end])? };
        let role_end = position.boundary() as usize;
        let actions_start = position_end
            .checked_add(position.authority_length() as usize)
            .ok_or(ProgramError::InvalidAccountData)?;
        if actions_start > role_end || role_end > roles.len() {
            return Err(ProgramError::InvalidAccountData);
        }

        let actions = &roles[actions_start..role_end];
        let mut action_cursor = 0usize;
        while action_cursor < actions.len() {
            let header_end = action_cursor
                .checked_add(Action::LEN)
                .ok_or(ProgramError::InvalidAccountData)?;
            if header_end > actions.len() {
                return Err(ProgramError::InvalidAccountData);
            }
            let header = unsafe { Action::load_unchecked(&actions[action_cursor..header_end])? };
            let data_end = header_end
                .checked_add(header.length() as usize)
                .ok_or(ProgramError::InvalidAccountData)?;
            if data_end > actions.len() {
                return Err(ProgramError::InvalidAccountData);
            }
            if header.permission()? == Permission::SubAccount {
                if header.length() as usize != SubAccount::LEN {
                    return Err(ProgramError::InvalidAccountData);
                }
                let child = unsafe { SubAccount::load_unchecked(&actions[header_end..data_end])? };
                if child.sub_account != [0u8; 32] {
                    count = count
                        .checked_add(1)
                        .ok_or(ProgramError::InvalidAccountData)?;
                }
            }
            action_cursor = data_end;
        }
        role_cursor = role_end;
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_round_trips() {
        let serialized = entry(42);
        assert_eq!(serialized.len(), ENTRY_LEN);
        assert_eq!(read(&serialized).unwrap(), Some(42));
        let parsed = read_first_of::<ActiveSubAccountCountEntry<'_>>(&serialized)
            .unwrap()
            .unwrap();
        assert!(parsed.reserved_is_zero());
    }

    #[test]
    fn write_updates_existing_entry() {
        let mut serialized = entry(1);
        assert!(write(&mut serialized, 7).unwrap());
        assert_eq!(read(&serialized).unwrap(), Some(7));
    }
}
