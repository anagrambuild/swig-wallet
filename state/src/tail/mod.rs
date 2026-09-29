//! Swig account "tail": optional, discriminated data appended after the roles.
//!
//! Layout of a swig account:
//!
//! ```text
//! [ Swig header (48 B) ][ roles_data (N B) ][ optional tail ]
//! ```
//!
//! The tail is detected purely by account length (see
//! [`crate::swig::Swig::roles_end_offset`]); no header field is used, so wallets
//! that never opt in are byte-for-byte unchanged.
//!
//! Each tail entry is a length-prefixed, versioned, **typed** TLV record:
//!
//! ```text
//! offset 0: kind       u8      kind of data (see TailKind)
//! offset 1: version    u8
//! offset 2: value_len  u16     length of `value`
//! offset 4: reserved   u8;4    zero
//! offset 8: value      [u8; value_len]
//! ```
//!
//! The 8-byte typed header is what makes the tail extensible: a new tail feature
//! (e.g. an auth lock) gets its own [`TailKind`] and a sibling module here, with
//! no changes to `swig.rs`.

pub mod active_sub_account_count;
pub mod rent_claimer;

use crate::SwigStateError;
use core::convert::TryInto;
use pinocchio::program_error::ProgramError;

/// Length of every tail entry header: `[kind][version][value_len:u16][reserved:u8;4]`.
pub const TAIL_HEADER_LEN: usize = 8;

/// Structured view of the 8-byte header common to each tail entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TailHeader {
    pub kind: u8,
    pub version: u8,
    pub value_len: u16,
    pub payload: [u8; 4],
}

impl TailHeader {
    /// Parses a header from the beginning of `bytes`.
    pub fn parse(bytes: &[u8]) -> Result<Self, TailReadError> {
        if bytes.len() < TAIL_HEADER_LEN {
            return Err(TailReadError::TooShort);
        }

        let value_len_bytes: [u8; 2] = bytes[2..4]
            .try_into()
            .map_err(|_| TailReadError::TooShort)?;
        let payload: [u8; 4] = bytes[4..8]
            .try_into()
            .map_err(|_| TailReadError::TooShort)?;

        Ok(Self {
            kind: bytes[0],
            version: bytes[1],
            value_len: u16::from_le_bytes(value_len_bytes),
            payload,
        })
    }

    /// Total bytes consumed by this entry: header + value bytes.
    pub fn total_len(&self) -> Result<usize, TailReadError> {
        TAIL_HEADER_LEN
            .checked_add(self.value_len as usize)
            .ok_or(TailReadError::LengthOverflow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailReadError {
    TooShort,
    UnknownKind(u8),
    LengthOverflow,
    InvalidKind { expected: u8, found: u8 },
    InvalidValueLen { expected: usize, found: usize },
}

impl From<TailReadError> for ProgramError {
    fn from(_: TailReadError) -> Self {
        SwigStateError::InvalidRentClaimerLayout.into()
    }
}

/// Shared parsing behavior for concrete typed tail descriptors.
pub trait TailDescriptor<'a>: Sized {
    const KIND: TailKind;

    /// Build a concrete typed entry from a parsed header and its value bytes.
    fn from_parts(header: TailHeader, value: &'a [u8]) -> Result<Self, TailReadError>;

    /// Reads a descriptor that starts at `buf[0]`.
    fn read(buf: &'a [u8]) -> Result<(Self, usize), TailReadError> {
        let header = TailHeader::parse(buf)?;
        let found = header.kind;
        let expected = Self::KIND as u8;
        if found != expected {
            return Err(TailReadError::InvalidKind { expected, found });
        }

        let end = header.total_len()?;
        if buf.len() < end {
            return Err(TailReadError::TooShort);
        }
        let value = &buf[TAIL_HEADER_LEN..end];

        Ok((Self::from_parts(header, value)?, end))
    }
}

/// A raw tail entry for kinds not yet modeled in code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownTailEntry<'a> {
    pub header: TailHeader,
    pub value: &'a [u8],
}

/// A parsed tail entry, dispatching to known concrete types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnyTailEntry<'a> {
    ActiveSubAccountCount(active_sub_account_count::ActiveSubAccountCountEntry<'a>),
    RentClaimer(rent_claimer::RentClaimerEntry<'a>),
    Unknown(UnknownTailEntry<'a>),
}

impl<'a> AnyTailEntry<'a> {
    /// Reads the first entry from `buf`.
    pub fn read(buf: &'a [u8]) -> Result<(Self, usize), TailReadError> {
        let header = TailHeader::parse(buf)?;
        match TailKind::from_u8(header.kind) {
            Some(TailKind::ActiveSubAccountCount) => {
                let (entry, consumed) =
                    active_sub_account_count::ActiveSubAccountCountEntry::read(buf)?;
                Ok((Self::ActiveSubAccountCount(entry), consumed))
            },
            Some(TailKind::RentClaimer) => {
                let (entry, consumed) = rent_claimer::RentClaimerEntry::read(buf)?;
                Ok((Self::RentClaimer(entry), consumed))
            },
            None => {
                let end = header.total_len()?;
                if buf.len() < end {
                    return Err(TailReadError::TooShort);
                }
                Ok((
                    Self::Unknown(UnknownTailEntry {
                        header,
                        value: &buf[TAIL_HEADER_LEN..end],
                    }),
                    end,
                ))
            },
        }
    }

    /// Parses every contiguous tail entry in `buf`.
    pub fn read_all(mut buf: &'a [u8]) -> Result<Vec<Self>, TailReadError> {
        let mut entries = Vec::new();
        while !buf.is_empty() {
            let (entry, consumed) = Self::read(buf)?;
            entries.push(entry);
            buf = &buf[consumed..];
        }
        Ok(entries)
    }
}

/// Scans a heterogenous tail buffer and returns the first entry of descriptor type `T`.
pub fn read_first_of<'a, T: TailDescriptor<'a>>(
    mut buf: &'a [u8],
) -> Result<Option<T>, TailReadError> {
    while !buf.is_empty() {
        let header = TailHeader::parse(buf)?;
        // Skip by full entry size: header bytes + value bytes.
        let entry_len = header.total_len()?;
        if buf.len() < entry_len {
            return Err(TailReadError::TooShort);
        }

        if header.kind == T::KIND.as_u8() {
            let (typed, _) = T::read(buf)?;
            return Ok(Some(typed));
        }

        buf = &buf[entry_len..];
    }
    Ok(None)
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailKind {
    /// A single immutable rent-claimer pubkey ([`rent_claimer`]).
    RentClaimer = 1,
    /// Number of live V1 and V2 sub-accounts.
    ActiveSubAccountCount = 2,
}

impl TailKind {
    /// Parses a kind byte, or `None` for an unknown kind.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            x if x == TailKind::RentClaimer as u8 => Some(TailKind::RentClaimer),
            x if x == TailKind::ActiveSubAccountCount as u8 => {
                Some(TailKind::ActiveSubAccountCount)
            },
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The largest tail any current tail type can produce. Used to allocate a scratch buffer for realloc handlers.
pub const MAX_TAIL_LEN: usize = rent_claimer::ENTRY_LEN + active_sub_account_count::ENTRY_LEN;

/// Validates the complete tail. Each known kind may occur at most once;
/// unknown kinds, malformed versions, and non-zero reserved bytes fail closed.
pub fn validate_strict(mut tail_data: &[u8]) -> Result<(), ProgramError> {
    let mut seen_rent_claimer = false;
    let mut seen_active_count = false;

    while !tail_data.is_empty() {
        let (entry, consumed) = AnyTailEntry::read(tail_data)?;
        match entry {
            AnyTailEntry::RentClaimer(entry) => {
                if seen_rent_claimer
                    || entry.header.version != rent_claimer::VERSION
                    || entry.header.payload != [0u8; 4]
                {
                    return Err(SwigStateError::InvalidRentClaimerLayout.into());
                }
                seen_rent_claimer = true;
            },
            AnyTailEntry::ActiveSubAccountCount(entry) => {
                if seen_active_count
                    || entry.header.version != active_sub_account_count::VERSION
                    || entry.header.payload != [0u8; 4]
                    || !entry.reserved_is_zero()
                {
                    return Err(SwigStateError::InvalidRentClaimerLayout.into());
                }
                seen_active_count = true;
            },
            AnyTailEntry::Unknown(_) => {
                return Err(SwigStateError::InvalidRentClaimerLayout.into());
            },
        }
        tail_data = &tail_data[consumed..];
    }
    Ok(())
}

/// A stack copy of the account tail, captured before a roles realloc so it can
/// be restored afterwards. Used to store the tail before and after a roles realloc.
pub struct SavedTail {
    bytes: [u8; MAX_TAIL_LEN],
    len: usize, // actual length of the tail
}

impl SavedTail {
    /// Copies the tail (the bytes after `roles_end`) onto the stack.
    pub fn take(tail_data: &[u8]) -> Result<Self, ProgramError> {
        validate_strict(tail_data)?;
        let len = tail_data.len();
        let mut bytes = [0u8; MAX_TAIL_LEN];
        bytes[..len].copy_from_slice(tail_data);
        Ok(Self { bytes, len })
    }

    /// Length of the captured tail (`0` when the wallet has no tail).
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no tail was captured.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Writes the saved tail at `offset`.
    pub fn restore_at(&self, account_data: &mut [u8], offset: usize) -> Result<(), ProgramError> {
        if self.len == 0 {
            return Ok(()); // no-op when there was no tail
        }
        let end = offset
            .checked_add(self.len)
            .ok_or(ProgramError::InvalidAccountData)?;
        if end > account_data.len() {
            return Err(ProgramError::InvalidAccountData);
        }
        account_data[offset..end].copy_from_slice(&self.bytes[..self.len]); // write the tail back
        Ok(())
    }

    /// Writes the saved tail back at the very end of the (already-resized) account buffer.
    pub fn restore(&self, account_data: &mut [u8]) -> Result<(), ProgramError> {
        let offset = account_data
            .len()
            .checked_sub(self.len)
            .ok_or(ProgramError::InvalidAccountData)?;
        self.restore_at(account_data, offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tail::{
        active_sub_account_count,
        rent_claimer::{self, ENTRY_LEN},
    };

    fn assert_invalid_layout(tail: &[u8]) {
        match SavedTail::take(tail) {
            Ok(_) => panic!("malformed tail must be rejected"),
            Err(err) => assert_eq!(
                err,
                ProgramError::Custom(SwigStateError::InvalidRentClaimerLayout as u32)
            ),
        }
    }

    #[test]
    fn take_accepts_empty_tail() {
        let saved = SavedTail::take(&[]).expect("empty tail is valid");
        assert_eq!(saved.len(), 0);
        assert!(saved.is_empty());

        // Restoring a no-tail save is a no-op and leaves the buffer untouched.
        let mut account = vec![7u8; 16];
        saved.restore(&mut account).expect("restore no-op");
        assert_eq!(account, vec![7u8; 16]);
    }

    #[test]
    fn take_accepts_single_entry_and_round_trips() {
        let claimer = [123u8; 32];
        let tail = rent_claimer::entry(&claimer);

        let saved = SavedTail::take(&tail).expect("single entry is valid");
        assert_eq!(saved.len(), ENTRY_LEN);
        assert!(!saved.is_empty());

        // restore_at writes the saved bytes back byte-for-byte.
        let mut account = vec![0u8; 4 + ENTRY_LEN];
        saved.restore_at(&mut account, 4).expect("restore_at");
        assert_eq!(&account[4..], tail.as_slice());

        // restore places the tail at the very end of the buffer.
        let mut account = vec![0u8; 8 + ENTRY_LEN];
        saved.restore(&mut account).expect("restore");
        assert_eq!(&account[8..], tail.as_slice());
    }

    #[test]
    fn take_accepts_both_known_entries_in_either_order() {
        let claimer = [123u8; 32];
        let rent_entry = rent_claimer::entry(&claimer);
        let count_entry = active_sub_account_count::entry(7);

        for tail in [
            [rent_entry.as_slice(), count_entry.as_slice()].concat(),
            [count_entry.as_slice(), rent_entry.as_slice()].concat(),
        ] {
            let saved = SavedTail::take(&tail).expect("both known entries are valid");
            assert_eq!(saved.len(), MAX_TAIL_LEN);

            let mut account = vec![0u8; 8 + MAX_TAIL_LEN];
            saved.restore(&mut account).expect("restore");
            assert_eq!(&account[8..], tail.as_slice());
        }
    }

    #[test]
    fn take_rejects_non_empty_all_zero_tail() {
        for len in [1usize, 8, 39, 40] {
            assert_invalid_layout(&vec![0u8; len]);
        }
    }

    #[test]
    fn take_rejects_entry_with_trailing_padding() {
        let tail = rent_claimer::entry(&[9u8; 32]);
        for pad in 1usize..=4 {
            let mut padded = tail.to_vec();
            padded.extend_from_slice(&vec![0u8; pad]);
            assert_invalid_layout(&padded);
        }
    }

    #[test]
    fn take_rejects_truncated_entry() {
        let mut tail = rent_claimer::entry(&[5u8; 32]).to_vec();
        tail.pop();
        assert_invalid_layout(&tail);
    }

    #[test]
    fn take_rejects_two_entries() {
        let mut tail = rent_claimer::entry(&[1u8; 32]).to_vec();
        tail.extend_from_slice(&rent_claimer::entry(&[2u8; 32]));
        assert_invalid_layout(&tail);
    }

    #[test]
    fn take_rejects_duplicate_active_count_entries() {
        let mut tail = active_sub_account_count::entry(1).to_vec();
        tail.extend_from_slice(&active_sub_account_count::entry(2));
        assert_invalid_layout(&tail);
    }
}
