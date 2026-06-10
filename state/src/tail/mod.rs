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
//! no changes to `swig.rs`. v1 ships a single tail type — [`rent_claimer`].

pub mod rent_claimer;

use core::convert::TryInto;
use pinocchio::program_error::ProgramError;
use crate::SwigStateError;

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
    RentClaimer(rent_claimer::RentClaimerEntry<'a>),
    Unknown(UnknownTailEntry<'a>),
}

impl<'a> AnyTailEntry<'a> {
    /// Reads the first entry from `buf`.
    pub fn read(buf: &'a [u8]) -> Result<(Self, usize), TailReadError> {
        let header = TailHeader::parse(buf)?;
        match TailKind::from_u8(header.kind) {
            Some(TailKind::RentClaimer) => {
                let (entry, consumed) = rent_claimer::RentClaimerEntry::read(buf)?;
                Ok((Self::RentClaimer(entry), consumed))
            }
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
            }
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
}



impl TailKind {
    /// Parses a kind byte, or `None` for an unknown kind.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            x if x == TailKind::RentClaimer as u8 => Some(TailKind::RentClaimer),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The largest tail any current tail type can produce. Used to allocate a scratch buffer for realloc handlers.
pub const MAX_TAIL_LEN: usize = rent_claimer::ENTRY_LEN;

/// A stack copy of the account tail, captured before a roles realloc so it can
/// be restored afterwards. Used to store the tail before and after a roles realloc.
pub struct SavedTail {
    bytes: [u8; MAX_TAIL_LEN],
    len: usize,     // actual length of the tail
}

impl SavedTail {
    /// Copies the tail (the bytes after `roles_end`) onto the stack.
    pub fn take(tail_data: &[u8]) -> Result<Self, ProgramError> {
        let len = tail_data.len();
        if len > MAX_TAIL_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
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

    /// Writes the saved tail back at the very end of the (already-resized) account buffer.
    pub fn restore(&self, account_data: &mut [u8]) {
        if self.len == 0 {
            return;    // no-op when there was no tail
        }
        let end = account_data.len();
        account_data[end - self.len..end].copy_from_slice(&self.bytes[..self.len]); // write the tail back
    }
}
