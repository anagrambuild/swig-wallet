//! Rent-claimer tail entry: a single immutable pubkey that close instructions
//! must route rent to. See [`crate::tail`] for the tail framework.

use core::convert::TryInto;

use pinocchio::program_error::ProgramError;

use crate::{
    tail::{read_first_of, TailDescriptor, TailHeader, TailKind, TailReadError, TAIL_HEADER_LEN},
};

pub const VERSION: u8 = 1;
pub const VALUE_LEN: usize = 32;
pub const ENTRY_LEN: usize = TAIL_HEADER_LEN + VALUE_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RentClaimerEntry<'a> {
    pub header: TailHeader,
    pub claimer: &'a [u8; VALUE_LEN],
}

impl<'a> TailDescriptor<'a> for RentClaimerEntry<'a> {
    const KIND: TailKind = TailKind::RentClaimer;

    fn from_parts(header: TailHeader, value: &'a [u8]) -> Result<Self, TailReadError> {
        if value.len() != VALUE_LEN {
            return Err(TailReadError::InvalidValueLen {
                expected: VALUE_LEN,
                found: value.len(),
            });
        }

        let claimer: &[u8; VALUE_LEN] = value
            .try_into()
            .map_err(|_| TailReadError::InvalidValueLen {
                expected: VALUE_LEN,
                found: value.len(),
            })?;
        Ok(Self { header, claimer })
    }
}


/// Reads through the tail data of different tail types until it finds a rent-claimer tail entry.
pub fn read(tail_data: &[u8]) -> Result<Option<&[u8; 32]>, ProgramError> {
    Ok(read_first_of::<RentClaimerEntry<'_>>(tail_data)?.map(|entry| entry.claimer))
}

/// Serializes a rent-claimer tail entry ready to append to the account buffer.
/// The single source of truth for the on-chain byte layout.
pub fn entry(claimer: &[u8; 32]) -> [u8; ENTRY_LEN] {
    let mut buf = [0u8; ENTRY_LEN];
    buf[0] = TailKind::RentClaimer.as_u8();
    buf[1] = VERSION;
    buf[2..4].copy_from_slice(&(VALUE_LEN as u16).to_le_bytes());
    // bytes [4..8] reserved, left zero.
    buf[TAIL_HEADER_LEN..].copy_from_slice(claimer);
    buf
}

#[cfg(test)]
mod tests {
    use pinocchio::program_error::ProgramError;

    use super::*;
    use crate::{tail::read_first_of, SwigStateError};

    fn unknown_entry(kind: u8, version: u8, value_fill: u8) -> [u8; ENTRY_LEN] {
        let mut buf = [0u8; ENTRY_LEN];
        buf[0] = kind;
        buf[1] = version;
        buf[2..4].copy_from_slice(&(VALUE_LEN as u16).to_le_bytes());
        buf[TAIL_HEADER_LEN..].fill(value_fill);
        buf
    }

    #[test]
    fn entry_serializes_expected_layout() {
        let claimer = [7u8; VALUE_LEN];
        let serialized = entry(&claimer);

        assert_eq!(serialized.len(), ENTRY_LEN);
        assert_eq!(serialized[0], TailKind::RentClaimer.as_u8());
        assert_eq!(serialized[1], VERSION);
        assert_eq!(
            serialized[2..4],
            (VALUE_LEN as u16).to_le_bytes(),
        );
        assert_eq!(serialized[4..8], [0u8; 4]);
        assert_eq!(serialized[TAIL_HEADER_LEN..], claimer);
    }

    #[test]
    fn read_returns_none_for_empty_tail() {
        let parsed = read(&[]).expect("empty buffer should parse");
        assert!(parsed.is_none());
    }

    #[test]
    fn read_returns_claimer_for_single_rent_entry() {
        let claimer = [11u8; VALUE_LEN];
        let tail = entry(&claimer);

        let parsed = read(&tail).expect("rent entry should parse");
        assert_eq!(parsed, Some(&claimer));
    }

    #[test]
    fn read_skips_unknown_kind_and_finds_rent_entry() {
        let mut tail = Vec::new();
        // Unknown kind, version 1, value_len 4, reserved 4 bytes.
        tail.extend_from_slice(&[99u8, 1, 4, 0, 0, 0, 0, 0]);
        tail.extend_from_slice(&[1, 2, 3, 4]);

        let claimer = [21u8; VALUE_LEN];
        tail.extend_from_slice(&entry(&claimer));

        let parsed = read(&tail).expect("mixed tail should parse");
        assert_eq!(parsed, Some(&claimer));
    }

    #[test]
    fn read_does_not_reject_newer_rent_version() {
        let claimer = [33u8; VALUE_LEN];
        let mut tail = entry(&claimer);
        tail[1] = VERSION + 1;

        let parsed = read(&tail).expect("version is informational");
        assert_eq!(parsed, Some(&claimer));
    }

    #[test]
    fn read_errors_on_truncated_rent_value() {
        let mut tail = entry(&[44u8; VALUE_LEN]).to_vec();
        tail.pop();

        let err = read(&tail).expect_err("truncated value must fail");
        assert_eq!(
            err,
            ProgramError::Custom(SwigStateError::InvalidRentClaimerLayout as u32)
        );
    }

    #[test]
    fn read_first_of_handles_120_byte_tail_with_rent_at_start() {
        let claimer = [55u8; VALUE_LEN];
        let mut tail = Vec::new();
        tail.extend_from_slice(&entry(&claimer));
        tail.extend_from_slice(&unknown_entry(99, 1, 9));
        tail.extend_from_slice(&unknown_entry(100, 2, 10));
        assert_eq!(tail.len(), 120);

        let parsed = read_first_of::<RentClaimerEntry<'_>>(&tail)
            .expect("valid mixed tail should parse")
            .expect("rent claimer must be present");

        assert_eq!(parsed.header.kind, TailKind::RentClaimer.as_u8());
        assert_eq!(parsed.header.version, VERSION);
        assert_eq!(parsed.header.value_len as usize, VALUE_LEN);
        assert_eq!(parsed.claimer, &claimer);

        let parsed_claimer = read(&tail).expect("read should succeed");
        assert_eq!(parsed_claimer, Some(&claimer));
    }

    #[test]
    fn read_first_of_handles_120_byte_tail_with_rent_in_middle() {
        let claimer = [77u8; VALUE_LEN];
        let mut tail = Vec::new();
        tail.extend_from_slice(&unknown_entry(90, 3, 4));
        tail.extend_from_slice(&entry(&claimer));
        tail.extend_from_slice(&unknown_entry(91, 4, 5));
        assert_eq!(tail.len(), 120);

        let parsed = read_first_of::<RentClaimerEntry<'_>>(&tail)
            .expect("valid mixed tail should parse")
            .expect("rent claimer must be present");

        assert_eq!(parsed.header.kind, TailKind::RentClaimer.as_u8());
        assert_eq!(parsed.header.version, VERSION);
        assert_eq!(parsed.header.value_len as usize, VALUE_LEN);
        assert_eq!(parsed.claimer, &claimer);

        let parsed_claimer = read(&tail).expect("read should succeed");
        assert_eq!(parsed_claimer, Some(&claimer));
    }
}
