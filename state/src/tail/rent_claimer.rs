//! Rent-claimer tail entry: a single immutable pubkey that close instructions
//! must route rent to. See [`crate::tail`] for the tail framework.

use core::convert::TryInto;

use pinocchio::program_error::ProgramError;

use crate::{
    tail::{read_first_of, TailDescriptor, TailHeader, TailKind, TailReadError, TAIL_HEADER_LEN},
    SwigStateError,
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

/// Strict parser for the swig trailing region.
///
/// Accepted layouts:
/// - empty tail (unset): `[]`
/// - all-zero tail bytes (unset)
/// - one rent-claimer entry (`ENTRY_LEN` bytes), optionally followed by zero padding
///
/// Any other shape or malformed header is rejected.
pub fn read_strict(tail_data: &[u8]) -> Result<Option<&[u8; 32]>, ProgramError> {
    if tail_data.is_empty() || tail_data.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    if tail_data.len() < ENTRY_LEN {
        return Err(SwigStateError::InvalidRentClaimerLayout.into());
    }

    let (entry, consumed) = RentClaimerEntry::read(&tail_data[..ENTRY_LEN])?;
    if consumed != ENTRY_LEN {
        return Err(SwigStateError::InvalidRentClaimerLayout.into());
    }
    if entry.header.version != VERSION {
        return Err(SwigStateError::InvalidRentClaimerLayout.into());
    }
    if entry.header.payload != [0u8; 4] {
        return Err(SwigStateError::InvalidRentClaimerLayout.into());
    }
    if tail_data[ENTRY_LEN..].iter().any(|byte| *byte != 0) {
        return Err(SwigStateError::InvalidRentClaimerLayout.into());
    }

    Ok(Some(entry.claimer))
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
    fn read_strict_returns_none_for_empty_tail() {
        let parsed = read_strict(&[]).expect("empty buffer should parse");
        assert!(parsed.is_none());
    }

    #[test]
    fn read_returns_claimer_for_single_rent_entry() {
        let claimer = [11u8; VALUE_LEN];
        let tail = entry(&claimer);

        let parsed = read(&tail).expect("rent entry should parse");
        assert_eq!(parsed, Some(&claimer));

        let strict = read_strict(&tail).expect("strict read should parse");
        assert_eq!(strict, Some(&claimer));
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
    fn read_strict_rejects_newer_rent_version() {
        let claimer = [33u8; VALUE_LEN];
        let mut tail = entry(&claimer);
        tail[1] = VERSION + 1;

        let err = read_strict(&tail).expect_err("strict parser rejects unknown version");
        assert_eq!(
            err,
            ProgramError::Custom(SwigStateError::InvalidRentClaimerLayout as u32)
        );
    }

    #[test]
    fn read_strict_rejects_non_zero_reserved_bytes() {
        let claimer = [88u8; VALUE_LEN];
        let mut tail = entry(&claimer);
        tail[4] = 1;

        let err = read_strict(&tail).expect_err("strict parser rejects non-zero reserved bytes");
        assert_eq!(
            err,
            ProgramError::Custom(SwigStateError::InvalidRentClaimerLayout as u32)
        );
    }

    #[test]
    fn read_strict_rejects_tail_len_other_than_empty_or_single_entry() {
        let claimer = [99u8; VALUE_LEN];
        let mut tail = Vec::new();
        tail.extend_from_slice(&entry(&claimer));
        tail.extend_from_slice(&entry(&claimer));

        let err = read_strict(&tail).expect_err("strict parser rejects extra entries");
        assert_eq!(
            err,
            ProgramError::Custom(SwigStateError::InvalidRentClaimerLayout as u32)
        );
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

    fn assert_invalid_layout(tail: &[u8]) {
        let err = read_strict(tail).expect_err("strict parser must reject malformed tail");
        assert_eq!(
            err,
            ProgramError::Custom(SwigStateError::InvalidRentClaimerLayout as u32)
        );
    }

    #[test]
    fn read_strict_rejects_wrong_kind_byte() {
        // Correct overall length (ENTRY_LEN) but the kind byte is not RentClaimer.
        let claimer = [5u8; VALUE_LEN];
        let mut tail = entry(&claimer);
        tail[0] = TailKind::RentClaimer.as_u8() + 1;
        assert_invalid_layout(&tail);
    }

    #[test]
    fn read_strict_rejects_zero_kind_byte() {
        let claimer = [6u8; VALUE_LEN];
        let mut tail = entry(&claimer);
        tail[0] = 0;
        assert_invalid_layout(&tail);
    }

    #[test]
    fn read_strict_rejects_inconsistent_value_len_field() {
        // Buffer is ENTRY_LEN long, but the header claims a value_len other than 32.
        for bad_value_len in [0u16, 1, 16, 31, 33, 64, u16::MAX] {
            let claimer = [9u8; VALUE_LEN];
            let mut tail = entry(&claimer);
            tail[2..4].copy_from_slice(&bad_value_len.to_le_bytes());
            assert_invalid_layout(&tail);
        }
    }

    #[test]
    fn read_strict_accepts_entry_with_trailing_zero_padding() {
        let claimer = [101u8; VALUE_LEN];
        for pad in 1usize..=7 {
            let mut tail = entry(&claimer).to_vec();
            tail.extend_from_slice(&vec![0u8; pad]);
            let parsed = read_strict(&tail).expect("entry + zero padding should parse");
            assert_eq!(parsed, Some(&claimer));
        }
    }

    #[test]
    fn read_strict_accepts_non_empty_all_zero_tail_as_unset() {
        for len in [1usize, 7, 8, 16, 32, 39, 41, 48, 72, 80, 120] {
            let tail = vec![0u8; len];
            let parsed = read_strict(&tail).expect("all-zero tail should parse as unset");
            assert_eq!(parsed, None);
        }
    }

    #[test]
    fn read_strict_rejects_entry_with_non_zero_trailing_bytes() {
        let claimer = [102u8; VALUE_LEN];
        let mut tail = entry(&claimer).to_vec();
        tail.extend_from_slice(&[0, 0, 7, 0]);
        assert_invalid_layout(&tail);
    }

    #[test]
    fn read_strict_rejects_each_individually_nonzero_reserved_byte() {
        for reserved_index in 4..TAIL_HEADER_LEN {
            let claimer = [12u8; VALUE_LEN];
            let mut tail = entry(&claimer);
            tail[reserved_index] = 1;
            assert_invalid_layout(&tail);
        }
    }

    #[test]
    fn read_strict_accepts_exactly_one_well_formed_entry() {
        let claimer = [200u8; VALUE_LEN];
        let tail = entry(&claimer);
        let parsed = read_strict(&tail).expect("well-formed single entry must parse");
        assert_eq!(parsed, Some(&claimer));
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
