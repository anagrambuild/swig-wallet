//! Immutable config PDA prefix. An absent entry means the original `swig`
//! prefix. The remaining seeds are always the header's `id` and `bump`;
//! reserved configs store their commitment in `id`.

use pinocchio::program_error::ProgramError;

use super::{read_first_of, TailDescriptor, TailHeader, TailKind, TailReadError, TAIL_HEADER_LEN};

pub const VERSION: u8 = 1;
pub const MAX_PREFIX_LEN: usize = 32;
pub const MAX_ENTRY_LEN: usize = TAIL_HEADER_LEN + MAX_PREFIX_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigSeedPrefixEntry<'a> {
    pub header: TailHeader,
    pub prefix: &'a [u8],
}

impl<'a> TailDescriptor<'a> for ConfigSeedPrefixEntry<'a> {
    const KIND: TailKind = TailKind::ConfigSeedPrefix;

    fn from_parts(header: TailHeader, value: &'a [u8]) -> Result<Self, TailReadError> {
        if value.is_empty() || value.len() > MAX_PREFIX_LEN {
            return Err(TailReadError::InvalidSeedPrefixLength(value.len()));
        }
        Ok(Self {
            header,
            prefix: value,
        })
    }
}

/// Validates the entire tail before selecting the stored prefix or the legacy
/// default. A malformed entry must never fall back to legacy signing seeds.
pub fn read(tail_data: &[u8]) -> Result<&[u8], ProgramError> {
    super::validate_strict(tail_data)?;
    Ok(read_first_of::<ConfigSeedPrefixEntry<'_>>(tail_data)?
        .map_or(b"swig".as_slice(), |entry| entry.prefix))
}

/// Writes an entry into its exact-sized destination, without padding.
pub fn write(buf: &mut [u8], prefix: &[u8]) -> Result<(), ProgramError> {
    if prefix.is_empty()
        || prefix.len() > MAX_PREFIX_LEN
        || buf.len() != TAIL_HEADER_LEN + prefix.len()
    {
        return Err(crate::SwigStateError::InvalidSeedPrefix.into());
    }
    buf.fill(0);
    buf[0] = TailKind::ConfigSeedPrefix.as_u8();
    buf[1] = VERSION;
    buf[2..4].copy_from_slice(&(prefix.len() as u16).to_le_bytes());
    buf[TAIL_HEADER_LEN..].copy_from_slice(prefix);
    Ok(())
}
