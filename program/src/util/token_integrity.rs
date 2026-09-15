use core::ops::Range;

use pinocchio::{program_error::ProgramError, pubkey::Pubkey};

use super::hash_except;

const TOKEN_ACCOUNT_BASE_DATA_LEN: usize = pinocchio_token::state::TokenAccount::LEN;
const TOKEN_MULTISIG_LEN: usize = 355;
const TOKEN_2022_TYPE_ACCOUNT: u8 = 2;

// Token-2022 ExtensionType::TransferFeeAmount has wire discriminant 2.
const TRANSFER_FEE_AMOUNT_TYPE: u16 = 2;
const TRANSFER_FEE_AMOUNT_LEN: usize = 8;

/// Locate the one mutable fee payload before CPI. All other extension bytes
/// remain protected, including unknown extensions and TLV headers.
pub(crate) fn transfer_fee_amount_offset(
    data: &[u8],
    owner: &Pubkey,
) -> Result<Option<u16>, ProgramError> {
    if owner != &crate::SPL_TOKEN_2022_ID {
        return Ok(None);
    }
    if data.len() < TOKEN_ACCOUNT_BASE_DATA_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    if data.len() == TOKEN_ACCOUNT_BASE_DATA_LEN {
        return Ok(None);
    }
    if data.len() == TOKEN_MULTISIG_LEN
        || data[TOKEN_ACCOUNT_BASE_DATA_LEN] != TOKEN_2022_TYPE_ACCOUNT
    {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut cursor = TOKEN_ACCOUNT_BASE_DATA_LEN + 1;
    let mut fee_offset = None;
    while cursor < data.len() {
        let remaining = &data[cursor..];
        // Token-2022 permits unused allocation and end padding.
        if remaining.iter().all(|byte| *byte == 0) {
            break;
        }
        let header = remaining.get(..4).ok_or(ProgramError::InvalidAccountData)?;
        let extension_type = u16::from_le_bytes([header[0], header[1]]);
        if extension_type == 0 {
            return Err(ProgramError::InvalidAccountData);
        }
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        let value_start = cursor
            .checked_add(4)
            .ok_or(ProgramError::InvalidAccountData)?;
        let value_end = value_start
            .checked_add(length)
            .ok_or(ProgramError::InvalidAccountData)?;
        data.get(value_start..value_end)
            .ok_or(ProgramError::InvalidAccountData)?;

        if extension_type == TRANSFER_FEE_AMOUNT_TYPE {
            if length != TRANSFER_FEE_AMOUNT_LEN || fee_offset.is_some() {
                return Err(ProgramError::InvalidAccountData);
            }
            fee_offset =
                Some(u16::try_from(value_start).map_err(|_| ProgramError::InvalidAccountData)?);
        }
        cursor = value_end;
    }
    Ok(fee_offset)
}

/// Use the offset captured before CPI; never select exclusions from post-CPI
/// extension metadata. The offset is relative to the supplied data slice.
pub(crate) fn hash_with_transfer_fee(
    data: &[u8],
    owner: &Pubkey,
    base_exclusions: &[Range<usize>],
    fee_offset: Option<u16>,
) -> Result<[u8; 32], ProgramError> {
    let Some(offset) = fee_offset else {
        // Preserve the existing hash path when no fee exception was selected.
        return Ok(hash_except(data, owner, base_exclusions));
    };
    let start = usize::from(offset);
    let fee_range = start..start + TRANSFER_FEE_AMOUNT_LEN;
    // At most amount, native reserve, and one fee payload. No heap allocation.
    let mut exclusions = [0..0, 0..0, 0..0];
    let mut count = 0;
    let mut previous_end = 0;
    for range in base_exclusions.iter().chain(core::iter::once(&fee_range)) {
        if count == exclusions.len()
            || range.start < previous_end
            || range.start > range.end
            || range.end > data.len()
        {
            return Err(ProgramError::InvalidAccountData);
        }
        exclusions[count] = range.clone();
        previous_end = range.end;
        count += 1;
    }
    Ok(hash_except(data, owner, &exclusions[..count]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_account() -> Vec<u8> {
        let mut data = vec![0; TOKEN_ACCOUNT_BASE_DATA_LEN + 1];
        data[TOKEN_ACCOUNT_BASE_DATA_LEN] = TOKEN_2022_TYPE_ACCOUNT;
        data
    }

    fn append_extension(data: &mut Vec<u8>, extension_type: u16, value: &[u8]) {
        data.extend_from_slice(&extension_type.to_le_bytes());
        data.extend_from_slice(&(value.len() as u16).to_le_bytes());
        data.extend_from_slice(value);
    }

    #[test]
    fn locates_fee_after_another_extension_and_accepts_padding() {
        let mut data = token_account();
        append_extension(&mut data, 7, &[]); // ImmutableOwner
        append_extension(&mut data, TRANSFER_FEE_AMOUNT_TYPE, &13u64.to_le_bytes());
        data.extend_from_slice(&[0; 6]);
        assert_eq!(
            transfer_fee_amount_offset(&data, &crate::SPL_TOKEN_2022_ID),
            Ok(Some(174))
        );
        // Legacy Token gets no new exception.
        assert_eq!(
            transfer_fee_amount_offset(&data, &crate::SPL_TOKEN_ID),
            Ok(None)
        );
    }

    #[test]
    fn no_fee_extension_means_no_exception() {
        let mut data = token_account();
        append_extension(&mut data, 7, &[]);
        assert_eq!(
            transfer_fee_amount_offset(&data, &crate::SPL_TOKEN_2022_ID),
            Ok(None)
        );
    }

    #[test]
    fn rejects_duplicate_wrong_sized_and_truncated_fee_extensions() {
        let mut duplicate = token_account();
        append_extension(&mut duplicate, TRANSFER_FEE_AMOUNT_TYPE, &[0; 8]);
        append_extension(&mut duplicate, TRANSFER_FEE_AMOUNT_TYPE, &[0; 8]);
        let mut wrong_size = token_account();
        append_extension(&mut wrong_size, TRANSFER_FEE_AMOUNT_TYPE, &[0; 7]);
        let mut truncated = token_account();
        append_extension(&mut truncated, TRANSFER_FEE_AMOUNT_TYPE, &[0; 8]);
        truncated.pop();
        for data in [duplicate, wrong_size, truncated] {
            assert_eq!(
                transfer_fee_amount_offset(&data, &crate::SPL_TOKEN_2022_ID),
                Err(ProgramError::InvalidAccountData)
            );
        }
    }

    #[test]
    fn rejects_wrong_account_type_and_nonzero_trailing_data() {
        let mut wrong_type = token_account();
        wrong_type[TOKEN_ACCOUNT_BASE_DATA_LEN] = 1;
        let mut trailing = token_account();
        append_extension(&mut trailing, TRANSFER_FEE_AMOUNT_TYPE, &[0; 8]);
        trailing.extend_from_slice(&[0, 0, 0, 1]);
        for data in [wrong_type, trailing] {
            assert_eq!(
                transfer_fee_amount_offset(&data, &crate::SPL_TOKEN_2022_ID),
                Err(ProgramError::InvalidAccountData)
            );
        }
    }

    #[test]
    fn saved_exclusion_must_fit_post_cpi_data() {
        assert_eq!(
            hash_with_transfer_fee(
                &[0; 177],
                &crate::SPL_TOKEN_2022_ID,
                core::slice::from_ref(&(64..72)),
                Some(170)
            ),
            Err(ProgramError::InvalidAccountData)
        );
    }
}
