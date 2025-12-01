//! External kill switch action type.
//!
//! This module defines the ExternalKillSwitch action type which allows reading
//! from an external account and comparing the value against an expected value.
//! If the values don't match, the action prevents instruction execution.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{
    constants::EXTERNAL_KILL_SWITCH_BYTE_SIZE, IntoBytes, SwigAuthenticateError, Transmutable,
    TransmutableMut,
};

/// Represents an external account kill switch that can disable operations
/// based on external account state.
///
/// This action monitors an external account and compares a specific field
/// with expected data. If the data doesn't match, it prevents the
/// authority from performing operations like sign_v1.
#[repr(C, align(8))]
#[derive(NoPadding)]
pub struct ExternalKillSwitch {
    /// Expected data that should be read from the external account (max 32
    /// bytes)
    pub expected_data: [u8; 32], // 32 bytes
    /// Length of expected data to compare (0-32)
    pub expected_data_len: u32, // 4 bytes
    /// Start index for reading the data field
    pub data_field_start: u32, // 4 bytes
    /// End index for reading the data field  
    pub data_field_end: u32, // 4 bytes
    /// Reserved for alignment
    pub _reserved: u32, // 4 bytes
    /// The external account to monitor
    pub external_account: [u8; 32], // 32 bytes
}

impl ExternalKillSwitch {
    /// Creates a new external kill switch.
    ///
    /// # Arguments
    /// * `external_account` - The account to monitor
    /// * `expected_data` - The expected data that should be present
    /// * `data_field_start` - Start index for the data field
    /// * `data_field_end` - End index for the data field
    pub fn new(
        external_account: [u8; 32],
        expected_data: &[u8],
        data_field_start: u32,
        data_field_end: u32,
    ) -> Result<Self, ProgramError> {
        if data_field_end <= data_field_start || data_field_end > 10_000_000 {
            return Err(ProgramError::InvalidArgument);
        }

        if expected_data.len() > 32 {
            return Err(ProgramError::InvalidArgument);
        }

        let data_len = data_field_end - data_field_start;
        if data_len as usize != expected_data.len() {
            return Err(ProgramError::InvalidArgument);
        }

        let mut expected_data_array = [0u8; 32];
        expected_data_array[..expected_data.len()].copy_from_slice(expected_data);

        Ok(Self {
            external_account,
            expected_data: expected_data_array,
            expected_data_len: expected_data.len() as u32,
            data_field_start,
            data_field_end,
            _reserved: 0,
        })
    }

    /// Reads the current data from the external account.
    ///
    /// # Arguments
    /// * `account_data` - The raw account data bytes to read from
    ///
    /// # Returns
    /// * `Result<&[u8], ProgramError>` - The data slice or an error
    ///
    /// # Errors
    /// Returns `ProgramError::InvalidAccountData` if:
    /// * The account data isn't long enough for the specified field range
    pub fn read_account_data<'a>(&self, account_data: &'a [u8]) -> Result<&'a [u8], ProgramError> {
        // Check if account data is long enough
        if account_data.len() < self.data_field_end as usize {
            return Err(ProgramError::InvalidAccountData);
        }

        let start = self.data_field_start as usize;
        let end = self.data_field_end as usize;

        Ok(&account_data[start..end])
    }

    /// Checks if the external account has the expected data.
    ///
    /// # Arguments
    /// * `account_data` - The raw account data to check
    ///
    /// # Returns
    /// * `Ok(())` - If the data matches the expected data
    /// * `Err(ProgramError)` - If the data doesn't match or reading fails
    pub fn validate_external_account(&self, account_data: &[u8]) -> Result<(), ProgramError> {
        let current_data = self.read_account_data(account_data)?;
        let expected_data_slice = &self.expected_data[..self.expected_data_len as usize];

        pinocchio::msg!(
            "Kill switch validation - start: {}, end: {}, expected_len: {}",
            self.data_field_start,
            self.data_field_end,
            self.expected_data_len
        );

        if current_data != expected_data_slice {
            pinocchio::msg!("Kill switch BLOCKING execution - data doesn't match");
            return Err(SwigAuthenticateError::PermissionDeniedExternalKillSwitchTriggered.into());
        }

        pinocchio::msg!("Kill switch ALLOWING execution - data matches");
        Ok(())
    }

    /// Updates the expected data.
    ///
    /// # Arguments
    /// * `new_expected_data` - The new expected data
    ///
    /// # Returns
    /// * `Ok(())` - If the data was updated successfully
    /// * `Err(ProgramError)` - If the data is too long
    pub fn set_expected_data(&mut self, new_expected_data: &[u8]) -> Result<(), ProgramError> {
        if new_expected_data.len() > 32 {
            return Err(ProgramError::InvalidArgument);
        }

        let data_len = self.data_field_end - self.data_field_start;
        if data_len as usize != new_expected_data.len() {
            return Err(ProgramError::InvalidArgument);
        }

        self.expected_data.fill(0);
        self.expected_data[..new_expected_data.len()].copy_from_slice(new_expected_data);
        self.expected_data_len = new_expected_data.len() as u32;
        Ok(())
    }
}

impl Transmutable for ExternalKillSwitch {
    const LEN: usize = EXTERNAL_KILL_SWITCH_BYTE_SIZE;
}

impl TransmutableMut for ExternalKillSwitch {}

impl IntoBytes for ExternalKillSwitch {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> Actionable<'a> for ExternalKillSwitch {
    /// This action represents the ExternalKillSwitch permission type
    const TYPE: Permission = Permission::ExternalKillSwitch;
    /// Only one external kill switch can exist per role
    const REPEATABLE: bool = false;

    /// Checks if this kill switch matches the provided external account.
    ///
    /// # Arguments
    /// * `data` - The external account public key to check against (32 bytes)
    fn match_data(&self, data: &[u8]) -> bool {
        if data.len() >= 32 {
            data[0..32] == self.external_account
        } else {
            false
        }
    }
}
