#![warn(unexpected_cfgs)]

use core::mem::MaybeUninit;

#[allow(unused_imports)]
use pinocchio::syscalls::{sol_keccak256, sol_secp256k1_recover};
use pinocchio::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
use swig_assertions::sol_assert_bytes_eq;

use super::{ed25519::ed25519_authenticate, Authority, AuthorityInfo, AuthorityType};
use crate::{IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable, TransmutableMut};

const MAX_SIGNATURE_AGE_IN_SLOTS: u64 = 60;

#[derive(Debug, no_padding::NoPadding)]
#[repr(C, align(8))]
pub struct CreateSecp256k1SessionAuthority {
    pub public_key: [u8; 64],
    pub session_key: [u8; 32],
    pub max_session_length: u64,
}

impl CreateSecp256k1SessionAuthority {
    pub fn new(public_key: [u8; 64], session_key: [u8; 32], max_session_length: u64) -> Self {
        Self {
            public_key,
            session_key,
            max_session_length,
        }
    }
}

impl Transmutable for CreateSecp256k1SessionAuthority {
    const LEN: usize = 64 + 32 + 8;
}

impl TransmutableMut for CreateSecp256k1SessionAuthority {}

impl IntoBytes for CreateSecp256k1SessionAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

#[derive(Debug, no_padding::NoPadding)]
#[repr(C, align(8))]
pub struct Secp256k1Authority {
    pub public_key: [u8; 33],
    _padding: [u8; 7],
}

impl Transmutable for Secp256k1Authority {
    const LEN: usize = core::mem::size_of::<Secp256k1Authority>();
}

impl TransmutableMut for Secp256k1Authority {}

impl Authority for Secp256k1Authority {
    const TYPE: AuthorityType = AuthorityType::Secp256k1;
    const SESSION_BASED: bool = false;

    fn set_into_bytes(create_data: &[u8], bytes: &mut [u8]) -> Result<(), ProgramError> {
        if create_data.len() != 64 {
            return Err(SwigStateError::InvalidRoleData.into());
        }
        let authority = unsafe { Secp256k1Authority::load_mut_unchecked(bytes)? };
        let compressed = compress(create_data.try_into().unwrap());
        authority.public_key = compressed;
        Ok(())
    }
}

impl AuthorityInfo for Secp256k1Authority {
    fn authority_type(&self) -> AuthorityType {
        Self::TYPE
    }

    fn length(&self) -> usize {
        Self::LEN
    }

    fn session_based(&self) -> bool {
        Self::SESSION_BASED
    }

    fn identity(&self) -> Result<&[u8], ProgramError> {
        Ok(self.public_key.as_ref())
    }

    fn match_data(&self, data: &[u8]) -> bool {
        if data.len() != 64 {
            return false;
        }
        let expanded = compress(data.try_into().unwrap());
        sol_assert_bytes_eq(&self.public_key, &expanded, 32)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn authenticate(
        &mut self,
        account_infos: &[pinocchio::account_info::AccountInfo],
        authority_payload: &[u8],
        data_payload: &[u8],
        slot: u64,
    ) -> Result<(), ProgramError> {
        secp_authority_authenticate(
            // &mut self.sig_filter,
            &self.public_key,
            authority_payload,
            data_payload,
            slot,
            account_infos,
        )
    }
}

impl IntoBytes for Secp256k1Authority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

#[derive(Debug, no_padding::NoPadding)]
#[repr(C, align(8))]
pub struct Secp256k1SessionAuthority {
    pub public_key: [u8; 33],
    _padding: [u8; 7],
    // pub sig_filter: Secp256k1SigFilter,
    pub session_key: [u8; 32],
    pub max_session_age: u64,
    pub current_session_expiration: u64,
}

impl Transmutable for Secp256k1SessionAuthority {
    const LEN: usize = core::mem::size_of::<Secp256k1SessionAuthority>();
}

impl TransmutableMut for Secp256k1SessionAuthority {}

impl Authority for Secp256k1SessionAuthority {
    const TYPE: AuthorityType = AuthorityType::Secp256k1Session;
    const SESSION_BASED: bool = true;

    fn set_into_bytes(create_data: &[u8], bytes: &mut [u8]) -> Result<(), ProgramError> {
        let create = unsafe { CreateSecp256k1SessionAuthority::load_unchecked(create_data)? };
        let authority = unsafe { Secp256k1SessionAuthority::load_mut_unchecked(bytes)? };
        let compressed = compress(&create.public_key);
        authority.public_key = compressed;
        authority.session_key = create.session_key;
        authority.max_session_age = create.max_session_length;
        Ok(())
    }
}

impl AuthorityInfo for Secp256k1SessionAuthority {
    fn authority_type(&self) -> AuthorityType {
        Self::TYPE
    }

    fn length(&self) -> usize {
        Self::LEN
    }

    fn session_based(&self) -> bool {
        Self::SESSION_BASED
    }

    fn match_data(&self, data: &[u8]) -> bool {
        if data.len() != 64 {
            return false;
        }
        let expanded = compress(data.try_into().unwrap());
        sol_assert_bytes_eq(data, &expanded, 33)
    }

    fn identity(&self) -> Result<&[u8], ProgramError> {
        Ok(self.public_key.as_ref())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn authenticate(
        &mut self,
        account_infos: &[pinocchio::account_info::AccountInfo],
        authority_payload: &[u8],
        data_payload: &[u8],
        slot: u64,
    ) -> Result<(), ProgramError> {
        secp_authority_authenticate(
            &self.public_key,
            authority_payload,
            data_payload,
            slot,
            account_infos,
        )
    }

    fn authenticate_session(
        &mut self,
        account_infos: &[AccountInfo],
        authority_payload: &[u8],
        _data_payload: &[u8],
        slot: u64,
    ) -> Result<(), ProgramError> {
        if slot > self.current_session_expiration {
            return Err(SwigAuthenticateError::PermissionDeniedSessionExpired.into());
        }
        ed25519_authenticate(
            account_infos,
            authority_payload[0] as usize,
            &self.session_key,
        )
    }

    fn start_session(
        &mut self,
        session_key: [u8; 32],
        current_slot: u64,
        duration: u64,
    ) -> Result<(), ProgramError> {
        if sol_assert_bytes_eq(&self.session_key, &session_key, 32) {
            return Err(SwigAuthenticateError::InvalidSessionKeyCannotReuseSessionKey.into());
        }
        if duration > self.max_session_age {
            return Err(SwigAuthenticateError::InvalidSessionDuration.into());
        }
        self.current_session_expiration = current_slot + duration;
        self.session_key = session_key;
        Ok(())
    }
}

impl IntoBytes for Secp256k1SessionAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

fn secp_authority_authenticate(
    expected_key: &[u8; 33],
    authority_payload: &[u8],
    data_payload: &[u8],
    current_slot: u64,
    account_infos: &[AccountInfo],
) -> Result<(), ProgramError> {
    if authority_payload.len() < 73 {
        return Err(SwigAuthenticateError::InvalidAuthorityPayload.into());
    }
    let authority_slot =
        u64::from_le_bytes(unsafe { authority_payload.get_unchecked(..8).try_into().unwrap() });

    secp256k1_authenticate(
        expected_key,
        authority_payload[8..].try_into().unwrap(),
        data_payload,
        authority_slot,
        current_slot,
        account_infos,
    )?;
    Ok(())
}

fn secp256k1_authenticate(
    expected_key: &[u8; 33],
    authority_payload: &[u8],
    data_payload: &[u8],
    authority_slot: u64,
    current_slot: u64,
    account_infos: &[AccountInfo],
) -> Result<(), ProgramError> {
    if authority_payload.len() != 65 {
        return Err(SwigAuthenticateError::InvalidAuthorityPayload.into());
    }
    if current_slot < authority_slot || current_slot - authority_slot > MAX_SIGNATURE_AGE_IN_SLOTS {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256k1InvalidSignature.into());
    }

    let mut accounts_payload = [0u8; 64 * AccountsPayload::LEN];

    let mut cursor = 0;

    for account in account_infos {
        let offset = cursor + AccountsPayload::LEN;
        accounts_payload[cursor..offset]
            .copy_from_slice(AccountsPayload::from(account).into_bytes()?);
        cursor = offset;
    }

    #[allow(unused)]
    let mut recovered_key = MaybeUninit::<[u8; 64]>::uninit();
    #[allow(unused)]
    let mut hash = MaybeUninit::<[u8; 32]>::uninit();
    #[allow(unused)]
    let data: &[&[u8]] = &[
        data_payload,
        &accounts_payload[..cursor],
        &authority_slot.to_le_bytes(),
    ];
    let matches = unsafe {
        // do not remove this line we must hash the instruction payload
        #[cfg(target_os = "solana")]
        let res = sol_keccak256(data.as_ptr() as *const u8, 3, hash.as_mut_ptr() as *mut u8);
        #[cfg(not(target_os = "solana"))]
        let res = 0;
        if res != 0 {
            return Err(SwigAuthenticateError::PermissionDeniedSecp256k1InvalidHash.into());
        }
        #[allow(unused)]
        let recovery_id = if *authority_payload.get_unchecked(64) == 27 {
            0
        } else {
            1
        };

        #[cfg(target_os = "solana")]
        let res = sol_secp256k1_recover(
            hash.as_ptr() as *const u8,
            recovery_id,
            authority_payload.get_unchecked(..64).as_ptr() as *const u8,
            recovered_key.as_mut_ptr() as *mut u8,
        );
        #[cfg(not(target_os = "solana"))]
        let res = 0;
        if res != 0 {
            return Err(SwigAuthenticateError::PermissionDeniedSecp256k1InvalidSignature.into());
        }
        // First compress the recovered key to 33 bytes
        let compressed_recovered_key = compress(&recovered_key.assume_init());
        sol_assert_bytes_eq(&compressed_recovered_key, expected_key, 32)
    };
    if !matches {
        return Err(SwigAuthenticateError::PermissionDenied.into());
    }
    Ok(())
}

/// Compress a 64 byte public key to a 33 byte compressed public key
/// the first byte is the prefix (0x02 if Y is even, 0x03 if Y is odd)
/// the next 32 bytes are the X coordinate
fn compress(key: &[u8; 64]) -> [u8; 33] {
    let mut compressed = [0u8; 33];
    compressed[0] = if key[63] & 1 == 0 { 0x02 } else { 0x03 };
    compressed[1..33].copy_from_slice(&key[..32]);
    compressed
}

#[repr(C, align(8))]
#[derive(Copy, Clone, no_padding::NoPadding)]
pub struct AccountsPayload {
    pub pubkey: Pubkey,
    pub is_writable: bool,
    pub is_signer: bool,
    _padding: [u8; 6],
}

impl AccountsPayload {
    pub fn new(pubkey: Pubkey, is_writable: bool, is_signer: bool) -> Self {
        Self {
            pubkey,
            is_writable,
            is_signer,
            _padding: [0u8; 6],
        }
    }
}

impl Transmutable for AccountsPayload {
    const LEN: usize = core::mem::size_of::<AccountsPayload>();
}

impl IntoBytes for AccountsPayload {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

impl From<&AccountInfo> for AccountsPayload {
    fn from(info: &AccountInfo) -> Self {
        Self::new(*info.key(), info.is_writable(), info.is_signer())
    }
}
