use alloy_signer_local::PrivateKeySigner;
use swig_state_x::{
    authority::{secp256k1::Secp256k1Authority, AuthorityType},
    swig::SwigWithRoles,
};

use crate::error::SwigError;

/// Gets the current signature counter for a Secp256k1 authority from a Swig
/// account.
///
/// This function is useful for constructing transactions with the correct
/// counter value to prevent replay attacks. The counter must be incremented by
/// 1 for each new transaction.
///
/// # Arguments
/// * `swig_account_data` - The raw account data bytes from the Swig account
/// * `wallet_pubkey` - The 64-byte uncompressed public key (without 0x04
///   prefix) of the Secp256k1 authority
///
/// # Returns
/// * `Ok(u32)` - The current signature counter (odometer) value
/// * `Err(SwigError)` - If the account data is invalid, authority is not found,
///   or is not a Secp256k1 authority
///
/// # Example
/// ```ignore
/// use swig_sdk::get_secp256k1_signature_counter;
///
/// // Get the Swig account data from RPC
/// let swig_account = rpc_client.get_account(&swig_pubkey)?;
///
/// // Get wallet's uncompressed public key (64 bytes, no 0x04 prefix)
/// let wallet_pubkey = wallet.credential().verifying_key().to_encoded_point(false).to_bytes();
/// let authority_bytes = &wallet_pubkey[1..]; // Remove 0x04 prefix
///
/// // Get current counter
/// let current_counter = get_secp256k1_signature_counter(&swig_account.data, authority_bytes)?;
/// let next_counter = current_counter + 1; // Use this for the next transaction
/// ```
pub fn get_secp256k1_signature_counter(
    swig_account_data: &[u8],
    wallet_pubkey: &[u8], // 64-byte uncompressed public key (without 0x04 prefix)
) -> Result<u32, SwigError> {
    // Parse the Swig account data
    let swig =
        SwigWithRoles::from_bytes(swig_account_data).map_err(|_| SwigError::InvalidSwigData)?;

    // Look up the role ID for this authority
    let role_id = swig
        .lookup_role_id(wallet_pubkey)
        .map_err(|_| SwigError::AuthorityNotFound)?
        .ok_or(SwigError::AuthorityNotFound)?;

    // Get the role
    let role = swig
        .get_role(role_id)
        .map_err(|_| SwigError::AuthorityNotFound)?
        .ok_or(SwigError::AuthorityNotFound)?;

    // Verify this is a Secp256k1Authority and get the counter
    if matches!(role.authority.authority_type(), AuthorityType::Secp256k1) {
        let secp_authority = role
            .authority
            .as_any()
            .downcast_ref::<Secp256k1Authority>()
            .ok_or(SwigError::AuthorityNotFound)?;

        Ok(secp_authority.signature_odometer)
    } else {
        Err(SwigError::InvalidAuthorityType)
    }
}
