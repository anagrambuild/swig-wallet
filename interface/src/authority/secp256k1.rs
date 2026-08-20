use solana_sdk::{hash as sha256, instruction::AccountMeta, keccak};
use swig_state::authority::secp256k1::hex_encode;

use super::account_payload;

pub(crate) const AUTHORITY_PAYLOAD_LEN: usize = 8 + 4 + 65;

pub(crate) fn build_authority_payload<F>(
    accounts: &[AccountMeta],
    signed_data: &[u8],
    current_slot: u64,
    counter: u32,
    authority_payload_fn: &mut F,
) -> anyhow::Result<[u8; AUTHORITY_PAYLOAD_LEN]>
where
    F: FnMut(&[u8]) -> [u8; 65],
{
    let accounts = account_payload(accounts)?;
    let compressed_payload = sha256::hash(
        &[
            signed_data,
            &accounts,
            &current_slot.to_le_bytes(),
            &counter.to_le_bytes(),
        ]
        .concat(),
    )
    .to_bytes();
    let mut compressed_payload_hex = [0u8; 64];
    hex_encode(&compressed_payload, &mut compressed_payload_hex);
    let message_hash = keccak::hash(&compressed_payload_hex).to_bytes();
    let signature = authority_payload_fn(&message_hash);

    let mut payload = [0u8; AUTHORITY_PAYLOAD_LEN];
    payload[..8].copy_from_slice(&current_slot.to_le_bytes());
    payload[8..12].copy_from_slice(&counter.to_le_bytes());
    payload[12..].copy_from_slice(&signature);
    Ok(payload)
}
