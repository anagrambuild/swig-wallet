pub(crate) mod secp256k1;
pub(crate) mod secp256r1;

use solana_sdk::instruction::AccountMeta;
use swig_state::{authority::secp256k1::AccountsPayload, IntoBytes, Transmutable};

fn account_payload(accounts: &[AccountMeta]) -> anyhow::Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(accounts.len() * AccountsPayload::LEN);
    for account in accounts {
        payload.extend_from_slice(
            AccountsPayload::new(
                account.pubkey.to_bytes(),
                account.is_writable,
                account.is_signer,
            )
            .into_bytes()
            .map_err(|error| anyhow::anyhow!("Failed to serialize account meta: {error:?}"))?,
        );
    }
    Ok(payload)
}
