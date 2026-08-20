use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    keccak,
};
use solana_secp256r1_program::new_secp256r1_instruction_with_signature;

use super::account_payload;

pub(crate) const AUTHORITY_PAYLOAD_LEN: usize = 8 + 4 + 1 + 4;

pub(crate) struct Authorization {
    pub(crate) verification_instruction: Instruction,
    pub(crate) authority_payload: [u8; AUTHORITY_PAYLOAD_LEN],
}

pub(crate) fn build_authorization<F>(
    accounts: &[AccountMeta],
    signed_data: &[u8],
    current_slot: u64,
    counter: u32,
    authority_payload_fn: &mut F,
    public_key: &[u8; 33],
) -> anyhow::Result<Authorization>
where
    F: FnMut(&[u8]) -> [u8; 64],
{
    let instruction_sysvar_index = instruction_sysvar_index(accounts)?;
    let accounts = account_payload(accounts)?;
    let message_hash = keccak::hash(
        &[
            signed_data,
            &accounts,
            &current_slot.to_le_bytes(),
            &counter.to_le_bytes(),
        ]
        .concat(),
    )
    .to_bytes();
    let signature = authority_payload_fn(&message_hash);
    let verification_instruction =
        new_secp256r1_instruction_with_signature(&message_hash, &signature, public_key);

    let mut authority_payload = [0u8; AUTHORITY_PAYLOAD_LEN];
    authority_payload[..8].copy_from_slice(&current_slot.to_le_bytes());
    authority_payload[8..12].copy_from_slice(&counter.to_le_bytes());
    authority_payload[12] = instruction_sysvar_index;

    Ok(Authorization {
        verification_instruction,
        authority_payload,
    })
}

pub(crate) fn build_instructions<F>(
    accounts: Vec<AccountMeta>,
    signed_data: &[u8],
    data_prefix: &[u8],
    current_slot: u64,
    counter: u32,
    authority_payload_fn: &mut F,
    public_key: &[u8; 33],
) -> anyhow::Result<Vec<Instruction>>
where
    F: FnMut(&[u8]) -> [u8; 64],
{
    let authorization = build_authorization(
        &accounts,
        signed_data,
        current_slot,
        counter,
        authority_payload_fn,
        public_key,
    )?;
    let main_instruction = Instruction {
        program_id: crate::program_id(),
        accounts,
        data: [data_prefix, &authorization.authority_payload].concat(),
    };
    Ok(vec![
        authorization.verification_instruction,
        main_instruction,
    ])
}

fn instruction_sysvar_index(accounts: &[AccountMeta]) -> anyhow::Result<u8> {
    let mut matches = accounts
        .iter()
        .enumerate()
        .filter(|(_, account)| account.pubkey == solana_sdk::sysvar::instructions::ID);
    let (index, _) = matches
        .next()
        .ok_or_else(|| anyhow::anyhow!("Secp256r1 authority requires the instructions sysvar"))?;
    if matches.next().is_some() {
        return Err(anyhow::anyhow!(
            "Secp256r1 authority requires exactly one instructions sysvar account"
        ));
    }
    u8::try_from(index).map_err(|_| anyhow::anyhow!("Instructions sysvar account index exceeds u8"))
}
