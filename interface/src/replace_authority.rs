use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    keccak,
    pubkey::Pubkey,
};
use solana_secp256r1_program::new_secp256r1_instruction_with_signature;
use swig::actions::replace_authority_v1::ReplaceAuthorityV1Args;
use swig_state::IntoBytes;

use crate::{
    accounts_payload_from_meta, build_program_exec_authority_payload, prepare_secp256k1_payload,
};

pub struct ReplaceAuthorityInstruction;

impl ReplaceAuthorityInstruction {
    fn build_data_payload(
        acting_role_id: u32,
        target_role_id: u32,
        new_authority: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        if !matches!(new_authority.len(), 32 | 33) {
            return Err(anyhow::anyhow!("new authority must contain 32 or 33 bytes"));
        }

        let args =
            ReplaceAuthorityV1Args::new(acting_role_id, target_role_id, new_authority.len() as u16);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        Ok([args_bytes, new_authority].concat())
    }

    /// Replaces a signer using an Ed25519 transaction signer. This is also the
    /// authentication shape used by active session authorities.
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        authority: Pubkey,
        acting_role_id: u32,
        target_role_id: u32,
        new_authority: &[u8],
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(authority, true),
        ];
        let authority_payload = [1u8];
        let data_payload = Self::build_data_payload(acting_role_id, target_role_id, new_authority)?;

        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [data_payload.as_slice(), &authority_payload].concat(),
        })
    }

    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        acting_role_id: u32,
        target_role_id: u32,
        new_authority: &[u8],
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        const AUTHORITY_PAYLOAD_LEN: usize = 8 + 4 + 65;

        let accounts = vec![AccountMeta::new(swig_account, false)];
        let data_payload = Self::build_data_payload(acting_role_id, target_role_id, new_authority)?;

        let mut accounts_payload = Vec::new();
        for account in &accounts {
            accounts_payload.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }
        let payload_to_sign =
            prepare_secp256k1_payload(current_slot, counter, &data_payload, &accounts_payload, &[]);
        let signature = authority_payload_fn(&payload_to_sign);
        let mut authority_payload = Vec::with_capacity(AUTHORITY_PAYLOAD_LEN);
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&counter.to_le_bytes());
        authority_payload.extend_from_slice(&signature);

        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [data_payload, authority_payload].concat(),
        })
    }

    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        acting_role_id: u32,
        target_role_id: u32,
        new_authority: &[u8],
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        const AUTHORITY_PAYLOAD_LEN: usize = 8 + 4 + 1 + 4;
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(INSTRUCTIONS_ID, false),
        ];
        let data_payload = Self::build_data_payload(acting_role_id, target_role_id, new_authority)?;

        let mut accounts_payload = Vec::new();
        for account in &accounts {
            accounts_payload.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }
        let message_hash = keccak::hash(
            &[
                data_payload.as_slice(),
                accounts_payload.as_slice(),
                &current_slot.to_le_bytes(),
                &counter.to_le_bytes(),
            ]
            .concat(),
        )
        .to_bytes();
        let signature = authority_payload_fn(&message_hash);
        let verify_ix =
            new_secp256r1_instruction_with_signature(&message_hash, &signature, public_key);

        let mut authority_payload = Vec::with_capacity(AUTHORITY_PAYLOAD_LEN);
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&counter.to_le_bytes());
        authority_payload.push(1);
        authority_payload.extend_from_slice(&[0; 4]);
        let main_ix = Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [data_payload, authority_payload].concat(),
        };

        Ok(vec![verify_ix, main_ix])
    }

    pub fn new_with_program_exec(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        preceding_instruction: Instruction,
        acting_role_id: u32,
        target_role_id: u32,
        new_authority: &[u8],
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let pending_recovery = preceding_instruction
            .accounts
            .get(2)
            .ok_or_else(|| anyhow::anyhow!("recovery execute instruction missing pending account"))?
            .pubkey;
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(swig_wallet_address, false),
            AccountMeta::new_readonly(INSTRUCTIONS_ID, false),
            AccountMeta::new_readonly(pending_recovery, false),
        ];
        let authority_payload = build_program_exec_authority_payload(2, None);
        let data_payload = Self::build_data_payload(acting_role_id, target_role_id, new_authority)?;

        let main_ix = Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [data_payload, authority_payload].concat(),
        };

        Ok(vec![preceding_instruction, main_ix])
    }
}
