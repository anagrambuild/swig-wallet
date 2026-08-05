use solana_sdk::{
    hash::hashv,
    instruction::{AccountMeta, Instruction},
    keccak,
    pubkey::Pubkey,
};
use solana_secp256r1_program::new_secp256r1_instruction_with_signature;
use swig::actions::replace_authority_v1::{
    ReplaceAuthorityV1Args, REPLACE_AUTHORITY_PROOF_V1_DISCRIMINATOR,
    REPLACE_AUTHORITY_PROOF_V1_DOMAIN,
};
use swig_state::{
    authority::{secp256k1::compress, AuthorityType},
    IntoBytes,
};

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
        if !matches!(new_authority.len(), 32 | 33 | 64) {
            return Err(anyhow::anyhow!(
                "new authority must contain 32, 33, or 64 bytes"
            ));
        }

        let args =
            ReplaceAuthorityV1Args::new(acting_role_id, target_role_id, new_authority.len() as u16);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        Ok([args_bytes, new_authority].concat())
    }

    /// Builds the exact state-change proof required when a ProgramExec role
    /// authorizes ReplaceAuthority.
    pub fn program_exec_proof_data(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        acting_role_id: u32,
        target_role_id: u32,
        target_authority_type: AuthorityType,
        current_authority: &[u8],
        new_authority: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let (current_authority, new_authority) = match target_authority_type {
            AuthorityType::Ed25519 | AuthorityType::Ed25519Session => {
                if current_authority.len() != 32 || new_authority.len() != 32 {
                    return Err(anyhow::anyhow!(
                        "current and new authority must match the target authority type"
                    ));
                }
                (current_authority.to_vec(), new_authority.to_vec())
            },
            AuthorityType::Secp256k1 | AuthorityType::Secp256k1Session => (
                normalize_secp256k1_authority(current_authority)?.to_vec(),
                normalize_secp256k1_authority(new_authority)?.to_vec(),
            ),
            AuthorityType::Secp256r1 | AuthorityType::Secp256r1Session => {
                if current_authority.len() != 33 || new_authority.len() != 33 {
                    return Err(anyhow::anyhow!(
                        "current and new authority must match the target authority type"
                    ));
                }
                (current_authority.to_vec(), new_authority.to_vec())
            },
            _ => return Err(anyhow::anyhow!("unsupported target authority type")),
        };

        let acting_role_id = acting_role_id.to_le_bytes();
        let target_role_id = target_role_id.to_le_bytes();
        let target_authority_type = (target_authority_type as u16).to_le_bytes();
        let replacement_hash = hashv(&[
            REPLACE_AUTHORITY_PROOF_V1_DOMAIN,
            swig_account.as_ref(),
            swig_wallet_address.as_ref(),
            &acting_role_id,
            &target_role_id,
            &target_authority_type,
            current_authority.as_slice(),
            new_authority.as_slice(),
        ]);

        Ok([
            REPLACE_AUTHORITY_PROOF_V1_DISCRIMINATOR.as_slice(),
            replacement_hash.as_ref(),
        ]
        .concat())
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

        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(swig_wallet_address, false),
            AccountMeta::new_readonly(INSTRUCTIONS_ID, false),
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

fn normalize_secp256k1_authority(authority: &[u8]) -> anyhow::Result<[u8; 33]> {
    match authority.len() {
        33 => authority
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid secp256k1 authority length")),
        64 => {
            let key: &[u8; 64] = authority
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid secp256k1 authority length"))?;
            Ok(compress(key))
        },
        _ => Err(anyhow::anyhow!(
            "secp256k1 authority must contain 33 or 64 bytes"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_exec_proof_data_has_exact_v1_envelope() {
        let proof = ReplaceAuthorityInstruction::program_exec_proof_data(
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            1,
            2,
            AuthorityType::Ed25519,
            &[3; 32],
            &[4; 32],
        )
        .unwrap();

        assert_eq!(proof.len(), 40);
        assert_eq!(&proof[..8], &REPLACE_AUTHORITY_PROOF_V1_DISCRIMINATOR);
    }

    #[test]
    fn program_exec_proof_data_rejects_invalid_signer_shape() {
        assert!(ReplaceAuthorityInstruction::program_exec_proof_data(
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            1,
            2,
            AuthorityType::Secp256k1,
            &[3; 32],
            &[4; 33],
        )
        .is_err());

        assert!(ReplaceAuthorityInstruction::program_exec_proof_data(
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            1,
            2,
            AuthorityType::ProgramExec,
            &[3; 32],
            &[4; 32],
        )
        .is_err());
    }

    #[test]
    fn program_exec_proof_data_canonicalizes_uncompressed_secp256k1() {
        let swig = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();
        let mut current_uncompressed = [0u8; 64];
        current_uncompressed[..32].fill(3);
        current_uncompressed[63] = 2;
        let mut new_uncompressed = [0u8; 64];
        new_uncompressed[..32].fill(4);
        new_uncompressed[63] = 3;

        let current_compressed = normalize_secp256k1_authority(&current_uncompressed).unwrap();
        let new_compressed = normalize_secp256k1_authority(&new_uncompressed).unwrap();
        let compressed_proof = ReplaceAuthorityInstruction::program_exec_proof_data(
            swig,
            wallet,
            1,
            2,
            AuthorityType::Secp256k1,
            &current_compressed,
            &new_compressed,
        )
        .unwrap();
        let uncompressed_proof = ReplaceAuthorityInstruction::program_exec_proof_data(
            swig,
            wallet,
            1,
            2,
            AuthorityType::Secp256k1,
            &current_uncompressed,
            &new_uncompressed,
        )
        .unwrap();

        assert_eq!(uncompressed_proof, compressed_proof);
    }
}
