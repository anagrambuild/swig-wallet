use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
use swig_state::IntoBytes;

use crate::{
    authority,
    instruction_data::{AddAuthorizationLockV1Args, RemoveAuthorizationLockV1Args},
    program_id,
};

/// Instruction builders for authorization locks.
///
/// A lock reserves `amount` of `asset_account` until `expiry_slot`. For native
/// SOL pass the swig wallet address as the asset account and an all-zero mint;
/// for tokens pass a token account owned by the swig wallet address and its
/// mint.
pub struct AddAuthorizationLockV1Instruction;

impl AddAuthorizationLockV1Instruction {
    /// Token locks also pass the mint, which Token-2022 locks require so the
    /// program can reject mints with a permanent delegate.
    fn accounts(
        swig_account: Pubkey,
        payer: Pubkey,
        swig_wallet_address: Pubkey,
        asset_account: Pubkey,
        mint: [u8; 32],
    ) -> Vec<AccountMeta> {
        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(swig_wallet_address, false),
            AccountMeta::new_readonly(asset_account, false),
        ];
        if mint != [0u8; 32] {
            accounts.push(AccountMeta::new_readonly(
                Pubkey::new_from_array(mint),
                false,
            ));
        }
        accounts
    }

    /// Create an add-lock instruction signed by an Ed25519 authority.
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        payer: Pubkey,
        authority: Pubkey,
        swig_wallet_address: Pubkey,
        asset_account: Pubkey,
        acting_role_id: u32,
        mint: [u8; 32],
        amount: u64,
        expiry_slot: u64,
    ) -> anyhow::Result<Instruction> {
        let mut accounts = Self::accounts(
            swig_account,
            payer,
            swig_wallet_address,
            asset_account,
            mint,
        );
        let authority_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(authority, true));

        let args = AddAuthorizationLockV1Args::new(
            acting_role_id,
            asset_account.to_bytes(),
            mint,
            amount,
            expiry_slot,
        );
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &[authority_index]].concat(),
        })
    }

    /// Create an add-lock instruction signed by a Secp256k1 authority.
    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        swig_wallet_address: Pubkey,
        asset_account: Pubkey,
        acting_role_id: u32,
        mint: [u8; 32],
        amount: u64,
        expiry_slot: u64,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = Self::accounts(
            swig_account,
            payer,
            swig_wallet_address,
            asset_account,
            mint,
        );
        let args = AddAuthorizationLockV1Args::new(
            acting_role_id,
            asset_account.to_bytes(),
            mint,
            amount,
            expiry_slot,
        );
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload = authority::secp256k1::build_authority_payload(
            &accounts,
            args_bytes,
            current_slot,
            counter,
            &mut authority_payload_fn,
        )?;

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        })
    }

    /// Create an add-lock instruction signed by a Secp256r1 authority. Returns
    /// the precompile verification instruction followed by the lock instruction.
    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        swig_wallet_address: Pubkey,
        asset_account: Pubkey,
        acting_role_id: u32,
        mint: [u8; 32],
        amount: u64,
        expiry_slot: u64,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let mut accounts = Self::accounts(
            swig_account,
            payer,
            swig_wallet_address,
            asset_account,
            mint,
        );
        accounts.push(AccountMeta::new_readonly(
            solana_sdk::sysvar::instructions::ID,
            false,
        ));
        let args = AddAuthorizationLockV1Args::new(
            acting_role_id,
            asset_account.to_bytes(),
            mint,
            amount,
            expiry_slot,
        );
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authorization = authority::secp256r1::build_authorization(
            &accounts,
            args_bytes,
            current_slot,
            counter,
            &mut authority_payload_fn,
            public_key,
        )?;

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authorization.authority_payload].concat(),
        };
        Ok(vec![authorization.verification_instruction, main_ix])
    }
}

/// Instruction builders for releasing or pruning an authorization lock.
pub struct RemoveAuthorizationLockV1Instruction;

impl RemoveAuthorizationLockV1Instruction {
    fn accounts(
        swig_account: Pubkey,
        payer: Pubkey,
        rent_claimer: Option<Pubkey>,
    ) -> Vec<AccountMeta> {
        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];
        if let Some(rent_claimer) = rent_claimer {
            accounts.push(AccountMeta::new(rent_claimer, false));
        }
        accounts
    }

    /// Create a remove-lock instruction signed by an Ed25519 authority. Pass
    /// the wallet's rent claimer when one is configured.
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        payer: Pubkey,
        authority: Pubkey,
        acting_role_id: u32,
        lock_id: u32,
        rent_claimer: Option<Pubkey>,
    ) -> anyhow::Result<Instruction> {
        let mut accounts = Self::accounts(swig_account, payer, rent_claimer);
        let authority_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(authority, true));

        let args = RemoveAuthorizationLockV1Args::new(acting_role_id, lock_id);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &[authority_index]].concat(),
        })
    }

    /// Create a remove-lock instruction signed by a Secp256k1 authority.
    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        acting_role_id: u32,
        lock_id: u32,
        rent_claimer: Option<Pubkey>,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = Self::accounts(swig_account, payer, rent_claimer);
        let args = RemoveAuthorizationLockV1Args::new(acting_role_id, lock_id);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload = authority::secp256k1::build_authority_payload(
            &accounts,
            args_bytes,
            current_slot,
            counter,
            &mut authority_payload_fn,
        )?;

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        })
    }

    /// Create a remove-lock instruction signed by a Secp256r1 authority.
    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        acting_role_id: u32,
        lock_id: u32,
        rent_claimer: Option<Pubkey>,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let mut accounts = Self::accounts(swig_account, payer, rent_claimer);
        accounts.push(AccountMeta::new_readonly(
            solana_sdk::sysvar::instructions::ID,
            false,
        ));
        let args = RemoveAuthorizationLockV1Args::new(acting_role_id, lock_id);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authorization = authority::secp256r1::build_authorization(
            &accounts,
            args_bytes,
            current_slot,
            counter,
            &mut authority_payload_fn,
            public_key,
        )?;

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authorization.authority_payload].concat(),
        };
        Ok(vec![authorization.verification_instruction, main_ix])
    }
}
