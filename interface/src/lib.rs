use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    system_program,
};
pub use swig;
use swig::{
    actions::{add_authority_v1::AddAuthorityV1Args, sign_v1::SignV1Args},
    authority_models::Secp256k1AuthorityPayload,
};
pub use swig_compact_instructions::*;
pub use swig_state;
use swig_state::{swig_account_seeds, util::ZeroCopy, Action, AuthorityType};

pub fn program_id() -> Pubkey {
    swig::ID.into()
}

pub fn swig_key(id: String) -> Pubkey {
    Pubkey::find_program_address(&swig_account_seeds(id.as_bytes()), &program_id()).0
}

pub type Secp256k1AuthorityPayloadFn = fn(&[u8]) -> Secp256k1AuthorityPayload;

pub struct AuthorityConfig<'a> {
    pub authority_type: AuthorityType,
    pub authority: &'a [u8],
}

pub struct CreateInstruction;
impl CreateInstruction {
    pub fn new(
        swig_account: Pubkey,
        swig_bump_seed: u8,
        payer: Pubkey,
        initial_authority: AuthorityConfig,
        id: &[u8],
        start: u64,
        end: u64,
    ) -> anyhow::Result<Instruction> {
        let create = swig_state::CreateV1 {
            id: id.try_into().unwrap(),
            bump: swig_bump_seed,
            initial_authority: initial_authority.authority_type,
            authority_data: initial_authority.authority.as_ref().to_vec(),
            start_slot: start,
            end_slot: end,
        };
        let mut write = Vec::new();
        create.serialize(&mut write).unwrap();
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts: vec![
                AccountMeta::new(swig_account, false),
                AccountMeta::new(payer, true),
                AccountMeta::new(system_program::ID, false),
            ],
            data: [&[0], write.as_slice()].concat(),
        })
    }
}

pub struct AddAuthorityInstruction;
impl AddAuthorityInstruction {
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        payer: Pubkey,
        authority: Pubkey,
        acting_role_id: u8,
        new_authority_config: AuthorityConfig,
        start: u64,
        end: u64,
        actions: Vec<Action>,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(authority, true),
        ];
        let mut data_vec = Vec::new();

        actions
            .serialize(&mut data_vec)
            .map_err(|e| anyhow::anyhow!("Failed to serialize actions {:?}", e))?;
        let args = AddAuthorityV1Args::new(
            acting_role_id,
            new_authority_config.authority_type,
            new_authority_config.authority.len() as u16,
            data_vec.len() as u16,
            start,
            end,
        );
        Vec::<Action>::try_from_slice(&data_vec).unwrap();
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [
                args.as_bytes(),
                new_authority_config.authority,
                &data_vec,
                &[3],
            ]
            .concat(),
        })
    }

    pub fn new_with_secp256k1_authority(
        swig_account: Pubkey,
        payer: Pubkey,
        authority_payload_fn: Secp256k1AuthorityPayloadFn,
        acting_role_id: u8,
        new_authority_config: AuthorityConfig,
        start: u64,
        end: u64,
        actions: Vec<Action>,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ];
        let mut data_vec = vec![0; AddAuthorityV1Args::SIZE];
        let args = AddAuthorityV1Args::new(
            acting_role_id,
            new_authority_config.authority_type,
            new_authority_config.authority.len() as u16,
            data_vec.len() as u16,
            start,
            end,
        );
        actions
            .serialize(&mut data_vec)
            .map_err(|e| anyhow::anyhow!("Failed to serialize actions {:?}", e))?;
        let authority_payload = authority_payload_fn(&data_vec);
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [
                args.as_bytes(),
                new_authority_config.authority,
                &data_vec,
                &authority_payload.as_bytes(),
            ]
            .concat(),
        })
    }
}

pub struct SignInstruction;
impl SignInstruction {
    pub fn new_ed25519(
        swig_account: Pubkey,
        payer: Pubkey,
        authority: Pubkey,
        inner_instruction: Instruction,
        role_id: u8,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
        ];
        let (accounts, ixs) = compact_instructions(swig_account, accounts, vec![inner_instruction]);
        let args = SignV1Args::new(role_id, 1, ixs.inner_instructions.len() as u16);
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [args.as_bytes(), &[2], &ixs.into_bytes()].concat(),
        })
    }

    pub fn new_secp256k1<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        authority_payload_fn: Secp256k1AuthorityPayloadFn,
        inner_instructions: Vec<Instruction>,
        role_id: u8,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
        ];
        let (accounts, ixs) = compact_instructions(swig_account, accounts, inner_instructions);
        let args = SignV1Args::new(role_id, 64, ixs.inner_instructions.len() as u16);
        let authority_payload = authority_payload_fn(&ixs.into_bytes());
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [
                args.as_bytes(),
                authority_payload.as_bytes(),
                &ixs.into_bytes(),
            ]
            .concat(),
        })
    }
}

pub struct RemoveAuthorityInstruction;
impl RemoveAuthorityInstruction {
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        payer: Pubkey,
        authority: Pubkey,
        acting_role_id: u8,
        authority_to_remove_id: u8,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(authority, true),
        ];

        let args = swig::actions::remove_authority_v1::RemoveAuthorityV1Args::new(
            acting_role_id,
            authority_to_remove_id,
            1,
        );

        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [args.as_bytes(), &[3]].concat(),
        })
    }

    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        authority_payload_fn: Secp256k1AuthorityPayloadFn,
        acting_role_id: u8,
        authority_to_remove_id: u8,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ];

        let args = swig::actions::remove_authority_v1::RemoveAuthorityV1Args::new(
            acting_role_id,
            authority_to_remove_id,
            65,
        );

        let data_payload: [u8; 0] = [];

        let authority_payload = authority_payload_fn(&data_payload);

        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [args.as_bytes(), authority_payload.as_bytes()].concat(),
        })
    }
}

pub struct ReplaceAuthorityInstruction;
impl ReplaceAuthorityInstruction {
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        payer: Pubkey,
        authority: Pubkey,
        acting_role_id: u8,
        authority_to_replace_id: u8,
        new_authority_config: AuthorityConfig,
        actions: Vec<Action>,
        start: u64,
        end: u64,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(authority, true),
        ];

        let authority_data = new_authority_config.authority;
        let authority_data_len = authority_data.len() as u16;

        let actions_bytes = borsh::to_vec(&actions)?;
        let actions_payload_len = actions_bytes.len() as u16;

        let args = swig::actions::replace_authority_v1::ReplaceAuthorityV1Args::new(
            acting_role_id,
            authority_to_replace_id,
            new_authority_config.authority_type,
            authority_data_len,
            actions_payload_len,
            start,
            end,
        );

        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [args.as_bytes(), authority_data, &actions_bytes, &[3]].concat(),
        })
    }

    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        authority_payload_fn: F,
        acting_role_id: u8,
        authority_to_replace_id: u8,
        new_authority_config: AuthorityConfig,
        actions: Vec<Action>,
        start: u64,
        end: u64,
    ) -> anyhow::Result<Instruction>
    where
        F: Fn(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ];

        let authority_data = new_authority_config.authority;
        let authority_data_len = authority_data.len() as u16;

        let actions_bytes = borsh::to_vec(&actions)?;
        let actions_payload_len = actions_bytes.len() as u16;

        let args = swig::actions::replace_authority_v1::ReplaceAuthorityV1Args::new(
            acting_role_id,
            authority_to_replace_id,
            new_authority_config.authority_type,
            authority_data_len,
            actions_payload_len,
            start,
            end,
        );

        let data_payload = [authority_data, &actions_bytes].concat();
        let authority_payload = authority_payload_fn(&data_payload);

        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [
                args.as_bytes(),
                authority_data,
                &actions_bytes,
                &authority_payload,
            ]
            .concat(),
        })
    }
}
