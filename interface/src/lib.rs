use borsh::{BorshDeserialize, BorshSerialize};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    system_program,
};
pub use swig;
use swig::{
    actions::{add_authority_v1::AddAuthorityV1Args, sign_v1::SignV1Args},
    util::ZeroCopy,
};
pub use swig_compact_instructions::*;
pub use swig_state;
use swig_state::{swig_account_seeds, Action, AuthorityType};

pub fn program_id() -> Pubkey {
    swig::ID.into()
}

pub fn swig_key(id: String) -> Pubkey {
    Pubkey::find_program_address(&swig_account_seeds(id.as_bytes()), &program_id()).0
}

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

    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        authority_payload_fn: F,
        acting_role_id: u8,
        new_authority_config: AuthorityConfig,
        start: u64,
        end: u64,
        actions: Vec<Action>,
    ) -> anyhow::Result<Instruction>
    where
        F: Fn(&[u8]) -> [u8; 64],
    {
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
                &authority_payload,
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

    pub fn new_secp256k1(
        swig_account: Pubkey,
        payer: Pubkey,
        authority: [u8; 64],
        inner_instructions: Vec<Instruction>,
        role_id: u8,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
        ];
        let (accounts, ixs) = compact_instructions(swig_account, accounts, inner_instructions);
        let args = SignV1Args::new(role_id, 64, ixs.inner_instructions.len() as u16);
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [args.as_bytes(), authority.as_ref(), &ixs.into_bytes()].concat(),
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
        authority_payload_fn: F,
        acting_role_id: u8,
        authority_to_remove_id: u8,
    ) -> anyhow::Result<Instruction>
    where
        F: Fn(&[u8]) -> [u8; 65],
    {
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
            data: [args.as_bytes(), &authority_payload].concat(),
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

pub struct InitializeBytecodeInstruction;
impl InitializeBytecodeInstruction {
    pub fn new(
        authority: Pubkey,
        bytecode_account: Pubkey,
        system_program: Pubkey,
        instructions: &[swig_state::VMInstruction],
    ) -> Instruction {
        let args = swig::actions::initialize_bytecode_v1::InitializeBytecodeV1Args::new(
            instructions.len() as u16,
        );
        let args_bytes = bytemuck::bytes_of(&args);
        let instructions_bytes =
            bytemuck::cast_slice::<swig_state::VMInstruction, u8>(instructions);

        // Create a buffer with proper alignment for both args and instructions
        let mut buffer = vec![0u8; args_bytes.len() + instructions_bytes.len()];
        buffer[..args_bytes.len()].copy_from_slice(args_bytes);
        buffer[args_bytes.len()..].copy_from_slice(instructions_bytes);

        println!("Args bytes: {:?}", args_bytes);
        println!("Instructions bytes: {:?}", instructions_bytes);

        Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts: vec![
                AccountMeta::new(authority, true),
                AccountMeta::new(bytecode_account, false),
                AccountMeta::new_readonly(system_program, false),
            ],
            data: buffer,
        }
    }
}

pub struct ExecuteBytecodeInstruction;
impl ExecuteBytecodeInstruction {
    pub fn new(
        bytecode_account: Pubkey,
        payer: Pubkey,
        account_indices: Option<Vec<u8>>,
    ) -> anyhow::Result<Instruction> {
        // Create the args first
        let args = swig::actions::execute_v1::ExecuteV1Args::new(
            account_indices.as_ref().map_or(0, |v| v.len() as u8),
        );

        // Create a buffer with proper alignment for the args
        let mut data = Vec::with_capacity(8 + account_indices.as_ref().map_or(0, |v| v.len()));

        // Add the args bytes (which are already properly aligned due to bytemuck)
        data.extend_from_slice(bytemuck::bytes_of(&args));

        // Add account indices if provided
        if let Some(ref indices) = account_indices {
            data.extend_from_slice(indices);
        }

        println!("Execute args bytes: {:?}", bytemuck::bytes_of(&args));
        println!("Account indices: {:?}", account_indices);
        println!("Final execute data: {:?}", data);

        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts: vec![
                AccountMeta::new(bytecode_account, false),
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data,
        })
    }
}

pub struct CreatePluginBytecodeInstruction;
impl CreatePluginBytecodeInstruction {
    pub fn new(
        plugin_bytecode_account: Pubkey,
        target_program: Pubkey,
        program_data: Pubkey,
        authority: Pubkey,
        system_program: Pubkey,
        instructions: &[swig_state::VMInstruction],
    ) -> Instruction {
        let args = swig::actions::create_plugin_bytecode_v1::CreatePluginBytecodeV1Args::new(
            instructions.len() as u16,
        );
        let args_bytes = bytemuck::bytes_of(&args);
        let instructions_bytes =
            bytemuck::cast_slice::<swig_state::VMInstruction, u8>(instructions);

        // Create a buffer with proper alignment for both args and instructions
        let mut buffer = vec![0u8; args_bytes.len() + instructions_bytes.len()];
        buffer[..args_bytes.len()].copy_from_slice(args_bytes);
        buffer[args_bytes.len()..].copy_from_slice(instructions_bytes);

        println!("Plugin Args bytes: {:?}", args_bytes);
        println!("Plugin Instructions bytes: {:?}", instructions_bytes);

        Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts: vec![
                AccountMeta::new(plugin_bytecode_account, false),
                AccountMeta::new_readonly(target_program, false),
                AccountMeta::new_readonly(program_data, false),
                AccountMeta::new(authority, true),
                AccountMeta::new_readonly(system_program, false),
            ],
            data: buffer,
        }
    }
}

pub struct ExecutePluginBytecodeInstruction;
impl ExecutePluginBytecodeInstruction {
    pub fn new(
        plugin_bytecode_account: Pubkey,
        target_program: Pubkey,
        result_account: Pubkey,
        payer: Pubkey,
        account_indices: Option<Vec<u8>>,
    ) -> anyhow::Result<Instruction> {
        // Create the args first
        let args = swig::actions::execute_plugin_v1::ExecutePluginV1Args::new(
            account_indices.as_ref().map_or(0, |v| v.len() as u8),
        );

        // Create a buffer with proper alignment for the args
        let mut data = Vec::with_capacity(8 + account_indices.as_ref().map_or(0, |v| v.len()));

        // Add the args bytes (which are already properly aligned due to bytemuck)
        data.extend_from_slice(bytemuck::bytes_of(&args));

        // Add account indices if provided
        if let Some(ref indices) = account_indices {
            data.extend_from_slice(indices);
        }

        println!("Plugin Execute args bytes: {:?}", bytemuck::bytes_of(&args));
        println!("Plugin Account indices: {:?}", account_indices);
        println!("Final plugin execute data: {:?}", data);

        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts: vec![
                AccountMeta::new(plugin_bytecode_account, false),
                AccountMeta::new_readonly(target_program, false),
                AccountMeta::new(result_account, false),
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data,
        })
    }
}
