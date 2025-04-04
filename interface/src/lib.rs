use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    system_program,
};
pub use swig;
use swig::actions::{
    add_authority_v1::AddAuthorityV1Args, create_v1::CreateV1Args,
    remove_authority_v1::RemoveAuthorityV1Args,
};
pub use swig_compact_instructions::*;
use swig_state_x::{
    action::{
        all::All, manage_authority::ManageAuthority, program::Program, sol_limit::SolLimit,
        sol_recurring_limit::SolRecurringLimit, sub_account::SubAccount, token_limit::TokenLimit,
        token_recurring_limit::TokenRecurringLimit, Action, Permission,
    },
    authority::AuthorityType,
    swig::swig_account_seeds,
    IntoBytes, Transmutable,
};

pub enum ClientAction {
    TokenLimit(TokenLimit),
    TokenRecurringLimit(TokenRecurringLimit),
    SolLimit(SolLimit),
    SolRecurringLimit(SolRecurringLimit),
    Program(Program),
    All(All),
    ManageAuthority(ManageAuthority),
    SubAccount(SubAccount),
}

impl ClientAction {
    pub fn write(&self, data: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        let (permission, length) = match self {
            ClientAction::TokenLimit(_) => (Permission::TokenLimit, TokenLimit::LEN),
            ClientAction::TokenRecurringLimit(_) => {
                (Permission::TokenRecurringLimit, TokenRecurringLimit::LEN)
            },
            ClientAction::SolLimit(_) => (Permission::SolLimit, SolLimit::LEN),
            ClientAction::SolRecurringLimit(_) => {
                (Permission::SolRecurringLimit, SolRecurringLimit::LEN)
            },
            ClientAction::Program(_) => (Permission::Program, Program::LEN),
            ClientAction::All(_) => (Permission::All, All::LEN),
            ClientAction::ManageAuthority(_) => (Permission::ManageAuthority, ManageAuthority::LEN),
            ClientAction::SubAccount(_) => (Permission::SubAccount, SubAccount::LEN),
            _ => panic!("Invalid action"),
        };
        let offset = data.len() as u32;
        let header = Action::new(
            permission,
            length as u16,
            offset + Action::LEN as u32 + length as u32,
        );
        let header_bytes = header
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize header {:?}", e))?;
        data.extend_from_slice(&header_bytes);
        let bytes_res = match self {
            ClientAction::TokenLimit(action) => action.into_bytes(),
            ClientAction::TokenRecurringLimit(action) => action.into_bytes(),
            ClientAction::SolLimit(action) => action.into_bytes(),
            ClientAction::SolRecurringLimit(action) => action.into_bytes(),
            ClientAction::Program(action) => action.into_bytes(),
            ClientAction::All(action) => action.into_bytes(),
            ClientAction::ManageAuthority(action) => action.into_bytes(),
            ClientAction::SubAccount(action) => action.into_bytes(),
        };
        data.extend_from_slice(
            bytes_res.map_err(|e| anyhow::anyhow!("Failed to serialize action {:?}", e))?,
        );
        Ok(())
    }
}

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
        actions: Vec<ClientAction>,
        id: [u8; 32],
    ) -> anyhow::Result<Instruction> {
        let create = CreateV1Args::new(
            id,
            swig_bump_seed,
            initial_authority.authority_type,
            initial_authority.authority.len() as u16,
            actions.len() as u8,
        );
        let mut write = Vec::new();
        write.extend_from_slice(
            create
                .into_bytes()
                .map_err(|e| anyhow::anyhow!("Failed to serialize create {:?}", e))?,
        );
        write.extend_from_slice(initial_authority.authority);
        let mut action_bytes = Vec::new();
        for action in actions {
            action
                .write(&mut action_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to serialize action {:?}", e))?;
        }
        write.append(&mut action_bytes);
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts: vec![
                AccountMeta::new(swig_account, false),
                AccountMeta::new(payer, true),
                AccountMeta::new(system_program::ID, false),
            ],
            data: write,
        })
    }
}

pub struct AddAuthorityInstruction;
impl AddAuthorityInstruction {
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        payer: Pubkey,
        authority: Pubkey,
        acting_role_id: u32,
        new_authority_config: AuthorityConfig,
        actions: Vec<ClientAction>,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(authority, true),
        ];

        let mut write = Vec::new();
        let mut action_bytes = Vec::new();
        let num_actions = actions.len() as u8;
        for action in actions {
            action
                .write(&mut action_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to serialize action {:?}", e))?;
        }
        let args = AddAuthorityV1Args::new(
            acting_role_id,
            new_authority_config.authority_type,
            new_authority_config.authority.len() as u16,
            action_bytes.len() as u16,
            num_actions,
        );
        write.extend_from_slice(args.into_bytes().unwrap());
        write.extend_from_slice(new_authority_config.authority);
        write.extend_from_slice(&action_bytes);
        write.extend_from_slice(&[3]);
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: write,
        })
    }

    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        authority_payload_fn: F,
        acting_role_id: u32,
        new_authority_config: AuthorityConfig,
        actions: Vec<ClientAction>,
    ) -> anyhow::Result<Instruction>
    where
        F: Fn(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ];
        let mut write = Vec::new();
        let mut action_bytes = Vec::new();
        let num_actions = actions.len() as u8;
        for action in actions {
            action
                .write(&mut action_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to serialize action {:?}", e))?;
        }
        let args = AddAuthorityV1Args::new(
            acting_role_id,
            new_authority_config.authority_type,
            new_authority_config.authority.len() as u16,
            action_bytes.len() as u16,
            num_actions,
        );
        write.extend_from_slice(
            args.into_bytes()
                .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?,
        );

        let authority_payload = authority_payload_fn(&write);
        write.extend_from_slice(&authority_payload);
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: write,
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
        let args = swig::actions::sign_v1::SignV1Args::new(
            role_id as u32,
            1,
            ixs.inner_instructions.len() as u16,
        );
        let arg_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [arg_bytes, &[2], &ixs.into_bytes()].concat(),
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
        let args = swig::actions::sign_v1::SignV1Args::new(
            role_id as u32,
            64,
            ixs.inner_instructions.len() as u16,
        );
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [
                swig::actions::sign_v1::SignV1Args::LEN
                    .to_le_bytes()
                    .as_ref(),
                authority.as_ref(),
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
        acting_role_id: u32,
        authority_to_remove_id: u32,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(authority, true),
        ];

        let args = RemoveAuthorityV1Args::new(acting_role_id, authority_to_remove_id, 1);
        let arg_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [arg_bytes, &[3]].concat(),
        })
    }

    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        authority_payload_fn: F,
        acting_role_id: u32,
        authority_to_remove_id: u32,
    ) -> anyhow::Result<Instruction>
    where
        F: Fn(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ];
        let args = RemoveAuthorityV1Args::new(
            acting_role_id,
            authority_to_remove_id,
            65,
        );
        let arg_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload = authority_payload_fn(arg_bytes);
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [arg_bytes, &authority_payload].concat(),
        })
    }
}
