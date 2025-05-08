use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    keccak::hash,
    pubkey::Pubkey,
    system_program,
};
pub use swig;
use swig::actions::{
    add_authority_v1::AddAuthorityV1Args, create_session_v1::CreateSessionV1Args,
    create_v1::CreateV1Args, remove_authority_v1::RemoveAuthorityV1Args,
};
pub use swig_compact_instructions::*;
use swig_state_x::{
    action::{
        all::All, manage_authority::ManageAuthority, program::Program, program_scope::ProgramScope,
        sol_limit::SolLimit, sol_recurring_limit::SolRecurringLimit, sub_account::SubAccount,
        token_limit::TokenLimit, token_recurring_limit::TokenRecurringLimit, Action, Permission,
    },
    authority::{secp256k1::AccountsPayload, AuthorityType},
    swig::swig_account_seeds,
    IntoBytes, Transmutable,
};

pub enum ClientAction {
    TokenLimit(TokenLimit),
    TokenRecurringLimit(TokenRecurringLimit),
    SolLimit(SolLimit),
    SolRecurringLimit(SolRecurringLimit),
    Program(Program),
    ProgramScope(ProgramScope),
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
            ClientAction::ProgramScope(_) => (Permission::ProgramScope, ProgramScope::LEN),
            ClientAction::All(_) => (Permission::All, All::LEN),
            ClientAction::ManageAuthority(_) => (Permission::ManageAuthority, ManageAuthority::LEN),
            ClientAction::SubAccount(_) => (Permission::SubAccount, SubAccount::LEN),
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
        data.extend_from_slice(header_bytes);
        let bytes_res = match self {
            ClientAction::TokenLimit(action) => action.into_bytes(),
            ClientAction::TokenRecurringLimit(action) => action.into_bytes(),
            ClientAction::SolLimit(action) => action.into_bytes(),
            ClientAction::SolRecurringLimit(action) => action.into_bytes(),
            ClientAction::Program(action) => action.into_bytes(),
            ClientAction::ProgramScope(action) => action.into_bytes(),
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

fn prepare_secp_payload(
    current_slot: u64,
    data_payload: &[u8],
    accounts_payload: &[u8],
) -> [u8; 32] {
    hash(&[data_payload, accounts_payload, &current_slot.to_le_bytes()].concat()).to_bytes()
}

fn accounts_payload_from_meta(meta: &AccountMeta) -> AccountsPayload {
    AccountsPayload::new(meta.pubkey.to_bytes(), meta.is_writable, meta.is_signer)
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
        mut authority_payload_fn: F,
        current_slot: u64,
        acting_role_id: u32,
        new_authority_config: AuthorityConfig,
        actions: Vec<ClientAction>,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ];
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
        let arg_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes
                .extend_from_slice(accounts_payload_from_meta(account).into_bytes().unwrap());
        }

        let mut signature_bytes = Vec::new();
        signature_bytes.extend_from_slice(arg_bytes);
        signature_bytes.extend_from_slice(new_authority_config.authority);
        signature_bytes.extend_from_slice(&action_bytes);
        let nonced_payload =
            prepare_secp_payload(current_slot, &signature_bytes, &account_payload_bytes);
        let signature = authority_payload_fn(&nonced_payload);
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&signature);
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [
                arg_bytes,
                new_authority_config.authority,
                &action_bytes,
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
        role_id: u32,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
        ];
        let (accounts, ixs) = compact_instructions(swig_account, accounts, vec![inner_instruction]);
        let ix_bytes = ixs.into_bytes();
        let args = swig::actions::sign_v1::SignV1Args::new(role_id, ix_bytes.len() as u16);
        let arg_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [arg_bytes, &ix_bytes, &[2]].concat(),
        })
    }

    pub fn new_secp256k1<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        inner_instruction: Instruction,
        role_id: u32,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ];
        let (accounts, ixs) = compact_instructions(swig_account, accounts, vec![inner_instruction]);
        let ix_bytes = ixs.into_bytes();
        let args = swig::actions::sign_v1::SignV1Args::new(role_id, ix_bytes.len() as u16);

        let arg_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        let mut signature_bytes = Vec::new();
        signature_bytes.extend_from_slice(&ix_bytes);
        let nonced_payload =
            prepare_secp_payload(current_slot, &signature_bytes, &account_payload_bytes);
        let signature = authority_payload_fn(&nonced_payload);
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&signature);
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [arg_bytes, &ix_bytes, &authority_payload].concat(),
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
        mut authority_payload_fn: F,
        acting_role_id: u32,
        authority_to_remove_id: u32,
        current_slot: u64,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ];
        let args = RemoveAuthorityV1Args::new(acting_role_id, authority_to_remove_id, 65);
        let arg_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        let mut signature_bytes = Vec::new();
        signature_bytes.extend_from_slice(arg_bytes);
        let nonced_payload =
            prepare_secp_payload(current_slot, &signature_bytes, &account_payload_bytes);
        let signature = authority_payload_fn(&nonced_payload);
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&signature);
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [arg_bytes, &authority_payload].concat(),
        })
    }
}

pub struct CreateSessionInstruction;
impl CreateSessionInstruction {
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        payer: Pubkey,
        authority: Pubkey,
        role_id: u32,
        session_key: Pubkey,
        session_duration: u64,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
        ];

        let create_session_args =
            CreateSessionV1Args::new(role_id, 1, session_duration, session_key.to_bytes());
        let args_bytes = create_session_args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [args_bytes, &[2]].concat(),
        })
    }

    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        role_id: u32,
        session_key: Pubkey,
        session_duration: u64,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ];
        let create_session_args =
            CreateSessionV1Args::new(role_id, 1, session_duration, session_key.to_bytes());
        let args_bytes = create_session_args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        let mut signature_bytes = Vec::new();
        signature_bytes.extend_from_slice(args_bytes);
        let nonced_payload =
            prepare_secp_payload(current_slot, &signature_bytes, &account_payload_bytes);
        let signature = authority_payload_fn(&nonced_payload);
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&signature);
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        })
    }
}

// Sub-account instruction structures
pub struct CreateSubAccountInstruction;

impl CreateSubAccountInstruction {
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        authority: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        sub_account_bump: u8,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(authority, true),
        ];

        let mut buffer = vec![];
        buffer.extend_from_slice(&(6u16).to_le_bytes()); // CreateSubAccountV1 = 6
        buffer.extend_from_slice(&0u16.to_le_bytes()); // padding
        buffer.extend_from_slice(&role_id.to_le_bytes());
        buffer.push(sub_account_bump);
        buffer.extend_from_slice(&[0; 7]); // padding
                                           // Add authority index (4 for Ed25519 authority - fifth account in accounts list)
        buffer.push(4);

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: buffer,
        })
    }

    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        sub_account: Pubkey,
        role_id: u32,
        sub_account_bump: u8,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ];

        let mut buffer = vec![];
        buffer.extend_from_slice(&(6u16).to_le_bytes()); // CreateSubAccountV1 = 6
        buffer.extend_from_slice(&0u16.to_le_bytes()); // padding
        buffer.extend_from_slice(&role_id.to_le_bytes());
        buffer.push(sub_account_bump);
        buffer.extend_from_slice(&[0; 7]); // padding

        let args_data = buffer.clone();

        // Create account payload for signature
        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        // Sign the payload
        let nonced_payload = prepare_secp_payload(current_slot, &args_data, &account_payload_bytes);
        let signature = authority_payload_fn(&nonced_payload);

        // Add authority payload
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&signature);

        // Combine all data
        buffer.extend_from_slice(&authority_payload);

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: buffer,
        })
    }
}

pub struct WithdrawFromSubAccountInstruction;

impl WithdrawFromSubAccountInstruction {
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        authority: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        amount: u64,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(authority, true),
        ];

        let mut buffer = vec![];
        buffer.extend_from_slice(&(7u16).to_le_bytes()); // WithdrawFromSubAccountV1 = 7
        buffer.extend_from_slice(&0u16.to_le_bytes()); // padding
        buffer.extend_from_slice(&role_id.to_le_bytes());
        buffer.extend_from_slice(&amount.to_le_bytes());
        // Add authority index (3 for Ed25519 authority - fourth account in accounts list)
        buffer.push(3);

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: buffer,
        })
    }

    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        sub_account: Pubkey,
        role_id: u32,
        amount: u64,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
        ];

        let mut buffer = vec![];
        buffer.extend_from_slice(&(7u16).to_le_bytes()); // WithdrawFromSubAccountV1 = 7
        buffer.extend_from_slice(&0u16.to_le_bytes()); // padding
        buffer.extend_from_slice(&role_id.to_le_bytes());
        buffer.extend_from_slice(&amount.to_le_bytes());

        let args_data = buffer.clone();

        // Create account payload for signature
        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        // Sign the payload
        let nonced_payload = prepare_secp_payload(current_slot, &args_data, &account_payload_bytes);
        let signature = authority_payload_fn(&nonced_payload);

        // Add authority payload
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&signature);

        // Combine all data
        buffer.extend_from_slice(&authority_payload);

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: buffer,
        })
    }
}

pub struct SubAccountSignInstruction;

impl SubAccountSignInstruction {
    pub fn new_with_ed25519_authority(
        sub_account: Pubkey,
        swig_account: Pubkey,
        authority: Pubkey,
        payer: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(authority, true),
        ];

        let mut instruction_data = vec![];
        for ix in &instructions {
            instruction_data.extend_from_slice(&ix.program_id.to_bytes());

            // Encode the accounts
            instruction_data.extend_from_slice(&(ix.accounts.len() as u16).to_le_bytes());
            for account in &ix.accounts {
                instruction_data.extend_from_slice(&account.pubkey.to_bytes());
                let meta_byte =
                    if account.is_signer { 1 } else { 0 } | if account.is_writable { 2 } else { 0 };
                instruction_data.push(meta_byte);
            }

            // Encode the data
            instruction_data.extend_from_slice(&(ix.data.len() as u16).to_le_bytes());
            instruction_data.extend_from_slice(&ix.data);
        }

        let instruction_payload_len = instruction_data.len() as u16;

        let mut buffer = vec![];
        buffer.extend_from_slice(&(9u16).to_le_bytes()); // SubAccountSignV1 = 9
        buffer.extend_from_slice(&instruction_payload_len.to_le_bytes());
        buffer.extend_from_slice(&role_id.to_le_bytes());
        buffer.extend_from_slice(&[0; 8]); // padding
        buffer.extend_from_slice(&instruction_data);
        // Add authority index (4 for Ed25519 authority - fifth account in accounts list)
        buffer.push(4);

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: buffer,
        })
    }

    pub fn new_with_secp256k1_authority<F>(
        sub_account: Pubkey,
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        role_id: u32,
        instructions: Vec<Instruction>,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ];

        let mut instruction_data = vec![];
        for ix in &instructions {
            instruction_data.extend_from_slice(&ix.program_id.to_bytes());

            // Encode the accounts
            instruction_data.extend_from_slice(&(ix.accounts.len() as u16).to_le_bytes());
            for account in &ix.accounts {
                instruction_data.extend_from_slice(&account.pubkey.to_bytes());
                let meta_byte =
                    if account.is_signer { 1 } else { 0 } | if account.is_writable { 2 } else { 0 };
                instruction_data.push(meta_byte);
            }

            // Encode the data
            instruction_data.extend_from_slice(&(ix.data.len() as u16).to_le_bytes());
            instruction_data.extend_from_slice(&ix.data);
        }

        let instruction_payload_len = instruction_data.len() as u16;

        let mut buffer = vec![];
        buffer.extend_from_slice(&(9u16).to_le_bytes()); // SubAccountSignV1 = 9
        buffer.extend_from_slice(&instruction_payload_len.to_le_bytes());
        buffer.extend_from_slice(&role_id.to_le_bytes());
        buffer.extend_from_slice(&[0; 8]); // padding
        buffer.extend_from_slice(&instruction_data);

        let args_data = buffer.clone();

        // Create account payload for signature
        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        // Sign the payload
        let nonced_payload = prepare_secp_payload(current_slot, &args_data, &account_payload_bytes);
        let signature = authority_payload_fn(&nonced_payload);

        // Add authority payload
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&signature);

        // Combine all data
        buffer.extend_from_slice(&authority_payload);

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: buffer,
        })
    }
}

pub struct ToggleSubAccountInstruction;

impl ToggleSubAccountInstruction {
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        authority: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        enabled: bool,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(authority, true),
        ];

        let mut buffer = vec![];
        buffer.extend_from_slice(&(10u16).to_le_bytes()); // ToggleSubAccountV1 = 10
        buffer.extend_from_slice(&[0]); // padding
        buffer.push(if enabled { 1 } else { 0 });
        buffer.extend_from_slice(&role_id.to_le_bytes());
        // Add authority index (3 for Ed25519 authority - fourth account in accounts list)
        buffer.push(3);

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: buffer,
        })
    }

    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        sub_account: Pubkey,
        role_id: u32,
        enabled: bool,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
        ];

        let mut buffer = vec![];
        buffer.extend_from_slice(&(10u16).to_le_bytes()); // ToggleSubAccountV1 = 10
        buffer.extend_from_slice(&[0]); // padding
        buffer.push(if enabled { 1 } else { 0 });
        buffer.extend_from_slice(&role_id.to_le_bytes());

        let args_data = buffer.clone();

        // Create account payload for signature
        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        // Sign the payload
        let nonced_payload = prepare_secp_payload(current_slot, &args_data, &account_payload_bytes);
        let signature = authority_payload_fn(&nonced_payload);

        // Add authority payload
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&signature);

        // Combine all data
        buffer.extend_from_slice(&authority_payload);

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: buffer,
        })
    }
}
