mod replace_authority;

pub use replace_authority::ReplaceAuthorityInstruction;
use solana_sdk::{
    hash as sha256,
    instruction::{AccountMeta, Instruction},
    keccak,
    pubkey::Pubkey,
};
use solana_secp256r1_program::new_secp256r1_instruction_with_signature;
pub use swig;
use swig::actions::{
    add_authority_v1::AddAuthorityV1Args,
    close_swig_v1::CloseSwigV1Args,
    close_token_account_v1::CloseTokenAccountV1Args,
    create_session_v1::CreateSessionV1Args,
    create_sub_account_v1::CreateSubAccountV1Args,
    create_sub_account_v2::CreateSubAccountV2Args,
    create_v1::CreateV1Args,
    remove_authority_v1::RemoveAuthorityV1Args,
    set_rent_claimer_v1::SetRentClaimerV1Args,
    sub_account_sign_v1::SubAccountSignV1Args,
    sub_account_sign_v2::SubAccountSignV2Args,
    toggle_sub_account_v1::ToggleSubAccountV1Args,
    toggle_sub_account_v2::ToggleSubAccountV2Args,
    transfer_assets_v1::TransferAssetsV1Args,
    update_authority_v1::{AuthorityUpdateOperation, UpdateAuthorityV1Args},
    withdraw_from_sub_account_v1::WithdrawFromSubAccountV1Args,
    withdraw_from_sub_account_v2::WithdrawFromSubAccountV2Args,
};
pub use swig_compact_instructions::*;
use swig_state::{
    action::{
        all::All,
        all_but_manage_authority::AllButManageAuthority,
        close_swig_authority::CloseSwigAuthority,
        manage_authority::ManageAuthority,
        program::Program,
        program_all::ProgramAll,
        program_curated::ProgramCurated,
        program_scope::ProgramScope,
        replace_authority::ReplaceAuthority,
        sol_destination_limit::SolDestinationLimit,
        sol_limit::SolLimit,
        sol_recurring_destination_limit::SolRecurringDestinationLimit,
        sol_recurring_limit::SolRecurringLimit,
        stake_all::StakeAll,
        stake_limit::StakeLimit,
        stake_recurring_limit::StakeRecurringLimit,
        sub_account::SubAccount,
        sub_account_v2::{
            SubAccountV2All, SubAccountV2Create, SubAccountV2Sign, SubAccountV2Toggle,
            SubAccountV2Withdraw,
        },
        token_destination_limit::TokenDestinationLimit,
        token_limit::TokenLimit,
        token_recurring_destination_limit::TokenRecurringDestinationLimit,
        token_recurring_limit::TokenRecurringLimit,
        Action, Permission,
    },
    authority::{
        secp256k1::{hex_encode, AccountsPayload},
        AuthorityType,
    },
    swig::{swig_account_seeds, swig_wallet_address_seeds},
    IntoBytes, Transmutable,
};

pub enum ClientAction {
    TokenLimit(TokenLimit),
    TokenDestinationLimit(TokenDestinationLimit),
    TokenRecurringLimit(TokenRecurringLimit),
    TokenRecurringDestinationLimit(TokenRecurringDestinationLimit),
    SolLimit(SolLimit),
    SolRecurringLimit(SolRecurringLimit),
    SolDestinationLimit(SolDestinationLimit),
    SolRecurringDestinationLimit(SolRecurringDestinationLimit),
    Program(Program),
    ProgramAll(ProgramAll),
    ProgramCurated(ProgramCurated),
    ProgramScope(ProgramScope),
    All(All),
    AllButManageAuthority(AllButManageAuthority),
    ManageAuthority(ManageAuthority),
    ReplaceAuthority(ReplaceAuthority),
    CloseSwigAuthority(CloseSwigAuthority),
    SubAccount(SubAccount),
    SubAccountV2Create(SubAccountV2Create),
    SubAccountV2All(SubAccountV2All),
    SubAccountV2Sign(SubAccountV2Sign),
    SubAccountV2Withdraw(SubAccountV2Withdraw),
    SubAccountV2Toggle(SubAccountV2Toggle),
    StakeLimit(StakeLimit),
    StakeRecurringLimit(StakeRecurringLimit),
    StakeAll(StakeAll),
}

impl ClientAction {
    pub fn write(&self, data: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        let (permission, length) = match self {
            ClientAction::TokenLimit(_) => (Permission::TokenLimit, TokenLimit::LEN),
            ClientAction::TokenDestinationLimit(_) => (
                Permission::TokenDestinationLimit,
                TokenDestinationLimit::LEN,
            ),
            ClientAction::TokenRecurringLimit(_) => {
                (Permission::TokenRecurringLimit, TokenRecurringLimit::LEN)
            },
            ClientAction::TokenRecurringDestinationLimit(_) => (
                Permission::TokenRecurringDestinationLimit,
                TokenRecurringDestinationLimit::LEN,
            ),
            ClientAction::SolLimit(_) => (Permission::SolLimit, SolLimit::LEN),
            ClientAction::SolRecurringLimit(_) => {
                (Permission::SolRecurringLimit, SolRecurringLimit::LEN)
            },
            ClientAction::SolDestinationLimit(_) => {
                (Permission::SolDestinationLimit, SolDestinationLimit::LEN)
            },
            ClientAction::SolRecurringDestinationLimit(_) => (
                Permission::SolRecurringDestinationLimit,
                SolRecurringDestinationLimit::LEN,
            ),
            ClientAction::Program(_) => (Permission::Program, Program::LEN),
            ClientAction::ProgramAll(_) => (Permission::ProgramAll, ProgramAll::LEN),
            ClientAction::ProgramCurated(_) => (Permission::ProgramCurated, ProgramCurated::LEN),
            ClientAction::ProgramScope(_) => (Permission::ProgramScope, ProgramScope::LEN),
            ClientAction::All(_) => (Permission::All, All::LEN),
            ClientAction::AllButManageAuthority(_) => (
                Permission::AllButManageAuthority,
                AllButManageAuthority::LEN,
            ),
            ClientAction::ManageAuthority(_) => (Permission::ManageAuthority, ManageAuthority::LEN),
            ClientAction::ReplaceAuthority(_) => {
                (Permission::ReplaceAuthority, ReplaceAuthority::LEN)
            },
            ClientAction::CloseSwigAuthority(_) => {
                (Permission::CloseSwigAuthority, CloseSwigAuthority::LEN)
            },
            ClientAction::SubAccount(_) => (Permission::SubAccount, SubAccount::LEN),
            ClientAction::SubAccountV2Create(_) => {
                (Permission::SubAccountV2Create, SubAccountV2Create::LEN)
            },
            ClientAction::SubAccountV2All(_) => (Permission::SubAccountV2All, SubAccountV2All::LEN),
            ClientAction::SubAccountV2Sign(_) => {
                (Permission::SubAccountV2Sign, SubAccountV2Sign::LEN)
            },
            ClientAction::SubAccountV2Withdraw(_) => {
                (Permission::SubAccountV2Withdraw, SubAccountV2Withdraw::LEN)
            },
            ClientAction::SubAccountV2Toggle(_) => {
                (Permission::SubAccountV2Toggle, SubAccountV2Toggle::LEN)
            },
            ClientAction::StakeLimit(_) => (Permission::StakeLimit, StakeLimit::LEN),
            ClientAction::StakeRecurringLimit(_) => {
                (Permission::StakeRecurringLimit, StakeRecurringLimit::LEN)
            },
            ClientAction::StakeAll(_) => (Permission::StakeAll, StakeAll::LEN),
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
            ClientAction::TokenDestinationLimit(action) => action.into_bytes(),
            ClientAction::TokenRecurringLimit(action) => action.into_bytes(),
            ClientAction::TokenRecurringDestinationLimit(action) => action.into_bytes(),
            ClientAction::SolLimit(action) => action.into_bytes(),
            ClientAction::SolRecurringLimit(action) => action.into_bytes(),
            ClientAction::SolDestinationLimit(action) => action.into_bytes(),
            ClientAction::SolRecurringDestinationLimit(action) => action.into_bytes(),
            ClientAction::Program(action) => action.into_bytes(),
            ClientAction::ProgramAll(action) => action.into_bytes(),
            ClientAction::ProgramCurated(action) => action.into_bytes(),
            ClientAction::ProgramScope(action) => action.into_bytes(),
            ClientAction::All(action) => action.into_bytes(),
            ClientAction::AllButManageAuthority(action) => action.into_bytes(),
            ClientAction::ManageAuthority(action) => action.into_bytes(),
            ClientAction::ReplaceAuthority(action) => action.into_bytes(),
            ClientAction::CloseSwigAuthority(action) => action.into_bytes(),
            ClientAction::SubAccount(action) => action.into_bytes(),
            ClientAction::SubAccountV2Create(action) => action.into_bytes(),
            ClientAction::SubAccountV2All(action) => action.into_bytes(),
            ClientAction::SubAccountV2Sign(action) => action.into_bytes(),
            ClientAction::SubAccountV2Withdraw(action) => action.into_bytes(),
            ClientAction::SubAccountV2Toggle(action) => action.into_bytes(),
            ClientAction::StakeLimit(action) => action.into_bytes(),
            ClientAction::StakeRecurringLimit(action) => action.into_bytes(),
            ClientAction::StakeAll(action) => action.into_bytes(),
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

pub const PROGRAM_ID: [u8; 32] = swig::ID;

pub fn swig_key_bytes(id: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&swig_account_seeds(id), &program_id()).0
}

pub fn swig_wallet_address(config_address: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &swig_wallet_address_seeds(config_address.as_ref()),
        &program_id(),
    )
    .0
}

/// Builds the authority payload for ProgramExec instructions.
///
/// When `target_ix_index` is `None`, produces a 1-byte payload (legacy
/// behavior: authenticate against `current_index - 1`).
/// When `Some(idx)`, produces a 2-byte payload that explicitly specifies which
/// transaction instruction index to authenticate against.
fn build_program_exec_authority_payload(
    instruction_sysvar_index: u8,
    target_ix_index: Option<u8>,
) -> Vec<u8> {
    match target_ix_index {
        Some(idx) => vec![instruction_sysvar_index, idx],
        None => vec![instruction_sysvar_index],
    }
}

pub struct AuthorityConfig<'a> {
    pub authority_type: AuthorityType,
    pub authority: &'a [u8],
}

fn prepare_secp256k1_payload(
    current_slot: u64,
    counter: u32,
    data_payload: &[u8],
    accounts_payload: &[u8],
    prefix: &[u8],
) -> [u8; 32] {
    let compressed_payload = sha256::hash(
        &[
            data_payload,
            accounts_payload,
            &current_slot.to_le_bytes(),
            &counter.to_le_bytes(),
        ]
        .concat(),
    )
    .to_bytes();
    let mut compressed_payload_hex = [0u8; 64];
    hex_encode(&compressed_payload, &mut compressed_payload_hex);
    keccak::hash(&[prefix, &compressed_payload_hex].concat()).to_bytes()
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
        swig_wallet_address: Pubkey,
        wallet_address_bump: u8,
        initial_authority: AuthorityConfig,
        actions: Vec<ClientAction>,
        id: [u8; 32],
    ) -> anyhow::Result<Instruction> {
        let create = CreateV1Args::new(
            id,
            swig_bump_seed,
            initial_authority.authority_type,
            initial_authority.authority.len() as u16,
            wallet_address_bump,
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
                AccountMeta::new(swig_wallet_address, false),
                AccountMeta::new(solana_system_interface::program::ID, false),
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
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
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
        counter: u32,
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
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
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
        let nonced_payload = prepare_secp256k1_payload(
            current_slot,
            counter,
            &signature_bytes,
            &account_payload_bytes,
            &[],
        );
        let signature = authority_payload_fn(&nonced_payload);
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&counter.to_le_bytes());
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

    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        acting_role_id: u32,
        public_key: &[u8; 33],
        new_authority_config: AuthorityConfig,
        actions: Vec<ClientAction>,
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
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
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        // Create the message hash for secp256r1 authentication
        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        let mut data_to_besigned_bytes = Vec::new();
        data_to_besigned_bytes.extend_from_slice(args_bytes);
        data_to_besigned_bytes.extend_from_slice(new_authority_config.authority);
        data_to_besigned_bytes.extend_from_slice(&action_bytes);

        // Compute message hash (keccak for secp256r1 compatibility)
        let slot_bytes = current_slot.to_le_bytes();
        let counter_bytes = counter.to_le_bytes();
        let message_hash = keccak::hash(
            &[
                &data_to_besigned_bytes,
                &account_payload_bytes,
                &slot_bytes[..],
                &counter_bytes[..],
            ]
            .concat(),
        )
        .to_bytes();

        // Get signature from authority function
        let signature = authority_payload_fn(&message_hash);
        // Create secp256r1 verify instruction
        let secp256r1_verify_ix =
            new_secp256r1_instruction_with_signature(&message_hash, &signature, public_key);
        // For secp256r1, the authority payload includes slot, counter, instruction
        // index, and padding Must be at least 17 bytes to satisfy
        // secp256r1_authority_authenticate() requirements
        let instruction_sysvar_index = 3; // Instructions sysvar is at index 3
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes()); // 8 bytes
        authority_payload.extend_from_slice(&counter.to_le_bytes()); // 4 bytes
        authority_payload.push(instruction_sysvar_index as u8); // 1 byte: index of instruction sysvar
        authority_payload.extend_from_slice(&[0u8; 4]); // 4 bytes padding to meet 17 byte minimum

        let main_ix = Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [
                args_bytes,
                new_authority_config.authority,
                &action_bytes,
                &authority_payload,
            ]
            .concat(),
        };

        Ok(vec![secp256r1_verify_ix, main_ix])
    }

    pub fn new_with_program_exec(
        swig_account: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        acting_role_id: u32,
        new_authority_config: AuthorityConfig,
        actions: Vec<ClientAction>,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        // Add instructions sysvar at a stable index
        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

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

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, None);

        let main_ix = Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [
                arg_bytes,
                new_authority_config.authority,
                &action_bytes,
                &authority_payload,
            ]
            .concat(),
        };

        // Return both instructions - preceding instruction must come first
        Ok(vec![preceding_instruction, main_ix])
    }

    pub fn new_with_program_exec_ix_index(
        swig_account: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        acting_role_id: u32,
        new_authority_config: AuthorityConfig,
        actions: Vec<ClientAction>,
        target_ix_index: u8,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

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

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, Some(target_ix_index));

        let main_ix = Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [
                arg_bytes,
                new_authority_config.authority,
                &action_bytes,
                &authority_payload,
            ]
            .concat(),
        };

        Ok(vec![preceding_instruction, main_ix])
    }
}

pub struct SignV2Instruction;
impl SignV2Instruction {
    pub fn new_ed25519(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        authority: Pubkey,
        inner_instruction: Instruction,
        role_id: u32,
    ) -> anyhow::Result<Instruction> {
        Self::new_ed25519_with_signers(
            swig_account,
            swig_wallet_address,
            authority,
            inner_instruction,
            role_id,
            &[],
        )
    }

    pub fn new_ed25519_with_signers(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        authority: Pubkey,
        inner_instruction: Instruction,
        role_id: u32,
        transaction_signers: &[Pubkey],
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(authority, true),
        ];
        let (mut accounts, ixs) =
            compact_instructions(swig_account, accounts, vec![inner_instruction]);
        for account in &mut accounts {
            if transaction_signers
                .iter()
                .any(|signer| signer == &account.pubkey)
            {
                account.is_signer = true;
            }
        }
        let ix_bytes = ixs.into_bytes();
        let args = swig::actions::sign_v2::SignV2Args::new(role_id, ix_bytes.len() as u16);
        let arg_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [arg_bytes, &ix_bytes, &[2]].concat(),
        })
    }

    pub fn new_program_exec(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        inner_instruction: Instruction,
        role_id: u32,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new(payer, true),
        ];

        let (mut accounts, ixs) =
            compact_instructions(swig_account, accounts, vec![inner_instruction]);

        // Add instructions sysvar AFTER compact_instructions to ensure stable index
        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let ix_bytes = ixs.into_bytes();
        let args = swig::actions::sign_v2::SignV2Args::new(role_id, ix_bytes.len() as u16);
        let arg_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, None);

        let sign_ix = Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [arg_bytes, &ix_bytes, &authority_payload].concat(),
        };

        // Return both instructions - preceding instruction must come first
        Ok(vec![preceding_instruction, sign_ix])
    }

    pub fn new_program_exec_with_ix_index(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        inner_instruction: Instruction,
        role_id: u32,
        target_ix_index: u8,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new(payer, true),
        ];

        let (mut accounts, ixs) =
            compact_instructions(swig_account, accounts, vec![inner_instruction]);

        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let ix_bytes = ixs.into_bytes();
        let args = swig::actions::sign_v2::SignV2Args::new(role_id, ix_bytes.len() as u16);
        let arg_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, Some(target_ix_index));

        let sign_ix = Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [arg_bytes, &ix_bytes, &authority_payload].concat(),
        };

        Ok(vec![preceding_instruction, sign_ix])
    }

    pub fn new_secp256k1<F>(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        inner_instruction: Instruction,
        role_id: u32,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        Self::new_secp256k1_with_signers(
            swig_account,
            swig_wallet_address,
            authority_payload_fn,
            current_slot,
            counter,
            inner_instruction,
            role_id,
            &[],
        )
    }

    pub fn new_secp256k1_with_signers<F>(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        inner_instruction: Instruction,
        role_id: u32,
        transaction_signers: &[Pubkey],
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];
        let (mut accounts, ixs) =
            compact_instructions(swig_account, accounts, vec![inner_instruction]);
        for account in &mut accounts {
            if transaction_signers
                .iter()
                .any(|signer| signer == &account.pubkey)
            {
                account.is_signer = true;
            }
        }
        let ix_bytes = ixs.into_bytes();
        let args = swig::actions::sign_v2::SignV2Args::new(role_id, ix_bytes.len() as u16);

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

        let nonced_payload = prepare_secp256k1_payload(
            current_slot,
            counter,
            &signature_bytes,
            &account_payload_bytes,
            &[],
        );
        let signature = authority_payload_fn(&nonced_payload);
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&counter.to_le_bytes());
        authority_payload.extend_from_slice(&signature);

        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [arg_bytes, &ix_bytes, &authority_payload].concat(),
        })
    }

    pub fn new_secp256r1<F>(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        inner_instruction: Instruction,
        role_id: u32,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        Self::new_secp256r1_with_signers(
            swig_account,
            swig_wallet_address,
            authority_payload_fn,
            current_slot,
            counter,
            inner_instruction,
            role_id,
            public_key,
            &[],
        )
    }

    pub fn new_secp256r1_with_signers<F>(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        inner_instruction: Instruction,
        role_id: u32,
        public_key: &[u8; 33],
        transaction_signers: &[Pubkey],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
        ];
        let (mut accounts, ixs) =
            compact_instructions(swig_account, accounts, vec![inner_instruction]);
        for account in &mut accounts {
            if transaction_signers
                .iter()
                .any(|signer| signer == &account.pubkey)
            {
                account.is_signer = true;
            }
        }
        let ix_bytes = ixs.into_bytes();
        let args = swig::actions::sign_v2::SignV2Args::new(role_id, ix_bytes.len() as u16);

        let arg_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        // Create the message hash for secp256r1 authentication
        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        // Compute message hash (keccak for secp256r1 compatibility)
        let slot_bytes = current_slot.to_le_bytes();
        let counter_bytes = counter.to_le_bytes();
        let message_hash = keccak::hash(
            &[
                &ix_bytes,
                &account_payload_bytes,
                &slot_bytes[..],
                &counter_bytes[..],
            ]
            .concat(),
        )
        .to_bytes();

        // Get signature from authority function
        let signature = authority_payload_fn(&message_hash);

        // Create secp256r1 verify instruction
        let secp256r1_verify_ix =
            new_secp256r1_instruction_with_signature(&message_hash, &signature, public_key);

        // For secp256r1, the authority payload includes slot, counter, instruction
        // index, and padding Must be at least 17 bytes to satisfy
        // secp256r1_authority_authenticate() requirements
        let instruction_sysvar_index = 3; // Instructions sysvar is at index 3 for SignV2
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes()); // 8 bytes
        authority_payload.extend_from_slice(&counter.to_le_bytes()); // 4 bytes
        authority_payload.push(instruction_sysvar_index as u8); // 1 byte: index of instruction sysvar
        authority_payload.extend_from_slice(&[0u8; 4]); // 4 bytes padding to meet 17 byte minimum

        let main_ix = Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [arg_bytes, &ix_bytes, &authority_payload].concat(),
        };

        Ok(vec![secp256r1_verify_ix, main_ix])
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
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
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
        current_slot: u64,
        counter: u32,
        acting_role_id: u32,
        authority_to_remove_id: u32,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
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
        let nonced_payload = prepare_secp256k1_payload(
            current_slot,
            counter,
            &signature_bytes,
            &account_payload_bytes,
            &[],
        );
        let signature = authority_payload_fn(&nonced_payload);
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&counter.to_le_bytes());
        authority_payload.extend_from_slice(&signature);

        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [arg_bytes, &authority_payload].concat(),
        })
    }

    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        acting_role_id: u32,
        authority_to_remove_id: u32,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
        ];
        let args = RemoveAuthorityV1Args::new(acting_role_id, authority_to_remove_id, 17); // 17 bytes for secp256r1 authority payload
        let arg_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        // Create the message hash for secp256r1 authentication
        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        let mut data_to_be_signed_bytes = Vec::new();
        data_to_be_signed_bytes.extend_from_slice(arg_bytes);

        // Compute message hash (keccak for secp256r1 compatibility)
        let slot_bytes = current_slot.to_le_bytes();
        let counter_bytes = counter.to_le_bytes();
        let message_hash = keccak::hash(
            &[
                &data_to_be_signed_bytes,
                &account_payload_bytes,
                &slot_bytes[..],
                &counter_bytes[..],
            ]
            .concat(),
        )
        .to_bytes();

        // Get signature from authority function
        let signature = authority_payload_fn(&message_hash);

        // Create secp256r1 verify instruction
        let secp256r1_verify_ix =
            new_secp256r1_instruction_with_signature(&message_hash, &signature, public_key);

        // For secp256r1, the authority payload includes slot, counter, instruction
        // index, and padding
        let instruction_sysvar_index = 3; // Instructions sysvar is at index 3
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes()); // 8 bytes
        authority_payload.extend_from_slice(&counter.to_le_bytes()); // 4 bytes
        authority_payload.push(instruction_sysvar_index as u8); // 1 byte: index of instruction sysvar
        authority_payload.extend_from_slice(&[0u8; 4]); // 4 bytes padding to meet 17 byte minimum

        let main_ix = Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [arg_bytes, &authority_payload].concat(),
        };

        Ok(vec![secp256r1_verify_ix, main_ix])
    }

    pub fn new_with_program_exec(
        swig_account: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        acting_role_id: u32,
        authority_to_remove_id: u32,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        // Add instructions sysvar at a stable index
        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let args = RemoveAuthorityV1Args::new(acting_role_id, authority_to_remove_id, 1);
        let arg_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, None);

        let main_ix = Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [arg_bytes, &authority_payload].concat(),
        };

        // Return both instructions - preceding instruction must come first
        Ok(vec![preceding_instruction, main_ix])
    }

    pub fn new_with_program_exec_ix_index(
        swig_account: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        acting_role_id: u32,
        authority_to_remove_id: u32,
        target_ix_index: u8,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let args = RemoveAuthorityV1Args::new(acting_role_id, authority_to_remove_id, 1);
        let arg_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, Some(target_ix_index));

        let main_ix = Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [arg_bytes, &authority_payload].concat(),
        };

        Ok(vec![preceding_instruction, main_ix])
    }
}
pub enum UpdateAuthorityData {
    ReplaceAll(Vec<ClientAction>),
    AddActions(Vec<ClientAction>),
    RemoveActionsByType(Vec<u8>),
    RemoveActionsByIndex(Vec<u16>),
}

impl UpdateAuthorityData {
    fn to_operation_and_data(self) -> anyhow::Result<(AuthorityUpdateOperation, Vec<u8>)> {
        match self {
            UpdateAuthorityData::ReplaceAll(actions) => Ok((
                AuthorityUpdateOperation::ReplaceAll,
                Self::serialize_actions(actions)?,
            )),
            UpdateAuthorityData::AddActions(actions) => Ok((
                AuthorityUpdateOperation::AddActions,
                Self::serialize_actions(actions)?,
            )),
            UpdateAuthorityData::RemoveActionsByType(action_types) => {
                Ok((AuthorityUpdateOperation::RemoveActionsByType, action_types))
            },
            UpdateAuthorityData::RemoveActionsByIndex(indices) => {
                let mut index_bytes = Vec::new();
                for index in indices {
                    index_bytes.extend_from_slice(&index.to_le_bytes());
                }
                Ok((AuthorityUpdateOperation::RemoveActionsByIndex, index_bytes))
            },
        }
    }

    fn serialize_actions(actions: Vec<ClientAction>) -> anyhow::Result<Vec<u8>> {
        let mut action_bytes = Vec::new();
        for action in actions {
            action
                .write(&mut action_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to serialize action {:?}", e))?;
        }
        Ok(action_bytes)
    }
}

pub struct UpdateAuthorityInstruction;
impl UpdateAuthorityInstruction {
    /// Update authority using Ed25519 signature.
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        payer: Pubkey,
        authority: Pubkey,
        acting_role_id: u32,
        authority_to_update_id: u32,
        update_data: UpdateAuthorityData,
    ) -> anyhow::Result<Instruction> {
        let (operation, operation_data) = update_data.to_operation_and_data()?;
        Self::build_ed25519_instruction(
            swig_account,
            payer,
            authority,
            acting_role_id,
            authority_to_update_id,
            operation,
            operation_data,
        )
    }

    fn build_ed25519_instruction(
        swig_account: Pubkey,
        payer: Pubkey,
        authority: Pubkey,
        acting_role_id: u32,
        authority_to_update_id: u32,
        operation: AuthorityUpdateOperation,
        operation_data: Vec<u8>,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(authority, true),
        ];

        // Encode operation type in the first byte of the data
        let mut encoded_data = Vec::new();
        encoded_data.push(operation as u8);
        encoded_data.extend_from_slice(&operation_data);

        let args = UpdateAuthorityV1Args::new(
            acting_role_id,
            authority_to_update_id,
            encoded_data.len() as u16,
            0, // num_actions will be calculated by the program
        );

        let mut write = Vec::new();
        write.extend_from_slice(args.into_bytes().unwrap());
        write.extend_from_slice(&encoded_data);
        write.extend_from_slice(&[3]); // Ed25519 authority type

        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: write,
        })
    }

    /// Update authority using Secp256k1 signature.
    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        acting_role_id: u32,
        authority_to_update_id: u32,
        update_data: UpdateAuthorityData,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let (operation, operation_data) = update_data.to_operation_and_data()?;
        Self::build_secp256k1_instruction(
            swig_account,
            payer,
            authority_payload_fn,
            current_slot,
            counter,
            acting_role_id,
            authority_to_update_id,
            operation,
            operation_data,
        )
    }

    fn build_secp256k1_instruction<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        acting_role_id: u32,
        authority_to_update_id: u32,
        operation: AuthorityUpdateOperation,
        operation_data: Vec<u8>,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        // Encode operation type in the first byte of the data
        let mut encoded_data = Vec::new();
        encoded_data.push(operation as u8);
        encoded_data.extend_from_slice(&operation_data);

        let args = UpdateAuthorityV1Args::new(
            acting_role_id,
            authority_to_update_id,
            encoded_data.len() as u16,
            0, // num_actions will be calculated by the program
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
        signature_bytes.extend_from_slice(&encoded_data);
        let nonced_payload = prepare_secp256k1_payload(
            current_slot,
            counter,
            &signature_bytes,
            &account_payload_bytes,
            &[],
        );
        let signature = authority_payload_fn(&nonced_payload);
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&counter.to_le_bytes());
        authority_payload.extend_from_slice(&signature);

        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [arg_bytes, &encoded_data, &authority_payload].concat(),
        })
    }

    /// Update authority using Secp256r1 signature.
    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        acting_role_id: u32,
        authority_to_update_id: u32,
        update_data: UpdateAuthorityData,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let (operation, operation_data) = update_data.to_operation_and_data()?;
        Self::build_secp256r1_instruction(
            swig_account,
            payer,
            authority_payload_fn,
            current_slot,
            counter,
            acting_role_id,
            authority_to_update_id,
            operation,
            operation_data,
            public_key,
        )
    }

    fn build_secp256r1_instruction<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        acting_role_id: u32,
        authority_to_update_id: u32,
        operation: AuthorityUpdateOperation,
        operation_data: Vec<u8>,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
        ];

        // Encode operation type in the first byte of the data
        let mut encoded_data = Vec::new();
        encoded_data.push(operation as u8);
        encoded_data.extend_from_slice(&operation_data);

        let args = UpdateAuthorityV1Args::new(
            acting_role_id,
            authority_to_update_id,
            encoded_data.len() as u16,
            0, // num_actions will be calculated by the program
        );
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        // Create the message hash for secp256r1 authentication
        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        let mut data_to_be_signed_bytes = Vec::new();
        data_to_be_signed_bytes.extend_from_slice(args_bytes);
        data_to_be_signed_bytes.extend_from_slice(&encoded_data);

        // Compute message hash (keccak for secp256r1 compatibility)
        let slot_bytes = current_slot.to_le_bytes();
        let counter_bytes = counter.to_le_bytes();
        let message_hash = keccak::hash(
            &[
                &data_to_be_signed_bytes,
                &account_payload_bytes,
                &slot_bytes[..],
                &counter_bytes[..],
            ]
            .concat(),
        )
        .to_bytes();

        // Get signature from authority function
        let signature = authority_payload_fn(&message_hash);

        // Create secp256r1 verify instruction
        let secp256r1_verify_ix =
            new_secp256r1_instruction_with_signature(&message_hash, &signature, public_key);

        // For secp256r1, the authority payload includes slot, counter, instruction
        // index, and padding
        let instruction_sysvar_index = 3; // Instructions sysvar is at index 3
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes()); // 8 bytes
        authority_payload.extend_from_slice(&counter.to_le_bytes()); // 4 bytes
        authority_payload.push(instruction_sysvar_index as u8); // 1 byte: index of instruction sysvar
        authority_payload.extend_from_slice(&[0u8; 4]); // 4 bytes padding to meet 17 byte minimum

        let main_ix = Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [args_bytes, &encoded_data, &authority_payload].concat(),
        };

        Ok(vec![secp256r1_verify_ix, main_ix])
    }

    pub fn new_with_program_exec(
        swig_account: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        acting_role_id: u32,
        authority_to_update_id: u32,
        update_data: UpdateAuthorityData,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        // Add instructions sysvar at a stable index
        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let (operation, operation_data) = update_data.to_operation_and_data()?;

        // Encode operation type in the first byte of the data
        let mut encoded_data = Vec::new();
        encoded_data.push(operation as u8);
        encoded_data.extend_from_slice(&operation_data);

        let args = UpdateAuthorityV1Args::new(
            acting_role_id,
            authority_to_update_id,
            encoded_data.len() as u16,
            0, // num_actions will be calculated by the program
        );
        let arg_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, None);

        let main_ix = Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [arg_bytes, &encoded_data, &authority_payload].concat(),
        };

        // Return both instructions - preceding instruction must come first
        Ok(vec![preceding_instruction, main_ix])
    }

    pub fn new_with_program_exec_ix_index(
        swig_account: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        acting_role_id: u32,
        authority_to_update_id: u32,
        update_data: UpdateAuthorityData,
        target_ix_index: u8,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let (operation, operation_data) = update_data.to_operation_and_data()?;

        let mut encoded_data = Vec::new();
        encoded_data.push(operation as u8);
        encoded_data.extend_from_slice(&operation_data);

        let args = UpdateAuthorityV1Args::new(
            acting_role_id,
            authority_to_update_id,
            encoded_data.len() as u16,
            0,
        );
        let arg_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, Some(target_ix_index));

        let main_ix = Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [arg_bytes, &encoded_data, &authority_payload].concat(),
        };

        Ok(vec![preceding_instruction, main_ix])
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
            CreateSessionV1Args::new(role_id, session_duration, session_key.to_bytes());
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
        counter: u32,
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
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];
        let create_session_args =
            CreateSessionV1Args::new(role_id, session_duration, session_key.to_bytes());
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
        let nonced_payload = prepare_secp256k1_payload(
            current_slot,
            counter,
            &signature_bytes,
            &account_payload_bytes,
            &[],
        );
        let signature = authority_payload_fn(&nonced_payload);
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&counter.to_le_bytes());
        authority_payload.extend_from_slice(&signature);

        Ok(Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        })
    }

    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        role_id: u32,
        session_key: Pubkey,
        session_duration: u64,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
        ];
        let create_session_args =
            CreateSessionV1Args::new(role_id, session_duration, session_key.to_bytes());
        let args_bytes = create_session_args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        // Create the message hash for secp256r1 authentication
        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        let mut data_to_be_signed_bytes = Vec::new();
        data_to_be_signed_bytes.extend_from_slice(args_bytes);

        // Compute message hash (keccak for secp256r1 compatibility)
        let slot_bytes = current_slot.to_le_bytes();
        let counter_bytes = counter.to_le_bytes();
        let message_hash = keccak::hash(
            &[
                &data_to_be_signed_bytes,
                &account_payload_bytes,
                &slot_bytes[..],
                &counter_bytes[..],
            ]
            .concat(),
        )
        .to_bytes();

        // Get signature from authority function
        let signature = authority_payload_fn(&message_hash);

        // Create secp256r1 verify instruction
        let secp256r1_verify_ix =
            new_secp256r1_instruction_with_signature(&message_hash, &signature, public_key);

        // For secp256r1, the authority payload includes slot, counter, instruction
        // index, and padding
        let instruction_sysvar_index = 3; // Instructions sysvar is at index 3
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes()); // 8 bytes
        authority_payload.extend_from_slice(&counter.to_le_bytes()); // 4 bytes
        authority_payload.push(instruction_sysvar_index as u8); // 1 byte: index of instruction sysvar
        authority_payload.extend_from_slice(&[0u8; 4]); // 4 bytes padding to meet 17 byte minimum

        let main_ix = Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        Ok(vec![secp256r1_verify_ix, main_ix])
    }

    pub fn new_with_program_exec(
        swig_account: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        role_id: u32,
        session_duration: u64,
        session_key: Pubkey,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        // Add instructions sysvar at a stable index
        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let create_session_args =
            CreateSessionV1Args::new(role_id, session_duration, session_key.to_bytes());
        let args_bytes = create_session_args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, None);

        let main_ix = Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        // Return both instructions - preceding instruction must come first
        Ok(vec![preceding_instruction, main_ix])
    }

    pub fn new_with_program_exec_ix_index(
        swig_account: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        role_id: u32,
        session_duration: u64,
        session_key: Pubkey,
        target_ix_index: u8,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let create_session_args =
            CreateSessionV1Args::new(role_id, session_duration, session_key.to_bytes());
        let args_bytes = create_session_args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, Some(target_ix_index));

        let main_ix = Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        Ok(vec![preceding_instruction, main_ix])
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
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(authority, true),
        ];

        let args = CreateSubAccountV1Args::new(role_id, sub_account_bump);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &[4]].concat(),
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
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        let args = CreateSubAccountV1Args::new(role_id, sub_account_bump);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

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
        let nonced_payload =
            prepare_secp256k1_payload(current_slot, 0u32, args_bytes, &account_payload_bytes, &[]);
        let signature = authority_payload_fn(&nonced_payload);

        // Add authority payload
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&signature);

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        })
    }

    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        sub_account: Pubkey,
        role_id: u32,
        sub_account_bump: u8,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
        ];

        let args = CreateSubAccountV1Args::new(role_id, sub_account_bump);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        // Create the message hash for secp256r1 authentication
        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        let mut data_to_be_signed_bytes = Vec::new();
        data_to_be_signed_bytes.extend_from_slice(args_bytes);

        // Compute message hash (keccak for secp256r1 compatibility)
        let slot_bytes = current_slot.to_le_bytes();
        let counter_bytes = counter.to_le_bytes();
        let message_hash = keccak::hash(
            &[
                &data_to_be_signed_bytes,
                &account_payload_bytes,
                &slot_bytes[..],
                &counter_bytes[..],
            ]
            .concat(),
        )
        .to_bytes();

        // Get signature from authority function
        let signature = authority_payload_fn(&message_hash);

        // Create secp256r1 verify instruction
        let secp256r1_verify_ix =
            new_secp256r1_instruction_with_signature(&message_hash, &signature, public_key);

        // For secp256r1, the authority payload includes slot, counter, instruction
        // index, and padding
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes()); // 8 bytes
        authority_payload.extend_from_slice(&counter.to_le_bytes()); // 4 bytes
        authority_payload.push(4); // this is the index of the instruction sysvar

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        Ok(vec![secp256r1_verify_ix, main_ix])
    }

    pub fn new_with_program_exec(
        swig_account: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        sub_account: Pubkey,
        role_id: u32,
        sub_account_bump: u8,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        // Add instructions sysvar at a stable index
        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let args = CreateSubAccountV1Args::new(role_id, sub_account_bump);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, None);

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        // Return both instructions - preceding instruction must come first
        Ok(vec![preceding_instruction, main_ix])
    }

    pub fn new_with_program_exec_ix_index(
        swig_account: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        sub_account: Pubkey,
        role_id: u32,
        sub_account_bump: u8,
        target_ix_index: u8,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let args = CreateSubAccountV1Args::new(role_id, sub_account_bump);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, Some(target_ix_index));

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        Ok(vec![preceding_instruction, main_ix])
    }
}

pub struct WithdrawFromSubAccountInstruction;

impl WithdrawFromSubAccountInstruction {
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        authority: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        swig_wallet_address: Pubkey,
        role_id: u32,
        amount: u64,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        let args = WithdrawFromSubAccountV1Args::new(role_id, amount);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &[3]].concat(),
        })
    }

    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        sub_account: Pubkey,
        swig_wallet_address: Pubkey,
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
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        let args = WithdrawFromSubAccountV1Args::new(role_id, amount);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

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
        let nonced_payload =
            prepare_secp256k1_payload(current_slot, 0u32, args_bytes, &account_payload_bytes, &[]);
        let signature = authority_payload_fn(&nonced_payload);

        // Add authority payload
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&signature);

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        })
    }

    pub fn new_token_with_ed25519_authority(
        swig_account: Pubkey,
        authority: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        swig_wallet_address: Pubkey,
        sub_account_token: Pubkey,
        swig_token: Pubkey,
        token_program: Pubkey,
        role_id: u32,
        amount: u64,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new(sub_account_token, false),
            AccountMeta::new(swig_token, false),
            AccountMeta::new_readonly(token_program, false),
        ];

        let args = WithdrawFromSubAccountV1Args::new(role_id, amount);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &[3]].concat(),
        })
    }

    pub fn new_token_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        sub_account: Pubkey,
        swig_wallet_address: Pubkey,
        sub_account_token: Pubkey,
        swig_token: Pubkey,
        token_program: Pubkey,
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
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new(sub_account_token, false),
            AccountMeta::new(swig_token, false),
            AccountMeta::new_readonly(token_program, false),
        ];

        let args = WithdrawFromSubAccountV1Args::new(role_id, amount);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

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
        let nonced_payload =
            prepare_secp256k1_payload(current_slot, 0u32, args_bytes, &account_payload_bytes, &[]);
        let signature = authority_payload_fn(&nonced_payload);

        // Add authority payload
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&signature);

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        })
    }

    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        sub_account: Pubkey,
        swig_wallet_address: Pubkey,
        role_id: u32,
        amount: u64,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        let args = WithdrawFromSubAccountV1Args::new(role_id, amount);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        // Create the message hash for secp256r1 authentication
        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        let mut data_to_be_signed_bytes = Vec::new();
        data_to_be_signed_bytes.extend_from_slice(args_bytes);

        // Compute message hash (keccak for secp256r1 compatibility)
        let slot_bytes = current_slot.to_le_bytes();
        let counter_bytes = counter.to_le_bytes();
        let message_hash = keccak::hash(
            &[
                &data_to_be_signed_bytes,
                &account_payload_bytes,
                &slot_bytes[..],
                &counter_bytes[..],
            ]
            .concat(),
        )
        .to_bytes();

        // Get signature from authority function
        let signature = authority_payload_fn(&message_hash);

        // Create secp256r1 verify instruction
        let secp256r1_verify_ix =
            new_secp256r1_instruction_with_signature(&message_hash, &signature, public_key);

        // For secp256r1, the authority payload includes slot, counter, instruction
        // index, and padding
        let instruction_sysvar_index = 3; // Instructions sysvar is at index 3
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes()); // 8 bytes
        authority_payload.extend_from_slice(&counter.to_le_bytes()); // 4 bytes
        authority_payload.push(instruction_sysvar_index as u8); // 1 byte: index of instruction sysvar
        authority_payload.extend_from_slice(&[0u8; 4]); // 4 bytes padding to meet 17 byte minimum

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        Ok(vec![secp256r1_verify_ix, main_ix])
    }

    pub fn new_token_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        sub_account: Pubkey,
        swig_wallet_address: Pubkey,
        sub_account_token: Pubkey,
        swig_token: Pubkey,
        token_program: Pubkey,
        role_id: u32,
        amount: u64,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new(sub_account_token, false),
            AccountMeta::new(swig_token, false),
            AccountMeta::new_readonly(token_program, false),
        ];

        let args = WithdrawFromSubAccountV1Args::new(role_id, amount);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        // Create the message hash for secp256r1 authentication
        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        let mut data_to_be_signed_bytes = Vec::new();
        data_to_be_signed_bytes.extend_from_slice(args_bytes);

        // Compute message hash (keccak for secp256r1 compatibility)
        let slot_bytes = current_slot.to_le_bytes();
        let counter_bytes = counter.to_le_bytes();
        let message_hash = keccak::hash(
            &[
                &data_to_be_signed_bytes,
                &account_payload_bytes,
                &slot_bytes[..],
                &counter_bytes[..],
            ]
            .concat(),
        )
        .to_bytes();

        // Get signature from authority function
        let signature = authority_payload_fn(&message_hash);

        // Create secp256r1 verify instruction
        let secp256r1_verify_ix =
            new_secp256r1_instruction_with_signature(&message_hash, &signature, public_key);

        // For secp256r1, the authority payload includes slot, counter, instruction
        // index, and padding
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes()); // 8 bytes
        authority_payload.extend_from_slice(&counter.to_le_bytes()); // 4 bytes
        authority_payload.push(3); // this is the index of the instruction sysvar (account 3)

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        Ok(vec![secp256r1_verify_ix, main_ix])
    }

    pub fn new_with_program_exec(
        swig_account: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        sub_account: Pubkey,
        swig_wallet_address: Pubkey,
        role_id: u32,
        amount: u64,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        // Add instructions sysvar at a stable index
        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let args = WithdrawFromSubAccountV1Args::new(role_id, amount);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, None);

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        // Return both instructions - preceding instruction must come first
        Ok(vec![preceding_instruction, main_ix])
    }

    pub fn new_token_with_program_exec(
        swig_account: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        sub_account: Pubkey,
        swig_wallet_address: Pubkey,
        sub_account_token: Pubkey,
        swig_token: Pubkey,
        token_program: Pubkey,
        role_id: u32,
        amount: u64,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new(sub_account_token, false),
            AccountMeta::new(swig_token, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(token_program, false),
        ];

        // Add instructions sysvar at a stable index
        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let args = WithdrawFromSubAccountV1Args::new(role_id, amount);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, None);

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        // Return both instructions - preceding instruction must come first
        Ok(vec![preceding_instruction, main_ix])
    }

    pub fn new_with_program_exec_ix_index(
        swig_account: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        sub_account: Pubkey,
        swig_wallet_address: Pubkey,
        role_id: u32,
        amount: u64,
        target_ix_index: u8,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let args = WithdrawFromSubAccountV1Args::new(role_id, amount);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, Some(target_ix_index));

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        Ok(vec![preceding_instruction, main_ix])
    }

    pub fn new_token_with_program_exec_ix_index(
        swig_account: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        sub_account: Pubkey,
        swig_wallet_address: Pubkey,
        sub_account_token: Pubkey,
        swig_token: Pubkey,
        token_program: Pubkey,
        role_id: u32,
        amount: u64,
        target_ix_index: u8,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new(sub_account_token, false),
            AccountMeta::new(swig_token, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(token_program, false),
        ];

        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let args = WithdrawFromSubAccountV1Args::new(role_id, amount);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, Some(target_ix_index));

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        Ok(vec![preceding_instruction, main_ix])
    }
}

pub struct SubAccountSignInstruction;

impl SubAccountSignInstruction {
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        sub_account: Pubkey,
        authority: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new_readonly(swig_account, false),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(authority, true),
        ];
        let (accounts, ixs) =
            compact_instructions_sub_account(swig_account, sub_account, accounts, instructions);
        let ix_bytes = ixs.into_bytes();
        let args = SubAccountSignV1Args::new(role_id, ix_bytes.len() as u16);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &ix_bytes, &[3]].concat(),
        })
    }

    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        sub_account: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        role_id: u32,
        instructions: Vec<Instruction>,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new_readonly(swig_account, false),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        let (accounts, ixs) =
            compact_instructions_sub_account(swig_account, sub_account, accounts, instructions);
        let ix_bytes = ixs.into_bytes();
        let args = SubAccountSignV1Args::new(role_id, ix_bytes.len() as u16);
        let args_bytes = args
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

        // Sign the payload
        let nonced_payload =
            prepare_secp256k1_payload(current_slot, 0u32, &ix_bytes, &account_payload_bytes, &[]);
        let signature = authority_payload_fn(&nonced_payload);

        // Add authority payload
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&signature);

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &ix_bytes, &authority_payload].concat(),
        })
    }

    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        sub_account: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        role_id: u32,
        instructions: Vec<Instruction>,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new_readonly(swig_account, false),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
        ];

        let (accounts, ixs) =
            compact_instructions_sub_account(swig_account, sub_account, accounts, instructions);
        let ix_bytes = ixs.into_bytes();
        let args = SubAccountSignV1Args::new(role_id, ix_bytes.len() as u16);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        // Create the message hash for secp256r1 authentication
        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        let mut data_to_be_signed_bytes = Vec::new();
        data_to_be_signed_bytes.extend_from_slice(&ix_bytes);

        // Compute message hash (keccak for secp256r1 compatibility)
        let slot_bytes = current_slot.to_le_bytes();
        let counter_bytes = counter.to_le_bytes();
        let message_hash = keccak::hash(
            &[
                &data_to_be_signed_bytes,
                &account_payload_bytes,
                &slot_bytes[..],
                &counter_bytes[..],
            ]
            .concat(),
        )
        .to_bytes();

        // Get signature from authority function
        let signature = authority_payload_fn(&message_hash);

        // Create secp256r1 verify instruction
        let secp256r1_verify_ix =
            new_secp256r1_instruction_with_signature(&message_hash, &signature, public_key);

        // For secp256r1, the authority payload includes slot, counter, instruction
        // index, and padding
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes()); // 8 bytes
        authority_payload.extend_from_slice(&counter.to_le_bytes()); // 4 bytes
        authority_payload.push(4); // this is the index of the instruction sysvar

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &ix_bytes, &authority_payload].concat(),
        };

        Ok(vec![secp256r1_verify_ix, main_ix])
    }

    pub fn new_with_program_exec(
        swig_account: Pubkey,
        sub_account: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        role_id: u32,
        instructions: Vec<Instruction>,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new_readonly(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        // Add instructions sysvar at a stable index
        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let (accounts, ixs) =
            compact_instructions_sub_account(swig_account, sub_account, accounts, instructions);
        let ix_bytes = ixs.into_bytes();
        let args = SubAccountSignV1Args::new(role_id, ix_bytes.len() as u16);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, None);

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &ix_bytes, &authority_payload].concat(),
        };

        // Return both instructions - preceding instruction must come first
        Ok(vec![preceding_instruction, main_ix])
    }

    pub fn new_with_program_exec_ix_index(
        swig_account: Pubkey,
        sub_account: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        role_id: u32,
        instructions: Vec<Instruction>,
        target_ix_index: u8,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new_readonly(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let (accounts, ixs) =
            compact_instructions_sub_account(swig_account, sub_account, accounts, instructions);
        let ix_bytes = ixs.into_bytes();
        let args = SubAccountSignV1Args::new(role_id, ix_bytes.len() as u16);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, Some(target_ix_index));

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &ix_bytes, &authority_payload].concat(),
        };

        Ok(vec![preceding_instruction, main_ix])
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
        auth_role_id: u32,
        enabled: bool,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(authority, true),
        ];

        let args = ToggleSubAccountV1Args::new(role_id, auth_role_id, enabled);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &[3]].concat(),
        })
    }

    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        sub_account: Pubkey,
        role_id: u32,
        auth_role_id: u32,
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

        let args = ToggleSubAccountV1Args::new(role_id, auth_role_id, enabled);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        // Create account payload for signature
        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        let prefix = &[];

        // Sign the payload
        let nonced_payload = prepare_secp256k1_payload(
            current_slot,
            0u32,
            args_bytes,
            &account_payload_bytes,
            prefix,
        );
        let signature = authority_payload_fn(&nonced_payload);

        // Add authority payload
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&signature);

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        })
    }

    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        sub_account: Pubkey,
        role_id: u32,
        auth_role_id: u32,
        enabled: bool,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
        ];

        let args = ToggleSubAccountV1Args::new(role_id, auth_role_id, enabled);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        // Create the message hash for secp256r1 authentication
        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        let mut data_to_be_signed_bytes = Vec::new();
        data_to_be_signed_bytes.extend_from_slice(args_bytes);

        // Compute message hash (keccak for secp256r1 compatibility)
        let slot_bytes = current_slot.to_le_bytes();
        let counter_bytes = counter.to_le_bytes();
        let message_hash = keccak::hash(
            &[
                &data_to_be_signed_bytes,
                &account_payload_bytes,
                &slot_bytes[..],
                &counter_bytes[..],
            ]
            .concat(),
        )
        .to_bytes();

        // Get signature from authority function
        let signature = authority_payload_fn(&message_hash);

        // Create secp256r1 verify instruction
        let secp256r1_verify_ix =
            new_secp256r1_instruction_with_signature(&message_hash, &signature, public_key);

        // For secp256r1, the authority payload includes slot, counter, instruction
        // index, and padding
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes()); // 8 bytes
        authority_payload.extend_from_slice(&counter.to_le_bytes()); // 4 bytes
        authority_payload.push(4); // this is the index of the instruction sysvar

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        Ok(vec![secp256r1_verify_ix, main_ix])
    }

    pub fn new_with_program_exec(
        swig_account: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        sub_account: Pubkey,
        role_id: u32,
        auth_role_id: u32,
        enabled: bool,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
        ];

        // Add instructions sysvar at a stable index
        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let args = ToggleSubAccountV1Args::new(role_id, auth_role_id, enabled);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, None);

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        // Return both instructions - preceding instruction must come first
        Ok(vec![preceding_instruction, main_ix])
    }

    pub fn new_with_program_exec_ix_index(
        swig_account: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        sub_account: Pubkey,
        role_id: u32,
        auth_role_id: u32,
        enabled: bool,
        target_ix_index: u8,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
        ];

        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let args = ToggleSubAccountV1Args::new(role_id, auth_role_id, enabled);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, Some(target_ix_index));

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        Ok(vec![preceding_instruction, main_ix])
    }
}

pub struct TransferAssetsV1Instruction;

impl TransferAssetsV1Instruction {
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        payer: Pubkey,
        authority: Pubkey,
        role_id: u32,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(authority, true),
        ];

        let args = TransferAssetsV1Args::new(role_id);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &[4]].concat(), // Ed25519 authority index
        })
    }

    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        role_id: u32,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        let args = TransferAssetsV1Args::new(role_id);
        let args_bytes = args
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

        let prefix = &[];

        // Sign the payload
        let nonced_payload = prepare_secp256k1_payload(
            current_slot,
            0u32,
            args_bytes,
            &account_payload_bytes,
            prefix,
        );
        let signature = authority_payload_fn(&nonced_payload);

        // Add authority payload
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&signature);

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        })
    }

    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        role_id: u32,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
        ];

        let args = TransferAssetsV1Args::new(role_id);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        // Create the message hash for secp256r1 authentication
        let mut account_payload_bytes = Vec::new();
        for account in &accounts {
            account_payload_bytes.extend_from_slice(
                accounts_payload_from_meta(account)
                    .into_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
            );
        }

        let mut data_to_be_signed_bytes = Vec::new();
        data_to_be_signed_bytes.extend_from_slice(args_bytes);

        // Compute message hash (keccak for secp256r1 compatibility)
        let slot_bytes = current_slot.to_le_bytes();
        let counter_bytes = counter.to_le_bytes();
        let message_hash = keccak::hash(
            &[
                &data_to_be_signed_bytes,
                &account_payload_bytes,
                &slot_bytes[..],
                &counter_bytes[..],
            ]
            .concat(),
        )
        .to_bytes();

        // Get signature from authority function
        let signature = authority_payload_fn(&message_hash);

        // Create secp256r1 verify instruction
        let secp256r1_verify_ix =
            new_secp256r1_instruction_with_signature(&message_hash, &signature, public_key);

        // For secp256r1, the authority payload includes slot, counter, instruction
        // index, and padding
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes()); // 8 bytes
        authority_payload.extend_from_slice(&counter.to_le_bytes()); // 4 bytes
        authority_payload.push(4); // this is the index of the instruction sysvar

        // Create the main instruction
        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        Ok(vec![secp256r1_verify_ix, main_ix])
    }

    pub fn new_with_program_exec(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        role_id: u32,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        // Add instructions sysvar at a stable index
        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let args = TransferAssetsV1Args::new(role_id);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, None);

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        // Return both instructions - preceding instruction must come first
        Ok(vec![preceding_instruction, main_ix])
    }

    pub fn new_with_program_exec_ix_index(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        role_id: u32,
        target_ix_index: u8,
    ) -> anyhow::Result<Vec<Instruction>> {
        use solana_sdk::sysvar::instructions::ID as INSTRUCTIONS_ID;

        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        let instruction_sysvar_index = accounts.len() as u8;
        accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_ID, false));

        let args = TransferAssetsV1Args::new(role_id);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        let authority_payload =
            build_program_exec_authority_payload(instruction_sysvar_index, Some(target_ix_index));

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        Ok(vec![preceding_instruction, main_ix])
    }
}

/// Instruction builder for setting an immutable rent claimer on a swig wallet.
pub struct SetRentClaimerV1Instruction;

impl SetRentClaimerV1Instruction {
    /// Create a set rent-claimer instruction with Ed25519 authority.
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        payer: Pubkey,
        authority: Pubkey,
        role_id: u32,
        rent_claimer: [u8; 32],
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(authority, true),
        ];

        let args = SetRentClaimerV1Args::new(role_id, rent_claimer);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &[3]].concat(),
        })
    }

    /// Create a set rent-claimer instruction with Secp256k1 authority.
    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        role_id: u32,
        rent_claimer: [u8; 32],
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        let args = SetRentClaimerV1Args::new(role_id, rent_claimer);
        let args_bytes = args
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

        let nonced_payload = prepare_secp256k1_payload(
            current_slot,
            counter,
            args_bytes,
            &account_payload_bytes,
            &[],
        );
        let signature = authority_payload_fn(&nonced_payload);
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&counter.to_le_bytes());
        authority_payload.extend_from_slice(&signature);

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        })
    }

    /// Create a set rent-claimer instruction with Secp256r1 authority.
    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        role_id: u32,
        rent_claimer: [u8; 32],
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
        ];

        let args = SetRentClaimerV1Args::new(role_id, rent_claimer);
        let args_bytes = args
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

        let slot_bytes = current_slot.to_le_bytes();
        let counter_bytes = counter.to_le_bytes();
        let message_hash = keccak::hash(
            &[
                args_bytes,
                &account_payload_bytes,
                &slot_bytes[..],
                &counter_bytes[..],
            ]
            .concat(),
        )
        .to_bytes();

        let signature = authority_payload_fn(&message_hash);
        let secp256r1_verify_ix =
            new_secp256r1_instruction_with_signature(&message_hash, &signature, public_key);

        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&counter.to_le_bytes());
        authority_payload.push(3); // instruction sysvar index
        authority_payload.extend_from_slice(&[0u8; 4]);

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        Ok(vec![secp256r1_verify_ix, main_ix])
    }
}

/// Instruction builder for closing a single token account owned by the swig
/// wallet.
pub struct CloseTokenAccountV1Instruction;

impl CloseTokenAccountV1Instruction {
    /// Create a close token account instruction with Ed25519 authority.
    ///
    /// # Arguments
    /// * `swig_account` - The swig wallet account
    /// * `swig_wallet_address` - The swig wallet address PDA
    /// * `authority` - The authority with All or ManageAuthority permission
    /// * `token_account` - The token account to close (must have zero balance)
    /// * `destination` - Where to send the rent
    /// * `token_program` - SPL Token or Token-2022 program
    /// * `role_id` - The role ID of the authority
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        authority: Pubkey,
        destination: Pubkey,
        token_program: Pubkey,
        token_accounts: Vec<Pubkey>,
        role_id: u32,
    ) -> anyhow::Result<Instruction> {
        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new(destination, false),
            // AccountMeta::new(token_account, false),
            AccountMeta::new_readonly(token_program, false),
            AccountMeta::new_readonly(authority, true),
        ];

        let token_account_index = accounts.len();

        let token_account_metas: Vec<AccountMeta> = token_accounts
            .into_iter()
            .map(|t| AccountMeta::new(t, false))
            .collect();

        accounts.extend(token_account_metas);

        let args = CloseTokenAccountV1Args::new(role_id, token_account_index as u16);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &[4]].concat(), // Ed25519 authority index
        })
    }

    /// Create a close token account instruction with Secp256k1 authority.
    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        destination: Pubkey,
        token_program: Pubkey,
        token_accounts: Vec<Pubkey>,
        role_id: u32,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new(destination, false),
            // AccountMeta::new(token_account, false),
            AccountMeta::new_readonly(token_program, false),
        ];

        let token_account_index = accounts.len();

        let token_account_metas: Vec<AccountMeta> = token_accounts
            .into_iter()
            .map(|t| AccountMeta::new(t, false))
            .collect();

        accounts.extend(token_account_metas);

        let args = CloseTokenAccountV1Args::new(role_id, token_account_index as u16);

        let args_bytes = args
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

        let nonced_payload = prepare_secp256k1_payload(
            current_slot,
            counter,
            args_bytes,
            &account_payload_bytes,
            &[],
        );
        let signature = authority_payload_fn(&nonced_payload);
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&counter.to_le_bytes());
        authority_payload.extend_from_slice(&signature);

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        })
    }

    /// Create a close token account instruction with Secp256r1 authority.
    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        destination: Pubkey,
        token_program: Pubkey,
        token_accounts: Vec<Pubkey>,
        role_id: u32,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let mut accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(token_program, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
        ];

        let token_account_index = accounts.len();

        let token_account_metas: Vec<AccountMeta> = token_accounts
            .into_iter()
            .map(|t| AccountMeta::new(t, false))
            .collect();

        accounts.extend(token_account_metas);

        let args = CloseTokenAccountV1Args::new(role_id, token_account_index as u16);
        let args_bytes = args
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

        let slot_bytes = current_slot.to_le_bytes();
        let counter_bytes = counter.to_le_bytes();
        let message_hash = keccak::hash(
            &[
                args_bytes,
                &account_payload_bytes,
                &slot_bytes[..],
                &counter_bytes[..],
            ]
            .concat(),
        )
        .to_bytes();

        let signature = authority_payload_fn(&message_hash);
        let secp256r1_verify_ix =
            new_secp256r1_instruction_with_signature(&message_hash, &signature, public_key);

        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&counter.to_le_bytes());
        authority_payload.push(4); // instruction sysvar index
        authority_payload.extend_from_slice(&[0u8; 4]);

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        Ok(vec![secp256r1_verify_ix, main_ix])
    }
}

/// Instruction builder for closing a swig wallet account.
pub struct CloseSwigV1Instruction;

impl CloseSwigV1Instruction {
    /// Create a close swig instruction with Ed25519 authority.
    ///
    /// # Arguments
    /// * `swig_account` - The swig wallet account to close
    /// * `swig_wallet_address` - The swig wallet address PDA
    /// * `authority` - The authority with All or ManageAuthority permission
    /// * `destination` - Where to send all SOL and rent
    /// * `role_id` - The role ID of the authority
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        authority: Pubkey,
        destination: Pubkey,
        role_id: u32,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(authority, true),
        ];

        let args = CloseSwigV1Args::new(role_id);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &[4]].concat(), // Ed25519 authority index
        })
    }

    /// Create a close swig instruction with Secp256k1 authority.
    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        destination: Pubkey,
        role_id: u32,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];

        let args = CloseSwigV1Args::new(role_id);
        let args_bytes = args
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

        let nonced_payload = prepare_secp256k1_payload(
            current_slot,
            counter,
            args_bytes,
            &account_payload_bytes,
            &[],
        );
        let signature = authority_payload_fn(&nonced_payload);
        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&counter.to_le_bytes());
        authority_payload.extend_from_slice(&signature);

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        })
    }

    /// Create a close swig instruction with Secp256r1 authority.
    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        destination: Pubkey,
        role_id: u32,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
        ];

        let args = CloseSwigV1Args::new(role_id);
        let args_bytes = args
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

        let slot_bytes = current_slot.to_le_bytes();
        let counter_bytes = counter.to_le_bytes();
        let message_hash = keccak::hash(
            &[
                args_bytes,
                &account_payload_bytes,
                &slot_bytes[..],
                &counter_bytes[..],
            ]
            .concat(),
        )
        .to_bytes();

        let signature = authority_payload_fn(&message_hash);
        let secp256r1_verify_ix =
            new_secp256r1_instruction_with_signature(&message_hash, &signature, public_key);

        let mut authority_payload = Vec::new();
        authority_payload.extend_from_slice(&current_slot.to_le_bytes());
        authority_payload.extend_from_slice(&counter.to_le_bytes());
        authority_payload.push(4); // instruction sysvar index
        authority_payload.extend_from_slice(&[0u8; 4]);

        let main_ix = Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        };

        Ok(vec![secp256r1_verify_ix, main_ix])
    }
}

/// Instruction builders for V2 sub-accounts (Ed25519, Secp256k1, Secp256r1).
///
/// The authority-payload construction mirrors the V1 builders: Ed25519 appends
/// the signer account index; Secp256k1 appends `slot ++ signature`; Secp256r1
/// emits a precompile verify instruction plus a `slot ++ counter ++
/// sysvar_index` payload.
pub struct CreateSubAccountV2Instruction;

impl CreateSubAccountV2Instruction {
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        authority: Pubkey,
        payer: Pubkey,
        sub_account_state: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        state_bump: u8,
        asset_bump: u8,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new(sub_account_state, false),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(authority, true),
        ];
        let args = CreateSubAccountV2Args::new(role_id, state_bump, asset_bump);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        // Ed25519 authority payload is the index of the authority signer account.
        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &[5]].concat(),
        })
    }

    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        sub_account_state: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        state_bump: u8,
        asset_bump: u8,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new(sub_account_state, false),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];
        let args = CreateSubAccountV2Args::new(role_id, state_bump, asset_bump);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        let account_payload_bytes = secp_account_payload(&accounts)?;
        let authority_payload = secp256k1_v2_authority_payload(
            args_bytes,
            &account_payload_bytes,
            current_slot,
            counter,
            &mut authority_payload_fn,
        );
        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        })
    }

    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        sub_account_state: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        state_bump: u8,
        asset_bump: u8,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new(sub_account_state, false),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
        ];
        let args = CreateSubAccountV2Args::new(role_id, state_bump, asset_bump);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        // Instructions sysvar is the last account (index 5).
        secp256r1_v2_instructions(
            &accounts,
            args_bytes,
            args_bytes,
            current_slot,
            counter,
            5,
            &mut authority_payload_fn,
            public_key,
        )
    }
}

pub struct ToggleSubAccountV2Instruction;

impl ToggleSubAccountV2Instruction {
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        authority: Pubkey,
        payer: Pubkey,
        sub_account_state: Pubkey,
        auth_role_id: u32,
        subacc_id: u32,
        enabled: bool,
    ) -> anyhow::Result<Instruction> {
        // The payer is writable to match the instruction's declared accounts and
        // the Secp variants below. Those cannot use `new_readonly`: the signed
        // account payload is built from these metas client-side but rebuilt from
        // the runtime `AccountInfo` on-chain, and a fee-paying account is always
        // writable at runtime, so the two would disagree.
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new(sub_account_state, false),
            AccountMeta::new_readonly(authority, true),
        ];
        let args = ToggleSubAccountV2Args::new(auth_role_id, subacc_id, enabled);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &[3]].concat(),
        })
    }

    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        sub_account_state: Pubkey,
        auth_role_id: u32,
        subacc_id: u32,
        enabled: bool,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new(sub_account_state, false),
        ];
        let args = ToggleSubAccountV2Args::new(auth_role_id, subacc_id, enabled);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        let account_payload_bytes = secp_account_payload(&accounts)?;
        let authority_payload = secp256k1_v2_authority_payload(
            args_bytes,
            &account_payload_bytes,
            current_slot,
            counter,
            &mut authority_payload_fn,
        );
        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        })
    }

    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        sub_account_state: Pubkey,
        auth_role_id: u32,
        subacc_id: u32,
        enabled: bool,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new(sub_account_state, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
        ];
        let args = ToggleSubAccountV2Args::new(auth_role_id, subacc_id, enabled);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        // Instructions sysvar is the last account (index 4).
        secp256r1_v2_instructions(
            &accounts,
            args_bytes,
            args_bytes,
            current_slot,
            counter,
            4,
            &mut authority_payload_fn,
            public_key,
        )
    }
}

pub struct SubAccountSignV2Instruction;

impl SubAccountSignV2Instruction {
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        sub_account_state: Pubkey,
        sub_account: Pubkey,
        authority: Pubkey,
        role_id: u32,
        subacc_id: u32,
        instructions: Vec<Instruction>,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(sub_account_state, false),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(authority, true),
        ];
        let (accounts, ixs) =
            compact_instructions_sub_account(swig_account, sub_account, accounts, instructions);
        let ix_bytes = ixs.into_bytes();
        let args = SubAccountSignV2Args::new(role_id, subacc_id, ix_bytes.len() as u16);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &ix_bytes, &[4]].concat(),
        })
    }

    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        sub_account_state: Pubkey,
        sub_account: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        role_id: u32,
        subacc_id: u32,
        instructions: Vec<Instruction>,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(sub_account_state, false),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];
        let (accounts, ixs) =
            compact_instructions_sub_account(swig_account, sub_account, accounts, instructions);
        let ix_bytes = ixs.into_bytes();
        let args = SubAccountSignV2Args::new(role_id, subacc_id, ix_bytes.len() as u16);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        let data_payload = [args_bytes, &ix_bytes].concat();
        let account_payload_bytes = secp_account_payload(&accounts)?;
        let authority_payload = secp256k1_v2_authority_payload(
            &data_payload,
            &account_payload_bytes,
            current_slot,
            counter,
            &mut authority_payload_fn,
        );
        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &ix_bytes, &authority_payload].concat(),
        })
    }

    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        sub_account_state: Pubkey,
        sub_account: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        role_id: u32,
        subacc_id: u32,
        instructions: Vec<Instruction>,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(sub_account_state, false),
            AccountMeta::new(sub_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
        ];
        let (accounts, ixs) =
            compact_instructions_sub_account(swig_account, sub_account, accounts, instructions);
        let ix_bytes = ixs.into_bytes();
        let args = SubAccountSignV2Args::new(role_id, subacc_id, ix_bytes.len() as u16);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        // Instructions sysvar is the last base account (index 4); CPI accounts
        // are appended after it by the compaction step.
        let data_prefix = [args_bytes, &ix_bytes].concat();
        secp256r1_v2_instructions(
            &accounts,
            &data_prefix,
            &data_prefix,
            current_slot,
            counter,
            4,
            &mut authority_payload_fn,
            public_key,
        )
    }
}

pub struct WithdrawFromSubAccountV2Instruction;

impl WithdrawFromSubAccountV2Instruction {
    /// Builds a SOL withdrawal.
    pub fn new_with_ed25519_authority(
        swig_account: Pubkey,
        authority: Pubkey,
        payer: Pubkey,
        sub_account_state: Pubkey,
        sub_account: Pubkey,
        swig_wallet_address: Pubkey,
        role_id: u32,
        subacc_id: u32,
        amount: u64,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(sub_account_state, false),
            AccountMeta::new(sub_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];
        let args = WithdrawFromSubAccountV2Args::new(role_id, subacc_id, amount);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        // Authority context (the Ed25519 signer) is at index 5.
        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &[5]].concat(),
        })
    }

    /// Builds a token withdrawal with all token accounts included before the
    /// instruction is signed.
    #[allow(clippy::too_many_arguments)]
    pub fn new_token_with_ed25519_authority(
        swig_account: Pubkey,
        authority: Pubkey,
        payer: Pubkey,
        sub_account_state: Pubkey,
        sub_account: Pubkey,
        swig_wallet_address: Pubkey,
        source_token: Pubkey,
        destination_token: Pubkey,
        token_program: Pubkey,
        role_id: u32,
        subacc_id: u32,
        amount: u64,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(sub_account_state, false),
            AccountMeta::new(sub_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new(source_token, false),
            AccountMeta::new(destination_token, false),
            AccountMeta::new_readonly(token_program, false),
        ];
        let args = WithdrawFromSubAccountV2Args::new(role_id, subacc_id, amount);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &[5]].concat(),
        })
    }

    pub fn new_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        sub_account_state: Pubkey,
        sub_account: Pubkey,
        swig_wallet_address: Pubkey,
        role_id: u32,
        subacc_id: u32,
        amount: u64,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(sub_account_state, false),
            AccountMeta::new(sub_account, false),
            AccountMeta::new(swig_wallet_address, false),
            // authority_context placeholder for Secp256k1
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];
        let args = WithdrawFromSubAccountV2Args::new(role_id, subacc_id, amount);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        let account_payload_bytes = secp_account_payload(&accounts)?;
        let authority_payload = secp256k1_v2_authority_payload(
            args_bytes,
            &account_payload_bytes,
            current_slot,
            counter,
            &mut authority_payload_fn,
        );
        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        })
    }

    /// Builds a Secp256k1 token withdrawal. Token accounts are part of the
    /// authenticated account payload and cannot be appended after signing.
    #[allow(clippy::too_many_arguments)]
    pub fn new_token_with_secp256k1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        sub_account_state: Pubkey,
        sub_account: Pubkey,
        swig_wallet_address: Pubkey,
        source_token: Pubkey,
        destination_token: Pubkey,
        token_program: Pubkey,
        role_id: u32,
        subacc_id: u32,
        amount: u64,
    ) -> anyhow::Result<Instruction>
    where
        F: FnMut(&[u8]) -> [u8; 65],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(sub_account_state, false),
            AccountMeta::new(sub_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new(source_token, false),
            AccountMeta::new(destination_token, false),
            AccountMeta::new_readonly(token_program, false),
        ];
        let args = WithdrawFromSubAccountV2Args::new(role_id, subacc_id, amount);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        let account_payload_bytes = secp_account_payload(&accounts)?;
        let authority_payload = secp256k1_v2_authority_payload(
            args_bytes,
            &account_payload_bytes,
            current_slot,
            counter,
            &mut authority_payload_fn,
        );
        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: [args_bytes, &authority_payload].concat(),
        })
    }

    pub fn new_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        sub_account_state: Pubkey,
        sub_account: Pubkey,
        swig_wallet_address: Pubkey,
        role_id: u32,
        subacc_id: u32,
        amount: u64,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(sub_account_state, false),
            AccountMeta::new(sub_account, false),
            AccountMeta::new(swig_wallet_address, false),
            // authority_context is the instructions sysvar for Secp256r1 (index 5)
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];
        let args = WithdrawFromSubAccountV2Args::new(role_id, subacc_id, amount);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        secp256r1_v2_instructions(
            &accounts,
            args_bytes,
            args_bytes,
            current_slot,
            counter,
            5,
            &mut authority_payload_fn,
            public_key,
        )
    }

    /// Builds a Secp256r1 token withdrawal. Token accounts are part of the
    /// authenticated account payload and cannot be appended after signing.
    #[allow(clippy::too_many_arguments)]
    pub fn new_token_with_secp256r1_authority<F>(
        swig_account: Pubkey,
        payer: Pubkey,
        mut authority_payload_fn: F,
        current_slot: u64,
        counter: u32,
        sub_account_state: Pubkey,
        sub_account: Pubkey,
        swig_wallet_address: Pubkey,
        source_token: Pubkey,
        destination_token: Pubkey,
        token_program: Pubkey,
        role_id: u32,
        subacc_id: u32,
        amount: u64,
        public_key: &[u8; 33],
    ) -> anyhow::Result<Vec<Instruction>>
    where
        F: FnMut(&[u8]) -> [u8; 64],
    {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(sub_account_state, false),
            AccountMeta::new(sub_account, false),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new(source_token, false),
            AccountMeta::new(destination_token, false),
            AccountMeta::new_readonly(token_program, false),
        ];
        let args = WithdrawFromSubAccountV2Args::new(role_id, subacc_id, amount);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        secp256r1_v2_instructions(
            &accounts,
            args_bytes,
            args_bytes,
            current_slot,
            counter,
            5,
            &mut authority_payload_fn,
            public_key,
        )
    }
}

/// Builds the Secp256k1 authority payload (`slot ++ counter ++ signature`) for
/// a V2 instruction. `counter` must be the authority's next odometer value
/// (on-chain odometer + 1); `signed_data` is the instruction data prefix the
/// program authenticates.
fn secp256k1_v2_authority_payload<F>(
    signed_data: &[u8],
    account_payload: &[u8],
    current_slot: u64,
    counter: u32,
    authority_payload_fn: &mut F,
) -> Vec<u8>
where
    F: FnMut(&[u8]) -> [u8; 65],
{
    let nonced =
        prepare_secp256k1_payload(current_slot, counter, signed_data, account_payload, &[]);
    let signature = authority_payload_fn(&nonced);
    let mut authority_payload = Vec::new();
    authority_payload.extend_from_slice(&current_slot.to_le_bytes());
    authority_payload.extend_from_slice(&counter.to_le_bytes());
    authority_payload.extend_from_slice(&signature);
    authority_payload
}

/// Concatenates the signed account-meta payload for a Secp instruction.
fn secp_account_payload(accounts: &[AccountMeta]) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for account in accounts {
        bytes.extend_from_slice(
            accounts_payload_from_meta(account)
                .into_bytes()
                .map_err(|e| anyhow::anyhow!("Failed to serialize account meta {:?}", e))?,
        );
    }
    Ok(bytes)
}

/// Builds the `[verify_ix, main_ix]` pair for a Secp256r1-authenticated V2
/// instruction.
///
/// - `signed_data` is the byte string the program authenticates over.
/// - `data_prefix` is what precedes the authority payload in the instruction
///   data: the args, or `args ++ ix_bytes` for sign.
/// - `sysvar_index` is the position of the instructions sysvar in `accounts`.
#[allow(clippy::too_many_arguments)]
fn secp256r1_v2_instructions<F>(
    accounts: &[AccountMeta],
    signed_data: &[u8],
    data_prefix: &[u8],
    current_slot: u64,
    counter: u32,
    sysvar_index: u8,
    authority_payload_fn: &mut F,
    public_key: &[u8; 33],
) -> anyhow::Result<Vec<Instruction>>
where
    F: FnMut(&[u8]) -> [u8; 64],
{
    let account_payload_bytes = secp_account_payload(accounts)?;
    let slot_bytes = current_slot.to_le_bytes();
    let counter_bytes = counter.to_le_bytes();
    let message_hash = keccak::hash(
        &[
            signed_data,
            &account_payload_bytes[..],
            &slot_bytes[..],
            &counter_bytes[..],
        ]
        .concat(),
    )
    .to_bytes();
    let signature = authority_payload_fn(&message_hash);
    let verify_ix = new_secp256r1_instruction_with_signature(&message_hash, &signature, public_key);

    let mut authority_payload = Vec::new();
    authority_payload.extend_from_slice(&current_slot.to_le_bytes()); // 8
    authority_payload.extend_from_slice(&counter.to_le_bytes()); // 4
    authority_payload.push(sysvar_index); // 1
    authority_payload.extend_from_slice(&[0u8; 4]); // padding to 17 bytes

    let main_ix = Instruction {
        program_id: program_id(),
        accounts: accounts.to_vec(),
        data: [data_prefix, &authority_payload].concat(),
    };
    Ok(vec![verify_ix, main_ix])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_inner_instruction() -> Instruction {
        Instruction {
            program_id: Pubkey::new_unique(),
            accounts: Vec::new(),
            data: vec![1, 2, 3],
        }
    }

    #[test]
    fn sub_account_sign_v2_secp_payloads_bind_role_id() {
        let swig = Pubkey::new_unique();
        let state = Pubkey::new_unique();
        let asset = Pubkey::new_unique();

        let mut k1_role_1 = [0u8; 32];
        SubAccountSignV2Instruction::new_with_secp256k1_authority(
            swig,
            state,
            asset,
            |payload| {
                k1_role_1.copy_from_slice(payload);
                [0u8; 65]
            },
            10,
            1,
            1,
            0,
            vec![test_inner_instruction()],
        )
        .unwrap();

        let mut k1_role_2 = [0u8; 32];
        SubAccountSignV2Instruction::new_with_secp256k1_authority(
            swig,
            state,
            asset,
            |payload| {
                k1_role_2.copy_from_slice(payload);
                [0u8; 65]
            },
            10,
            1,
            2,
            0,
            vec![test_inner_instruction()],
        )
        .unwrap();
        assert_ne!(k1_role_1, k1_role_2);

        let public_key = [2u8; 33];
        let mut r1_role_1 = [0u8; 32];
        SubAccountSignV2Instruction::new_with_secp256r1_authority(
            swig,
            state,
            asset,
            |payload| {
                r1_role_1.copy_from_slice(payload);
                [0u8; 64]
            },
            10,
            1,
            1,
            0,
            vec![test_inner_instruction()],
            &public_key,
        )
        .unwrap();

        let mut r1_role_2 = [0u8; 32];
        SubAccountSignV2Instruction::new_with_secp256r1_authority(
            swig,
            state,
            asset,
            |payload| {
                r1_role_2.copy_from_slice(payload);
                [0u8; 64]
            },
            10,
            1,
            2,
            0,
            vec![test_inner_instruction()],
            &public_key,
        )
        .unwrap();
        assert_ne!(r1_role_1, r1_role_2);
    }

    #[test]
    fn toggle_sub_account_v2_secp_payer_is_writable() {
        let swig = Pubkey::new_unique();
        let payer = Pubkey::new_unique();
        let state = Pubkey::new_unique();

        let k1 = ToggleSubAccountV2Instruction::new_with_secp256k1_authority(
            swig,
            payer,
            |_| [0u8; 65],
            10,
            1,
            state,
            1,
            0,
            false,
        )
        .unwrap();
        assert!(k1.accounts[1].is_writable);

        let r1 = ToggleSubAccountV2Instruction::new_with_secp256r1_authority(
            swig,
            payer,
            |_| [0u8; 64],
            10,
            1,
            state,
            1,
            0,
            false,
            &[2u8; 33],
        )
        .unwrap();
        assert!(r1[1].accounts[1].is_writable);
    }
}
