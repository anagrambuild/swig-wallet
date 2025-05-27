use solana_program::{instruction::Instruction, pubkey::Pubkey};
use swig_interface::{
    program_id, AddAuthorityInstruction, AuthorityConfig, ClientAction, CreateInstruction,
    CreateSessionInstruction, CreateSubAccountInstruction, RemoveAuthorityInstruction,
    SignInstruction, SubAccountSignInstruction, ToggleSubAccountInstruction,
    WithdrawFromSubAccountInstruction,
};
use swig_state_x::{
    authority::{
        ed25519::CreateEd25519SessionAuthority, secp256k1::CreateSecp256k1SessionAuthority,
        AuthorityType,
    },
    swig::{sub_account_seeds, swig_account_seeds},
    IntoBytes,
};

use crate::{error::SwigError, types::Permission as ClientPermission};

/// Represents the type of authority used for signing transactions
pub enum AuthorityManager {
    Ed25519(Pubkey),
    Secp256k1(Box<[u8]>, Box<dyn Fn(&[u8]) -> [u8; 65]>),
    Ed25519Session(CreateEd25519SessionAuthority),
    Secp256k1Session(
        CreateSecp256k1SessionAuthority,
        Box<dyn Fn(&[u8]) -> [u8; 65]>,
    ),
}

/// A builder for creating and managing Swig wallet instructions.
///
/// This struct provides methods to create various instructions for managing a
/// Swig wallet, including initialization, authority management, and transaction
/// signing.
pub struct SwigInstructionBuilder {
    /// The id of the Swig account
    swig_id: [u8; 32],
    /// The public key of the Swig account
    swig_account: Pubkey,
    /// The type of authority for this wallet
    authority_manager: AuthorityManager,
    /// The public key of the fee payer
    payer: Pubkey,
    /// The role id of the wallet
    role_id: u32,
}

impl SwigInstructionBuilder {
    /// Creates a new SwigInstructionBuilder instance
    ///
    /// # Arguments
    ///
    /// * `swig_id` - The unique identifier for the Swig account
    /// * `authority_manager` - The authority manager specifying the type of
    ///   signing authority
    /// * `payer` - The public key of the fee payer
    /// * `role_id` - The role identifier for this wallet
    ///
    /// # Returns
    ///
    /// Returns a new instance of `SwigInstructionBuilder`
    pub fn new(
        swig_id: [u8; 32],
        authority_manager: AuthorityManager,
        payer: Pubkey,
        role_id: u32,
    ) -> Self {
        let swig_account = Self::swig_key(&swig_id);

        Self {
            swig_id,
            swig_account,
            authority_manager,
            payer,
            role_id,
        }
    }

    /// Creates an instruction to initialize a new Swig account
    ///
    /// # Arguments
    ///
    /// * `self` - The SwigInstructionBuilder instance
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the `Instruction` for creating a Swig
    /// account or a `SwigError`
    pub fn build_swig_account(&self) -> Result<Instruction, SwigError> {
        let program_id = program_id();
        let (swig_account, swig_bump_seed) =
            Pubkey::find_program_address(&swig_account_seeds(&self.swig_id), &program_id);

        let (authority_type, auth_bytes): (AuthorityType, &[u8]) = match &self.authority_manager {
            AuthorityManager::Ed25519(authority) => (AuthorityType::Ed25519, &authority.to_bytes()),
            AuthorityManager::Secp256k1(authority, _) => {
                (AuthorityType::Secp256k1, &authority[1..])
            },
            AuthorityManager::Ed25519Session(session_authority) => (
                AuthorityType::Ed25519Session,
                &session_authority.into_bytes().unwrap(),
            ),
            AuthorityManager::Secp256k1Session(session_authority, _) => (
                AuthorityType::Secp256k1Session,
                &session_authority.into_bytes().unwrap(),
            ),
        };

        let actions = vec![ClientAction::All(swig_state_x::action::all::All {})];

        let instruction = CreateInstruction::new(
            swig_account,
            swig_bump_seed,
            self.payer,
            AuthorityConfig {
                authority_type,
                authority: auth_bytes,
            },
            actions,
            self.swig_id,
        )?;
        Ok(instruction)
    }

    /// Creates signed instructions for the provided instructions
    ///
    /// # Arguments
    ///
    /// * `instructions` - Vector of instructions to sign
    /// * `current_slot` - Optional current slot number (required for Secp256k1)
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing a vector of signed instructions or a
    /// `SwigError`
    pub fn sign_instruction(
        &mut self,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let mut signed_instructions = Vec::new();
        for instruction in instructions {
            match &mut self.authority_manager {
                AuthorityManager::Ed25519(authority) => {
                    let swig_signed_instruction = SignInstruction::new_ed25519(
                        self.swig_account,
                        self.payer,
                        *authority,
                        instruction,
                        self.role_id,
                    )?;
                    signed_instructions.push(swig_signed_instruction);
                },
                AuthorityManager::Secp256k1(authority, signing_fn) => {
                    let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
                    let swig_signed_instruction = SignInstruction::new_secp256k1(
                        self.swig_account,
                        self.payer,
                        signing_fn,
                        current_slot,
                        instruction,
                        self.role_id,
                    )?;
                    signed_instructions.push(swig_signed_instruction);
                },
                AuthorityManager::Ed25519Session(session_authority) => {
                    let session_authority_pubkey =
                        Pubkey::new_from_array(session_authority.public_key);
                    let swig_signed_instruction = SignInstruction::new_ed25519(
                        self.swig_account,
                        self.payer,
                        session_authority_pubkey,
                        instruction,
                        self.role_id,
                    )?;
                    signed_instructions.push(swig_signed_instruction);
                },
                AuthorityManager::Secp256k1Session(session_authority, signing_fn) => {
                    let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
                    let swig_signed_instruction = SignInstruction::new_secp256k1(
                        self.swig_account,
                        self.payer,
                        signing_fn,
                        current_slot,
                        instruction,
                        self.role_id,
                    )?;
                    signed_instructions.push(swig_signed_instruction);
                },
            }
        }
        Ok(signed_instructions)
    }

    /// Creates an instruction to add a new authority to the wallet
    ///
    /// # Arguments
    ///
    /// * `new_authority_type` - The type of authority to add
    /// * `new_authority` - The authority credentials as bytes
    /// * `permissions` - Vector of permissions to grant to the new authority
    /// * `current_slot` - Optional current slot number (required for Secp256k1)
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the add authority instruction or a
    /// `SwigError`
    pub fn add_authority_instruction(
        &mut self,
        new_authority_type: AuthorityType,
        new_authority: &[u8],
        permissions: Vec<ClientPermission>,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        let actions = ClientPermission::to_client_actions(permissions);

        match &mut self.authority_manager {
            AuthorityManager::Ed25519(authority) => {
                Ok(AddAuthorityInstruction::new_with_ed25519_authority(
                    self.swig_account,
                    self.payer,
                    *authority,
                    self.role_id,
                    AuthorityConfig {
                        authority_type: new_authority_type,
                        authority: new_authority,
                    },
                    actions,
                )?)
            },
            AuthorityManager::Secp256k1(authority, signing_fn) => {
                let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
                Ok(AddAuthorityInstruction::new_with_secp256k1_authority(
                    self.swig_account,
                    self.payer,
                    signing_fn,
                    current_slot,
                    self.role_id,
                    AuthorityConfig {
                        authority_type: new_authority_type,
                        authority: &new_authority[1..],
                    },
                    actions,
                )?)
            },
            AuthorityManager::Ed25519Session(session_authority) => {
                Ok(AddAuthorityInstruction::new_with_ed25519_authority(
                    self.swig_account,
                    self.payer,
                    session_authority.public_key.into(),
                    self.role_id,
                    AuthorityConfig {
                        authority_type: new_authority_type,
                        authority: new_authority,
                    },
                    actions,
                )?)
            },
            AuthorityManager::Secp256k1Session(session_authority, signing_fn) => {
                let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
                Ok(AddAuthorityInstruction::new_with_secp256k1_authority(
                    self.swig_account,
                    self.payer,
                    signing_fn,
                    current_slot,
                    self.role_id,
                    AuthorityConfig {
                        authority_type: new_authority_type,
                        authority: new_authority,
                    },
                    actions,
                )?)
            },
        }
    }

    /// Creates an instruction to remove an authority from the wallet
    ///
    /// # Arguments
    ///
    /// * `authority_to_remove_id` - The ID of the authority to remove
    /// * `current_slot` - Optional current slot number (required for Secp256k1)
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the remove authority instruction or a
    /// `SwigError`
    pub fn remove_authority(
        &mut self,
        authority_to_remove_id: u32,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        match &mut self.authority_manager {
            AuthorityManager::Ed25519(authority) => {
                Ok(RemoveAuthorityInstruction::new_with_ed25519_authority(
                    self.swig_account,
                    self.payer,
                    *authority,
                    self.role_id,
                    authority_to_remove_id,
                )?)
            },
            AuthorityManager::Secp256k1(authority, signing_fn) => {
                let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
                Ok(RemoveAuthorityInstruction::new_with_secp256k1_authority(
                    self.swig_account,
                    self.payer,
                    signing_fn,
                    self.role_id,
                    authority_to_remove_id,
                    current_slot,
                )?)
            },
            AuthorityManager::Ed25519Session(session_authority) => {
                Ok(RemoveAuthorityInstruction::new_with_ed25519_authority(
                    self.swig_account,
                    self.payer,
                    session_authority.public_key.into(),
                    self.role_id,
                    authority_to_remove_id,
                )?)
            },
            AuthorityManager::Secp256k1Session(session_authority, signing_fn) => {
                let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
                Ok(RemoveAuthorityInstruction::new_with_secp256k1_authority(
                    self.swig_account,
                    self.payer,
                    signing_fn,
                    self.role_id,
                    authority_to_remove_id,
                    current_slot,
                )?)
            },
        }
    }

    /// Creates instructions to replace an existing authority with a new one
    ///
    /// # Arguments
    ///
    /// * `authority_to_replace_id` - The ID of the authority to replace
    /// * `new_authority_type` - The type of the new authority
    /// * `new_authority` - The new authority's credentials as bytes
    /// * `permissions` - Vector of permissions to grant to the new authority
    /// * `current_slot` - Optional current slot number (required for Secp256k1)
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing a vector of instructions or a `SwigError`
    pub fn replace_authority(
        &mut self,
        authority_to_replace_id: u32,
        new_authority_type: AuthorityType,
        new_authority: &[u8],
        permissions: Vec<ClientPermission>,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let actions = ClientPermission::to_client_actions(permissions);

        match &mut self.authority_manager {
            AuthorityManager::Ed25519(authority) => {
                let remove_authority_instruction =
                    RemoveAuthorityInstruction::new_with_ed25519_authority(
                        self.swig_account,
                        self.payer,
                        *authority,
                        self.role_id,
                        authority_to_replace_id,
                    )?;
                let add_authority_instruction =
                    AddAuthorityInstruction::new_with_ed25519_authority(
                        self.swig_account,
                        self.payer,
                        *authority,
                        self.role_id,
                        AuthorityConfig {
                            authority_type: new_authority_type,
                            authority: new_authority,
                        },
                        actions,
                    )?;
                Ok(vec![
                    remove_authority_instruction,
                    add_authority_instruction,
                ])
            },
            AuthorityManager::Ed25519Session(session_authority) => {
                let authority: Pubkey = session_authority.public_key.into();
                let remove_authority_instruction =
                    RemoveAuthorityInstruction::new_with_ed25519_authority(
                        self.swig_account,
                        self.payer,
                        authority,
                        self.role_id,
                        authority_to_replace_id,
                    )?;
                let add_authority_instruction =
                    AddAuthorityInstruction::new_with_ed25519_authority(
                        self.swig_account,
                        self.payer,
                        authority,
                        self.role_id,
                        AuthorityConfig {
                            authority_type: new_authority_type,
                            authority: new_authority,
                        },
                        actions,
                    )?;
                Ok(vec![
                    remove_authority_instruction,
                    add_authority_instruction,
                ])
            },
            AuthorityManager::Secp256k1(authority, signing_fn) => {
                todo!("Must manually remove and add authority due to Signing Function")
                // let current_slot =
                // current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
                // Ok(vec![
                //     RemoveAuthorityInstruction::new_with_secp256k1_authority(
                //         self.swig_account,
                //         self.payer,
                //         signing_fn,
                //         self.role_id,
                //         authority_to_replace_id,
                //         current_slot,
                //     )?,
                //     AddAuthorityInstruction::new_with_secp256k1_authority(
                //         self.swig_account,
                //         self.payer,
                //         signing_fn,
                //         current_slot,
                //         self.role_id,
                //         AuthorityConfig {
                //             authority_type: new_authority_type,
                //             authority: new_authority,
                //         },
                //         actions,
                //     )?,
                // ])
            },
            _ => todo!(),
        }
    }

    /// Creates an instruction to create a new session
    ///
    /// # Arguments
    ///
    /// * `session_key` - The public key for the new session
    /// * `session_duration` - The duration of the session in slots
    /// * `current_slot` - Optional current slot number (required for Secp256k1)
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the create session instruction or a
    /// `SwigError`
    pub fn create_session_instruction(
        &self,
        session_key: Pubkey,
        session_duration: u64,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        match &self.authority_manager {
            AuthorityManager::Ed25519Session(session_authority) => {
                Ok(CreateSessionInstruction::new_with_ed25519_authority(
                    self.swig_account,
                    self.payer,
                    session_authority.public_key.into(),
                    self.role_id,
                    session_key,
                    session_duration,
                )?)
            },
            AuthorityManager::Secp256k1Session(session_authority, signing_fn) => {
                let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
                Ok(CreateSessionInstruction::new_with_secp256k1_authority(
                    self.swig_account,
                    self.payer,
                    signing_fn,
                    current_slot,
                    self.role_id,
                    session_key,
                    session_duration,
                )?)
            },
            AuthorityManager::Ed25519(authority) => {
                Ok(CreateSessionInstruction::new_with_ed25519_authority(
                    self.swig_account,
                    self.payer,
                    *authority,
                    self.role_id,
                    session_key,
                    session_duration,
                )?)
            },
            AuthorityManager::Secp256k1(authority, signing_fn) => {
                let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
                Ok(CreateSessionInstruction::new_with_secp256k1_authority(
                    self.swig_account,
                    self.payer,
                    signing_fn,
                    current_slot,
                    self.role_id,
                    session_key,
                    session_duration,
                )?)
            },
        }
    }

    /// Returns the public key of the Swig account
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the Swig account's public key or a
    /// `SwigError`
    pub fn get_swig_account(&self) -> Result<Pubkey, SwigError> {
        Ok(self.swig_account)
    }

    /// Returns the swig id
    ///
    /// # Returns
    ///
    /// Returns the swig id as a `[u8; 32]`
    pub fn get_swig_id(&self) -> &[u8; 32] {
        &self.swig_id
    }

    /// Derives the Swig account public key from an ID
    ///
    /// # Arguments
    ///
    /// * `id` - The 32-byte identifier used to derive the Swig account
    ///
    /// # Returns
    ///
    /// Returns the derived Swig account public key
    pub fn swig_key(id: &[u8; 32]) -> Pubkey {
        Pubkey::find_program_address(&swig_account_seeds(id), &program_id()).0
    }

    /// Returns the current role ID of the Swig account
    ///
    /// # Returns
    ///
    /// Returns the role ID as a u32
    pub fn get_role_id(&self) -> u32 {
        self.role_id
    }

    /// Switches the authority and role ID of the Swig instruction builder
    ///
    /// # Arguments
    ///
    /// * `role_id` - The new role ID to switch to
    /// * `authority` - The new authority's public key
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing unit type or a `SwigError`
    pub fn switch_authority(
        &mut self,
        role_id: u32,
        new_authority_manager: AuthorityManager,
    ) -> Result<(), SwigError> {
        self.role_id = role_id;
        self.authority_manager = new_authority_manager;
        Ok(())
    }

    /// Updates the fee payer for the Swig instruction builder
    ///
    /// # Arguments
    ///
    /// * `payer` - The new fee payer's public key
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing unit type or a `SwigError`
    pub fn switch_payer(&mut self, payer: Pubkey) -> Result<(), SwigError> {
        self.payer = payer;
        Ok(())
    }

    /// Creates a Subaccount for the Swig account
    ///
    /// # Arguments
    ///
    /// * `subaccount_id` - The ID of the subaccount to create
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the subaccount's public key or a `SwigError`
    pub fn create_sub_account(&self, current_slot: Option<u64>) -> Result<Instruction, SwigError> {
        let role_id_bytes = self.role_id.to_le_bytes();
        let swig_id_bytes = self.swig_id;
        let (sub_account, sub_account_bump) = Pubkey::find_program_address(
            &sub_account_seeds(&swig_id_bytes, &role_id_bytes),
            &swig_interface::program_id(),
        );

        match &self.authority_manager {
            AuthorityManager::Ed25519(authority) => {
                Ok(CreateSubAccountInstruction::new_with_ed25519_authority(
                    self.swig_account,
                    *authority,
                    self.payer,
                    sub_account,
                    self.role_id,
                    sub_account_bump,
                )?)
            },
            AuthorityManager::Secp256k1(authority, signing_fn) => {
                let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
                Ok(CreateSubAccountInstruction::new_with_secp256k1_authority(
                    self.swig_account,
                    self.payer,
                    signing_fn,
                    current_slot,
                    sub_account,
                    self.role_id,
                    sub_account_bump,
                )?)
            },
            _ => todo!(),
        }
    }

    /// Signs a instruction with sub-account
    ///
    /// # Arguments
    ///
    /// * `instructions` - The instructions to sign
    /// * `current_slot` - Optional current slot number (required for Secp256k1)
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the signed instruction or a `SwigError`
    pub fn sign_instruction_with_sub_account(
        &self,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        println!("Signing instruction with sub-account");
        println!("Swig account: {}", self.swig_account);
        println!("Payer: {}", self.payer);
        println!("Role ID: {}", self.role_id);
        println!("Swig ID: {:?}", self.swig_id);
        println!("Program ID: {:?}", program_id());
        let role_id_bytes = self.role_id.to_le_bytes();
        let swig_id_bytes = self.swig_id;
        let (sub_account, sub_account_bump) = Pubkey::find_program_address(
            &sub_account_seeds(&swig_id_bytes, &role_id_bytes),
            &swig_interface::program_id(),
        );
        println!("Sub-account: {}", sub_account);

        match &self.authority_manager {
            AuthorityManager::Ed25519(authority) => {
                println!("authority: {:?}", &authority);

                Ok(SubAccountSignInstruction::new_with_ed25519_authority(
                    self.swig_account,
                    sub_account,
                    *authority,
                    self.payer,
                    self.role_id,
                    instructions,
                )?)
            },
            AuthorityManager::Secp256k1(authority, signing_fn) => {
                let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
                Ok(SubAccountSignInstruction::new_with_secp256k1_authority(
                    self.swig_account,
                    sub_account,
                    self.payer,
                    signing_fn,
                    current_slot,
                    self.role_id,
                    instructions,
                )?)
            },
            _ => todo!(),
        }
    }

    /// Withdraws funds from a sub-account
    ///
    /// # Arguments
    ///
    /// * `sub_account` - The public key of the sub-account
    /// * `amount` - The amount to withdraw
    /// * `current_slot` - Optional current slot number (required for Secp256k1)
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the withdraw instruction or a `SwigError`
    pub fn withdraw_from_sub_account(
        &self,
        sub_account: Pubkey,
        amount: u64,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        match &self.authority_manager {
            AuthorityManager::Ed25519(authority) => {
                WithdrawFromSubAccountInstruction::new_with_ed25519_authority(
                    self.swig_account,
                    *authority,
                    self.payer,
                    sub_account,
                    self.role_id,
                    amount,
                )
                .map_err(|e| {
                    anyhow::anyhow!("Failed to create withdraw instruction: {:?}", e).into()
                })
            },
            AuthorityManager::Secp256k1(authority, signing_fn) => {
                let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
                WithdrawFromSubAccountInstruction::new_with_secp256k1_authority(
                    self.swig_account,
                    self.payer,
                    signing_fn,
                    current_slot,
                    sub_account,
                    self.role_id,
                    amount,
                )
                .map_err(|e| {
                    anyhow::anyhow!("Failed to create withdraw instruction: {:?}", e).into()
                })
            },
            _ => todo!(),
        }
    }

    /// Withdraws tokens from a sub-account
    ///
    /// # Arguments
    ///
    /// * `sub_account` - The public key of the sub-account
    /// * `sub_account_token` - The token account of the sub-account
    /// * `swig_token` - The token account of the Swig account
    /// * `token_program` - The token program ID
    /// * `amount` - The amount of tokens to withdraw
    /// * `current_slot` - Optional current slot number (required for Secp256k1)
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the withdraw token instruction or a `SwigError`
    pub fn withdraw_token_from_sub_account(
        &self,
        sub_account: Pubkey,
        sub_account_token: Pubkey,
        swig_token: Pubkey,
        token_program: Pubkey,
        amount: u64,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        match &self.authority_manager {
            AuthorityManager::Ed25519(authority) => {
                WithdrawFromSubAccountInstruction::new_token_with_ed25519_authority(
                    self.swig_account,
                    *authority,
                    self.payer,
                    sub_account,
                    sub_account_token,
                    swig_token,
                    token_program,
                    self.role_id,
                    amount,
                )
                .map_err(|e| {
                    anyhow::anyhow!("Failed to create withdraw token instruction: {:?}", e).into()
                })
            },
            AuthorityManager::Secp256k1(authority, signing_fn) => {
                let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
                WithdrawFromSubAccountInstruction::new_token_with_secp256k1_authority(
                    self.swig_account,
                    self.payer,
                    signing_fn,
                    current_slot,
                    sub_account,
                    sub_account_token,
                    swig_token,
                    token_program,
                    self.role_id,
                    amount,
                )
                .map_err(|e| {
                    anyhow::anyhow!("Failed to create withdraw token instruction: {:?}", e).into()
                })
            },
            _ => todo!(),
        }
    }

    /// Toggles a sub-account's enabled state
    ///
    /// # Arguments
    ///
    /// * `sub_account` - The public key of the sub-account
    /// * `enabled` - Whether to enable or disable the sub-account
    /// * `current_slot` - Optional current slot number (required for Secp256k1)
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the toggle instruction or a `SwigError`
    pub fn toggle_sub_account(
        &self,
        sub_account: Pubkey,
        enabled: bool,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        match &self.authority_manager {
            AuthorityManager::Ed25519(authority) => {
                ToggleSubAccountInstruction::new_with_ed25519_authority(
                    self.swig_account,
                    *authority,
                    self.payer,
                    sub_account,
                    self.role_id,
                    enabled,
                )
                .map_err(|e| anyhow::anyhow!("Failed to create toggle instruction: {:?}", e).into())
            },
            AuthorityManager::Secp256k1(authority, signing_fn) => {
                let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
                ToggleSubAccountInstruction::new_with_secp256k1_authority(
                    self.swig_account,
                    self.payer,
                    signing_fn,
                    current_slot,
                    sub_account,
                    self.role_id,
                    enabled,
                )
                .map_err(|e| anyhow::anyhow!("Failed to create toggle instruction: {:?}", e).into())
            },
            _ => todo!(),
        }
    }

    /// Returns the current authority's public key as bytes
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the authority's public key as bytes or a
    /// `SwigError`
    pub fn get_current_authority(&self) -> Result<Vec<u8>, SwigError> {
        match &self.authority_manager {
            AuthorityManager::Ed25519(authority) => Ok(authority.to_bytes().to_vec()),
            AuthorityManager::Secp256k1(authority, _) => Ok(authority[1..].to_vec()),
            AuthorityManager::Ed25519Session(session_authority) => {
                Ok(session_authority.public_key.to_vec())
            },
            AuthorityManager::Secp256k1Session(session_authority, _) => {
                Ok(session_authority.public_key.to_vec())
            },
        }
    }
}
