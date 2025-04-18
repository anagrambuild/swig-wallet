use solana_program::{instruction::Instruction, pubkey::Pubkey};
use swig_interface::{
    program_id, AddAuthorityInstruction, AuthorityConfig, ClientAction, CreateInstruction,
    RemoveAuthorityInstruction, SignInstruction,
};
use swig_state_x::{authority::AuthorityType, swig::swig_account_seeds};

use crate::{error::SwigError, types::Permission as ClientPermission};

pub enum AuthorityManager {
    Ed25519(Pubkey),
    Secp256k1(Box<[u8]>, Box<dyn FnMut(&[u8]) -> [u8; 65]>),
}

/// Represents a Swig wallet instance
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
    /// Creates a new SwigWallet instance
    ///
    /// # Arguments
    /// * `swig_account` - The public key of the Swig account
    /// * `authority_type` - The type of authority for this wallet
    /// * `authority` - The wallet's authority credentials
    /// * `payer` - The public key of the fee payer
    /// * `role_id` - The role id for this wallet
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
    /// * `authority_type` - The type of authority for the new account
    /// * `authority` - The authority string (base58 for Ed25519, hex for
    ///   Secp256k1)
    /// * `payer` - The public key of the fee payer
    /// * `id` - A unique 13-byte identifier for the account
    pub fn build_swig_account(&self) -> Result<Instruction, SwigError> {
        let program_id = program_id();
        let (swig_account, swig_bump_seed) =
            Pubkey::find_program_address(&swig_account_seeds(&self.swig_id), &program_id);

        let (authority_type, auth_bytes): (AuthorityType, &[u8]) = match &self.authority_manager {
            AuthorityManager::Ed25519(authority) => (AuthorityType::Ed25519, &authority.to_bytes()),
            AuthorityManager::Secp256k1(authority, _) => {
                (AuthorityType::Secp256k1, &authority[1..])
            },
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

    /// Creates a signed instruction
    ///
    /// # Arguments
    /// * `instructions` - The instructions to sign
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
                    let current_slot = current_slot.unwrap();
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
                _ => todo!(),
            }
        }
        Ok(signed_instructions)
    }

    /// Creates an instruction to add a new authority
    ///
    /// # Arguments
    /// * `new_authority_type` - The type of the new authority
    /// * `new_authority` - The new authority's credentials
    /// * `permissions` - Vector of permissions to grant to the new authority
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
                let current_slot = current_slot.unwrap();
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
            _ => todo!(),
        }
    }

    /// Removes an authority from the wallet
    ///
    /// # Arguments
    /// * `authority_to_remove_id` - The ID of the authority to remove
    pub fn remove_authority(&self, authority_to_remove_id: u32) -> Result<Instruction, SwigError> {
        match self.authority_manager {
            AuthorityManager::Ed25519(authority) => {
                Ok(RemoveAuthorityInstruction::new_with_ed25519_authority(
                    self.swig_account,
                    self.payer,
                    authority,
                    self.role_id,
                    authority_to_remove_id,
                )?)
            },
            _ => todo!(),
        }
    }

    /// Creates an instruction to replace an existing authority
    ///
    /// # Arguments
    /// * `authority_to_replace_id` - The ID of the authority to replace
    /// * `new_authority_type` - The type of the new authority
    /// * `new_authority` - The new authority's credentials
    /// * `permissions` - Vector of permissions to grant to the new authority
    pub fn replace_authority(
        &self,
        authority_to_replace_id: u32,
        new_authority_type: AuthorityType,
        new_authority: &[u8],
        permissions: Vec<ClientPermission>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let actions = ClientPermission::to_client_actions(permissions);

        match self.authority_manager {
            AuthorityManager::Ed25519(authority) => {
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
            _ => todo!(),
        }
    }

    /// Returns the public key of the Swig account
    pub fn get_swig_account(&self) -> Result<Pubkey, SwigError> {
        Ok(self.swig_account)
    }

    /// Returns the public key of the Swig account
    pub fn swig_key(id: &[u8; 32]) -> Pubkey {
        Pubkey::find_program_address(&swig_account_seeds(id), &program_id()).0
    }

    /// Returns the role id of the Swig account
    pub fn get_role_id(&self) -> u32 {
        self.role_id
    }

    /// Switches the authority of the Swig instruction builder
    ///
    /// # Arguments
    /// * `authority_id` - The ID of the authority to switch to
    pub fn switch_authority(&mut self, role_id: u32, authority: Pubkey) -> Result<(), SwigError> {
        self.role_id = role_id;
        self.authority_manager = match self.authority_manager {
            AuthorityManager::Ed25519(_) => AuthorityManager::Ed25519(authority),
            _ => todo!("Secp256k1 not yet implemented"),
        };
        Ok(())
    }

    /// Switches the payer of the Swig instruction builder
    ///
    /// # Arguments
    /// * `payer` - The new payer
    pub fn switch_payer(&mut self, payer: Pubkey) -> Result<(), SwigError> {
        self.payer = payer;
        Ok(())
    }
}
