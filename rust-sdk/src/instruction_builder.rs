use solana_program::{instruction::Instruction, pubkey::Pubkey};
use swig_interface::{
    program_id, AddAuthorityInstruction, AuthorityConfig, ClientAction, CreateInstruction,
    RemoveAuthorityInstruction, SignInstruction,
};
use swig_state_x::{authority::AuthorityType, swig::swig_account_seeds};

use crate::{
    error::SwigError,
    types::{Permission as ClientPermission, WalletAuthority},
};

/// Represents a Swig wallet instance
#[derive(Debug, Clone)]
pub struct SwigInstructionBuilder {
    /// The public key of the Swig account
    swig_account: Pubkey,
    /// The type of authority for this wallet
    //_authority_type: AuthorityType, // TODO: Will replace the wallet authority type with this
    /// The wallet's authority credentials
    authority: WalletAuthority,
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
        swig_account: Pubkey,
        //authority_type: AuthorityType,
        authority: WalletAuthority,
        payer: Pubkey,
        role_id: u32,
    ) -> Self {
        Self {
            swig_account,
            // _authority_type: authority_type,
            authority,
            payer,
            role_id,
        }
    }

    /// Creates an instruction to initialize a new Swig account
    ///
    /// # Arguments
    /// * `authority_type` - The type of authority for the new account
    /// * `authority` - The authority string (base58 for Ed25519, hex for Secp256k1)
    /// * `payer` - The public key of the fee payer
    /// * `id` - A unique 13-byte identifier for the account
    pub fn create_swig_account_instruction(
        &self,
        authority_type: AuthorityType,
        authority: String,
        payer: Pubkey,
        id: [u8; 32],
    ) -> Result<Instruction, SwigError> {
        let program_id = program_id();
        let (swig_account, swig_bump_seed) =
            Pubkey::find_program_address(&swig_account_seeds(&id), &program_id);

        let auth_bytes = match authority_type {
            AuthorityType::Ed25519 => bs58::decode(authority).into_vec()?,
            AuthorityType::Secp256k1 => hex::decode(authority).unwrap(),
            _ => todo!(),
        };

        let actions = vec![ClientAction::All(swig_state_x::action::all::All {})];

        let instruction = CreateInstruction::new(
            swig_account,
            swig_bump_seed,
            payer,
            AuthorityConfig {
                authority_type,
                authority: &auth_bytes,
            },
            actions,
            id,
        )?;
        Ok(instruction)
    }

    /// Creates a signed instruction
    ///
    /// # Arguments
    /// * `instructions` - The instructions to sign
    pub fn sign_instruction(
        &self,
        instructions: Vec<Instruction>,
    ) -> Result<Instruction, SwigError> {
        match self.authority {
            WalletAuthority::Ed25519(authority) => {
                let swig_signed_instruction = SignInstruction::new_ed25519(
                    self.swig_account,
                    self.payer,
                    authority,
                    instructions[0].clone(),
                    self.role_id,
                )?;
                Ok(swig_signed_instruction)
            },
            WalletAuthority::Secp256k1(_) => {
                // Secp256k1 signing is not yet implemented
                todo!("Secp256k1 signing not yet implemented")
            },
        }
    }

    /// Creates an instruction to add a new authority
    ///
    /// # Arguments
    /// * `new_authority_type` - The type of the new authority
    /// * `new_authority` - The new authority's credentials
    /// * `permissions` - Vector of permissions to grant to the new authority
    pub fn add_authority_instruction(
        &self,
        new_authority_type: AuthorityType,
        new_authority: &[u8],
        permissions: Vec<ClientPermission>,
    ) -> Result<Instruction, SwigError> {
        let actions = ClientPermission::to_client_actions(permissions);

        match self.authority {
            WalletAuthority::Ed25519(authority) => {
                Ok(AddAuthorityInstruction::new_with_ed25519_authority(
                    self.swig_account,
                    self.payer,
                    authority,
                    self.role_id,
                    AuthorityConfig {
                        authority_type: new_authority_type,
                        authority: new_authority,
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
        match self.authority {
            WalletAuthority::Ed25519(authority) => {
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

        match self.authority {
            WalletAuthority::Ed25519(authority) => {
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
}
