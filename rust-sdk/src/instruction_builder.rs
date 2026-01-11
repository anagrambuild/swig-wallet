use solana_program::{instruction::Instruction, pubkey::Pubkey};
use swig_interface::{
    program_id, AddAuthorityInstruction, AuthorityConfig, ClientAction, CreateInstruction,
    CreateSessionInstruction, CreateSubAccountInstruction, RemoveAuthorityInstruction,
    SignV2Instruction, SubAccountSignInstruction, ToggleSubAccountInstruction,
    UpdateAuthorityData as InterfaceUpdateAuthorityData, WithdrawFromSubAccountInstruction,
};
use swig_state::{
    authority::{
        ed25519::CreateEd25519SessionAuthority, secp256k1::CreateSecp256k1SessionAuthority,
        secp256r1::CreateSecp256r1SessionAuthority, AuthorityType,
    },
    swig::{sub_account_seeds, swig_account_seeds, swig_wallet_address_seeds},
    IntoBytes,
};

use crate::{
    client_role::ClientRole,
    error::SwigError,
    types::{Permission as ClientPermission, UpdateAuthorityData},
};

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
    /// The client role implementation for this wallet
    client_role: Box<dyn ClientRole>,
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
    /// * `client_role` - The client role implementation specifying the type of
    ///   signing authority
    /// * `payer` - The public key of the fee payer
    /// * `role_id` - The role identifier for this wallet
    ///
    /// # Returns
    ///
    /// Returns a new instance of `SwigInstructionBuilder`
    pub fn new(
        swig_id: [u8; 32],
        client_role: Box<dyn ClientRole>,
        payer: Pubkey,
        role_id: u32,
    ) -> Self {
        let swig_account = Self::swig_key(&swig_id);

        Self {
            swig_id,
            swig_account,
            client_role,
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

        let (swig_wallet_address, wallet_address_bump) = Pubkey::find_program_address(
            &swig_state::swig::swig_wallet_address_seeds(swig_account.as_ref()),
            &program_id,
        );

        let authority_type = self.client_role.authority_type();
        let auth_bytes = self.client_role.authority_bytes()?;

        let actions = vec![ClientAction::All(swig_state::action::all::All {})];

        let instruction = CreateInstruction::new(
            swig_account,
            swig_bump_seed,
            self.payer,
            swig_wallet_address,
            wallet_address_bump,
            AuthorityConfig {
                authority_type,
                authority: &auth_bytes,
            },
            actions,
            self.swig_id,
        )?;
        Ok(instruction)
    }

    /// Creates a SignV2 instruction for signing transactions
    ///
    /// SignV2 instructions use the swig_wallet_address PDA as the transaction
    /// authority, which is different from the regular sign instruction that
    /// uses the swig account directly.
    ///
    /// # Arguments
    ///
    /// * `instructions` - Vector of instructions to be signed
    /// * `current_slot` - Optional current slot number (required for
    ///   Secp256k1/Secp256r1)
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the SignV2 instruction or a `SwigError`
    pub fn sign_v2_instruction(
        &mut self,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        // Derive the swig_wallet_address from the swig account
        use swig_state::swig::swig_wallet_address_seeds;
        let (swig_wallet_address, _) = Pubkey::find_program_address(
            &swig_wallet_address_seeds(self.swig_account.as_ref()),
            &program_id(),
        );

        self.client_role.sign_v2_instruction(
            self.swig_account,
            swig_wallet_address,
            self.role_id,
            instructions,
            current_slot,
            core::slice::from_ref(&self.payer),
        )
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
    ) -> Result<Vec<Instruction>, SwigError> {
        let actions = ClientPermission::to_client_actions(permissions);

        self.client_role.add_authority_instruction(
            self.swig_account,
            self.payer,
            self.role_id,
            new_authority_type,
            new_authority,
            actions,
            current_slot,
        )
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
    ) -> Result<Vec<Instruction>, SwigError> {
        self.client_role.remove_authority_instruction(
            self.swig_account,
            self.payer,
            self.role_id,
            authority_to_remove_id,
            current_slot,
        )
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
    pub fn update_authority(
        &mut self,
        authority_to_replace_id: u32,
        current_slot: Option<u64>,
        update_data: UpdateAuthorityData,
    ) -> Result<Vec<Instruction>, SwigError> {
        let update_authority_instructions = self.client_role.update_authority_instruction(
            self.swig_account,
            self.payer,
            self.role_id,
            authority_to_replace_id,
            update_data.to_interface_data(),
            current_slot,
        )?;

        Ok(update_authority_instructions)
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
        counter: Option<u32>,
    ) -> Result<Vec<Instruction>, SwigError> {
        self.client_role.create_session_instruction(
            self.swig_account,
            self.payer,
            self.role_id,
            session_key,
            session_duration,
            current_slot,
        )
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

    /// Derives the Swig wallet address public key from a Swig account pubkey
    ///
    /// # Arguments
    ///
    /// * `swig_account` - The Swig account public key
    ///
    /// # Returns
    ///
    /// Returns the derived Swig wallet address public key
    pub fn swig_wallet_address_key(swig_account: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(
            &swig_wallet_address_seeds(swig_account.as_ref()),
            &program_id(),
        )
        .0
    }

    /// Derives the Swig wallet address public key from an ID
    ///
    /// # Arguments
    ///
    /// * `id` - The 32-byte identifier used to derive the Swig wallet address
    ///
    /// # Returns
    ///
    /// Returns the derived Swig wallet address public key
    pub fn swig_wallet_address(&self) -> Pubkey {
        Pubkey::find_program_address(
            &swig_wallet_address_seeds(self.swig_account.as_ref()),
            &program_id(),
        )
        .0
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
    /// * `client_role` - The new client role implementation
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing unit type or a `SwigError`
    pub fn switch_authority(
        &mut self,
        role_id: u32,
        client_role: Box<dyn ClientRole>,
    ) -> Result<(), SwigError> {
        self.role_id = role_id;
        self.client_role = client_role;
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
    /// Returns a `Result` containing the subaccount's public key or a
    /// `SwigError`
    pub fn create_sub_account(
        &self,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let role_id_bytes = self.role_id.to_le_bytes();
        let swig_id_bytes = self.swig_id;
        let (sub_account, sub_account_bump) = Pubkey::find_program_address(
            &sub_account_seeds(&swig_id_bytes, &role_id_bytes),
            &swig_interface::program_id(),
        );

        self.client_role.create_sub_account_instruction(
            self.swig_account,
            self.payer,
            self.role_id,
            sub_account,
            sub_account_bump,
            current_slot,
        )
    }

    /// Signs instructions with a sub-account
    ///
    /// # Arguments
    ///
    /// * `instructions` - Vector of instructions to sign with the sub-account
    /// * `current_slot` - Optional current slot number (required for Secp256k1)
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the signed instruction or a `SwigError`
    pub fn sign_instruction_with_sub_account(
        &self,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let role_id_bytes = self.role_id.to_le_bytes();
        let swig_id_bytes = self.swig_id;
        let (sub_account, _) = Pubkey::find_program_address(
            &sub_account_seeds(&swig_id_bytes, &role_id_bytes),
            &swig_interface::program_id(),
        );

        self.client_role.sub_account_sign_instruction(
            self.swig_account,
            sub_account,
            self.role_id,
            instructions,
            current_slot,
        )
    }

    /// Withdraws native SOL from a sub-account
    ///
    /// # Arguments
    ///
    /// * `sub_account` - The public key of the sub-account
    /// * `amount` - The amount of SOL to withdraw in lamports
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
    ) -> Result<Vec<Instruction>, SwigError> {
        self.client_role.withdraw_from_sub_account_instruction(
            self.swig_account,
            self.payer,
            sub_account,
            self.role_id,
            amount,
            current_slot,
        )
    }

    /// Withdraws tokens from a sub-account
    ///
    /// # Arguments
    ///
    /// * `sub_account` - The public key of the sub-account
    /// * `sub_account_token` - The public key of the sub-account's token
    ///   account
    /// * `swig_token` - The public key of the Swig wallet's token account
    /// * `token_program` - The token program ID
    /// * `amount` - The amount of tokens to withdraw
    /// * `current_slot` - Optional current slot number (required for Secp256k1)
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the withdraw token instruction or a
    /// `SwigError`
    pub fn withdraw_token_from_sub_account(
        &self,
        sub_account: Pubkey,
        sub_account_token: Pubkey,
        swig_token: Pubkey,
        token_program: Pubkey,
        amount: u64,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        self.client_role
            .withdraw_token_from_sub_account_instruction(
                self.swig_account,
                self.payer,
                sub_account,
                sub_account_token,
                swig_token,
                token_program,
                self.role_id,
                amount,
                current_slot,
            )
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
        sub_account_role_id: u32,
        auth_role_id: u32,
        enabled: bool,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        self.client_role.toggle_sub_account_instruction(
            self.swig_account,
            self.payer,
            sub_account,
            sub_account_role_id,
            auth_role_id,
            enabled,
            current_slot,
        )
    }

    /// Returns the current authority's public key as bytes
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the authority's public key as bytes or a
    /// `SwigError`
    pub fn get_current_authority(&self) -> Result<Vec<u8>, SwigError> {
        self.client_role.authority_bytes()
    }

    /// Returns the odometer for the current authority if it is a Secp based
    /// authority
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the odometer or a `SwigError`
    pub fn get_odometer(&self) -> Result<u32, SwigError> {
        self.client_role.odometer()
    }

    /// Increments the odometer for the current authority if it is Secp based
    /// authority
    pub fn increment_odometer(&mut self) -> Result<(), SwigError> {
        self.client_role.increment_odometer()
    }
}
