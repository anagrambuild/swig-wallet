use solana_program::{instruction::Instruction, pubkey::Pubkey};
use swig_interface::{
    AddAuthorityInstruction, AuthorityConfig, ClientAction, CreateSessionInstruction,
    CreateSubAccountInstruction, RemoveAuthorityInstruction, SignInstruction, SignV2Instruction,
    SubAccountSignInstruction, ToggleSubAccountInstruction, UpdateAuthorityData,
    UpdateAuthorityInstruction, WithdrawFromSubAccountInstruction,
};
use swig_state::{
    authority::{
        ed25519::CreateEd25519SessionAuthority, secp256k1::CreateSecp256k1SessionAuthority,
        secp256r1::CreateSecp256r1SessionAuthority, AuthorityType,
    },
    IntoBytes,
};

use crate::{error::SwigError, types::Permission as ClientPermission};

/// Trait for client-side role implementations that handle instruction creation
/// for different authority types.
pub trait ClientRole {
    /// Creates a sign instruction for the given inner instructions
    fn sign_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError>;

    /// Creates an add authority instruction
    fn add_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        new_authority_type: AuthorityType,
        new_authority: &[u8],
        actions: Vec<ClientAction>,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError>;

    /// Creates a remove authority instruction
    fn remove_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_remove_id: u32,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError>;

    /// Creates an update authority instruction
    fn update_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_update_id: u32,
        update_data: UpdateAuthorityData,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError>;

    /// Creates a create session instruction
    fn create_session_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        session_key: Pubkey,
        session_duration: u64,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError>;

    /// Creates a create sub account instruction
    fn create_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        sub_account: Pubkey,
        sub_account_bump: u8,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError>;

    /// Creates a sub account sign instruction
    fn sub_account_sign_instruction(
        &self,
        swig_account: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError>;

    /// Creates a withdraw from sub account instruction
    fn withdraw_from_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        amount: u64,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError>;

    /// Creates a withdraw token from sub account instruction
    fn withdraw_token_from_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        sub_account_token: Pubkey,
        swig_token: Pubkey,
        token_program: Pubkey,
        role_id: u32,
        amount: u64,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError>;

    /// Creates a toggle sub account instruction
    fn toggle_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        auth_role_id: u32,
        enabled: bool,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError>;

    /// Returns the authority type
    fn authority_type(&self) -> AuthorityType;

    /// Returns the authority bytes for creating the Swig account
    fn authority_bytes(&self) -> Result<Vec<u8>, SwigError>;

    /// Returns the odometer for the current authority if it is a Secp256k1
    /// authority
    fn odometer(&self) -> Result<u32, SwigError>;

    /// Increments the odometer for the current authority if it is a Secp256k1
    /// authority
    fn increment_odometer(&mut self) -> Result<(), SwigError>;

    /// Update the odometer for the authority
    fn update_odometer(&mut self, odometer: u32) -> Result<(), SwigError>;

    /// Creates a SignV2 instruction for the given inner instructions
    fn sign_v2_instruction(
        &self,
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
        transaction_signers: &[Pubkey],
    ) -> Result<Vec<Instruction>, SwigError>;
}

/// Ed25519 authority implementation
pub struct Ed25519ClientRole {
    pub authority: Pubkey,
}

impl Ed25519ClientRole {
    pub fn new(authority: Pubkey) -> Self {
        Self { authority }
    }
}

impl ClientRole for Ed25519ClientRole {
    fn sign_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let mut signed_instructions = Vec::new();
        for instruction in instructions {
            let swig_signed_instruction = SignInstruction::new_ed25519(
                swig_account,
                payer,
                self.authority,
                instruction,
                role_id,
            )?;
            signed_instructions.push(swig_signed_instruction);
        }
        Ok(signed_instructions)
    }

    fn add_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        new_authority_type: AuthorityType,
        new_authority: &[u8],
        actions: Vec<ClientAction>,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let instructions = AddAuthorityInstruction::new_with_ed25519_authority(
            swig_account,
            payer,
            self.authority,
            role_id,
            AuthorityConfig {
                authority_type: new_authority_type,
                authority: new_authority,
            },
            actions,
        )?;

        Ok(vec![instructions])
    }

    fn remove_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_remove_id: u32,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        Ok(vec![
            RemoveAuthorityInstruction::new_with_ed25519_authority(
                swig_account,
                payer,
                self.authority,
                role_id,
                authority_to_remove_id,
            )?,
        ])
    }

    fn update_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_update_id: u32,
        update_data: UpdateAuthorityData,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        Ok(vec![
            UpdateAuthorityInstruction::new_with_ed25519_authority(
                swig_account,
                payer,
                self.authority,
                role_id,
                authority_to_update_id,
                update_data,
            )?,
        ])
    }

    fn create_session_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        session_key: Pubkey,
        session_duration: u64,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        Ok(vec![CreateSessionInstruction::new_with_ed25519_authority(
            swig_account,
            payer,
            self.authority,
            role_id,
            session_key,
            session_duration,
        )?])
    }

    fn create_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        sub_account: Pubkey,
        sub_account_bump: u8,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        Ok(vec![
            CreateSubAccountInstruction::new_with_ed25519_authority(
                swig_account,
                self.authority,
                payer,
                sub_account,
                role_id,
                sub_account_bump,
            )?,
        ])
    }

    fn sub_account_sign_instruction(
        &self,
        swig_account: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        Ok(vec![SubAccountSignInstruction::new_with_ed25519_authority(
            swig_account,
            sub_account,
            self.authority,
            role_id,
            instructions,
        )?])
    }

    fn withdraw_from_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        amount: u64,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        // Derive the swig wallet address
        let (swig_wallet_address, _) = Pubkey::find_program_address(
            &swig_state::swig::swig_wallet_address_seeds(swig_account.as_ref()),
            &swig_interface::program_id(),
        );

        Ok(vec![
            WithdrawFromSubAccountInstruction::new_with_ed25519_authority(
                swig_account,
                self.authority,
                payer,
                sub_account,
                swig_wallet_address,
                role_id,
                amount,
            )?,
        ])
    }

    fn withdraw_token_from_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        sub_account_token: Pubkey,
        swig_token: Pubkey,
        token_program: Pubkey,
        role_id: u32,
        amount: u64,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        // Derive the swig wallet address
        let (swig_wallet_address, _) = Pubkey::find_program_address(
            &swig_state::swig::swig_wallet_address_seeds(swig_account.as_ref()),
            &swig_interface::program_id(),
        );

        Ok(vec![
            WithdrawFromSubAccountInstruction::new_token_with_ed25519_authority(
                swig_account,
                self.authority,
                payer,
                sub_account,
                swig_wallet_address,
                sub_account_token,
                swig_token,
                token_program,
                role_id,
                amount,
            )?,
        ])
    }

    fn toggle_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        auth_role_id: u32,
        enabled: bool,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        Ok(vec![
            ToggleSubAccountInstruction::new_with_ed25519_authority(
                swig_account,
                self.authority,
                payer,
                sub_account,
                role_id,
                auth_role_id,
                enabled,
            )?,
        ])
    }

    fn authority_type(&self) -> AuthorityType {
        AuthorityType::Ed25519
    }

    fn authority_bytes(&self) -> Result<Vec<u8>, SwigError> {
        Ok(self.authority.to_bytes().to_vec())
    }

    fn odometer(&self) -> Result<u32, SwigError> {
        Ok(0)
    }

    fn increment_odometer(&mut self) -> Result<(), SwigError> {
        // Ed25519 authorities don't use odometer-based replay protection
        Ok(())
    }

    fn update_odometer(&mut self, odometer: u32) -> Result<(), SwigError> {
        Ok(())
    }

    fn sign_v2_instruction(
        &self,
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        _current_slot: Option<u64>,
        transaction_signers: &[Pubkey],
    ) -> Result<Vec<Instruction>, SwigError> {
        let mut signed_instructions = Vec::new();
        for instruction in instructions {
            let swig_signed_instruction = SignV2Instruction::new_ed25519_with_signers(
                swig_account,
                swig_wallet_address,
                self.authority,
                instruction,
                role_id,
                transaction_signers,
            )?;
            signed_instructions.push(swig_signed_instruction);
        }
        Ok(signed_instructions)
    }
}

/// Secp256k1 authority implementation
pub struct Secp256k1ClientRole {
    pub authority: Box<[u8]>,
    pub signing_fn: Box<dyn Fn(&[u8]) -> [u8; 65]>,
    pub odometer: u32,
}

impl Secp256k1ClientRole {
    pub fn new(authority: Box<[u8]>, signing_fn: Box<dyn Fn(&[u8]) -> [u8; 65]>) -> Self {
        Self {
            authority,
            signing_fn,
            odometer: 0,
        }
    }

    pub fn new_without_odometer(
        authority: Box<[u8]>,
        signing_fn: Box<dyn Fn(&[u8]) -> [u8; 65]>,
    ) -> Self {
        Self {
            authority,
            signing_fn,
            odometer: 0,
        }
    }
}

impl ClientRole for Secp256k1ClientRole {
    fn sign_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);
        let mut signed_instructions = Vec::new();
        for instruction in instructions {
            let swig_signed_instruction = SignInstruction::new_secp256k1(
                swig_account,
                payer,
                &self.signing_fn,
                current_slot,
                new_odometer,
                instruction,
                role_id,
            )?;
            signed_instructions.push(swig_signed_instruction);
        }
        Ok(signed_instructions)
    }

    fn add_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        new_authority_type: AuthorityType,
        new_authority: &[u8],
        actions: Vec<ClientAction>,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        let instructions = AddAuthorityInstruction::new_with_secp256k1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            new_odometer,
            role_id,
            AuthorityConfig {
                authority_type: new_authority_type,
                authority: &new_authority[1..],
            },
            actions,
        )?;

        Ok(vec![instructions])
    }

    fn remove_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_remove_id: u32,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        Ok(vec![
            RemoveAuthorityInstruction::new_with_secp256k1_authority(
                swig_account,
                payer,
                &self.signing_fn,
                current_slot,
                new_odometer,
                role_id,
                authority_to_remove_id,
            )?,
        ])
    }

    fn update_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_update_id: u32,
        update_data: UpdateAuthorityData,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        Ok(vec![
            UpdateAuthorityInstruction::new_with_secp256k1_authority(
                swig_account,
                payer,
                &self.signing_fn,
                current_slot,
                new_odometer,
                role_id,
                authority_to_update_id,
                update_data,
            )?,
        ])
    }

    fn create_session_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        session_key: Pubkey,
        session_duration: u64,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);
        Ok(vec![
            CreateSessionInstruction::new_with_secp256k1_authority(
                swig_account,
                payer,
                &self.signing_fn,
                current_slot,
                new_odometer,
                role_id,
                session_key,
                session_duration,
            )?,
        ])
    }

    fn create_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        sub_account: Pubkey,
        sub_account_bump: u8,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;

        Ok(vec![
            CreateSubAccountInstruction::new_with_secp256k1_authority(
                swig_account,
                payer,
                &self.signing_fn,
                current_slot,
                sub_account,
                role_id,
                sub_account_bump,
            )?,
        ])
    }

    fn sub_account_sign_instruction(
        &self,
        swig_account: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;

        Ok(vec![
            SubAccountSignInstruction::new_with_secp256k1_authority(
                swig_account,
                sub_account,
                &self.signing_fn,
                current_slot,
                role_id,
                instructions,
            )?,
        ])
    }

    fn withdraw_from_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        amount: u64,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;

        // Derive the swig wallet address
        let (swig_wallet_address, _) = Pubkey::find_program_address(
            &swig_state::swig::swig_wallet_address_seeds(swig_account.as_ref()),
            &swig_interface::program_id(),
        );

        Ok(vec![
            WithdrawFromSubAccountInstruction::new_with_secp256k1_authority(
                swig_account,
                payer,
                &self.signing_fn,
                current_slot,
                sub_account,
                swig_wallet_address,
                role_id,
                amount,
            )?,
        ])
    }

    fn withdraw_token_from_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        sub_account_token: Pubkey,
        swig_token: Pubkey,
        token_program: Pubkey,
        role_id: u32,
        amount: u64,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;

        // Derive the swig wallet address
        let (swig_wallet_address, _) = Pubkey::find_program_address(
            &swig_state::swig::swig_wallet_address_seeds(swig_account.as_ref()),
            &swig_interface::program_id(),
        );

        Ok(vec![
            WithdrawFromSubAccountInstruction::new_token_with_secp256k1_authority(
                swig_account,
                payer,
                &self.signing_fn,
                current_slot,
                sub_account,
                swig_wallet_address,
                sub_account_token,
                swig_token,
                token_program,
                role_id,
                amount,
            )?,
        ])
    }

    fn toggle_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        auth_role_id: u32,
        enabled: bool,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;

        Ok(vec![
            ToggleSubAccountInstruction::new_with_secp256k1_authority(
                swig_account,
                payer,
                &self.signing_fn,
                current_slot,
                sub_account,
                role_id,
                auth_role_id,
                enabled,
            )?,
        ])
    }

    fn authority_type(&self) -> AuthorityType {
        AuthorityType::Secp256k1
    }

    fn authority_bytes(&self) -> Result<Vec<u8>, SwigError> {
        // For Secp256k1, the authority can be either 64 bytes (uncompressed, no 0x04
        // prefix) or 65 bytes (uncompressed with 0x04 prefix)
        match self.authority.len() {
            64 => Ok(self.authority.to_vec()),
            65 => {
                // Check if it starts with 0x04 prefix and remove it
                if self.authority[0] == 0x04 {
                    Ok(self.authority[1..].to_vec())
                } else {
                    Err(SwigError::InvalidAuthorityType)
                }
            },
            _ => Err(SwigError::InvalidAuthorityType),
        }
    }

    fn odometer(&self) -> Result<u32, SwigError> {
        Ok(self.odometer)
    }

    fn increment_odometer(&mut self) -> Result<(), SwigError> {
        self.odometer = self.odometer.wrapping_add(1);
        Ok(())
    }

    fn update_odometer(&mut self, odometer: u32) -> Result<(), SwigError> {
        self.odometer = odometer;
        Ok(())
    }

    fn sign_v2_instruction(
        &self,
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
        transaction_signers: &[Pubkey],
    ) -> Result<Vec<Instruction>, SwigError> {
        let mut signed_instructions = Vec::new();
        let current_slot = current_slot.ok_or(SwigError::SlotRequired)?;
        let new_odometer = self.odometer.wrapping_add(1);

        for instruction in instructions {
            let swig_signed_instruction = SignV2Instruction::new_secp256k1_with_signers(
                swig_account,
                swig_wallet_address,
                &self.signing_fn,
                current_slot,
                new_odometer,
                instruction,
                role_id,
                transaction_signers,
            )?;
            signed_instructions.push(swig_signed_instruction);
        }
        Ok(signed_instructions)
    }
}

/// Secp256r1 authority implementation
pub struct Secp256r1ClientRole {
    pub authority: [u8; 33],
    pub signing_fn: Box<dyn Fn(&[u8]) -> [u8; 64]>,
    pub odometer: u32,
}

impl Secp256r1ClientRole {
    pub fn new(authority: [u8; 33], signing_fn: Box<dyn Fn(&[u8]) -> [u8; 64]>) -> Self {
        Self {
            authority,
            signing_fn,
            odometer: 0,
        }
    }

    pub fn new_without_odometer(
        authority: [u8; 33],
        signing_fn: Box<dyn Fn(&[u8]) -> [u8; 64]>,
    ) -> Self {
        Self {
            authority,
            signing_fn,
            odometer: 0,
        }
    }
}

impl ClientRole for Secp256r1ClientRole {
    fn sign_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);
        let mut signed_instructions = Vec::new();
        for instruction in instructions {
            let swig_signed_instruction = SignInstruction::new_secp256r1(
                swig_account,
                payer,
                &self.signing_fn,
                current_slot,
                new_odometer,
                instruction,
                role_id,
                &self.authority,
            )?;
            signed_instructions.extend(swig_signed_instruction);
        }
        Ok(signed_instructions)
    }

    fn add_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        new_authority_type: AuthorityType,
        new_authority: &[u8],
        actions: Vec<ClientAction>,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        let instructions = AddAuthorityInstruction::new_with_secp256r1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            new_odometer,
            role_id,
            &self.authority,
            AuthorityConfig {
                authority_type: new_authority_type,
                authority: new_authority,
            },
            actions,
        )?;

        Ok(instructions)
    }

    fn remove_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_remove_id: u32,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        let instructions = RemoveAuthorityInstruction::new_with_secp256r1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            new_odometer,
            role_id,
            authority_to_remove_id,
            &self.authority,
        )?;

        Ok(instructions)
    }

    fn update_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_update_id: u32,
        update_data: UpdateAuthorityData,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        Ok(UpdateAuthorityInstruction::new_with_secp256r1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            new_odometer,
            role_id,
            authority_to_update_id,
            update_data,
            &self.authority,
        )?)
    }

    fn create_session_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        session_key: Pubkey,
        session_duration: u64,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        let instructions = CreateSessionInstruction::new_with_secp256r1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            new_odometer,
            role_id,
            session_key,
            session_duration,
            &self.authority,
        )?;

        Ok(instructions)
    }

    fn create_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        sub_account: Pubkey,
        sub_account_bump: u8,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        let instructions = CreateSubAccountInstruction::new_with_secp256r1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            new_odometer,
            sub_account,
            role_id,
            sub_account_bump,
            &self.authority,
        )?;

        Ok(instructions)
    }

    fn sub_account_sign_instruction(
        &self,
        swig_account: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        let swig_instructions = SubAccountSignInstruction::new_with_secp256r1_authority(
            swig_account,
            sub_account,
            &self.signing_fn,
            current_slot,
            new_odometer,
            role_id,
            instructions,
            &self.authority,
        )?;

        Ok(swig_instructions)
    }

    fn withdraw_from_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        amount: u64,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        // Derive the swig wallet address
        let (swig_wallet_address, _) = Pubkey::find_program_address(
            &swig_state::swig::swig_wallet_address_seeds(swig_account.as_ref()),
            &swig_interface::program_id(),
        );

        let instructions = WithdrawFromSubAccountInstruction::new_with_secp256r1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            new_odometer,
            sub_account,
            swig_wallet_address,
            role_id,
            amount,
            &self.authority,
        )?;

        Ok(instructions)
    }

    fn withdraw_token_from_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        sub_account_token: Pubkey,
        swig_token: Pubkey,
        token_program: Pubkey,
        role_id: u32,
        amount: u64,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        // Derive the swig wallet address
        let (swig_wallet_address, _) = Pubkey::find_program_address(
            &swig_state::swig::swig_wallet_address_seeds(swig_account.as_ref()),
            &swig_interface::program_id(),
        );

        let instructions = WithdrawFromSubAccountInstruction::new_token_with_secp256r1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            new_odometer,
            sub_account,
            swig_wallet_address,
            sub_account_token,
            swig_token,
            token_program,
            role_id,
            amount,
            &self.authority,
        )?;

        Ok(instructions)
    }

    fn toggle_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        auth_role_id: u32,
        enabled: bool,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        let instructions = ToggleSubAccountInstruction::new_with_secp256r1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            new_odometer,
            sub_account,
            role_id,
            auth_role_id,
            enabled,
            &self.authority,
        )?;

        Ok(instructions)
    }

    fn authority_type(&self) -> AuthorityType {
        AuthorityType::Secp256r1
    }

    fn authority_bytes(&self) -> Result<Vec<u8>, SwigError> {
        Ok(self.authority.to_vec())
    }

    fn odometer(&self) -> Result<u32, SwigError> {
        Ok(self.odometer)
    }

    fn increment_odometer(&mut self) -> Result<(), SwigError> {
        self.odometer = self.odometer.wrapping_add(1);
        Ok(())
    }

    fn update_odometer(&mut self, odometer: u32) -> Result<(), SwigError> {
        self.odometer = odometer;
        Ok(())
    }

    fn sign_v2_instruction(
        &self,
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
        transaction_signers: &[Pubkey],
    ) -> Result<Vec<Instruction>, SwigError> {
        let mut signed_instructions = Vec::new();
        let current_slot = current_slot.ok_or(SwigError::SlotRequired)?;
        let new_odometer = self.odometer.wrapping_add(1);

        for instruction in instructions {
            let swig_signed_instructions = SignV2Instruction::new_secp256r1_with_signers(
                swig_account,
                swig_wallet_address,
                &self.signing_fn,
                current_slot,
                new_odometer,
                instruction,
                role_id,
                &self.authority,
                transaction_signers,
            )?;
            signed_instructions.extend(swig_signed_instructions);
        }
        Ok(signed_instructions)
    }
}

/// Ed25519 Session authority implementation
pub struct Ed25519SessionClientRole {
    pub session_authority: CreateEd25519SessionAuthority,
}

impl Ed25519SessionClientRole {
    pub fn new(session_authority: CreateEd25519SessionAuthority) -> Self {
        Self { session_authority }
    }
}

impl ClientRole for Ed25519SessionClientRole {
    fn sign_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let session_authority_pubkey = Pubkey::new_from_array(self.session_authority.public_key);

        let mut signed_instructions = Vec::new();
        for instruction in instructions {
            let swig_signed_instruction = SignInstruction::new_ed25519(
                swig_account,
                payer,
                session_authority_pubkey,
                instruction,
                role_id,
            )?;
            signed_instructions.push(swig_signed_instruction);
        }
        Ok(signed_instructions)
    }

    fn add_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        new_authority_type: AuthorityType,
        new_authority: &[u8],
        actions: Vec<ClientAction>,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let instructions = AddAuthorityInstruction::new_with_ed25519_authority(
            swig_account,
            payer,
            self.session_authority.public_key.into(),
            role_id,
            AuthorityConfig {
                authority_type: new_authority_type,
                authority: new_authority,
            },
            actions,
        )?;

        Ok(vec![instructions])
    }

    fn remove_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_remove_id: u32,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        Ok(vec![
            RemoveAuthorityInstruction::new_with_ed25519_authority(
                swig_account,
                payer,
                self.session_authority.public_key.into(),
                role_id,
                authority_to_remove_id,
            )?,
        ])
    }

    fn update_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_update_id: u32,
        update_data: UpdateAuthorityData,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        Ok(vec![
            UpdateAuthorityInstruction::new_with_ed25519_authority(
                swig_account,
                payer,
                self.session_authority.public_key.into(),
                role_id,
                authority_to_update_id,
                update_data,
            )?,
        ])
    }

    fn create_session_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        session_key: Pubkey,
        session_duration: u64,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        Ok(vec![CreateSessionInstruction::new_with_ed25519_authority(
            swig_account,
            payer,
            self.session_authority.public_key.into(),
            role_id,
            session_key,
            session_duration,
        )?])
    }

    fn create_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _role_id: u32,
        _sub_account: Pubkey,
        _sub_account_bump: u8,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        todo!("Session authorities don't support sub-account creation")
    }

    fn sub_account_sign_instruction(
        &self,
        _swig_account: Pubkey,
        _sub_account: Pubkey,
        _role_id: u32,
        _instructions: Vec<Instruction>,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        todo!("Session authorities don't support sub-account signing")
    }

    fn withdraw_from_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _sub_account: Pubkey,
        _role_id: u32,
        _amount: u64,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        todo!("Session authorities don't support sub-account operations")
    }

    fn withdraw_token_from_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _sub_account: Pubkey,
        _sub_account_token: Pubkey,
        _swig_token: Pubkey,
        _token_program: Pubkey,
        _role_id: u32,
        _amount: u64,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        todo!("Session authorities don't support sub-account operations")
    }

    fn toggle_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _sub_account: Pubkey,
        _role_id: u32,
        _auth_role_id: u32,
        _enabled: bool,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        todo!("Session authorities don't support sub-account operations")
    }

    fn authority_type(&self) -> AuthorityType {
        AuthorityType::Ed25519Session
    }

    fn authority_bytes(&self) -> Result<Vec<u8>, SwigError> {
        Ok(self.session_authority.into_bytes().unwrap().to_vec())
    }

    fn odometer(&self) -> Result<u32, SwigError> {
        Ok(0)
    }

    fn increment_odometer(&mut self) -> Result<(), SwigError> {
        // Ed25519 session authorities don't use odometer-based replay protection
        Ok(())
    }

    fn update_odometer(&mut self, odometer: u32) -> Result<(), SwigError> {
        Ok(())
    }

    fn sign_v2_instruction(
        &self,
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        _current_slot: Option<u64>,
        transaction_signers: &[Pubkey],
    ) -> Result<Vec<Instruction>, SwigError> {
        let mut signed_instructions = Vec::new();
        for instruction in instructions {
            let session_key_pubkey = Pubkey::new_from_array(self.session_authority.session_key);
            let swig_signed_instruction = SignV2Instruction::new_ed25519_with_signers(
                swig_account,
                swig_wallet_address,
                session_key_pubkey,
                instruction,
                role_id,
                transaction_signers,
            )?;
            signed_instructions.push(swig_signed_instruction);
        }
        Ok(signed_instructions)
    }
}

/// Secp256k1 Session authority implementation
pub struct Secp256k1SessionClientRole {
    pub session_authority: CreateSecp256k1SessionAuthority,
    pub signing_fn: Box<dyn Fn(&[u8]) -> [u8; 65]>,
    pub odometer: u32,
}

impl Secp256k1SessionClientRole {
    pub fn new(
        session_authority: CreateSecp256k1SessionAuthority,
        signing_fn: Box<dyn Fn(&[u8]) -> [u8; 65]>,
    ) -> Self {
        Self {
            session_authority,
            signing_fn,
            odometer: 0,
        }
    }

    pub fn new_with_odometer(
        session_authority: CreateSecp256k1SessionAuthority,
        signing_fn: Box<dyn Fn(&[u8]) -> [u8; 65]>,
        odometer: u32,
    ) -> Self {
        Self {
            session_authority,
            signing_fn,
            odometer,
        }
    }
}

impl ClientRole for Secp256k1SessionClientRole {
    fn sign_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;

        let mut signed_instructions = Vec::new();
        for instruction in instructions {
            let swig_signed_instruction = SignInstruction::new_secp256k1(
                swig_account,
                payer,
                &self.signing_fn,
                current_slot,
                0u32,
                instruction,
                role_id,
            )?;
            signed_instructions.push(swig_signed_instruction);
        }
        Ok(signed_instructions)
    }

    fn add_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        new_authority_type: AuthorityType,
        new_authority: &[u8],
        actions: Vec<ClientAction>,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;

        let instructions = AddAuthorityInstruction::new_with_secp256k1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            0u32,
            role_id,
            AuthorityConfig {
                authority_type: new_authority_type,
                authority: new_authority,
            },
            actions,
        )?;

        Ok(vec![instructions])
    }

    fn remove_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_remove_id: u32,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        Ok(vec![
            RemoveAuthorityInstruction::new_with_secp256k1_authority(
                swig_account,
                payer,
                &self.signing_fn,
                current_slot,
                new_odometer,
                authority_to_remove_id,
                role_id,
            )?,
        ])
    }

    fn update_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_update_id: u32,
        update_data: UpdateAuthorityData,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        Ok(vec![
            UpdateAuthorityInstruction::new_with_secp256k1_authority(
                swig_account,
                payer,
                &self.signing_fn,
                current_slot,
                new_odometer,
                role_id,
                authority_to_update_id,
                update_data,
            )?,
        ])
    }

    fn create_session_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        session_key: Pubkey,
        session_duration: u64,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        Ok(vec![
            CreateSessionInstruction::new_with_secp256k1_authority(
                swig_account,
                payer,
                &self.signing_fn,
                current_slot,
                new_odometer,
                role_id,
                session_key,
                session_duration,
            )?,
        ])
    }

    fn create_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _role_id: u32,
        _sub_account: Pubkey,
        _sub_account_bump: u8,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        todo!("Session authorities don't support sub-account creation")
    }

    fn sub_account_sign_instruction(
        &self,
        _swig_account: Pubkey,
        _sub_account: Pubkey,
        _role_id: u32,
        _instructions: Vec<Instruction>,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        todo!("Session authorities don't support sub-account signing")
    }

    fn withdraw_from_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _sub_account: Pubkey,
        _role_id: u32,
        _amount: u64,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        todo!("Session authorities don't support sub-account operations")
    }

    fn withdraw_token_from_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _sub_account: Pubkey,
        _sub_account_token: Pubkey,
        _swig_token: Pubkey,
        _token_program: Pubkey,
        _role_id: u32,
        _amount: u64,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        todo!("Session authorities don't support sub-account operations")
    }

    fn toggle_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _sub_account: Pubkey,
        _role_id: u32,
        _auth_role_id: u32,
        _enabled: bool,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        todo!("Session authorities don't support sub-account operations")
    }

    fn authority_type(&self) -> AuthorityType {
        AuthorityType::Secp256k1Session
    }

    fn authority_bytes(&self) -> Result<Vec<u8>, SwigError> {
        Ok(self.session_authority.into_bytes().unwrap().to_vec())
    }

    fn odometer(&self) -> Result<u32, SwigError> {
        Ok(self.odometer)
    }

    fn increment_odometer(&mut self) -> Result<(), SwigError> {
        self.odometer = self.odometer.wrapping_add(1);
        Ok(())
    }

    fn update_odometer(&mut self, odometer: u32) -> Result<(), SwigError> {
        self.odometer = odometer;
        Ok(())
    }

    fn sign_v2_instruction(
        &self,
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
        transaction_signers: &[Pubkey],
    ) -> Result<Vec<Instruction>, SwigError> {
        let mut signed_instructions = Vec::new();
        let current_slot = current_slot.ok_or(SwigError::SlotRequired)?;
        let new_odometer = self.odometer.wrapping_add(1);

        for instruction in instructions {
            let swig_signed_instruction = SignV2Instruction::new_secp256k1_with_signers(
                swig_account,
                swig_wallet_address,
                &self.signing_fn,
                current_slot,
                new_odometer,
                instruction,
                role_id,
                transaction_signers,
            )?;
            signed_instructions.push(swig_signed_instruction);
        }
        Ok(signed_instructions)
    }
}

/// Secp256r1 Session authority implementation
pub struct Secp256r1SessionClientRole {
    pub session_authority: CreateSecp256r1SessionAuthority,
    pub signing_fn: Box<dyn Fn(&[u8]) -> [u8; 64]>,
    pub odometer: u32,
}

impl Secp256r1SessionClientRole {
    pub fn new(
        session_authority: CreateSecp256r1SessionAuthority,
        signing_fn: Box<dyn Fn(&[u8]) -> [u8; 64]>,
    ) -> Self {
        Self {
            session_authority,
            signing_fn,
            odometer: 0,
        }
    }

    pub fn new_with_odometer(
        session_authority: CreateSecp256r1SessionAuthority,
        signing_fn: Box<dyn Fn(&[u8]) -> [u8; 64]>,
        odometer: u32,
    ) -> Self {
        Self {
            session_authority,
            signing_fn,
            odometer,
        }
    }
}

impl ClientRole for Secp256r1SessionClientRole {
    fn sign_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        let mut signed_instructions = Vec::new();
        for instruction in instructions {
            let swig_signed_instruction = SignInstruction::new_secp256r1(
                swig_account,
                payer,
                &self.signing_fn,
                current_slot,
                new_odometer,
                instruction,
                role_id,
                &self.session_authority.public_key,
            )?;
            signed_instructions.extend(swig_signed_instruction);
        }
        Ok(signed_instructions)
    }

    fn add_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        new_authority_type: AuthorityType,
        new_authority: &[u8],
        actions: Vec<ClientAction>,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);
        let instructions = AddAuthorityInstruction::new_with_secp256r1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            new_odometer,
            role_id,
            &self.session_authority.public_key,
            AuthorityConfig {
                authority_type: new_authority_type,
                authority: new_authority,
            },
            actions,
        )?;

        Ok(instructions)
    }

    fn remove_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_remove_id: u32,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        let instructions = RemoveAuthorityInstruction::new_with_secp256r1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            new_odometer,
            role_id,
            authority_to_remove_id,
            &self.session_authority.public_key,
        )?;

        Ok(instructions)
    }

    fn update_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_update_id: u32,
        update_data: UpdateAuthorityData,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        Ok(UpdateAuthorityInstruction::new_with_secp256r1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            new_odometer,
            role_id,
            authority_to_update_id,
            update_data,
            &self.session_authority.public_key,
        )?)
    }

    fn create_session_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        session_key: Pubkey,
        session_duration: u64,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        let instructions = CreateSessionInstruction::new_with_secp256r1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            new_odometer,
            role_id,
            session_key,
            session_duration,
            &self.session_authority.public_key,
        )?;

        Ok(instructions)
    }

    fn create_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _role_id: u32,
        _sub_account: Pubkey,
        _sub_account_bump: u8,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        todo!("Session authorities don't support sub-account creation")
    }

    fn sub_account_sign_instruction(
        &self,
        _swig_account: Pubkey,
        _sub_account: Pubkey,
        _role_id: u32,
        _instructions: Vec<Instruction>,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        todo!("Session authorities don't support sub-account signing")
    }

    fn withdraw_from_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _sub_account: Pubkey,
        _role_id: u32,
        _amount: u64,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        todo!("Session authorities don't support sub-account operations")
    }

    fn withdraw_token_from_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _sub_account: Pubkey,
        _sub_account_token: Pubkey,
        _swig_token: Pubkey,
        _token_program: Pubkey,
        _role_id: u32,
        _amount: u64,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        todo!("Session authorities don't support sub-account operations")
    }

    fn toggle_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _sub_account: Pubkey,
        _role_id: u32,
        _auth_role_id: u32,
        _enabled: bool,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        todo!("Session authorities don't support sub-account operations")
    }

    fn authority_type(&self) -> AuthorityType {
        AuthorityType::Secp256r1Session
    }

    fn authority_bytes(&self) -> Result<Vec<u8>, SwigError> {
        Ok(self.session_authority.into_bytes().unwrap().to_vec())
    }

    fn odometer(&self) -> Result<u32, SwigError> {
        Ok(self.odometer)
    }

    fn increment_odometer(&mut self) -> Result<(), SwigError> {
        self.odometer = self.odometer.wrapping_add(1);
        Ok(())
    }

    fn update_odometer(&mut self, odometer: u32) -> Result<(), SwigError> {
        self.odometer = odometer;
        Ok(())
    }

    fn sign_v2_instruction(
        &self,
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
        transaction_signers: &[Pubkey],
    ) -> Result<Vec<Instruction>, SwigError> {
        let mut signed_instructions = Vec::new();
        let current_slot = current_slot.ok_or(SwigError::SlotRequired)?;
        let new_odometer = self.odometer.wrapping_add(1);
        for instruction in instructions {
            let swig_signed_instructions = SignV2Instruction::new_secp256r1_with_signers(
                swig_account,
                swig_wallet_address,
                &self.signing_fn,
                current_slot,
                new_odometer,
                instruction,
                role_id,
                &self.session_authority.public_key,
                transaction_signers,
            )?;
            signed_instructions.extend(swig_signed_instructions);
        }
        Ok(signed_instructions)
    }
}

/// Client role for ProgramExec authority.
///
/// This authority type validates that a preceding instruction in the
/// transaction matches the configured program ID and instruction discriminator.
/// The preceding instruction must be provided when creating sign instructions.
///
/// ProgramExec authority works with SignV2 only, as it requires separate config
/// and wallet address accounts.
pub struct ProgramExecClientRole {
    /// The program ID that must execute the preceding instruction
    pub program_id: Pubkey,
    /// The instruction discriminator/prefix to match
    pub instruction_prefix: Vec<u8>,
}

impl ProgramExecClientRole {
    /// Creates a new ProgramExecClientRole.
    ///
    /// # Arguments
    /// * `program_id` - The program ID that must execute the preceding
    ///   instruction
    /// * `instruction_prefix` - The instruction discriminator/prefix to match
    ///   (up to 40 bytes)
    pub fn new(program_id: Pubkey, instruction_prefix: Vec<u8>) -> Self {
        Self {
            program_id,
            instruction_prefix,
        }
    }

    /// Creates authority data for a ProgramExec authority.
    ///
    /// This is a convenience method that generates the authority data bytes
    /// needed when adding a ProgramExec authority to a Swig wallet.
    pub fn authority_data(&self) -> Vec<u8> {
        use swig_state::authority::programexec::ProgramExecAuthority;
        ProgramExecAuthority::create_authority_data(
            &self.program_id.to_bytes(),
            &self.instruction_prefix,
        )
    }

    /// Creates a sign instruction with a preceding program instruction.
    ///
    /// This method creates both the preceding instruction and the sign
    /// instruction that must be executed together in the same transaction.
    ///
    /// # Arguments
    /// * `swig_account` - The Swig wallet config account
    /// * `swig_wallet_address` - The Swig wallet address PDA
    /// * `payer` - The transaction fee payer
    /// * `preceding_instruction` - The instruction that must precede the sign
    ///   instruction
    /// * `inner_instruction` - The instruction to be signed by the Swig wallet
    /// * `role_id` - The role ID that has ProgramExec authority
    ///
    /// # Returns
    /// Returns a vector containing both instructions that must be executed in
    /// order: [preceding_instruction, sign_instruction]
    pub fn sign_with_program_exec(
        &self,
        swig_account: Pubkey,
        swig_wallet_address: Pubkey,
        payer: Pubkey,
        preceding_instruction: Instruction,
        inner_instruction: Instruction,
        role_id: u32,
    ) -> Result<Vec<Instruction>, SwigError> {
        SignV2Instruction::new_program_exec(
            swig_account,
            swig_wallet_address,
            payer,
            preceding_instruction,
            inner_instruction,
            role_id,
        )
        .map_err(|e| SwigError::InterfaceError(e.to_string()))
    }
}

impl ClientRole for ProgramExecClientRole {
    fn sign_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _role_id: u32,
        _instructions: Vec<Instruction>,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        // ProgramExec requires a preceding instruction, so this method cannot be used
        // directly. Users should use sign_with_program_exec instead.
        Err(SwigError::InterfaceError(
            "ProgramExec authority requires a preceding instruction. Use sign_with_program_exec \
             instead."
                .to_string(),
        ))
    }

    fn add_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        new_authority_type: AuthorityType,
        new_authority: &[u8],
        actions: Vec<ClientAction>,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        Err(SwigError::InterfaceError(
            "ProgramExec authority requires a root Ed25519 authority for management operations. \
             Use a root authority to add authorities."
                .to_string(),
        ))
    }

    fn update_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_update_id: u32,
        update_data: UpdateAuthorityData,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        Err(SwigError::InterfaceError(
            "ProgramExec authority requires a root Ed25519 authority for management operations. \
             Use a root authority to update this authority."
                .to_string(),
        ))
    }

    fn remove_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_remove_id: u32,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        Err(SwigError::InterfaceError(
            "ProgramExec authority requires a root Ed25519 authority for management operations. \
             Use a root authority to remove this authority."
                .to_string(),
        ))
    }

    fn create_session_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _role_id: u32,
        _session_key: Pubkey,
        _session_duration: u64,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        Err(SwigError::InterfaceError(
            "ProgramExec authority does not support session creation".to_string(),
        ))
    }

    fn sub_account_sign_instruction(
        &self,
        _swig_account: Pubkey,
        _sub_account: Pubkey,
        _payer: Pubkey,
        _role_id: u32,
        _instructions: Vec<Instruction>,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        Err(SwigError::InterfaceError(
            "ProgramExec authority does not support sub-account signing".to_string(),
        ))
    }

    fn withdraw_token_from_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _sub_account: Pubkey,
        _sub_account_token: Pubkey,
        _swig_token: Pubkey,
        _token_program: Pubkey,
        _role_id: u32,
        _amount: u64,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        Err(SwigError::InterfaceError(
            "ProgramExec authority does not support token withdraw from sub-account".to_string(),
        ))
    }

    fn create_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _role_id: u32,
        _sub_account: Pubkey,
        _sub_account_bump: u8,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        Err(SwigError::InterfaceError(
            "ProgramExec authority does not support sub-account operations".to_string(),
        ))
    }

    fn withdraw_from_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _sub_account: Pubkey,
        _role_id: u32,
        _amount: u64,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        Err(SwigError::InterfaceError(
            "ProgramExec authority does not support sub-account operations".to_string(),
        ))
    }

    fn toggle_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _sub_account: Pubkey,
        _role_id: u32,
        _enabled: bool,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        Err(SwigError::InterfaceError(
            "ProgramExec authority does not support sub-account operations".to_string(),
        ))
    }

    fn authority_type(&self) -> AuthorityType {
        AuthorityType::ProgramExec
    }

    fn authority_bytes(&self) -> Result<Vec<u8>, SwigError> {
        Ok(self.authority_data())
    }

    fn odometer(&self) -> Result<u32, SwigError> {
        Err(SwigError::InterfaceError(
            "ProgramExec authority does not use odometer".to_string(),
        ))
    }

    fn increment_odometer(&mut self) -> Result<(), SwigError> {
        Err(SwigError::InterfaceError(
            "ProgramExec authority does not use odometer".to_string(),
        ))
    }

    fn update_odometer(&mut self, _odometer: u32) -> Result<(), SwigError> {
        Err(SwigError::InterfaceError(
            "ProgramExec authority does not use odometer".to_string(),
        ))
    }

    fn sign_v2_instruction(
        &self,
        _swig_account: Pubkey,
        _swig_wallet_address: Pubkey,
        _payer: Pubkey,
        _role_id: u32,
        _instructions: Vec<Instruction>,
        _current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        // ProgramExec requires a preceding instruction, so this method cannot be used
        // directly. Users should use sign_with_program_exec instead.
        Err(SwigError::InterfaceError(
            "ProgramExec authority requires a preceding instruction. Use sign_with_program_exec \
             instead."
                .to_string(),
        ))
    }
}
