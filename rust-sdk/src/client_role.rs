use solana_program::{instruction::Instruction, pubkey::Pubkey};
use swig_interface::{
    AddAuthorityInstruction, AuthorityConfig, ClientAction, CreateSessionInstruction,
    CreateSubAccountInstruction, RemoveAuthorityInstruction, SignInstruction,
    SubAccountSignInstruction, ToggleSubAccountInstruction, WithdrawFromSubAccountInstruction,
};
use swig_state_x::{
    authority::{
        ed25519::CreateEd25519SessionAuthority, secp256k1::CreateSecp256k1SessionAuthority,
        AuthorityType,
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
    ) -> Result<Instruction, SwigError>;

    /// Creates a remove authority instruction
    fn remove_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_remove_id: u32,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError>;

    /// Creates a create session instruction
    fn create_session_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        session_key: Pubkey,
        session_duration: u64,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError>;

    /// Creates a create sub account instruction
    fn create_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        sub_account: Pubkey,
        sub_account_bump: u8,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError>;

    /// Creates a sub account sign instruction
    fn sub_account_sign_instruction(
        &self,
        swig_account: Pubkey,
        sub_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError>;

    /// Creates a withdraw from sub account instruction
    fn withdraw_from_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        amount: u64,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError>;

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
    ) -> Result<Instruction, SwigError>;

    /// Creates a toggle sub account instruction
    fn toggle_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        enabled: bool,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError>;

    /// Returns the authority type
    fn authority_type(&self) -> AuthorityType;

    /// Returns the authority bytes for creating the Swig account
    fn authority_bytes(&self) -> Result<Vec<u8>, SwigError>;

    /// Returns the odometer for the current authority if it is a Secp256k1 authority
    fn odometer(&self) -> Result<u32, SwigError>;

    /// Increments the odometer for the current authority if it is a Secp256k1 authority
    fn increment_odometer(&mut self) -> Result<(), SwigError>;

    /// Update the odometer for the authority
    fn update_odometer(&mut self, odometer: u32) -> Result<(), SwigError>;
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
    ) -> Result<Instruction, SwigError> {
        Ok(AddAuthorityInstruction::new_with_ed25519_authority(
            swig_account,
            payer,
            self.authority,
            role_id,
            AuthorityConfig {
                authority_type: new_authority_type,
                authority: new_authority,
            },
            actions,
        )?)
    }

    fn remove_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_remove_id: u32,
        _current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        Ok(RemoveAuthorityInstruction::new_with_ed25519_authority(
            swig_account,
            payer,
            self.authority,
            role_id,
            authority_to_remove_id,
        )?)
    }

    fn create_session_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        session_key: Pubkey,
        session_duration: u64,
        _current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        Ok(CreateSessionInstruction::new_with_ed25519_authority(
            swig_account,
            payer,
            self.authority,
            role_id,
            session_key,
            session_duration,
        )?)
    }

    fn create_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        sub_account: Pubkey,
        sub_account_bump: u8,
        _current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        Ok(CreateSubAccountInstruction::new_with_ed25519_authority(
            swig_account,
            self.authority,
            payer,
            sub_account,
            role_id,
            sub_account_bump,
        )?)
    }

    fn sub_account_sign_instruction(
        &self,
        swig_account: Pubkey,
        sub_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        _current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        Ok(SubAccountSignInstruction::new_with_ed25519_authority(
            swig_account,
            sub_account,
            self.authority,
            payer,
            role_id,
            instructions,
        )?)
    }

    fn withdraw_from_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        amount: u64,
        _current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        WithdrawFromSubAccountInstruction::new_with_ed25519_authority(
            swig_account,
            self.authority,
            payer,
            sub_account,
            role_id,
            amount,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create withdraw instruction: {:?}", e).into())
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
    ) -> Result<Instruction, SwigError> {
        WithdrawFromSubAccountInstruction::new_token_with_ed25519_authority(
            swig_account,
            self.authority,
            payer,
            sub_account,
            sub_account_token,
            swig_token,
            token_program,
            role_id,
            amount,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create withdraw token instruction: {:?}", e).into())
    }

    fn toggle_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        enabled: bool,
        _current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        ToggleSubAccountInstruction::new_with_ed25519_authority(
            swig_account,
            self.authority,
            payer,
            sub_account,
            role_id,
            enabled,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create toggle instruction: {:?}", e).into())
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
    ) -> Result<Instruction, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        Ok(AddAuthorityInstruction::new_with_secp256k1_authority(
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
        )?)
    }

    fn remove_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_remove_id: u32,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        Ok(RemoveAuthorityInstruction::new_with_secp256k1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            new_odometer,
            role_id,
            authority_to_remove_id,
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
    ) -> Result<Instruction, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);
        Ok(CreateSessionInstruction::new_with_secp256k1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            new_odometer,
            role_id,
            session_key,
            session_duration,
        )?)
    }

    fn create_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        sub_account: Pubkey,
        sub_account_bump: u8,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;

        Ok(CreateSubAccountInstruction::new_with_secp256k1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            sub_account,
            role_id,
            sub_account_bump,
        )?)
    }

    fn sub_account_sign_instruction(
        &self,
        swig_account: Pubkey,
        sub_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        instructions: Vec<Instruction>,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;

        Ok(SubAccountSignInstruction::new_with_secp256k1_authority(
            swig_account,
            sub_account,
            payer,
            &self.signing_fn,
            current_slot,
            role_id,
            instructions,
        )?)
    }

    fn withdraw_from_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        amount: u64,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;

        WithdrawFromSubAccountInstruction::new_with_secp256k1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            sub_account,
            role_id,
            amount,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create withdraw instruction: {:?}", e).into())
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
    ) -> Result<Instruction, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;

        WithdrawFromSubAccountInstruction::new_token_with_secp256k1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            sub_account,
            sub_account_token,
            swig_token,
            token_program,
            role_id,
            amount,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create withdraw token instruction: {:?}", e).into())
    }

    fn toggle_sub_account_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        enabled: bool,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;

        ToggleSubAccountInstruction::new_with_secp256k1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            sub_account,
            role_id,
            enabled,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create toggle instruction: {:?}", e).into())
    }

    fn authority_type(&self) -> AuthorityType {
        AuthorityType::Secp256k1
    }

    fn authority_bytes(&self) -> Result<Vec<u8>, SwigError> {
        Ok(self.authority[1..].to_vec())
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
    ) -> Result<Instruction, SwigError> {
        Ok(AddAuthorityInstruction::new_with_ed25519_authority(
            swig_account,
            payer,
            self.session_authority.public_key.into(),
            role_id,
            AuthorityConfig {
                authority_type: new_authority_type,
                authority: new_authority,
            },
            actions,
        )?)
    }

    fn remove_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_remove_id: u32,
        _current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        Ok(RemoveAuthorityInstruction::new_with_ed25519_authority(
            swig_account,
            payer,
            self.session_authority.public_key.into(),
            role_id,
            authority_to_remove_id,
        )?)
    }

    fn create_session_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        session_key: Pubkey,
        session_duration: u64,
        _current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        Ok(CreateSessionInstruction::new_with_ed25519_authority(
            swig_account,
            payer,
            self.session_authority.public_key.into(),
            role_id,
            session_key,
            session_duration,
        )?)
    }

    fn create_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _role_id: u32,
        _sub_account: Pubkey,
        _sub_account_bump: u8,
        _current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        todo!("Session authorities don't support sub-account creation")
    }

    fn sub_account_sign_instruction(
        &self,
        _swig_account: Pubkey,
        _sub_account: Pubkey,
        _payer: Pubkey,
        _role_id: u32,
        _instructions: Vec<Instruction>,
        _current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
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
    ) -> Result<Instruction, SwigError> {
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
    ) -> Result<Instruction, SwigError> {
        todo!("Session authorities don't support sub-account operations")
    }

    fn toggle_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _sub_account: Pubkey,
        _role_id: u32,
        _enabled: bool,
        _current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
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
    ) -> Result<Instruction, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;

        Ok(AddAuthorityInstruction::new_with_secp256k1_authority(
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
        )?)
    }

    fn remove_authority_instruction(
        &self,
        swig_account: Pubkey,
        payer: Pubkey,
        role_id: u32,
        authority_to_remove_id: u32,
        current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        Ok(RemoveAuthorityInstruction::new_with_secp256k1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            new_odometer,
            authority_to_remove_id,
            role_id,
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
    ) -> Result<Instruction, SwigError> {
        let current_slot = current_slot.ok_or(SwigError::CurrentSlotNotSet)?;
        let new_odometer = self.odometer.wrapping_add(1);

        Ok(CreateSessionInstruction::new_with_secp256k1_authority(
            swig_account,
            payer,
            &self.signing_fn,
            current_slot,
            new_odometer,
            role_id,
            session_key,
            session_duration,
        )?)
    }

    fn create_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _role_id: u32,
        _sub_account: Pubkey,
        _sub_account_bump: u8,
        _current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
        todo!("Session authorities don't support sub-account creation")
    }

    fn sub_account_sign_instruction(
        &self,
        _swig_account: Pubkey,
        _sub_account: Pubkey,
        _payer: Pubkey,
        _role_id: u32,
        _instructions: Vec<Instruction>,
        _current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
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
    ) -> Result<Instruction, SwigError> {
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
    ) -> Result<Instruction, SwigError> {
        todo!("Session authorities don't support sub-account operations")
    }

    fn toggle_sub_account_instruction(
        &self,
        _swig_account: Pubkey,
        _payer: Pubkey,
        _sub_account: Pubkey,
        _role_id: u32,
        _enabled: bool,
        _current_slot: Option<u64>,
    ) -> Result<Instruction, SwigError> {
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
}
