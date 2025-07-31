use crate::{
    types::{Permission, UpdateAuthorityData},
    Ed25519ClientRole, SwigInstructionBuilder,
};
use solana_program::{
    decode_error::DecodeError,
    program_error::{PrintProgramError, ProgramError},
};
use solana_sdk::{instruction::Instruction, pubkey::Pubkey};
use swig_state::authority::AuthorityType;

use crate::SwigError;

#[derive(Debug)]
pub enum InstructionType {
    CreateSwig {
        swig_id: [u8; 32],
        new_authority_type: AuthorityType,
        new_authority: Vec<u8>,
        permissions: Vec<Permission>,
    },
    AddAuthority {
        new_authority_type: AuthorityType,
        new_authority: Vec<u8>,
        permissions: Vec<Permission>,
    },
    RemoveAuthority {
        authority_to_remove_id: u32,
    },
    UpdateAuthority {
        authority_to_replace_id: u32,
        update_data: UpdateAuthorityData,
    },
    Sign {
        inner_instructions: Vec<Instruction>,
    },
    CreateSubAccount,
    CreateSession,
    SignWithSubAccount,
    WithdrawFromSubAccount,
    WithdrawTokenFromSubAccount,
    ToggleSubAccount,
    WithdrawSol,
    WithdrawToken,
}

#[derive(Debug)]
pub struct DecodedInstruction {
    /// The type of SWIG instruction
    pub instruction_type: InstructionType,
    /// Human-readable description of what the instruction does
    pub description: String,
    /// Role ID used for this instruction
    pub role_id: u32,
    /// Authority type used
    pub authority_type: AuthorityType,
    /// Decoded compact instructions
    pub compact_instructions: Option<Vec<DecodedCompactInstruction>>,
    /// Additional instruction-specific data
    pub data: Option<serde_json::Value>,
    /// Fee payer
    pub fee_payer: String,
}

/// JSON response structure for decoded compact instructions
#[derive(Debug)]
pub struct DecodedCompactInstruction {
    /// Program ID as string
    pub program_id: String,
    /// Human-readable program name (if known)
    pub program_name: Option<String>,
    /// Decoded instruction type (if known)
    pub instruction_type: Option<String>,
    /// Human-readable description of what this instruction does
    pub description: Option<String>,
    /// Account metadata
    pub accounts: Vec<DecodedAccount>,
    /// Decoded instruction data (if known)
    pub data: Option<serde_json::Value>,
    /// Raw instruction data as base64
    pub raw_data: String,
}

/// JSON response structure for decoded accounts
#[derive(Debug)]
pub struct DecodedAccount {
    /// Account public key as string
    pub pubkey: String,
    /// Human-readable account name/role
    pub name: Option<String>,
    /// Whether this account is a signer
    pub is_signer: bool,
    /// Whether this account is writable
    pub is_writable: bool,
}

pub fn authority_type_to_string(authority_type: AuthorityType) -> String {
    match authority_type {
        AuthorityType::Ed25519 => "Ed25519".to_string(),
        AuthorityType::Secp256k1 => "Secp256k1".to_string(),
        AuthorityType::Secp256r1 => "Secp256r1".to_string(),
        AuthorityType::Ed25519Session => "Ed25519Session".to_string(),
        AuthorityType::Secp256k1Session => "Secp256k1Session".to_string(),
        AuthorityType::Secp256r1Session => "Secp256r1Session".to_string(),
        AuthorityType::None => "None".to_string(),
    }
}

impl DecodedInstruction {
    pub fn new(
        instruction_type: InstructionType,
        description: String,
        role_id: u32,
        authority_type: AuthorityType,
        compact_instructions: Option<Vec<DecodedCompactInstruction>>,
        data: Option<serde_json::Value>,
        fee_payer: String,
    ) -> Self {
        Self {
            instruction_type,
            description,
            role_id,
            authority_type,
            compact_instructions,
            data,
            fee_payer,
        }
    }
}
