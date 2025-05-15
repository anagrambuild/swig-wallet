use std::mem::MaybeUninit;

use pinocchio::{
    account_info::AccountInfo,
    cpi::invoke_signed,
    instruction::{AccountMeta, Instruction, Signer},
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};
use swig_state_x::{
    action::{
        program_scope::{NumericType, ProgramScope},
        Action, Permission,
    },
    constants::PROGRAM_SCOPE_BYTE_SIZE,
    read_numeric_field,
    swig::{Swig, SwigWithRoles},
    Transmutable,
};

use crate::error::SwigError;

pub(crate) struct ProgramScopeCache {
    // Maps target account pubkey to (role_id, raw program scope bytes)
    scopes: Vec<([u8; 32], (u8, [u8; PROGRAM_SCOPE_BYTE_SIZE]))>,
}

impl ProgramScopeCache {
    pub(crate) fn new() -> Self {
        Self {
            scopes: Vec::with_capacity(16), // Reasonable initial capacity
        }
    }

    pub(crate) fn load_from_swig(data: &[u8]) -> Option<Self> {
        if data.len() < Swig::LEN {
            return None;
        }

        let swig_with_roles = SwigWithRoles::from_bytes(data).ok()?;
        let mut cache = Self::new();

        // Iterate through all roles and their program scopes
        for role_id in 0..swig_with_roles.state.role_counter {
            if let Ok(Some(role)) = swig_with_roles.get_role(role_id) {
                let mut cursor = 0;
                while cursor < role.actions.len() {
                    if cursor + Action::LEN > role.actions.len() {
                        break;
                    }

                    // Load the action header
                    if let Ok(action_header) = unsafe {
                        Action::load_unchecked(&role.actions[cursor..cursor + Action::LEN])
                    } {
                        cursor += Action::LEN;

                        let action_len = action_header.length() as usize;
                        if cursor + action_len > role.actions.len() {
                            break;
                        }

                        // Try to load as ProgramScope
                        if action_header.permission().ok() == Some(Permission::ProgramScope) {
                            let action_data = &role.actions[cursor..cursor + action_len];
                            if action_data.len() == PROGRAM_SCOPE_BYTE_SIZE {
                                // Size of ProgramScope
                                // Store in cache using target account as key
                                let program_scope = unsafe {
                                    // SAFETY: We've verified the length matches exactly
                                    let mut scope_bytes = [0u8; PROGRAM_SCOPE_BYTE_SIZE];
                                    core::ptr::copy_nonoverlapping(
                                        action_data.as_ptr(),
                                        scope_bytes.as_mut_ptr(),
                                        PROGRAM_SCOPE_BYTE_SIZE,
                                    );
                                    let program_scope: ProgramScope =
                                        core::mem::transmute(scope_bytes);
                                    program_scope
                                };

                                let mut target_account = [0u8; 32];
                                target_account.copy_from_slice(&program_scope.target_account);

                                // Store raw bytes
                                let scope_bytes = unsafe {
                                    core::mem::transmute::<
                                        ProgramScope,
                                        [u8; PROGRAM_SCOPE_BYTE_SIZE],
                                    >(program_scope)
                                };
                                cache
                                    .scopes
                                    .push((target_account, (role_id as u8, scope_bytes)));
                            }
                        }

                        cursor += action_len;
                    } else {
                        break;
                    }
                }
            }
        }

        Some(cache)
    }

    pub(crate) fn find_program_scope(&self, target_account: &[u8]) -> Option<(u8, ProgramScope)> {
        self.scopes
            .iter()
            .find(|(key, _)| key == target_account)
            .map(|(_, (role_id, scope_bytes))| {
                // SAFETY: We know these bytes represent a valid ProgramScope since we stored
                // them that way
                let program_scope = unsafe {
                    core::mem::transmute::<[u8; PROGRAM_SCOPE_BYTE_SIZE], ProgramScope>(
                        *scope_bytes,
                    )
                };
                (*role_id, program_scope)
            })
    }
}

/// Reads a numeric balance from an account's data based on a `ProgramScope`
/// configuration.
///
/// This function extracts a numeric value (balance) from the raw data of an
/// account according to the field positions and numeric type specified in the
/// `ProgramScope`. It supports reading different size integers (u8, u32, u64,
/// u128) and handles byte order assembly for little-endian representation.
///
/// # Arguments
/// * `data` - The raw account data to read from
/// * `program_scope` - The ProgramScope containing balance field specifications
///
/// # Returns
/// * `Result<u128, ProgramError>` - The account balance as u128 or an error if
///   reading fails
///
/// # Errors
/// Returns `SwigError::InvalidProgramScopeBalanceFields` if:
/// * The balance field range is invalid
/// * The account data doesn't have enough bytes
/// * The specified numeric type doesn't match the field width
///
/// # Safety
/// This function uses unchecked memory access for performance and assumes the
/// caller has verified the `data` parameter contains valid account data.
#[inline(always)]
pub unsafe fn read_program_scope_account_balance(
    data: &[u8],
    program_scope: &ProgramScope,
) -> Result<u128, ProgramError> {
    // For Basic scope, return 0
    if program_scope.scope_type == 0 {
        return Ok(0);
    }

    // Check if we can read the balance directly from data
    let start = program_scope.balance_field_start as usize;
    let end = program_scope.balance_field_end as usize;
    // Index out of bounds check & return error
    if data.len() < end {
        return Err(SwigError::InvalidProgramScopeBalanceFields.into());
    }

    // Handle Possible NumericType fields
    let error = SwigError::InvalidProgramScopeBalanceFields.into();
    match program_scope.numeric_type as u8 {
        numeric_type if numeric_type == NumericType::U8 as u8 => {
            read_numeric_field!(data, start, end, u8, 1, error)
        },
        numeric_type if numeric_type == NumericType::U32 as u8 => {
            read_numeric_field!(data, start, end, u32, 4, error)
        },
        numeric_type if numeric_type == NumericType::U64 as u8 => {
            read_numeric_field!(data, start, end, u64, 8, error)
        },
        numeric_type if numeric_type == NumericType::U128 as u8 => {
            read_numeric_field!(data, start, end, u128, 16, error)
        },
        _ => Err(SwigError::InvalidProgramScopeBalanceFields.into()),
    }
}

// Adapted from pinocchio-token
const UNINIT_BYTE: MaybeUninit<u8> = MaybeUninit::<u8>::uninit();
pub struct TokenTransfer<'a> {
    pub token_program: &'a Pubkey,
    /// Sender account.
    pub from: &'a AccountInfo,
    /// Recipient account.
    pub to: &'a AccountInfo,
    /// Authority account.
    pub authority: &'a AccountInfo,
    /// Amount of microtokens to transfer.
    pub amount: u64,
}

impl<'a> TokenTransfer<'a> {
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        // account metadata
        let account_metas: [AccountMeta; 3] = [
            AccountMeta::writable(self.from.key()),
            AccountMeta::writable(self.to.key()),
            AccountMeta::readonly_signer(self.authority.key()),
        ];

        // Instruction data layout:
        // - [0]: instruction discriminator (1 byte, u8)
        // - [1..9]: amount (8 bytes, u64)
        let mut instruction_data = [0u8; 9];

        // Set discriminator as u8 at offset [0]
        instruction_data[0] = 3;
        // Set amount as u64 at offset [1..9]
        instruction_data[1..9].copy_from_slice(&self.amount.to_le_bytes());

        let instruction = Instruction {
            program_id: self.token_program,
            accounts: &account_metas,
            data: &instruction_data,
        };

        invoke_signed(&instruction, &[self.from, self.to, self.authority], signers)
    }
}
