use std::mem::MaybeUninit;

use pinocchio::{
    account_info::AccountInfo,
    cpi::invoke_signed,
    instruction::{AccountMeta, Instruction, Signer},
    pubkey::Pubkey,
    ProgramResult,
};
use swig_state_x::{
    action::{program_scope::ProgramScope, Action, Permission},
    swig::{Swig, SwigWithRoles},
    Transmutable,
};

pub(crate) struct ProgramScopeCache {
    // Maps target account pubkey to (role_id, raw program scope bytes)
    scopes: Vec<([u8; 32], (u8, [u8; 128]))>, // 128 is size of ProgramScope
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
                            if action_data.len() == 128 {
                                // Size of ProgramScope
                                // Store in cache using target account as key
                                let program_scope = unsafe {
                                    // SAFETY: We've verified the length matches exactly
                                    let mut scope_bytes = [0u8; 128];
                                    core::ptr::copy_nonoverlapping(
                                        action_data.as_ptr(),
                                        scope_bytes.as_mut_ptr(),
                                        128,
                                    );
                                    let program_scope: ProgramScope =
                                        core::mem::transmute(scope_bytes);
                                    program_scope
                                };

                                let mut target_account = [0u8; 32];
                                target_account.copy_from_slice(&program_scope.target_account);

                                // Store raw bytes
                                let scope_bytes = unsafe {
                                    core::mem::transmute::<ProgramScope, [u8; 128]>(program_scope)
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
                let program_scope =
                    unsafe { core::mem::transmute::<[u8; 128], ProgramScope>(*scope_bytes) };
                (*role_id, program_scope)
            })
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
        // -  [0]: instruction discriminator (1 byte, u8)
        // -  [1..9]: amount (8 bytes, u64)
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
