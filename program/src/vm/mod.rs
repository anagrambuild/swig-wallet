use pinocchio::{account_info::AccountInfo, msg, program_error::ProgramError};
use swig_state::{PluginBytecodeAccount, VMInstruction};

use crate::error::SwigError;

#[inline(always)]
pub fn execute_plugin_vm_bytecode(
    plugin_bytecode_account: &PluginBytecodeAccount,
    primary_account: &AccountInfo,
    _index: usize,
    account_indices: &[u8],
    all_accounts: &[AccountInfo],
) -> Result<i64, SwigError> {
    let mut stack = Vec::with_capacity(8);
    let mut pc = 0;
    let instr_len = plugin_bytecode_account.instructions_len as usize;

    while pc < instr_len {
        let instr = plugin_bytecode_account.instructions[pc];
        match instr {
            VMInstruction::PushValue { value } => {
                stack.push(value);
                pc += 1;
            },
            VMInstruction::LoadField {
                account_index,
                field_offset,
                ..
            } => {
                // Use account_index to determine which account to read from
                let account_data = if account_index == 0 {
                    primary_account.try_borrow_data().unwrap()
                } else if account_index == 0xFF {
                    // Special case: Load the account's own pubkey as data (used for key
                    // comparisons)
                    let pubkey_bytes = primary_account.key();
                    let bytes = &pubkey_bytes[field_offset as usize..field_offset as usize + 8];

                    let value = i64::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ]);
                    stack.push(value);
                    pc += 1;
                    continue;
                } else if account_index as usize <= account_indices.len() {
                    // Get the account using the provided index
                    let idx = account_indices[account_index as usize - 1] as usize;

                    if idx >= all_accounts.len() {
                        return Err(SwigError::InvalidAccountIndex);
                    }

                    // Check if we should load the account's pubkey instead of its data
                    if field_offset >= 0xFF00 {
                        // Load from account's public key bytes
                        let pubkey_bytes = all_accounts[idx].key();
                        let offset = (field_offset - 0xFF00) as usize;
                        if offset + 8 > 32 {
                            return Err(SwigError::InvalidFieldOffset);
                        }
                        let bytes = &pubkey_bytes[offset..offset + 8];

                        let value = i64::from_le_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                            bytes[7],
                        ]);

                        stack.push(value);
                        pc += 1;
                        continue;
                    }
                    all_accounts[idx].try_borrow_data().unwrap()
                } else {
                    return Err(SwigError::InvalidAccountIndex); // InvalidAccountIndex
                };

                let offset = field_offset as usize;
                if offset + 8 > account_data.len() {
                    return Err(SwigError::InvalidFieldOffset); // InvalidFieldOffset
                }

                let bytes = &account_data[offset..offset + 8];
                let value = i64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);

                stack.push(value);
                pc += 1;
            },
            VMInstruction::Add => {
                if stack.len() < 2 {
                    return Err(SwigError::StackUnderflow); // StackUnderflow
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a + b);
                pc += 1;
            },
            VMInstruction::Subtract => {
                if stack.len() < 2 {
                    return Err(SwigError::StackUnderflow);
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a - b);
                pc += 1;
            },
            VMInstruction::Multiply => {
                if stack.len() < 2 {
                    return Err(SwigError::StackUnderflow);
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a * b);
                pc += 1;
            },
            VMInstruction::Divide => {
                if stack.len() < 2 {
                    return Err(SwigError::StackUnderflow);
                }
                let b = stack.pop().unwrap();
                if b == 0 {
                    return Err(SwigError::DivisionByZero); // DivisionByZero
                }
                let a = stack.pop().unwrap();
                stack.push(a / b);
                pc += 1;
            },
            VMInstruction::Equal => {
                if stack.len() < 2 {
                    return Err(SwigError::StackUnderflow);
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(if a == b { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::GreaterThan => {
                if stack.len() < 2 {
                    return Err(SwigError::StackUnderflow);
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(if a > b { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::LessThan => {
                if stack.len() < 2 {
                    return Err(SwigError::StackUnderflow);
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(if a < b { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::And => {
                if stack.len() < 2 {
                    return Err(SwigError::StackUnderflow);
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(if a != 0 && b != 0 { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::Or => {
                if stack.len() < 2 {
                    return Err(SwigError::StackUnderflow);
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(if a != 0 || b != 0 { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::Not => {
                if stack.is_empty() {
                    return Err(SwigError::StackUnderflow);
                }
                let a = stack.pop().unwrap();
                stack.push(if a == 0 { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::JumpIf { offset, .. } => {
                if stack.is_empty() {
                    return Err(SwigError::StackUnderflow);
                }
                let condition = stack.pop().unwrap();
                if condition != 0 {
                    pc = pc.wrapping_add(offset as usize);
                    if pc >= instr_len {
                        return Err(SwigError::InvalidJump); // InvalidJump
                    }
                } else {
                    pc += 1;
                }
            },
            VMInstruction::Return => {
                if stack.is_empty() {
                    return Err(SwigError::StackUnderflow);
                }
                break;
            },
        }

        // Check stack overflow (32 is a reasonable limit for a bytecode VM)
        if stack.len() > 32 {
            return Err(SwigError::StackOverflow); // StackOverflow
        }
    }

    let result = stack.last().copied().unwrap_or(0);
    msg!("result: {}", result);

    // If the plugin validation fails (result is 0), we error out so the transaction
    // can't continue
    if result == 0 {
        msg!("Plugin validation failed: authorities do not match");
        return Err(SwigError::VMValidationFailed); // ValidationFailed
    }

    // Return the result for success
    Ok(result)
}
