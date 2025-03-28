use pinocchio::{account_info::AccountInfo, msg, program_error::ProgramError};
use swig_state::{PluginBytecodeAccount, VMInstruction};

// Extract the plugin execution logic into a separate function to improve
// readability and enable inlining optimizations
#[inline(always)]
pub fn execute_plugin_bytecode(
    plugin_bytecode_account: &PluginBytecodeAccount,
    primary_account: &AccountInfo,
    _index: usize,
    account_indices: &[u8],
    all_accounts: &[AccountInfo],
) -> Result<i64, ProgramError> {
    // Initialize stack with fixed capacity
    let mut stack = Vec::with_capacity(8);
    let mut pc = 0;
    let instr_len = plugin_bytecode_account.instructions_len as usize;

    // msg!(
    //     "Executing plugin for primary_account: {:?}",
    //     primary_account.key()
    // );
    // msg!("Account indices for plugin: {:?}", account_indices);
    // for (i, &idx) in account_indices.iter().enumerate() {
    //     if (idx as usize) < all_accounts.len() {
    //         msg!(
    //             "Account at index {}: {:?}",
    //             idx,
    //             all_accounts[idx as usize].key()
    //         );
    //     }
    // }

    // Fast path VM implementation
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
                    // Use the primary account (typically the stake account)
                    // msg!("Loading from primary account at offset {}", field_offset);
                    primary_account.try_borrow_data()?
                } else if account_index == 0xFF {
                    // Special case: Load the account's own pubkey as data (used for key
                    // comparisons)
                    // msg!("Loading pubkey bytes from primary account");
                    let pubkey_bytes = primary_account.key(); // Already a &[u8; 32]
                    let bytes = &pubkey_bytes[field_offset as usize..field_offset as usize + 8];
                    // msg!("Loaded pubkey bytes: {:?}", bytes);

                    // Print as hex values
                    let mut hex_str = String::new();
                    for b in bytes.iter() {
                        hex_str.push_str(&format!("{:02x} ", b));
                    }
                    // msg!("Pubkey bytes as hex: {}", hex_str);

                    let value = i64::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ]);
                    // msg!("Pushing value into stack: {}", value);
                    stack.push(value);
                    pc += 1;
                    continue;
                } else if account_index as usize <= account_indices.len() {
                    // Get the actual transaction account using the provided index
                    let idx = account_indices[account_index as usize - 1] as usize;

                    // Debug the account index resolution
                    // msg!(
                    //     "Resolving account_index {} to transaction account at index {}",
                    //     account_index,
                    //     idx
                    // );
                    if idx >= all_accounts.len() {
                        return Err(ProgramError::Custom(400)); // InvalidAccountIndex
                    }

                    // Check if we should load the account's pubkey instead of its data
                    if field_offset >= 0xFF00 {
                        // Load from account's public key bytes
                        let pubkey_bytes = all_accounts[idx].key(); // Already a &[u8; 32]
                        let offset = (field_offset - 0xFF00) as usize;
                        if offset + 8 > 32 {
                            // pubkey is 32 bytes
                            return Err(ProgramError::Custom(401)); // InvalidFieldOffset
                        }

                        let bytes = &pubkey_bytes[offset..offset + 8];
                        // msg!(
                        //     "Loading pubkey bytes from account at index {}, offset {}: {:?}",
                        //     idx,
                        //     offset,
                        //     bytes
                        // );

                        // Print as hex values
                        let mut hex_str = String::new();
                        for b in bytes.iter() {
                            hex_str.push_str(&format!("{:02x} ", b));
                        }
                        // msg!("Pubkey bytes as hex: {}", hex_str);

                        let value = i64::from_le_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                            bytes[7],
                        ]);
                        // msg!("Pushing value into stack: {}", value);
                        stack.push(value);
                        pc += 1;
                        continue;
                    }

                    // Print the actual account key we're accessing
                    // msg!(
                    //     "Loading from account {} ({}), key: {:?}",
                    //     account_index,
                    //     idx,
                    //     all_accounts[idx].key()
                    // );
                    all_accounts[idx].try_borrow_data()?
                } else {
                    // msg!(
                    //     "invalid account index: {:?} : {:?}",
                    //     account_index,
                    //     account_indices.len()
                    // );
                    return Err(ProgramError::Custom(400)); // InvalidAccountIndex
                };

                let offset = field_offset as usize;
                if offset + 8 > account_data.len() {
                    return Err(ProgramError::Custom(401)); // InvalidFieldOffset
                }

                let bytes = &account_data[offset..offset + 8];
                // msg!("Loaded bytes: {:?}", bytes);

                // Print as decimal values for easier comparison
                let mut hex_str = String::new();
                for b in bytes.iter() {
                    hex_str.push_str(&format!("{:02x} ", b));
                }
                // msg!("Bytes as hex: {}", hex_str);

                let value = i64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                // msg!("Pushing value into stack: {}", value);
                stack.push(value);
                pc += 1;
            },
            VMInstruction::Add => {
                if stack.len() < 2 {
                    return Err(ProgramError::Custom(402)); // StackUnderflow
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a + b);
                pc += 1;
            },
            VMInstruction::Subtract => {
                if stack.len() < 2 {
                    return Err(ProgramError::Custom(402));
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a - b);
                pc += 1;
            },
            VMInstruction::Multiply => {
                if stack.len() < 2 {
                    return Err(ProgramError::Custom(402));
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a * b);
                pc += 1;
            },
            VMInstruction::Divide => {
                if stack.len() < 2 {
                    return Err(ProgramError::Custom(402));
                }
                let b = stack.pop().unwrap();
                if b == 0 {
                    return Err(ProgramError::Custom(403)); // DivisionByZero
                }
                let a = stack.pop().unwrap();
                stack.push(a / b);
                pc += 1;
            },
            VMInstruction::Equal => {
                if stack.len() < 2 {
                    return Err(ProgramError::Custom(402));
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                // msg!("a: {:?}", a);
                // msg!("b: {:?}", b);
                // msg!("a == b: {:?}", a == b);
                stack.push(if a == b { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::GreaterThan => {
                if stack.len() < 2 {
                    return Err(ProgramError::Custom(402));
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(if a > b { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::LessThan => {
                if stack.len() < 2 {
                    return Err(ProgramError::Custom(402));
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(if a < b { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::And => {
                if stack.len() < 2 {
                    return Err(ProgramError::Custom(402));
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(if a != 0 && b != 0 { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::Or => {
                if stack.len() < 2 {
                    return Err(ProgramError::Custom(402));
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(if a != 0 || b != 0 { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::Not => {
                if stack.is_empty() {
                    return Err(ProgramError::Custom(402));
                }
                let a = stack.pop().unwrap();
                stack.push(if a == 0 { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::JumpIf { offset, .. } => {
                if stack.is_empty() {
                    return Err(ProgramError::Custom(402));
                }
                let condition = stack.pop().unwrap();
                if condition != 0 {
                    pc = pc.wrapping_add(offset as usize);
                    if pc >= instr_len {
                        return Err(ProgramError::Custom(404)); // InvalidJump
                    }
                } else {
                    pc += 1;
                }
            },
            VMInstruction::Return => {
                if stack.is_empty() {
                    return Err(ProgramError::Custom(402));
                }
                // Exit the loop
                break;
            },
        }

        // Check stack overflow (32 is a reasonable limit for a bytecode VM)
        if stack.len() > 32 {
            return Err(ProgramError::Custom(405)); // StackOverflow
        }
    }

    // We run until stack has 1 value which is the result
    // result of 1 means validation passes, 0 means validation fails
    let result = stack.last().copied().unwrap_or(0);
    msg!("result: {}", result);

    // If the plugin validation fails (result is 0), return an error
    if result == 0 {
        msg!("Plugin validation failed: authorities do not match");
        return Err(ProgramError::Custom(406)); // ValidationFailed
    }

    // Return the result for success
    Ok(result)
}
