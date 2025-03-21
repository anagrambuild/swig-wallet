use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_state::{ExecutionResultAccount, PluginBytecodeAccount, VMInstruction};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, ExecutePluginBytecodeV1Accounts},
        SwigInstruction,
    },
    util::ZeroCopy,
};

#[derive(Pod, Zeroable, Copy, Clone)]
#[repr(C, align(8))]
pub struct ExecutePluginV1Args {
    pub instruction: u8,
    pub padding: [u8; 6],
    pub account_indices_len: u8,
}

impl ExecutePluginV1Args {
    pub fn new(account_indices_len: u8) -> Self {
        Self {
            instruction: SwigInstruction::ExecutePluginBytecodeV1 as u8,
            account_indices_len,
            padding: [0; 6],
        }
    }
}

impl<'a> ZeroCopy<'a, ExecutePluginV1Args> for ExecutePluginV1Args {}

impl ExecutePluginV1Args {
    const SIZE: usize = core::mem::size_of::<Self>();
}

pub struct ExecutePluginV1<'a> {
    pub args: &'a ExecutePluginV1Args,
    account_indices: &'a [u8],
}

impl<'a> ExecutePluginV1<'a> {
    const SIZE: usize = ExecutePluginV1Args::SIZE;

    pub fn load(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }

        let args = unsafe { &*(data.as_ptr() as *const ExecutePluginV1Args) };
        let account_indices = &data[Self::SIZE..Self::SIZE + args.account_indices_len as usize];

        Ok(Self {
            args,
            account_indices,
        })
    }
}

pub fn execute_plugin_bytecode_v1(
    ctx: Context<ExecutePluginBytecodeV1Accounts>,
    data: &[u8],
) -> ProgramResult {
    // Parse instruction data
    let execute = ExecutePluginV1::load(data).map_err(|e| {
        msg!("ExecutePluginV1 Args Error: {:?}", e);
        ProgramError::InvalidInstructionData
    })?;

    // Get plugin bytecode account data
    let plugin_bytecode_account_data =
        unsafe { ctx.accounts.plugin_bytecode_account.borrow_data_unchecked() };
    let plugin_bytecode_account: &PluginBytecodeAccount =
        bytemuck::from_bytes(plugin_bytecode_account_data);

    // Verify target program matches
    if plugin_bytecode_account.target_program != *ctx.accounts.target_program.key() {
        msg!("Target program mismatch");
        return Err(SwigError::InvalidTargetProgram.into());
    }

    // Initialize VM state with pre-allocated capacity
    let mut stack = Vec::with_capacity(8); // Pre-allocate for common operations
    let mut pc: usize = 0;

    // Process account indices
    let indices = execute.account_indices;

    // Execute instructions until Return or end of bytecode
    while pc < plugin_bytecode_account.instructions_len as usize {
        let instruction = &plugin_bytecode_account.instructions[pc];
        match instruction {
            VMInstruction::PushValue { value } => {
                stack.push(*value);
                pc += 1;
            },
            VMInstruction::LoadField {
                account_index,
                field_offset,
                padding: _,
            } => {
                if (*account_index as usize) >= indices.len() {
                    return Err(SwigError::InvalidAccountIndex.into());
                }
                let remaining_account_idx = indices[*account_index as usize] as usize;
                if remaining_account_idx >= ctx.remaining_accounts.len() {
                    return Err(SwigError::InvalidAccountIndex.into());
                }
                let account = &ctx.remaining_accounts[remaining_account_idx];
                let data = account.try_borrow_data()?;
                if (*field_offset as usize + 8) > data.len() {
                    return Err(SwigError::InvalidFieldOffset.into());
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&data[*field_offset as usize..(*field_offset as usize + 8)]);
                stack.push(i64::from_le_bytes(bytes));
                pc += 1;
            },
            VMInstruction::Add => {
                if stack.len() < 2 {
                    return Err(SwigError::StackUnderflow.into());
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a + b);
                pc += 1;
            },
            VMInstruction::Subtract => {
                if stack.len() < 2 {
                    return Err(SwigError::StackUnderflow.into());
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a - b);
                pc += 1;
            },
            VMInstruction::Multiply => {
                if stack.len() < 2 {
                    return Err(SwigError::StackUnderflow.into());
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a * b);
                pc += 1;
            },
            VMInstruction::Divide => {
                if stack.len() < 2 {
                    return Err(SwigError::StackUnderflow.into());
                }
                let b = stack.pop().unwrap();
                if b == 0 {
                    return Err(SwigError::DivisionByZero.into());
                }
                let a = stack.pop().unwrap();
                stack.push(a / b);
                pc += 1;
            },
            VMInstruction::Equal => {
                if stack.len() < 2 {
                    return Err(SwigError::StackUnderflow.into());
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(if a == b { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::GreaterThan => {
                if stack.len() < 2 {
                    return Err(SwigError::StackUnderflow.into());
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(if a > b { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::LessThan => {
                if stack.len() < 2 {
                    return Err(SwigError::StackUnderflow.into());
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(if a < b { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::And => {
                if stack.len() < 2 {
                    return Err(SwigError::StackUnderflow.into());
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(if a != 0 && b != 0 { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::Or => {
                if stack.len() < 2 {
                    return Err(SwigError::StackUnderflow.into());
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(if a != 0 || b != 0 { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::Not => {
                if stack.is_empty() {
                    return Err(SwigError::StackUnderflow.into());
                }
                let a = stack.pop().unwrap();
                stack.push(if a == 0 { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::JumpIf { offset, padding: _ } => {
                if stack.is_empty() {
                    return Err(SwigError::StackUnderflow.into());
                }
                let condition = stack.pop().unwrap();
                if condition != 0 {
                    pc = pc.wrapping_add(*offset as usize);
                    if pc >= plugin_bytecode_account.instructions_len as usize {
                        return Err(SwigError::InvalidJump.into());
                    }
                } else {
                    pc += 1;
                }
            },
            VMInstruction::Return => {
                if stack.is_empty() {
                    return Err(SwigError::StackUnderflow.into());
                }
                break;
            },
        }

        if stack.len() > 32 {
            return Err(SwigError::StackOverflow.into());
        }
    }

    // Return the final result
    let final_result = stack.pop().unwrap();
    // TODO remove this and just return an error or not if it's 0 or 1
    msg!("Plugin execution completed with result: {}", final_result);
    Ok(())
}
