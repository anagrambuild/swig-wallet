use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_state::{BytecodeAccount, ExecutionResultAccount, VMInstruction};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, ExecuteAccounts},
        SwigInstruction,
    },
    util::ZeroCopy,
};

#[derive(Pod, Zeroable, Copy, Clone)]
#[repr(C, align(8))]
pub struct ExecuteV1Args {
    pub instruction: u8,
    pub padding: [u8; 6],
    pub account_indices_len: u8,
}

impl ExecuteV1Args {
    pub fn new(account_indices_len: u8) -> Self {
        Self {
            instruction: SwigInstruction::Execute as u8,
            account_indices_len,
            padding: [0; 6],
        }
    }
}

impl<'a> ZeroCopy<'a, ExecuteV1Args> for ExecuteV1Args {}

impl ExecuteV1Args {
    const SIZE: usize = core::mem::size_of::<Self>();
}

pub struct ExecuteV1<'a> {
    pub args: &'a ExecuteV1Args,
    account_indices: &'a [u8],
}

impl<'a> ExecuteV1<'a> {
    const SIZE: usize = ExecuteV1Args::SIZE;

    pub fn load(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }

        let args = unsafe { &*(data.as_ptr() as *const ExecuteV1Args) };
        let account_indices = &data[Self::SIZE..Self::SIZE + args.account_indices_len as usize];

        Ok(Self {
            args,
            account_indices,
        })
    }
}

pub fn execute_v1(ctx: Context<ExecuteAccounts>, data: &[u8]) -> ProgramResult {
    // Parse instruction data
    let execute = ExecuteV1::load(data).map_err(|e| {
        msg!("ExecuteV1 Args Error: {:?}", e);
        ProgramError::InvalidInstructionData
    })?;

    // Get bytecode account data
    let bytecode_account_data = unsafe { ctx.accounts.bytecode_account.borrow_data_unchecked() };
    let bytecode_account = BytecodeAccount::try_from_slice(bytecode_account_data)
        .map_err(|_| SwigError::SerializationError)?;

    // Initialize VM state
    let mut stack: Vec<i64> = Vec::new();
    let mut pc: usize = 0; // Program counter

    // Process account indices
    let indices = execute.account_indices;

    // Execute instructions until Return or end of bytecode
    while pc < bytecode_account.instructions.len() {
        let instruction = &bytecode_account.instructions[pc];
        msg!("Executing instruction at PC={}: {:?}", pc, instruction);

        match instruction {
            VMInstruction::PushValue { value } => {
                msg!("Pushing value: {}", value);
                stack.push(*value);
                pc += 1;
            },
            VMInstruction::LoadField {
                account_index,
                field_offset,
            } => {
                msg!(
                    "LoadField: account_index={}, field_offset={}",
                    account_index,
                    field_offset
                );

                // Ensure account index is valid
                if (*account_index as usize) >= indices.len() {
                    msg!("Invalid account index: {}", account_index);
                    return Err(SwigError::InvalidAccountIndex.into());
                }

                // Get the index in remaining_accounts
                let remaining_account_idx = indices[*account_index as usize] as usize;

                // Ensure the index is within bounds
                if remaining_account_idx >= ctx.remaining_accounts.len() {
                    msg!("Invalid remaining account index: {}", remaining_account_idx);
                    return Err(SwigError::InvalidAccountIndex.into());
                }

                // Get account data
                let account = &ctx.remaining_accounts[remaining_account_idx];
                let data = account.try_borrow_data()?;

                // Ensure field offset is valid
                if (*field_offset as usize + 8) > data.len() {
                    msg!("Invalid field offset: {}", field_offset);
                    return Err(SwigError::InvalidFieldOffset.into());
                }

                // Read 8 bytes (i64) from the specified offset
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&data[*field_offset as usize..(*field_offset as usize + 8)]);
                let value = i64::from_le_bytes(bytes);
                msg!("Loaded value: {}", value);

                stack.push(value);
                pc += 1;
            },
            VMInstruction::Add => {
                if stack.len() < 2 {
                    msg!("Stack underflow in Add operation");
                    return Err(SwigError::StackUnderflow.into());
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                let result = a + b;
                msg!("Add: {} + {} = {}", a, b, result);
                stack.push(result);
                pc += 1;
            },
            VMInstruction::Subtract => {
                if stack.len() < 2 {
                    msg!("Stack underflow in Subtract operation");
                    return Err(SwigError::StackUnderflow.into());
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                let result = a - b;
                msg!("Subtract: {} - {} = {}", a, b, result);
                stack.push(result);
                pc += 1;
            },
            VMInstruction::Multiply => {
                if stack.len() < 2 {
                    msg!("Stack underflow in Multiply operation");
                    return Err(SwigError::StackUnderflow.into());
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                let result = a * b;
                msg!("Multiply: {} * {} = {}", a, b, result);
                stack.push(result);
                pc += 1;
            },
            VMInstruction::Divide => {
                if stack.len() < 2 {
                    msg!("Stack underflow in Divide operation");
                    return Err(SwigError::StackUnderflow.into());
                }
                let b = stack.pop().unwrap();
                if b == 0 {
                    msg!("Division by zero");
                    return Err(SwigError::DivisionByZero.into());
                }
                let a = stack.pop().unwrap();
                let result = a / b;
                msg!("Divide: {} / {} = {}", a, b, result);
                stack.push(result);
                pc += 1;
            },
            VMInstruction::Equal => {
                if stack.len() < 2 {
                    msg!("Stack underflow in Equal operation");
                    return Err(SwigError::StackUnderflow.into());
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                let result = if a == b { 1 } else { 0 };
                msg!("Equal: {} == {} ? {}", a, b, result);
                stack.push(result);
                pc += 1;
            },
            VMInstruction::GreaterThan => {
                if stack.len() < 2 {
                    msg!("Stack underflow in GreaterThan operation");
                    return Err(SwigError::StackUnderflow.into());
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                let result = if a > b { 1 } else { 0 };
                msg!("GreaterThan: {} > {} ? {}", a, b, result);
                stack.push(result);
                pc += 1;
            },
            VMInstruction::LessThan => {
                if stack.len() < 2 {
                    msg!("Stack underflow in LessThan operation");
                    return Err(SwigError::StackUnderflow.into());
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                let result = if a < b { 1 } else { 0 };
                msg!("LessThan: {} < {} ? {}", a, b, result);
                stack.push(result);
                pc += 1;
            },
            VMInstruction::And => {
                if stack.len() < 2 {
                    msg!("Stack underflow in And operation");
                    return Err(SwigError::StackUnderflow.into());
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                let result = if a != 0 && b != 0 { 1 } else { 0 };
                msg!("And: {} && {} = {}", a, b, result);
                stack.push(result);
                pc += 1;
            },
            VMInstruction::Or => {
                if stack.len() < 2 {
                    msg!("Stack underflow in Or operation");
                    return Err(SwigError::StackUnderflow.into());
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                let result = if a != 0 || b != 0 { 1 } else { 0 };
                msg!("Or: {} || {} = {}", a, b, result);
                stack.push(result);
                pc += 1;
            },
            VMInstruction::Not => {
                if stack.is_empty() {
                    msg!("Stack underflow in Not operation");
                    return Err(SwigError::StackUnderflow.into());
                }
                let a = stack.pop().unwrap();
                let result = if a == 0 { 1 } else { 0 };
                msg!("Not: !{} = {}", a, result);
                stack.push(result);
                pc += 1;
            },
            VMInstruction::JumpIf { offset } => {
                if stack.is_empty() {
                    msg!("Stack underflow in JumpIf operation");
                    return Err(SwigError::StackUnderflow.into());
                }
                let condition = stack.pop().unwrap();
                msg!("JumpIf: popped condition {}", condition);

                if condition != 0 {
                    // Store the current PC before jumping
                    let old_pc = pc;

                    // Add the offset to the current PC
                    pc = pc.wrapping_add(*offset as usize);

                    msg!(
                        "JumpIf: condition true, jumping from PC={} to PC={} (offset={})",
                        old_pc,
                        pc,
                        offset
                    );

                    // Check for potential out-of-bounds jump
                    if pc >= bytecode_account.instructions.len() {
                        msg!("Invalid jump destination: {}", pc);
                        return Err(SwigError::InvalidJump.into());
                    }
                } else {
                    pc += 1;
                    msg!("JumpIf: condition false, continuing to PC={}", pc);
                }

                // Log the stack state after the jump
                msg!("Stack after JumpIf: {:?}", stack);
            },
            VMInstruction::Return => {
                if stack.is_empty() {
                    msg!("Stack underflow in Return operation");
                    return Err(SwigError::StackUnderflow.into());
                }
                msg!("Return instruction reached");
                // Exit the execution loop
                break;
            },
        }

        // Log stack after each instruction (except JumpIf, which already logs it)
        if !matches!(instruction, VMInstruction::JumpIf { .. }) {
            msg!("Stack after instruction: {:?}", stack);
        }

        // Check for stack overflow (arbitrary limit for safety)
        if stack.len() > 32 {
            msg!("Stack overflow: {} items", stack.len());
            return Err(SwigError::StackOverflow.into());
        }
    }

    // Store the result
    if stack.is_empty() {
        msg!("No result: stack is empty at end of execution");
        return Err(SwigError::NoResult.into());
    }

    let final_result = stack.pop().unwrap();
    msg!("Final result: {}", final_result);

    // Initialize result account if needed
    if ctx.accounts.result_account.data_is_empty() {
        let result_account = ExecutionResultAccount {
            result: final_result,
            executed_at: Clock::get()?.unix_timestamp,
        };

        let mut max_initial_result = Vec::with_capacity(128);
        result_account
            .serialize(&mut max_initial_result)
            .map_err(|e| SwigError::SerializationError)?;
        let space_needed = max_initial_result.len();

        // Create result account
        pinocchio_system::instructions::CreateAccount {
            from: ctx.accounts.payer,
            to: ctx.accounts.result_account,
            lamports: 0,
            space: space_needed as u64,
            owner: &crate::ID,
        }
        .invoke()?;

        // Write account data
        unsafe {
            ctx.accounts.result_account.borrow_mut_data_unchecked()[..space_needed]
                .copy_from_slice(&max_initial_result);
        }
    } else {
        // Update existing result account
        let mut result_account = ExecutionResultAccount::try_from_slice(unsafe {
            ctx.accounts.result_account.borrow_data_unchecked()
        })
        .map_err(|_| SwigError::SerializationError)?;
        result_account.result = final_result;
        result_account.executed_at = Clock::get()?.unix_timestamp;

        let mut max_initial_result = Vec::with_capacity(128);
        result_account
            .serialize(&mut max_initial_result)
            .map_err(|e| SwigError::SerializationError)?;
        let space_needed = max_initial_result.len();

        unsafe {
            ctx.accounts.result_account.borrow_mut_data_unchecked()[..space_needed]
                .copy_from_slice(&max_initial_result);
        }
    }

    msg!("Execution completed. Result stored: {}", final_result);
    Ok(())
}
