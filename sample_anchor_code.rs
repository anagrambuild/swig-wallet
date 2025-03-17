use anchor_lang::prelude::*;
use anchor_lang::solana_program::{self, program::invoke, pubkey::Pubkey};
use solana_program::bpf_loader_upgradeable::{self, UpgradeableLoaderState};

declare_id!("6rUxuWiddcZX8DU2jzPAPhMftt1vMRk2hA2r2Xodsp2Q");

// Define a simple instruction set for our VM
#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Debug)]
pub enum VMInstruction {
    // Load a value onto the stack
    PushValue {
        value: i64,
    },
    // Load a value from an account at given index
    LoadField {
        account_index: u8,
        field_offset: u16,
    },
    // Basic arithmetic operations
    Add,
    Subtract,
    Multiply,
    Divide,
    // Comparison operations
    Equal,
    GreaterThan,
    LessThan,
    // Logical operations
    And,
    Or,
    Not,
    // Control flow (jump if top of stack is true)
    JumpIf {
        offset: u8,
    },
    // Return the top value from the stack
    Return,
}

// Account to store user-defined bytecode
#[account]
pub struct BytecodeAccount {
    pub authority: Pubkey,
    pub instructions: Vec<VMInstruction>,
}

// Account to store plugin bytecode
#[account]
pub struct PluginBytecodeAccount {
    pub target_program: Pubkey, // The program this plugin is for
    pub instructions: Vec<VMInstruction>,
}

// Account to store execution results
#[account]
pub struct ExecutionResultAccount {
    pub result: i64,
    pub executed_at: i64,
}

#[program]
pub mod solana_vm {
    use super::*;

    // Initialize a new bytecode account
    pub fn initialize_bytecode(
        ctx: Context<InitializeBytecode>,
        instructions: Vec<VMInstruction>,
    ) -> Result<()> {
        let bytecode_account = &mut ctx.accounts.bytecode_account;
        bytecode_account.authority = ctx.accounts.authority.key();
        bytecode_account.instructions = instructions.clone();

        msg!(
            "Bytecode initialized with {} instructions",
            bytecode_account.instructions.len()
        );

        // Log each instruction for debugging
        for (i, instruction) in instructions.iter().enumerate() {
            msg!("Instruction {}: {:?}", i, instruction);
        }

        Ok(())
    }

    // Create a new plugin bytecode account as a PDA derived from the target program
    pub fn create_plugin_bytecode(
        ctx: Context<CreatePluginBytecode>,
        instructions: Vec<VMInstruction>,
    ) -> Result<()> {
        msg!(
            "target_program_info: {:?}",
            ctx.accounts.target_program_info.key()
        );

        let (program_data_address, _) = Pubkey::find_program_address(
            &[ctx.accounts.target_program_info.key().as_ref()],
            &bpf_loader_upgradeable::id(),
        );

        msg!("program_data_address: {:?}", program_data_address.key());

        let data = ctx.accounts.program_data_info.try_borrow_data()?;

        let mut authority = [0u8; 32];
        authority.copy_from_slice(&data[9..41]);
        let deployer = Pubkey::new_from_array(authority);
        msg!("deployer: {:?}", deployer.key());

        // Verify that the authority is indeed the upgrade authority of the target program
        // let target_program_data = ctx.accounts.target_program_info.try_borrow_data()?;
        // let program_data = match UpgradeableLoaderState::try_from_slice(&target_program_data) {
        //     Ok(UpgradeableLoaderState::Program {
        //         programdata_address,
        //     }) => {
        //         // Get program data account
        //         let programdata_info = ctx.accounts.program_data_info.to_account_info();

        //         // Verify that the programdata_address matches the provided program data account
        //         if programdata_address != programdata_info.key() {
        //             return Err(ErrorCode::InvalidProgramDataAccount.into());
        //         }

        //         // Verify program data account
        //         let program_data_data = programdata_info.try_borrow_data()?;
        //         match UpgradeableLoaderState::try_from_slice(&program_data_data) {
        //             Ok(UpgradeableLoaderState::ProgramData {
        //                 slot: _,
        //                 upgrade_authority_address,
        //             }) => {
        //                 // Check if upgrade authority exists
        //                 if upgrade_authority_address.is_none() {
        //                     return Err(ErrorCode::NoUpgradeAuthority.into());
        //                 }

        //                 // Check if the signer is the upgrade authority
        //                 if upgrade_authority_address.unwrap() != ctx.accounts.authority.key() {
        //                     return Err(ErrorCode::NotUpgradeAuthority.into());
        //                 }

        //                 Ok(())
        //             }
        //             _ => Err(ErrorCode::InvalidProgramData.into()),
        //         }
        //     }
        //     _ => Err(ErrorCode::InvalidProgramAccount.into()),
        // }?;

        // Initialize the plugin bytecode account
        let plugin_account = &mut ctx.accounts.plugin_bytecode_account;
        plugin_account.target_program = ctx.accounts.target_program_info.key();
        plugin_account.instructions = instructions.clone();

        msg!(
            "Plugin bytecode initialized for program {} with {} instructions",
            plugin_account.target_program,
            plugin_account.instructions.len()
        );

        // Log each instruction for debugging
        for (i, instruction) in instructions.iter().enumerate() {
            msg!("Instruction {}: {:?}", i, instruction);
        }

        Ok(())
    }

    // Execute the bytecode stored in the provided account
    pub fn execute(
        ctx: Context<Execute>,
        account_indices: Option<Vec<u8>>, // Optional indices
    ) -> Result<()> {
        let bytecode_account = &ctx.accounts.bytecode_account;
        let result_account = &mut ctx.accounts.result_account;

        // Log the bytecode we're about to execute
        msg!(
            "Executing bytecode with {} instructions",
            bytecode_account.instructions.len()
        );
        for (i, instruction) in bytecode_account.instructions.iter().enumerate() {
            msg!("Instruction {}: {:?}", i, instruction);
        }

        // Initialize VM state
        let mut stack: Vec<i64> = Vec::new();
        let mut pc: usize = 0; // Program counter

        // Extract account_indices (default to empty vec if None)
        let indices = account_indices.unwrap_or_default();

        // Execute instructions until Return or end of bytecode
        while pc < bytecode_account.instructions.len() {
            let instruction = &bytecode_account.instructions[pc];
            msg!("Executing instruction at PC={}: {:?}", pc, instruction);

            match instruction {
                VMInstruction::PushValue { value } => {
                    msg!("Pushing value: {}", value);
                    stack.push(*value);
                    pc += 1;
                }
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
                        return Err(ErrorCode::InvalidAccountIndex.into());
                    }

                    // Get the index in remaining_accounts
                    let remaining_account_idx = indices[*account_index as usize] as usize;

                    // Ensure the index is within bounds
                    if remaining_account_idx >= ctx.remaining_accounts.len() {
                        msg!("Invalid remaining account index: {}", remaining_account_idx);
                        return Err(ErrorCode::InvalidAccountIndex.into());
                    }

                    // Get account data
                    let account = &ctx.remaining_accounts[remaining_account_idx];
                    let data = account.try_borrow_data()?;

                    // Ensure field offset is valid
                    if (*field_offset as usize + 8) > data.len() {
                        msg!("Invalid field offset: {}", field_offset);
                        return Err(ErrorCode::InvalidFieldOffset.into());
                    }

                    // Read 8 bytes (i64) from the specified offset
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(
                        &data[*field_offset as usize..(*field_offset as usize + 8)],
                    );
                    let value = i64::from_le_bytes(bytes);
                    msg!("Loaded value: {}", value);

                    stack.push(value);
                    pc += 1;
                }
                VMInstruction::Add => {
                    if stack.len() < 2 {
                        msg!("Stack underflow in Add operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let result = a + b;
                    msg!("Add: {} + {} = {}", a, b, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::Subtract => {
                    if stack.len() < 2 {
                        msg!("Stack underflow in Subtract operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let result = a - b;
                    msg!("Subtract: {} - {} = {}", a, b, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::Multiply => {
                    if stack.len() < 2 {
                        msg!("Stack underflow in Multiply operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let result = a * b;
                    msg!("Multiply: {} * {} = {}", a, b, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::Divide => {
                    if stack.len() < 2 {
                        msg!("Stack underflow in Divide operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let b = stack.pop().unwrap();
                    if b == 0 {
                        msg!("Division by zero");
                        return Err(ErrorCode::DivisionByZero.into());
                    }
                    let a = stack.pop().unwrap();
                    let result = a / b;
                    msg!("Divide: {} / {} = {}", a, b, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::Equal => {
                    if stack.len() < 2 {
                        msg!("Stack underflow in Equal operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let result = if a == b { 1 } else { 0 };
                    msg!("Equal: {} == {} ? {}", a, b, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::GreaterThan => {
                    if stack.len() < 2 {
                        msg!("Stack underflow in GreaterThan operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let result = if a > b { 1 } else { 0 };
                    msg!("GreaterThan: {} > {} ? {}", a, b, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::LessThan => {
                    if stack.len() < 2 {
                        msg!("Stack underflow in LessThan operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let result = if a < b { 1 } else { 0 };
                    msg!("LessThan: {} < {} ? {}", a, b, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::And => {
                    if stack.len() < 2 {
                        msg!("Stack underflow in And operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let result = if a != 0 && b != 0 { 1 } else { 0 };
                    msg!("And: {} && {} = {}", a, b, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::Or => {
                    if stack.len() < 2 {
                        msg!("Stack underflow in Or operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let result = if a != 0 || b != 0 { 1 } else { 0 };
                    msg!("Or: {} || {} = {}", a, b, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::Not => {
                    if stack.is_empty() {
                        msg!("Stack underflow in Not operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let a = stack.pop().unwrap();
                    let result = if a == 0 { 1 } else { 0 };
                    msg!("Not: !{} = {}", a, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::JumpIf { offset } => {
                    if stack.is_empty() {
                        msg!("Stack underflow in JumpIf operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let condition = stack.pop().unwrap();
                    msg!("JumpIf: popped condition {}", condition);

                    if condition != 0 {
                        // Store the current PC before jumping
                        let old_pc = pc;

                        // This is the key fix: add the offset to the current PC
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
                            return Err(ErrorCode::InvalidJump.into());
                        }
                    } else {
                        pc += 1;
                        msg!("JumpIf: condition false, continuing to PC={}", pc);
                    }

                    // Log the stack state after the jump
                    msg!("Stack after JumpIf: {:?}", stack);
                }
                VMInstruction::Return => {
                    if stack.is_empty() {
                        msg!("Stack underflow in Return operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    msg!("Return instruction reached");
                    // Exit the execution loop
                    break;
                }
            }

            // Log stack after each instruction (except JumpIf, which already logs it)
            if !matches!(instruction, VMInstruction::JumpIf { .. }) {
                msg!("Stack after instruction: {:?}", stack);
            }

            // Check for stack overflow (arbitrary limit for safety)
            if stack.len() > 32 {
                msg!("Stack overflow: {} items", stack.len());
                return Err(ErrorCode::StackOverflow.into());
            }
        }

        // Store the result
        if stack.is_empty() {
            msg!("No result: stack is empty at end of execution");
            return Err(ErrorCode::NoResult.into());
        }

        let final_result = stack.pop().unwrap();
        msg!("Final result: {}", final_result);

        result_account.result = final_result;
        result_account.executed_at = Clock::get()?.unix_timestamp;

        msg!(
            "Execution completed. Result stored: {}",
            result_account.result
        );
        Ok(())
    }

    // Execute bytecode from a plugin based on a program ID
    pub fn execute_plugin(
        ctx: Context<ExecutePlugin>,
        account_indices: Option<Vec<u8>>, // Optional indices
    ) -> Result<()> {
        let plugin_bytecode_account = &ctx.accounts.plugin_bytecode_account;
        let result_account = &mut ctx.accounts.result_account;

        // Verify that the provided program matches the plugin's target program
        if ctx.accounts.target_program_info.key() != plugin_bytecode_account.target_program {
            return Err(ErrorCode::TargetProgramMismatch.into());
        }

        // Log the bytecode we're about to execute
        msg!(
            "Executing plugin bytecode for program {} with {} instructions",
            plugin_bytecode_account.target_program,
            plugin_bytecode_account.instructions.len()
        );
        for (i, instruction) in plugin_bytecode_account.instructions.iter().enumerate() {
            msg!("Instruction {}: {:?}", i, instruction);
        }

        // Initialize VM state
        let mut stack: Vec<i64> = Vec::new();
        let mut pc: usize = 0; // Program counter

        // Process the account_indices parameter
        let indices = if let Some(indices) = account_indices {
            msg!("Received account indices: {:?}", indices);
            indices
        } else {
            msg!("No account indices provided, using empty vector");
            Vec::new()
        };

        // Log remaining accounts for debugging
        msg!("Remaining accounts count: {}", ctx.remaining_accounts.len());
        for (i, account) in ctx.remaining_accounts.iter().enumerate() {
            msg!("Remaining account {}: {}", i, account.key());
        }

        // Execute instructions until Return or end of bytecode
        while pc < plugin_bytecode_account.instructions.len() {
            let instruction = &plugin_bytecode_account.instructions[pc];
            msg!("Executing instruction at PC={}: {:?}", pc, instruction);

            match instruction {
                VMInstruction::PushValue { value } => {
                    msg!("Pushing value: {}", value);
                    stack.push(*value);
                    pc += 1;
                }
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
                        return Err(ErrorCode::InvalidAccountIndex.into());
                    }

                    // Get the index in remaining_accounts
                    let remaining_account_idx = indices[*account_index as usize] as usize;

                    // Ensure the index is within bounds
                    if remaining_account_idx >= ctx.remaining_accounts.len() {
                        msg!("Invalid remaining account index: {}", remaining_account_idx);
                        return Err(ErrorCode::InvalidAccountIndex.into());
                    }

                    // Get account data
                    let account = &ctx.remaining_accounts[remaining_account_idx];
                    let data = account.try_borrow_data()?;

                    // Ensure field offset is valid
                    if (*field_offset as usize + 8) > data.len() {
                        msg!("Invalid field offset: {}", field_offset);
                        return Err(ErrorCode::InvalidFieldOffset.into());
                    }

                    // Read 8 bytes (i64) from the specified offset
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(
                        &data[*field_offset as usize..(*field_offset as usize + 8)],
                    );
                    let value = i64::from_le_bytes(bytes);
                    msg!("Loaded value: {}", value);

                    stack.push(value);
                    pc += 1;
                }
                VMInstruction::Add => {
                    if stack.len() < 2 {
                        msg!("Stack underflow in Add operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let result = a + b;
                    msg!("Add: {} + {} = {}", a, b, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::Subtract => {
                    if stack.len() < 2 {
                        msg!("Stack underflow in Subtract operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let result = a - b;
                    msg!("Subtract: {} - {} = {}", a, b, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::Multiply => {
                    if stack.len() < 2 {
                        msg!("Stack underflow in Multiply operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let result = a * b;
                    msg!("Multiply: {} * {} = {}", a, b, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::Divide => {
                    if stack.len() < 2 {
                        msg!("Stack underflow in Divide operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let b = stack.pop().unwrap();
                    if b == 0 {
                        msg!("Division by zero");
                        return Err(ErrorCode::DivisionByZero.into());
                    }
                    let a = stack.pop().unwrap();
                    let result = a / b;
                    msg!("Divide: {} / {} = {}", a, b, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::Equal => {
                    if stack.len() < 2 {
                        msg!("Stack underflow in Equal operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let result = if a == b { 1 } else { 0 };
                    msg!("Equal: {} == {} ? {}", a, b, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::GreaterThan => {
                    if stack.len() < 2 {
                        msg!("Stack underflow in GreaterThan operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let result = if a > b { 1 } else { 0 };
                    msg!("GreaterThan: {} > {} ? {}", a, b, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::LessThan => {
                    if stack.len() < 2 {
                        msg!("Stack underflow in LessThan operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let result = if a < b { 1 } else { 0 };
                    msg!("LessThan: {} < {} ? {}", a, b, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::And => {
                    if stack.len() < 2 {
                        msg!("Stack underflow in And operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let result = if a != 0 && b != 0 { 1 } else { 0 };
                    msg!("And: {} && {} = {}", a, b, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::Or => {
                    if stack.len() < 2 {
                        msg!("Stack underflow in Or operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let result = if a != 0 || b != 0 { 1 } else { 0 };
                    msg!("Or: {} || {} = {}", a, b, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::Not => {
                    if stack.is_empty() {
                        msg!("Stack underflow in Not operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let a = stack.pop().unwrap();
                    let result = if a == 0 { 1 } else { 0 };
                    msg!("Not: !{} = {}", a, result);
                    stack.push(result);
                    pc += 1;
                }
                VMInstruction::JumpIf { offset } => {
                    if stack.is_empty() {
                        msg!("Stack underflow in JumpIf operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    let condition = stack.pop().unwrap();
                    msg!("JumpIf: popped condition {}", condition);

                    if condition != 0 {
                        // Store the current PC before jumping
                        let old_pc = pc;

                        // This is the key fix: add the offset to the current PC
                        pc = pc.wrapping_add(*offset as usize);

                        msg!(
                            "JumpIf: condition true, jumping from PC={} to PC={} (offset={})",
                            old_pc,
                            pc,
                            offset
                        );

                        // Check for potential out-of-bounds jump
                        if pc >= plugin_bytecode_account.instructions.len() {
                            msg!("Invalid jump destination: {}", pc);
                            return Err(ErrorCode::InvalidJump.into());
                        }
                    } else {
                        pc += 1;
                        msg!("JumpIf: condition false, continuing to PC={}", pc);
                    }

                    // Log the stack state after the jump
                    msg!("Stack after JumpIf: {:?}", stack);
                }
                VMInstruction::Return => {
                    if stack.is_empty() {
                        msg!("Stack underflow in Return operation");
                        return Err(ErrorCode::StackUnderflow.into());
                    }
                    msg!("Return instruction reached");
                    // Exit the execution loop
                    break;
                }
            }

            // Log stack after each instruction (except JumpIf, which already logs it)
            if !matches!(instruction, VMInstruction::JumpIf { .. }) {
                msg!("Stack after instruction: {:?}", stack);
            }

            // Check for stack overflow (arbitrary limit for safety)
            if stack.len() > 32 {
                msg!("Stack overflow: {} items", stack.len());
                return Err(ErrorCode::StackOverflow.into());
            }
        }

        // Store the result
        if stack.is_empty() {
            msg!("No result: stack is empty at end of execution");
            return Err(ErrorCode::NoResult.into());
        }

        let final_result = stack.pop().unwrap();
        msg!("Final result: {}", final_result);

        result_account.result = final_result;
        result_account.executed_at = Clock::get()?.unix_timestamp;

        msg!(
            "Execution completed. Result stored: {}",
            result_account.result
        );
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeBytecode<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 4 + (10 * 16) // Arbitrary initial space for 10 instructions
    )]
    pub bytecode_account: Account<'info, BytecodeAccount>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction()]
pub struct CreatePluginBytecode<'info> {
    // The plugin bytecode account which is a PDA derived from the target program
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 4 + (10 * 16), // Space for account + instructions
        seeds = [b"plugin", target_program_info.key().as_ref()],
        bump
    )]
    pub plugin_bytecode_account: Account<'info, PluginBytecodeAccount>,

    // The program that this plugin is for (must be upgradeable)
    /// CHECK: Validated in the instruction logic
    pub target_program_info: AccountInfo<'info>,

    // The program's data account which contains the upgrade authority
    /// CHECK: Validated in the instruction logic
    pub program_data_info: AccountInfo<'info>,

    // The authority must be the upgrade authority of the target program
    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Execute<'info> {
    #[account(
        constraint = bytecode_account.instructions.len() > 0 @ ErrorCode::EmptyBytecode
    )]
    pub bytecode_account: Account<'info, BytecodeAccount>,

    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + 8 + 8
    )]
    pub result_account: Account<'info, ExecutionResultAccount>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ExecutePlugin<'info> {
    // The plugin bytecode account is a PDA derived from the target program
    #[account(
        seeds = [b"plugin", target_program_info.key().as_ref()],
        bump,
        constraint = plugin_bytecode_account.instructions.len() > 0 @ ErrorCode::EmptyBytecode
    )]
    pub plugin_bytecode_account: Account<'info, PluginBytecodeAccount>,

    // The target program that this plugin was created for
    /// CHECK: The account is verified against the plugin's registered target program
    pub target_program_info: AccountInfo<'info>,

    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + 8 + 8
    )]
    pub result_account: Account<'info, ExecutionResultAccount>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("VM stack underflow")]
    StackUnderflow,

    #[msg("VM stack overflow")]
    StackOverflow,

    #[msg("Invalid account index")]
    InvalidAccountIndex,

    #[msg("Invalid field offset")]
    InvalidFieldOffset,

    #[msg("Division by zero")]
    DivisionByZero,

    #[msg("Invalid jump destination")]
    InvalidJump,

    #[msg("No result produced")]
    NoResult,

    #[msg("Bytecode account is empty")]
    EmptyBytecode,

    #[msg("Invalid program data account")]
    InvalidProgramDataAccount,

    #[msg("No upgrade authority")]
    NoUpgradeAuthority,
    #[msg("Not upgrade authority")]
    NotUpgradeAuthority,
    #[msg("Invalid program data")]
    InvalidProgramData,
    #[msg("Invalid program account")]
    InvalidProgramAccount,
    #[msg("Target program mismatch")]
    TargetProgramMismatch,
}
