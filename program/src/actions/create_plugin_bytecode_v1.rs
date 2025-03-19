use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;
use swig_state::{PluginBytecodeAccount, VMInstruction};

use crate::{
    assertions::{check_system_owner, check_zero_balance},
    error::SwigError,
    instruction::{
        accounts::{Context, CreatePluginBytecodeV1Accounts},
        SwigInstruction,
    },
    util::ZeroCopy,
};

#[derive(Pod, Zeroable, Copy, Clone)]
#[repr(C, align(8))]
pub struct CreatePluginBytecodeV1Args {
    pub instruction: u8,
    pub padding: [u8; 3],
    pub instructions_len: u32,
}

impl CreatePluginBytecodeV1Args {
    pub fn new(instructions_len: u32) -> Self {
        Self {
            instruction: SwigInstruction::CreatePluginBytecodeV1 as u8,
            instructions_len,
            padding: [0; 3],
        }
    }
}

impl<'a> ZeroCopy<'a, CreatePluginBytecodeV1Args> for CreatePluginBytecodeV1Args {}

impl CreatePluginBytecodeV1Args {
    const SIZE: usize = core::mem::size_of::<Self>();
}

pub struct CreatePluginBytecodeV1<'a> {
    pub args: &'a CreatePluginBytecodeV1Args,
    instructions: &'a [u8],
}

impl<'a> CreatePluginBytecodeV1<'a> {
    const SIZE: usize = CreatePluginBytecodeV1Args::SIZE;

    pub fn load(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }

        let args = unsafe { &*(data.as_ptr() as *const CreatePluginBytecodeV1Args) };
        let instructions = &data[Self::SIZE..Self::SIZE + args.instructions_len as usize];

        Ok(Self { args, instructions })
    }
}

pub fn create_plugin_bytecode_v1(
    ctx: Context<CreatePluginBytecodeV1Accounts>,
    data: &[u8],
) -> ProgramResult {
    // Basic account validations
    check_system_owner(
        ctx.accounts.plugin_bytecode_account,
        SwigError::OwnerMismatch("plugin_bytecode_account"),
    )?;
    check_zero_balance(
        ctx.accounts.plugin_bytecode_account,
        SwigError::AccountNotEmpty("plugin_bytecode_account"),
    )?;

    // Parse instruction data
    let create_plugin = CreatePluginBytecodeV1::load(data).map_err(|e| {
        msg!("CreatePluginBytecodeV1 Args Error: {:?}", e);
        ProgramError::InvalidInstructionData
    })?;

    // Create plugin bytecode account with instructions
    let mut plugin_bytecode_account = PluginBytecodeAccount {
        target_program: *ctx.accounts.target_program.key(),
        instructions_len: create_plugin.args.instructions_len,
        padding: [0; 4],
        instructions: [VMInstruction::Return; 32], // Initialize with default value
    };

    // Deserialize and copy instructions
    let mut cursor = 0;
    let mut instruction_count = 0;
    while cursor < create_plugin.instructions.len() && instruction_count < 32 {
        let instruction: &VMInstruction = bytemuck::from_bytes(
            &create_plugin.instructions[cursor..cursor + core::mem::size_of::<VMInstruction>()],
        );
        plugin_bytecode_account.instructions[instruction_count] = *instruction;
        cursor += core::mem::size_of::<VMInstruction>();
        instruction_count += 1;
    }

    if instruction_count >= 32 {
        return Err(SwigError::TooManyInstructions.into());
    }

    // Calculate space needed for the account
    let space_needed = core::mem::size_of::<PluginBytecodeAccount>();

    // Create plugin bytecode account
    pinocchio_system::instructions::CreateAccount {
        from: ctx.accounts.authority,
        to: ctx.accounts.plugin_bytecode_account,
        lamports: 0,
        space: space_needed as u64,
        owner: &crate::ID,
    }
    .invoke()?;

    // Write account data
    unsafe {
        ctx.accounts
            .plugin_bytecode_account
            .borrow_mut_data_unchecked()[..space_needed]
            .copy_from_slice(bytemuck::bytes_of(&plugin_bytecode_account));
    }

    msg!("Plugin bytecode account created successfully");
    Ok(())
}
