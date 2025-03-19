use borsh::{BorshDeserialize, BorshSerialize};
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
    pub padding: [u8; 5],
    pub instructions_len: u16,
}

impl CreatePluginBytecodeV1Args {
    pub fn new(instructions_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::CreatePluginBytecodeV1 as u8,
            padding: [0; 5],
            instructions_len,
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

    // Deserialize instructions
    let mut instructions = Vec::new();
    let mut cursor = 0;
    while cursor < create_plugin.instructions.len() {
        let instruction = VMInstruction::try_from_slice(&create_plugin.instructions[cursor..])
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        cursor += instruction.size();
        instructions.push(instruction);
    }

    // Create plugin bytecode account
    let plugin_bytecode_account = PluginBytecodeAccount {
        target_program: *ctx.accounts.target_program.key(),
        instructions: instructions.clone(),
    };

    let mut max_initial_plugin = Vec::with_capacity(128);
    plugin_bytecode_account
        .serialize(&mut max_initial_plugin)
        .map_err(|e| SwigError::SerializationError)?;
    let space_needed = max_initial_plugin.len();
    let lamports_needed = Rent::get()?.minimum_balance(space_needed);

    CreateAccount {
        from: ctx.accounts.authority,
        to: ctx.accounts.plugin_bytecode_account,
        lamports: lamports_needed,
        space: space_needed as u64,
        owner: &crate::ID,
    }
    .invoke()?;

    // Write account data
    unsafe {
        ctx.accounts
            .plugin_bytecode_account
            .borrow_mut_data_unchecked()[..space_needed]
            .copy_from_slice(&max_initial_plugin);
    }

    msg!(
        "Plugin bytecode account initialized for program {:?} with {} instructions",
        ctx.accounts.target_program.key(),
        instructions.len()
    );
    Ok(())
}
