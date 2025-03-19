use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;
use swig_state::{BytecodeAccount, VMInstruction};

use crate::{
    assertions::{check_system_owner, check_zero_balance},
    error::SwigError,
    instruction::{
        accounts::{Context, InitializeBytecodeV1Accounts},
        SwigInstruction,
    },
    util::ZeroCopy,
};

#[derive(Pod, Zeroable, Copy, Clone)]
#[repr(C, align(8))]
pub struct InitializeBytecodeV1Args {
    pub instruction: u8,
    pub padding: [u8; 5],
    pub instructions_len: u16,
}

impl InitializeBytecodeV1Args {
    pub fn new(instructions_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::InitializeBytecodeV1 as u8,
            instructions_len,
            padding: [0; 5],
        }
    }
}

impl<'a> ZeroCopy<'a, InitializeBytecodeV1Args> for InitializeBytecodeV1Args {}

impl InitializeBytecodeV1Args {
    const SIZE: usize = core::mem::size_of::<Self>();
}

pub struct InitializeBytecodeV1<'a> {
    pub args: &'a InitializeBytecodeV1Args,
    instructions: &'a [u8],
}

impl<'a> InitializeBytecodeV1<'a> {
    const SIZE: usize = InitializeBytecodeV1Args::SIZE;

    pub fn load(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }

        let args = unsafe { &*(data.as_ptr() as *const InitializeBytecodeV1Args) };
        // Read all remaining data after the args
        let instructions = &data[Self::SIZE..];

        Ok(Self { args, instructions })
    }
}

pub fn initialize_bytecode_v1(
    ctx: Context<InitializeBytecodeV1Accounts>,
    data: &[u8],
) -> ProgramResult {
    msg!("init bytecode v1");
    msg!("Instruction data length: {}", data.len());
    msg!("Instruction data: {:?}", data);

    // Basic account validations
    check_system_owner(
        ctx.accounts.bytecode_account,
        SwigError::OwnerMismatch("bytecode_account"),
    )?;
    check_zero_balance(
        ctx.accounts.bytecode_account,
        SwigError::AccountNotEmpty("bytecode_account"),
    )?;

    // Parse instruction data
    let initialize_bytecode = InitializeBytecodeV1::load(data).map_err(|e| {
        msg!("InitializeBytecodeV1 Args Error: {:?}", e);
        msg!("Data length: {}", data.len());
        msg!("Expected size: {}", InitializeBytecodeV1::SIZE);
        msg!("Raw data: {:?}", data);
        ProgramError::InvalidInstructionData
    })?;

    msg!("Successfully loaded args");
    msg!(
        "Instructions length from args: {}",
        initialize_bytecode.args.instructions_len
    );
    msg!(
        "Instructions data length: {}",
        initialize_bytecode.instructions.len()
    );

    // Deserialize the instructions using bytemuck
    let instructions_data =
        &initialize_bytecode.instructions[..initialize_bytecode.args.instructions_len as usize
            * core::mem::size_of::<VMInstruction>()];
    let instructions: &[VMInstruction] = bytemuck::cast_slice(instructions_data);

    msg!(
        "Successfully deserialized {} instructions",
        instructions.len()
    );

    // Create bytecode account with instructions
    let mut bytecode_account = BytecodeAccount {
        authority: *ctx.accounts.authority.key(),
        instructions_len: instructions.len() as u32,
        padding: [0; 4],
        instructions: [VMInstruction::Return; 32], // Initialize with default value
    };

    // Copy instructions into the fixed-size array
    for (i, instruction) in instructions.iter().enumerate().take(32) {
        bytecode_account.instructions[i] = *instruction;
    }

    let space_needed = core::mem::size_of::<BytecodeAccount>();
    let lamports_needed = Rent::get()?.minimum_balance(space_needed);

    CreateAccount {
        from: ctx.accounts.authority,
        to: ctx.accounts.bytecode_account,
        lamports: lamports_needed,
        space: space_needed as u64,
        owner: &crate::ID,
    }
    .invoke()?;

    // Write account data
    unsafe {
        ctx.accounts.bytecode_account.borrow_mut_data_unchecked()[..space_needed]
            .copy_from_slice(bytemuck::bytes_of(&bytecode_account));
    }

    msg!(
        "Bytecode account initialized with {} instructions",
        instructions.len()
    );
    Ok(())
}
