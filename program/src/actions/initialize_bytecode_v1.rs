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
use swig_state::{BytecodeAccount, VMInstruction};

use crate::{
    assertions::{check_system_owner, check_zero_balance},
    error::SwigError,
    instruction::{
        accounts::{Context, InitializeBytecodeAccounts},
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
            instruction: SwigInstruction::InitializeBytecode as u8,
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
        let instructions = &data[Self::SIZE..Self::SIZE + args.instructions_len as usize];

        Ok(Self { args, instructions })
    }
}

pub fn initialize_bytecode_v1(
    ctx: Context<InitializeBytecodeAccounts>,
    data: &[u8],
) -> ProgramResult {
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
        ProgramError::InvalidInstructionData
    })?;

    // Deserialize instructions
    let mut instructions = Vec::new();
    let mut cursor = 0;
    while cursor < initialize_bytecode.instructions.len() {
        let instruction =
            VMInstruction::try_from_slice(&initialize_bytecode.instructions[cursor..])
                .map_err(|_| ProgramError::InvalidInstructionData)?;
        cursor += instruction.size();
        instructions.push(instruction);
    }

    // Create bytecode account
    let bytecode_account = BytecodeAccount {
        authority: *ctx.accounts.authority.key(),
        instructions: instructions.clone(),
    };

    let mut max_initial_bytecode = Vec::with_capacity(128);
    bytecode_account
        .serialize(&mut max_initial_bytecode)
        .map_err(|e| SwigError::SerializationError)?;
    let space_needed = max_initial_bytecode.len();
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
            .copy_from_slice(&max_initial_bytecode);
    }

    msg!(
        "Bytecode account initialized with {} instructions",
        instructions.len()
    );
    Ok(())
}
