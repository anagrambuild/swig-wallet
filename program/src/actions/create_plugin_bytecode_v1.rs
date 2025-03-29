use std::borrow::Borrow;

use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;
use swig_state::{swig_pim_account_signer, GlobalConfig, PluginBytecodeAccount, VMInstruction};

use crate::{
    assertions::{check_self_owned, check_signer, check_system_owner, check_zero_balance},
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
            instructions_len,
            padding: [0; 5],
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
        // Read all remaining data after the args
        let instructions = &data[Self::SIZE..];

        Ok(Self { args, instructions })
    }
}

pub fn create_plugin_bytecode_v1(
    ctx: Context<CreatePluginBytecodeV1Accounts>,
    data: &[u8],
) -> ProgramResult {
    msg!("create plugin bytecode v1");
    msg!("Instruction data length: {}", data.len());

    // Basic account validations
    check_system_owner(
        ctx.accounts.plugin_bytecode_account,
        SwigError::OwnerMismatch("plugin_bytecode_account"),
    )?;
    check_zero_balance(
        ctx.accounts.plugin_bytecode_account,
        SwigError::AccountNotEmpty("plugin_bytecode_account"),
    )?;

    // Check that the config account is owned by the program
    // check_self_owned(ctx.accounts.config, SwigError::OwnerMismatch("config"))?;

    // Verify admin signature
    check_signer(ctx.accounts.admin, SwigError::AdminSignatureRequired)?;

    // Verify that the admin account matches the one in the config
    let config_data = ctx.accounts.config.try_borrow_data()?;
    let config = unsafe { &*(config_data.as_ptr() as *const GlobalConfig) };

    msg!("config.admin: {:?}", config);
    msg!("admin: {:?}", ctx.accounts.admin.key());

    if config.admin != *ctx.accounts.admin.key() {
        msg!("Admin account does not match the one in config");
        msg!("Expected: {:?}", &config.admin);
        msg!("Provided: {:?}", ctx.accounts.admin.key());
        return Err(SwigError::NotConfiguredAdmin.into());
    }

    // Parse instruction data
    let create_plugin = CreatePluginBytecodeV1::load(data).map_err(|e| {
        msg!("CreatePluginBytecodeV1 Args Error: {:?}", e);
        msg!("Data length: {}", data.len());
        msg!("Expected size: {}", CreatePluginBytecodeV1::SIZE);
        msg!("Raw data: {:?}", data);
        ProgramError::InvalidInstructionData
    })?;

    msg!("Successfully loaded args");
    msg!(
        "Instructions length from args: {}",
        create_plugin.args.instructions_len
    );
    msg!(
        "Instructions data length: {}",
        create_plugin.instructions.len()
    );

    // Deserialize the instructions using bytemuck
    let instructions_data = &create_plugin.instructions
        [..create_plugin.args.instructions_len as usize * core::mem::size_of::<VMInstruction>()];
    let instructions: &[VMInstruction] = bytemuck::cast_slice(instructions_data);

    msg!(
        "Successfully deserialized {} instructions",
        instructions.len()
    );

    // Create plugin bytecode account with instructions
    let mut plugin_bytecode_account = PluginBytecodeAccount {
        target_program: *ctx.accounts.target_program.key(),
        instructions_len: instructions.len() as u32,
        padding: [0; 4],
        instructions: [VMInstruction::Return; 32], // Initialize with default value
    };

    msg!("plugin bytecode account struct created");

    // Copy instructions into the fixed-size array
    for (i, instruction) in instructions.iter().enumerate().take(32) {
        plugin_bytecode_account.instructions[i] = *instruction;
    }

    // Calculate space needed for the account
    let space_needed = core::mem::size_of::<PluginBytecodeAccount>();
    let lamports_needed = Rent::get()?.minimum_balance(space_needed);

    // Create plugin bytecode account using PDA
    // Derive seeds for the plugin PDA: "swig-pim" and target program
    let seeds = &[b"swig-pim", ctx.accounts.target_program.key().as_ref()];
    let (expected_pda, bump) = pinocchio::pubkey::find_program_address(seeds, &crate::ID);

    // Check that provided account matches expected PDA
    if *ctx.accounts.plugin_bytecode_account.key() != expected_pda {
        msg!("Provided plugin bytecode account does not match derived PDA");
        msg!("Expected: {:?}", expected_pda);
        msg!("Provided: {:?}", ctx.accounts.plugin_bytecode_account.key());
        return Err(SwigError::InvalidPDA.into());
    }

    pinocchio_system::instructions::CreateAccount {
        from: ctx.accounts.authority,
        to: ctx.accounts.plugin_bytecode_account,
        lamports: lamports_needed,
        space: space_needed as u64,
        owner: &crate::ID,
    }
    .invoke_signed(&[swig_pim_account_signer(
        &ctx.accounts.target_program.key().as_ref(),
        &[bump],
    )
    .as_slice()
    .into()])?;

    println!("bytecode account created");

    // Write account data
    unsafe {
        ctx.accounts
            .plugin_bytecode_account
            .borrow_mut_data_unchecked()[..space_needed]
            .copy_from_slice(bytemuck::bytes_of(&plugin_bytecode_account));
    }

    msg!(
        "Plugin bytecode account created successfully with {} instructions",
        instructions.len()
    );
    Ok(())
}
