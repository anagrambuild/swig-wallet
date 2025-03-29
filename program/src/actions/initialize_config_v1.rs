use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;
use swig_state::{config_seeds, config_signer, GlobalConfig};

use crate::{
    assertions::{check_system_owner, check_zero_balance},
    error::SwigError,
    instruction::{
        accounts::{Context, InitializeConfigV1Accounts},
        SwigInstruction,
    },
    util::ZeroCopy,
};

#[derive(Pod, Zeroable, Copy, Clone)]
#[repr(C, align(8))]
pub struct InitializeConfigV1Args {
    pub instruction: u8,
    pub padding: [u8; 7],
}

impl InitializeConfigV1Args {
    pub fn new() -> Self {
        Self {
            instruction: SwigInstruction::InitializeConfigV1 as u8,
            padding: [0; 7],
        }
    }
}

impl<'a> ZeroCopy<'a, InitializeConfigV1Args> for InitializeConfigV1Args {}

impl InitializeConfigV1Args {
    const SIZE: usize = core::mem::size_of::<Self>();
}

pub struct InitializeConfigV1<'a> {
    pub args: &'a InitializeConfigV1Args,
}

impl<'a> InitializeConfigV1<'a> {
    const SIZE: usize = InitializeConfigV1Args::SIZE;

    pub fn load(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }

        let args = unsafe { &*(data.as_ptr() as *const InitializeConfigV1Args) };

        Ok(Self { args })
    }
}

pub fn initialize_config_v1(
    ctx: Context<InitializeConfigV1Accounts>,
    data: &[u8],
) -> ProgramResult {
    msg!("initialize config v1");

    // Basic account validations
    check_system_owner(ctx.accounts.config, SwigError::OwnerMismatch("config"))?;
    check_zero_balance(ctx.accounts.config, SwigError::AccountNotEmpty("config"))?;

    // Parse instruction data
    let _initialize_config = InitializeConfigV1::load(data).map_err(|e| {
        msg!("InitializeConfigV1 Args Error: {:?}", e);
        msg!("Data length: {}", data.len());
        msg!("Expected size: {}", InitializeConfigV1::SIZE);
        msg!("Raw data: {:?}", data);
        ProgramError::InvalidInstructionData
    })?;

    msg!("Successfully loaded args");

    // Check that the provided config account matches the expected PDA
    let seeds = &config_seeds();
    let (expected_pda, bump) = pinocchio::pubkey::find_program_address(seeds, &crate::ID);

    // Check that provided account matches expected PDA
    if *ctx.accounts.config.key() != expected_pda {
        msg!("Provided config account does not match derived PDA");
        msg!("Expected: {:?}", expected_pda);
        msg!("Provided: {:?}", ctx.accounts.config.key());
        return Err(SwigError::InvalidPDA.into());
    }

    // Initialize the config account with the provided admin
    let config = GlobalConfig {
        admin: *ctx.accounts.admin.key(),
        padding: [0; 32],
    };

    msg!("config: {:?}", config);

    // Calculate space needed for the account
    let space_needed = core::mem::size_of::<GlobalConfig>();
    let lamports_needed = Rent::get()?.minimum_balance(space_needed);

    // Create the config account
    pinocchio_system::instructions::CreateAccount {
        from: ctx.accounts.payer,
        to: ctx.accounts.config,
        lamports: lamports_needed,
        space: space_needed as u64,
        owner: &crate::ID,
    }
    .invoke_signed(&[config_signer(&[bump]).as_slice().into()])?;

    // Write account data
    unsafe {
        ctx.accounts.config.borrow_mut_data_unchecked()[..space_needed]
            .copy_from_slice(bytemuck::bytes_of(&config));
    }

    msg!(
        "Global config initialized with admin: {:?}",
        ctx.accounts.admin.key()
    );
    Ok(())
}
