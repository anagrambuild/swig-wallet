use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};
use solana_system_interface::{instruction as system_instruction, program as system_program};

use crate::{
    error::RecoveryError,
    instruction::{
        find_pending_recovery_address, find_recovery_config_address,
        CANCEL_RECOVERY_V1_DISCRIMINATOR, CONFIGURE_RECOVERY_V1_DISCRIMINATOR,
        EXECUTE_RECOVERY_V1_DISCRIMINATOR, PENDING_RECOVERY_SEED, RECOVERY_CONFIG_SEED,
        START_RECOVERY_V1_DISCRIMINATOR,
    },
    state::{
        hash_authority, PendingRecoveryV1, RecoveryConfigV1, PENDING_RECOVERY_STATUS_CANCELLED,
        PENDING_RECOVERY_STATUS_EXECUTED, PENDING_RECOVERY_STATUS_PENDING, PENDING_RECOVERY_V1_LEN,
        RECOVERY_CONFIG_V1_LEN,
    },
};

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let discriminator: [u8; 8] = instruction_data
        .get(..8)
        .ok_or(RecoveryError::InvalidInstruction)?
        .try_into()
        .map_err(|_| RecoveryError::InvalidInstruction)?;
    let data = &instruction_data[8..];

    match discriminator {
        CONFIGURE_RECOVERY_V1_DISCRIMINATOR => {
            process_configure_recovery_v1(program_id, accounts, data)
        },
        START_RECOVERY_V1_DISCRIMINATOR => process_start_recovery_v1(program_id, accounts, data),
        CANCEL_RECOVERY_V1_DISCRIMINATOR => process_cancel_recovery_v1(program_id, accounts, data),
        EXECUTE_RECOVERY_V1_DISCRIMINATOR => {
            process_execute_recovery_v1(program_id, accounts, data)
        },
        _ => Err(RecoveryError::InvalidInstruction.into()),
    }
}

fn process_configure_recovery_v1(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != 32 + 4 + 32 + 8 {
        return Err(RecoveryError::InvalidInstruction.into());
    }

    let account_info_iter = &mut accounts.iter();
    let payer = next_account_info(account_info_iter)?;
    let config_account = next_account_info(account_info_iter)?;
    let operator = next_account_info(account_info_iter)?;
    let swig_wallet = next_account_info(account_info_iter)?;
    let system_program_account = next_account_info(account_info_iter)?;

    require_signer(payer)?;
    require_signer(operator)?;
    require_system_program(system_program_account)?;

    let org_config = read_pubkey(data, 0)?;
    let target_role_id = read_u32(data, 32)?;
    let guardian = read_pubkey(data, 36)?;
    let delay_slots = read_u64(data, 68)?;

    let (expected_config, bump) = find_recovery_config_address(program_id, swig_wallet.key);
    if config_account.key != &expected_config {
        return Err(RecoveryError::InvalidPda.into());
    }

    create_pda_if_needed(
        program_id,
        payer,
        config_account,
        system_program_account,
        RECOVERY_CONFIG_V1_LEN,
        &[RECOVERY_CONFIG_SEED, swig_wallet.key.as_ref(), &[bump]],
    )?;
    require_owned(config_account, program_id)?;

    let config = RecoveryConfigV1 {
        org_config,
        swig_wallet: *swig_wallet.key,
        target_role_id,
        guardian,
        delay_slots,
        bump,
    };
    config.pack(&mut config_account.try_borrow_mut_data()?)?;

    msg!("Swig recovery configured");
    Ok(())
}

fn process_start_recovery_v1(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != 33 + 33 {
        return Err(RecoveryError::InvalidInstruction.into());
    }

    let account_info_iter = &mut accounts.iter();
    let payer = next_account_info(account_info_iter)?;
    let guardian = next_account_info(account_info_iter)?;
    let config_account = next_account_info(account_info_iter)?;
    let pending_account = next_account_info(account_info_iter)?;
    let system_program_account = next_account_info(account_info_iter)?;

    require_signer(payer)?;
    require_signer(guardian)?;
    require_owned(config_account, program_id)?;
    require_system_program(system_program_account)?;

    let old_authority = read_authority(data, 0)?;
    let new_authority = read_authority(data, 33)?;
    let config = RecoveryConfigV1::unpack(&config_account.try_borrow_data()?)?;

    let (expected_config, _) = find_recovery_config_address(program_id, &config.swig_wallet);
    if config_account.key != &expected_config {
        return Err(RecoveryError::InvalidPda.into());
    }
    if guardian.key != &config.guardian {
        return Err(RecoveryError::GuardianMismatch.into());
    }

    let (expected_pending, bump) =
        find_pending_recovery_address(program_id, &config.swig_wallet, config.target_role_id);
    if pending_account.key != &expected_pending {
        return Err(RecoveryError::InvalidPda.into());
    }

    create_pda_if_needed(
        program_id,
        payer,
        pending_account,
        system_program_account,
        PENDING_RECOVERY_V1_LEN,
        &[
            PENDING_RECOVERY_SEED,
            config.swig_wallet.as_ref(),
            &config.target_role_id.to_le_bytes(),
            &[bump],
        ],
    )?;
    require_owned(pending_account, program_id)?;
    reject_existing_pending(pending_account)?;

    let clock = Clock::get()?;
    let pending = PendingRecoveryV1 {
        org_config: config.org_config,
        swig_wallet: config.swig_wallet,
        target_role_id: config.target_role_id,
        guardian: config.guardian,
        old_authority_hash: hash_authority(&old_authority),
        new_authority_hash: hash_authority(&new_authority),
        start_slot: clock.slot,
        executable_after_slot: clock
            .slot
            .checked_add(config.delay_slots)
            .ok_or(RecoveryError::InvalidInstruction)?,
        status: PENDING_RECOVERY_STATUS_PENDING,
        bump,
    };
    pending.pack(&mut pending_account.try_borrow_mut_data()?)?;

    msg!("Swig recovery started");
    Ok(())
}

fn process_cancel_recovery_v1(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if !data.is_empty() {
        return Err(RecoveryError::InvalidInstruction.into());
    }

    let account_info_iter = &mut accounts.iter();
    let swig_wallet = next_account_info(account_info_iter)?;
    let pending_account = next_account_info(account_info_iter)?;

    require_signer(swig_wallet)?;
    require_owned(pending_account, program_id)?;

    let mut pending = PendingRecoveryV1::unpack(&pending_account.try_borrow_data()?)?;
    if pending.swig_wallet != *swig_wallet.key {
        return Err(RecoveryError::WalletMismatch.into());
    }
    require_pending(&pending)?;

    pending.status = PENDING_RECOVERY_STATUS_CANCELLED;
    pending.pack(&mut pending_account.try_borrow_mut_data()?)?;

    msg!("Swig recovery cancelled");
    Ok(())
}

fn process_execute_recovery_v1(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != 33 + 33 {
        return Err(RecoveryError::InvalidInstruction.into());
    }

    let account_info_iter = &mut accounts.iter();
    let _swig_config = next_account_info(account_info_iter)?;
    let swig_wallet = next_account_info(account_info_iter)?;
    let pending_account = next_account_info(account_info_iter)?;

    require_owned(pending_account, program_id)?;

    let old_authority = read_authority(data, 0)?;
    let new_authority = read_authority(data, 33)?;
    let mut pending = PendingRecoveryV1::unpack(&pending_account.try_borrow_data()?)?;

    if pending.swig_wallet != *swig_wallet.key {
        return Err(RecoveryError::WalletMismatch.into());
    }
    require_pending(&pending)?;
    if Clock::get()?.slot < pending.executable_after_slot {
        return Err(RecoveryError::TimelockNotElapsed.into());
    }
    if hash_authority(&old_authority) != pending.old_authority_hash {
        return Err(RecoveryError::OldAuthorityMismatch.into());
    }
    if hash_authority(&new_authority) != pending.new_authority_hash {
        return Err(RecoveryError::NewAuthorityMismatch.into());
    }

    pending.status = PENDING_RECOVERY_STATUS_EXECUTED;
    pending.pack(&mut pending_account.try_borrow_mut_data()?)?;

    msg!("Swig recovery executed");
    Ok(())
}

fn reject_existing_pending(pending_account: &AccountInfo) -> ProgramResult {
    let data = pending_account.try_borrow_data()?;
    let Ok(pending) = PendingRecoveryV1::unpack(&data) else {
        return Ok(());
    };
    if pending.status == PENDING_RECOVERY_STATUS_PENDING {
        return Err(RecoveryError::AlreadyPending.into());
    }
    Ok(())
}

fn require_pending(pending: &PendingRecoveryV1) -> ProgramResult {
    if pending.status == PENDING_RECOVERY_STATUS_PENDING {
        return Ok(());
    }
    if pending.status == PENDING_RECOVERY_STATUS_CANCELLED
        || pending.status == PENDING_RECOVERY_STATUS_EXECUTED
    {
        return Err(RecoveryError::NotPending.into());
    }
    Err(RecoveryError::InvalidState.into())
}

fn create_pda_if_needed<'a>(
    program_id: &Pubkey,
    payer: &AccountInfo<'a>,
    pda: &AccountInfo<'a>,
    system_program_account: &AccountInfo<'a>,
    space: usize,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    if !pda.data_is_empty() {
        return Ok(());
    }

    let lamports = Rent::get()?.minimum_balance(space);
    invoke_signed(
        &system_instruction::create_account(payer.key, pda.key, lamports, space as u64, program_id),
        &[payer.clone(), pda.clone(), system_program_account.clone()],
        &[signer_seeds],
    )
}

fn require_signer(account: &AccountInfo) -> ProgramResult {
    if account.is_signer {
        return Ok(());
    }
    Err(RecoveryError::MissingRequiredSignature.into())
}

fn require_owned(account: &AccountInfo, owner: &Pubkey) -> ProgramResult {
    if account.owner == owner {
        return Ok(());
    }
    Err(RecoveryError::InvalidAccount.into())
}

fn require_system_program(account: &AccountInfo) -> ProgramResult {
    if account.key == &system_program::id() {
        return Ok(());
    }
    Err(RecoveryError::InvalidAccount.into())
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, ProgramError> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or(RecoveryError::InvalidInstruction)?
        .try_into()
        .map_err(|_| RecoveryError::InvalidInstruction)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, ProgramError> {
    let bytes: [u8; 8] = data
        .get(offset..offset + 8)
        .ok_or(RecoveryError::InvalidInstruction)?
        .try_into()
        .map_err(|_| RecoveryError::InvalidInstruction)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_pubkey(data: &[u8], offset: usize) -> Result<Pubkey, ProgramError> {
    let bytes: [u8; 32] = data
        .get(offset..offset + 32)
        .ok_or(RecoveryError::InvalidInstruction)?
        .try_into()
        .map_err(|_| RecoveryError::InvalidInstruction)?;
    Ok(Pubkey::new_from_array(bytes))
}

fn read_authority(data: &[u8], offset: usize) -> Result<[u8; 33], ProgramError> {
    data.get(offset..offset + 33)
        .ok_or(RecoveryError::InvalidInstruction)?
        .try_into()
        .map_err(|_| RecoveryError::InvalidInstruction.into())
}
