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
use solana_sdk_ids::bpf_loader_upgradeable;
use solana_system_interface::{instruction as system_instruction, program as system_program};

use crate::{
    error::RecoveryError,
    instruction::{
        find_operator_config_address, find_pending_recovery_address, find_recovery_config_address,
        CANCEL_RECOVERY_V1_DISCRIMINATOR, CONFIGURE_RECOVERY_V1_DISCRIMINATOR,
        EXECUTE_RECOVERY_V1_DISCRIMINATOR, OPERATOR_CONFIG_SEED, PENDING_RECOVERY_SEED,
        RECOVERY_CONFIG_SEED, SET_OPERATOR_V1_DISCRIMINATOR, START_RECOVERY_V1_DISCRIMINATOR,
    },
    state::{
        hash_authority, OperatorConfigV1, PendingRecoveryV1, RecoveryConfigV1,
        OPERATOR_CONFIG_V1_LEN, PENDING_RECOVERY_STATUS_CANCELLED,
        PENDING_RECOVERY_STATUS_EXECUTED, PENDING_RECOVERY_STATUS_PENDING, PENDING_RECOVERY_V1_LEN,
        RECOVERY_CONFIG_V1_LEN,
    },
};

const UPGRADEABLE_LOADER_PROGRAMDATA_TAG: u32 = 3;
const PROGRAMDATA_UPGRADE_AUTHORITY_OPTION_OFFSET: usize = 12;
const PROGRAMDATA_UPGRADE_AUTHORITY_OFFSET: usize = 13;
const PROGRAMDATA_WITH_AUTHORITY_LEN: usize = PROGRAMDATA_UPGRADE_AUTHORITY_OFFSET + 32;
const RECOVERY_AUTHORITY_DATA_HEADER_LEN: usize = 2 + 2 + 2;
const MAX_RECOVERY_AUTHORITY_LEN: usize = 64;

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
        SET_OPERATOR_V1_DISCRIMINATOR => process_set_operator_v1(program_id, accounts, data),
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

fn process_set_operator_v1(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != 32 {
        return Err(RecoveryError::InvalidInstruction.into());
    }

    let account_info_iter = &mut accounts.iter();
    let payer = next_account_info(account_info_iter)?;
    let operator_config_account = next_account_info(account_info_iter)?;
    let admin = next_account_info(account_info_iter)?;
    let program_data = next_account_info(account_info_iter)?;
    let system_program_account = next_account_info(account_info_iter)?;

    require_signer(payer)?;
    require_system_program(system_program_account)?;
    require_program_upgrade_authority(program_id, admin, program_data)?;

    let operator = read_pubkey(data, 0)?;
    let (expected_operator_config, bump) = find_operator_config_address(program_id);
    if operator_config_account.key != &expected_operator_config {
        return Err(RecoveryError::InvalidPda.into());
    }

    create_pda_if_needed(
        program_id,
        payer,
        operator_config_account,
        system_program_account,
        OPERATOR_CONFIG_V1_LEN,
        &[OPERATOR_CONFIG_SEED, &[bump]],
    )?;
    require_owned(operator_config_account, program_id)?;

    let config = OperatorConfigV1 { operator, bump };
    config.pack(&mut operator_config_account.try_borrow_mut_data()?)?;

    msg!("Swig recovery operator set");
    Ok(())
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
    let operator_config_account = next_account_info(account_info_iter)?;
    let operator = next_account_info(account_info_iter)?;
    let swig_wallet = next_account_info(account_info_iter)?;
    let system_program_account = next_account_info(account_info_iter)?;

    require_signer(payer)?;
    require_signer(operator)?;
    require_operator(program_id, operator_config_account, operator)?;
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

fn require_operator(
    program_id: &Pubkey,
    operator_config_account: &AccountInfo,
    operator: &AccountInfo,
) -> ProgramResult {
    require_owned(operator_config_account, program_id)?;

    let (expected_operator_config, _) = find_operator_config_address(program_id);
    if operator_config_account.key != &expected_operator_config {
        return Err(RecoveryError::InvalidPda.into());
    }

    let operator_config = OperatorConfigV1::unpack(&operator_config_account.try_borrow_data()?)?;
    if operator_config.operator != *operator.key {
        return Err(RecoveryError::OperatorMismatch.into());
    }

    Ok(())
}

fn require_program_upgrade_authority(
    program_id: &Pubkey,
    admin: &AccountInfo,
    program_data: &AccountInfo,
) -> ProgramResult {
    require_signer(admin)?;

    let (expected_program_data, _) =
        Pubkey::find_program_address(&[program_id.as_ref()], &bpf_loader_upgradeable::id());
    if program_data.key != &expected_program_data {
        return Err(RecoveryError::InvalidProgramData.into());
    }
    if program_data.owner != &bpf_loader_upgradeable::id() {
        return Err(RecoveryError::InvalidProgramData.into());
    }

    let data = program_data.try_borrow_data()?;
    if data.len() < PROGRAMDATA_WITH_AUTHORITY_LEN {
        return Err(RecoveryError::InvalidProgramData.into());
    }

    let tag = u32::from_le_bytes(
        data.get(0..4)
            .ok_or(RecoveryError::InvalidProgramData)?
            .try_into()
            .map_err(|_| RecoveryError::InvalidProgramData)?,
    );
    if tag != UPGRADEABLE_LOADER_PROGRAMDATA_TAG {
        return Err(RecoveryError::InvalidProgramData.into());
    }

    let authority_is_some = data
        .get(PROGRAMDATA_UPGRADE_AUTHORITY_OPTION_OFFSET)
        .copied()
        .ok_or(RecoveryError::InvalidProgramData)?;
    if authority_is_some != 1 {
        return Err(RecoveryError::AdminMismatch.into());
    }

    let authority = data
        .get(PROGRAMDATA_UPGRADE_AUTHORITY_OFFSET..PROGRAMDATA_WITH_AUTHORITY_LEN)
        .ok_or(RecoveryError::InvalidProgramData)?;
    if authority != admin.key.as_ref() {
        return Err(RecoveryError::AdminMismatch.into());
    }

    Ok(())
}

fn process_start_recovery_v1(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let authority_data = parse_recovery_authority_data(data)?;

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
        old_authority_hash: hash_authority(authority_data.old_authority),
        new_authority_hash: hash_authority(authority_data.new_authority),
        start_slot: clock.slot,
        executable_after_slot: clock
            .slot
            .checked_add(config.delay_slots)
            .ok_or(RecoveryError::InvalidInstruction)?,
        status: PENDING_RECOVERY_STATUS_PENDING,
        bump,
        authority_type: authority_data.authority_type,
        old_authority_len: authority_data.old_authority.len() as u16,
        new_authority_len: authority_data.new_authority.len() as u16,
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
    let authority_data = parse_recovery_authority_data(data)?;

    let account_info_iter = &mut accounts.iter();
    let _swig_config = next_account_info(account_info_iter)?;
    let swig_wallet = next_account_info(account_info_iter)?;
    let pending_account = next_account_info(account_info_iter)?;

    require_owned(pending_account, program_id)?;

    let mut pending = PendingRecoveryV1::unpack(&pending_account.try_borrow_data()?)?;

    if pending.swig_wallet != *swig_wallet.key {
        return Err(RecoveryError::WalletMismatch.into());
    }
    require_pending(&pending)?;
    if Clock::get()?.slot < pending.executable_after_slot {
        return Err(RecoveryError::TimelockNotElapsed.into());
    }
    if authority_data.authority_type != pending.authority_type {
        return Err(RecoveryError::InvalidInstruction.into());
    }
    if authority_data.old_authority.len() as u16 != pending.old_authority_len {
        return Err(RecoveryError::OldAuthorityMismatch.into());
    }
    if authority_data.new_authority.len() as u16 != pending.new_authority_len {
        return Err(RecoveryError::NewAuthorityMismatch.into());
    }
    if hash_authority(authority_data.old_authority) != pending.old_authority_hash {
        return Err(RecoveryError::OldAuthorityMismatch.into());
    }
    if hash_authority(authority_data.new_authority) != pending.new_authority_hash {
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

fn read_u16(data: &[u8], offset: usize) -> Result<u16, ProgramError> {
    let bytes: [u8; 2] = data
        .get(offset..offset + 2)
        .ok_or(RecoveryError::InvalidInstruction)?
        .try_into()
        .map_err(|_| RecoveryError::InvalidInstruction)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_pubkey(data: &[u8], offset: usize) -> Result<Pubkey, ProgramError> {
    let bytes: [u8; 32] = data
        .get(offset..offset + 32)
        .ok_or(RecoveryError::InvalidInstruction)?
        .try_into()
        .map_err(|_| RecoveryError::InvalidInstruction)?;
    Ok(Pubkey::new_from_array(bytes))
}

struct RecoveryAuthorityData<'a> {
    authority_type: u16,
    old_authority: &'a [u8],
    new_authority: &'a [u8],
}

fn parse_recovery_authority_data(data: &[u8]) -> Result<RecoveryAuthorityData<'_>, ProgramError> {
    if data.len() < RECOVERY_AUTHORITY_DATA_HEADER_LEN {
        return Err(RecoveryError::InvalidInstruction.into());
    }

    let authority_type = read_u16(data, 0)?;
    let old_authority_len = read_u16(data, 2)? as usize;
    let new_authority_len = read_u16(data, 4)? as usize;
    if old_authority_len == 0
        || old_authority_len > MAX_RECOVERY_AUTHORITY_LEN
        || new_authority_len == 0
        || new_authority_len > MAX_RECOVERY_AUTHORITY_LEN
    {
        return Err(RecoveryError::InvalidInstruction.into());
    }

    let old_start = RECOVERY_AUTHORITY_DATA_HEADER_LEN;
    let new_start = old_start
        .checked_add(old_authority_len)
        .ok_or(RecoveryError::InvalidInstruction)?;
    let expected_len = new_start
        .checked_add(new_authority_len)
        .ok_or(RecoveryError::InvalidInstruction)?;
    if data.len() != expected_len {
        return Err(RecoveryError::InvalidInstruction.into());
    }

    let old_authority = data
        .get(old_start..new_start)
        .ok_or(RecoveryError::InvalidInstruction)?;
    let new_authority = data
        .get(new_start..expected_len)
        .ok_or(RecoveryError::InvalidInstruction)?;

    Ok(RecoveryAuthorityData {
        authority_type,
        old_authority,
        new_authority,
    })
}
