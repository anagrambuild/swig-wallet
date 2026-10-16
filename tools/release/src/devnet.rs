use std::{fs, path::Path, time::Duration};

use anyhow::{anyhow, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_loader_v3_interface::{instruction, state::UpgradeableLoaderState};
use solana_sdk::{
    account::Account,
    commitment_config::CommitmentConfig,
    hash::Hash,
    instruction::Instruction,
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    transaction::Transaction,
};
use solana_sdk_ids::{bpf_loader_upgradeable, system_program};
use solana_system_interface::MAX_PERMITTED_DATA_LENGTH;
use squads_multisig::{
    solana_rpc_client::nonblocking::rpc_client::RpcClient,
    solana_rpc_client_api::config::RpcSendTransactionConfig,
};

use crate::{
    accounts::{validate_buffer, validate_capacity, validate_program},
    config::DevnetConfig,
    proposal::validate_release_identity,
};

pub const DEVNET_GENESIS_HASH: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
// Same conservative upload/fee reserve as the mainnet preflight.
const UPLOAD_FEE_RESERVE: u64 = 100_000_000;
const PROGRAM_EXTENSION_INCREMENT: usize = 10_240;

#[derive(Deserialize, Serialize)]
pub struct DevnetCheckReceipt {
    pub program: Pubkey,
    pub authority: Pubkey,
    pub binary_bytes: usize,
    pub binary_sha256: String,
    pub program_capacity_bytes: usize,
    pub additional_program_bytes: u32,
    pub program_extension_rent_lamports: u64,
    pub buffer_rent_lamports: u64,
    pub minimum_authority_balance_lamports: u64,
}

#[derive(Serialize)]
pub struct ProgramExtensionReceipt {
    pub program: Pubkey,
    pub previous_capacity_bytes: usize,
    pub additional_bytes: u32,
    pub program_capacity_bytes: usize,
    pub signature: String,
}

pub struct DeploymentRequest {
    pub buffer: Pubkey,
    pub source_commit: String,
    pub tag: String,
}

#[derive(Serialize)]
pub struct DeploymentReceipt {
    pub program: Pubkey,
    pub authority: Pubkey,
    pub genesis_hash: String,
    pub source_commit: String,
    pub tag: String,
    pub binary_sha256: String,
    pub binary_bytes: usize,
    pub program_capacity_bytes: usize,
    pub buffer: String,
    pub signature: String,
}

pub fn required_program_extension(binary_len: usize, capacity: usize) -> Result<u32> {
    let maximum_capacity = usize::try_from(MAX_PERMITTED_DATA_LENGTH)?
        - UpgradeableLoaderState::size_of_programdata_metadata();
    ensure!(
        binary_len <= maximum_capacity && capacity <= maximum_capacity,
        "Program exceeds the loader-v3 account size limit"
    );
    let additional_bytes = binary_len
        .saturating_sub(capacity)
        .div_ceil(PROGRAM_EXTENSION_INCREMENT)
        * PROGRAM_EXTENSION_INCREMENT;
    ensure!(
        capacity + additional_bytes <= maximum_capacity,
        "Program expansion rounded to 10240 bytes would exceed the loader-v3 account size limit"
    );
    Ok(u32::try_from(additional_bytes)?)
}

pub async fn check(
    rpc: &RpcClient,
    config: &DevnetConfig,
    authority: &Keypair,
    binary: &[u8],
) -> Result<DevnetCheckReceipt> {
    let genesis = rpc
        .get_genesis_hash()
        .await
        .map_err(|_| anyhow!("Could not read the devnet genesis hash"))?;
    ensure!(
        genesis == DEVNET_GENESIS_HASH.parse::<Hash>()?,
        "SOLANA_RPC_URL must point to Solana devnet"
    );
    let program_data_address =
        Pubkey::find_program_address(&[config.program.as_ref()], &bpf_loader_upgradeable::id()).0;
    let fetched = rpc
        .get_multiple_accounts(&[config.program, program_data_address, authority.pubkey()])
        .await
        .map_err(|_| anyhow!("Could not read devnet upgrade accounts"))?;
    let mut accounts = fetched.into_iter();
    let program = accounts
        .next()
        .flatten()
        .context("Program account does not exist")?;
    let program_data = accounts
        .next()
        .flatten()
        .context("ProgramData account does not exist")?;
    let payer = accounts
        .next()
        .flatten()
        .context("Program authority account is unfunded")?;
    let capacity = validate_program(config.program, &program, &program_data, authority.pubkey())?;
    let additional_bytes = required_program_extension(binary.len(), capacity)?;
    ensure!(
        payer.owner == system_program::id() && payer.data.is_empty() && !payer.executable,
        "Program authority must be a funded System account"
    );
    let buffer_rent = rpc
        .get_minimum_balance_for_rent_exemption(UpgradeableLoaderState::size_of_buffer(
            binary.len(),
        ))
        .await
        .map_err(|_| anyhow!("Could not fetch buffer rent"))?;
    let extension_rent = if additional_bytes == 0 {
        0
    } else {
        rpc.get_minimum_balance_for_rent_exemption(UpgradeableLoaderState::size_of_programdata(
            capacity + usize::try_from(additional_bytes)?,
        ))
        .await
        .map_err(|_| anyhow!("Could not fetch expanded ProgramData rent"))?
        .saturating_sub(program_data.lamports)
    };
    let minimum_balance = buffer_rent
        .checked_add(extension_rent)
        .and_then(|rent| rent.checked_add(UPLOAD_FEE_RESERVE))
        // Keep the upload reserve intact after paying the extension fee.
        .and_then(|balance| {
            balance.checked_add(if additional_bytes == 0 { 0 } else { UPLOAD_FEE_RESERVE })
        })
        .context("Funding calculation overflow")?;
    ensure!(
        payer.lamports >= minimum_balance,
        "Program authority needs at least {minimum_balance} lamports for buffer rent, program \
         expansion rent and transaction fee reserves"
    );
    Ok(DevnetCheckReceipt {
        program: config.program,
        authority: authority.pubkey(),
        binary_bytes: binary.len(),
        binary_sha256: format!("{:x}", Sha256::digest(binary)),
        program_capacity_bytes: capacity,
        additional_program_bytes: additional_bytes,
        program_extension_rent_lamports: extension_rent,
        buffer_rent_lamports: buffer_rent,
        minimum_authority_balance_lamports: minimum_balance,
    })
}

pub fn validate_preflight(saved: &DevnetCheckReceipt, current: &DevnetCheckReceipt) -> Result<()> {
    ensure!(
        saved.program == current.program && saved.authority == current.authority,
        "Preflight deployment or authority does not match the current configuration"
    );
    ensure!(
        saved.binary_bytes == current.binary_bytes && saved.binary_sha256 == current.binary_sha256,
        "Preflight binary does not match the current binary"
    );
    ensure!(
        saved.program_capacity_bytes <= current.program_capacity_bytes,
        "Program capacity changed after preflight"
    );
    Ok(())
}

pub async fn ensure_capacity(
    rpc: &RpcClient,
    config: &DevnetConfig,
    authority: &Keypair,
    binary: &[u8],
    saved: &DevnetCheckReceipt,
    output_dir: &Path,
) -> Result<Option<ProgramExtensionReceipt>> {
    // Recompute from live accounts: another permissionless extension may have
    // already supplied some or all of the capacity since preflight.
    let current = check(rpc, config, authority, binary).await?;
    validate_preflight(saved, &current)?;
    eprintln!(
        "Devnet capacity: binary={} allocated={} additional={} expansion_rent={}",
        current.binary_bytes,
        current.program_capacity_bytes,
        current.additional_program_bytes,
        current.program_extension_rent_lamports
    );
    if current.additional_program_bytes == 0 {
        return Ok(None);
    }
    let extend = instruction::extend_program(
        &config.program,
        Some(&authority.pubkey()),
        current.additional_program_bytes,
    );
    let signature = send_and_confirm(
        rpc,
        authority,
        extend,
        DevnetTransaction::Extension,
        output_dir,
    )
    .await?;
    // Confirm separately from the upgrade and verify allocation and remaining
    // upload funds before creating a buffer.
    let expanded = check(rpc, config, authority, binary).await?;
    ensure!(
        expanded.program_capacity_bytes
            >= current.program_capacity_bytes + usize::try_from(current.additional_program_bytes)?,
        "Program expansion {signature} confirmed, but the allocated capacity is below the target"
    );
    validate_capacity(binary.len(), expanded.program_capacity_bytes)?;
    Ok(Some(ProgramExtensionReceipt {
        program: config.program,
        previous_capacity_bytes: current.program_capacity_bytes,
        additional_bytes: current.additional_program_bytes,
        program_capacity_bytes: expanded.program_capacity_bytes,
        signature: signature.to_string(),
    }))
}

pub fn validate_deployed_binary(program_data: &Account, binary: &[u8]) -> Result<()> {
    let payload = program_data
        .data
        .get(UpgradeableLoaderState::size_of_programdata_metadata()..)
        .context("Truncated deployed ProgramData account")?;
    ensure!(
        payload.starts_with(binary)
            && payload
                .get(binary.len()..)
                .is_some_and(|padding| padding.iter().all(|byte| *byte == 0)),
        "Deployed program bytes do not match the release binary"
    );
    Ok(())
}

pub async fn deploy(
    rpc: &RpcClient,
    config: &DevnetConfig,
    authority: &Keypair,
    binary: &[u8],
    request: DeploymentRequest,
    output_dir: &Path,
) -> Result<DeploymentReceipt> {
    validate_release_identity(&request.source_commit, &request.tag)?;
    let genesis = rpc
        .get_genesis_hash()
        .await
        .map_err(|_| anyhow!("Could not read the devnet genesis hash"))?;
    ensure!(
        genesis == DEVNET_GENESIS_HASH.parse::<Hash>()?,
        "SOLANA_RPC_URL must point to Solana devnet"
    );
    let program_data_address =
        Pubkey::find_program_address(&[config.program.as_ref()], &bpf_loader_upgradeable::id()).0;
    let fetched = rpc
        .get_multiple_accounts(&[config.program, program_data_address, request.buffer])
        .await
        .map_err(|_| anyhow!("Could not read devnet deployment accounts"))?;
    let mut accounts = fetched.into_iter();
    let program = accounts
        .next()
        .flatten()
        .context("Program account does not exist")?;
    let program_data = accounts
        .next()
        .flatten()
        .context("ProgramData account does not exist")?;
    let buffer = accounts
        .next()
        .flatten()
        .context("Upload buffer does not exist")?;
    let capacity = validate_program(config.program, &program, &program_data, authority.pubkey())?;
    validate_capacity(binary.len(), capacity)?;
    validate_buffer(&buffer, binary, authority.pubkey())?;
    let buffer_rent = rpc
        .get_minimum_balance_for_rent_exemption(buffer.data.len())
        .await
        .map_err(|_| anyhow!("Could not fetch buffer rent"))?;
    ensure!(buffer.lamports >= buffer_rent, "Buffer must be rent exempt");

    // The authority signs directly and receives the reclaimed buffer rent.
    let upgrade = instruction::upgrade(
        &config.program,
        &request.buffer,
        &authority.pubkey(),
        &authority.pubkey(),
    );
    eprintln!("Devnet upgrade buffer={}", request.buffer);
    let signature = send_and_confirm(
        rpc,
        authority,
        upgrade,
        DevnetTransaction::Upgrade,
        output_dir,
    )
    .await?;
    let fetched = rpc
        .get_multiple_accounts(&[config.program, program_data_address])
        .await
        .map_err(|_| {
            anyhow!("Upgrade {signature} confirmed, but could not read deployed accounts")
        })?;
    let mut accounts = fetched.into_iter();
    let program = accounts
        .next()
        .flatten()
        .context("Deployed program account is missing")?;
    let program_data = accounts
        .next()
        .flatten()
        .context("Deployed ProgramData account is missing")?;
    let capacity = validate_program(config.program, &program, &program_data, authority.pubkey())?;
    validate_deployed_binary(&program_data, binary)?;
    Ok(DeploymentReceipt {
        program: config.program,
        authority: authority.pubkey(),
        genesis_hash: genesis.to_string(),
        source_commit: request.source_commit,
        tag: request.tag,
        binary_sha256: format!("{:x}", Sha256::digest(binary)),
        binary_bytes: binary.len(),
        program_capacity_bytes: capacity,
        buffer: request.buffer.to_string(),
        signature: signature.to_string(),
    })
}

// Both devnet mutations preserve the signed transaction identifier before
// submission and wait for confirmed status before the next operation.
enum DevnetTransaction {
    Extension,
    Upgrade,
}

async fn send_and_confirm(
    rpc: &RpcClient,
    authority: &Keypair,
    instruction: Instruction,
    operation: DevnetTransaction,
    output_dir: &Path,
) -> Result<Signature> {
    let (operation, signature_file) = match operation {
        DevnetTransaction::Extension => ("Program expansion", "extension-signature.txt"),
        DevnetTransaction::Upgrade => ("Upgrade", "transaction-signature.txt"),
    };
    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|_| anyhow!("Could not fetch a recent blockhash"))?;
    let message =
        Message::new_with_blockhash(&[instruction], Some(&authority.pubkey()), &blockhash);
    let mut transaction = Transaction::new_unsigned(message);
    transaction.try_sign(&[authority], blockhash)?;
    let signature = *transaction
        .signatures
        .first()
        .context("Missing transaction signature")?;
    // Persist the public identifier before submission, including unknown outcomes.
    fs::write(output_dir.join(signature_file), format!("{signature}\n"))
        .context("Could not save transaction signature")?;
    eprintln!("Submitting devnet {operation} {signature}");
    let returned = rpc
        .send_transaction_with_config(
            &transaction,
            RpcSendTransactionConfig {
                skip_preflight: false,
                preflight_commitment: Some(CommitmentConfig::confirmed().commitment),
                max_retries: Some(0),
                ..RpcSendTransactionConfig::default()
            },
        )
        .await
        .map_err(|_| {
            anyhow!(
                "{operation} submission failed or is uncertain; inspect transaction {signature} \
                 and the public recovery files before retrying"
            )
        })?;
    ensure!(
        returned == signature,
        "RPC returned an unexpected {operation} signature; inspect {signature}"
    );
    let mut confirmed = false;
    for _ in 0..60 {
        match rpc
            .get_signature_status_with_commitment_and_history(
                &signature,
                CommitmentConfig::confirmed(),
                true,
            )
            .await
            .map_err(|_| {
                anyhow!("{operation} confirmation is uncertain; inspect transaction {signature}")
            })? {
            Some(Ok(())) => {
                confirmed = true;
                break;
            },
            Some(Err(_)) => anyhow::bail!(
                "{operation} transaction {signature} failed on-chain; inspect the public recovery files"
            ),
            None => tokio::time::sleep(Duration::from_secs(2)).await,
        }
    }
    ensure!(
        confirmed,
        "{operation} confirmation timed out; inspect transaction {signature} before retrying"
    );
    Ok(signature)
}
