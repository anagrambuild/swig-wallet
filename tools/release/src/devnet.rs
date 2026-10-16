use std::{fs, path::Path, time::Duration};

use anyhow::{anyhow, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_loader_v3_interface::{instruction, state::UpgradeableLoaderState};
use solana_sdk::{
    account::Account,
    commitment_config::CommitmentConfig,
    hash::Hash,
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use solana_sdk_ids::{bpf_loader_upgradeable, system_program};
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

#[derive(Deserialize, Serialize)]
pub struct DevnetCheckReceipt {
    pub program: Pubkey,
    pub authority: Pubkey,
    pub binary_bytes: usize,
    pub binary_sha256: String,
    pub program_capacity_bytes: usize,
    pub buffer_rent_lamports: u64,
    pub minimum_authority_balance_lamports: u64,
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
    pub buffer: String,
    pub signature: String,
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
    // Match mainnet: extend the program separately, before starting a release.
    validate_capacity(binary.len(), capacity)?;
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
    let minimum_balance = buffer_rent
        .checked_add(UPLOAD_FEE_RESERVE)
        .context("Funding calculation overflow")?;
    ensure!(
        payer.lamports >= minimum_balance,
        "Program authority needs at least {minimum_balance} lamports for buffer rent and upload \
         fee reserve"
    );
    Ok(DevnetCheckReceipt {
        program: config.program,
        authority: authority.pubkey(),
        binary_bytes: binary.len(),
        binary_sha256: format!("{:x}", Sha256::digest(binary)),
        program_capacity_bytes: capacity,
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
        saved.program_capacity_bytes == current.program_capacity_bytes,
        "Program capacity changed after preflight"
    );
    Ok(())
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
    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|_| anyhow!("Could not fetch a recent blockhash"))?;
    let message = Message::new_with_blockhash(&[upgrade], Some(&authority.pubkey()), &blockhash);
    let mut transaction = Transaction::new_unsigned(message);
    transaction.try_sign(&[authority], blockhash)?;
    let signature = *transaction
        .signatures
        .first()
        .context("Missing upgrade signature")?;
    // Persist the public identifier before submission, including unknown outcomes.
    fs::write(
        output_dir.join("transaction-signature.txt"),
        format!("{signature}\n"),
    )
    .context("Could not save upgrade transaction signature")?;
    eprintln!(
        "Submitting devnet upgrade {signature}; buffer={}",
        request.buffer
    );
    let returned = rpc
        .send_transaction_with_config(
            &transaction,
            RpcSendTransactionConfig {
                skip_preflight: false,
                preflight_commitment: Some(CommitmentConfig::finalized().commitment),
                max_retries: Some(0),
                ..RpcSendTransactionConfig::default()
            },
        )
        .await
        .map_err(|_| {
            anyhow!(
                "Upgrade submission failed or is uncertain; inspect transaction {signature} and \
                 buffer {} before retrying",
                request.buffer
            )
        })?;
    ensure!(
        returned == signature,
        "RPC returned an unexpected upgrade signature; inspect {signature}"
    );
    let mut finalized = false;
    for _ in 0..60 {
        match rpc
            .get_signature_status_with_commitment_and_history(
                &signature,
                CommitmentConfig::finalized(),
                true,
            )
            .await
            .map_err(|_| {
                anyhow!("Upgrade confirmation is uncertain; inspect transaction {signature}")
            })? {
            Some(Ok(())) => {
                finalized = true;
                break;
            },
            Some(Err(_)) => anyhow::bail!(
                "Upgrade transaction {signature} failed on-chain; the authority retains the \
                 buffer for recovery"
            ),
            None => tokio::time::sleep(Duration::from_secs(2)).await,
        }
    }
    ensure!(
        finalized,
        "Upgrade confirmation timed out; inspect transaction {signature} before retrying"
    );
    let fetched = rpc
        .get_multiple_accounts(&[config.program, program_data_address])
        .await
        .map_err(|_| {
            anyhow!("Upgrade {signature} finalized, but could not read deployed accounts")
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
    validate_program(config.program, &program, &program_data, authority.pubkey())?;
    validate_deployed_binary(&program_data, binary)?;
    Ok(DeploymentReceipt {
        program: config.program,
        authority: authority.pubkey(),
        genesis_hash: genesis.to_string(),
        source_commit: request.source_commit,
        tag: request.tag,
        binary_sha256: format!("{:x}", Sha256::digest(binary)),
        binary_bytes: binary.len(),
        buffer: request.buffer.to_string(),
        signature: signature.to_string(),
    })
}
