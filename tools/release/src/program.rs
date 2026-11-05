use std::{fs, path::Path, time::Duration};

use anyhow::{anyhow, ensure, Context, Result};
use serde::Serialize;
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::Instruction,
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    transaction::Transaction,
};
use solana_system_interface::MAX_PERMITTED_DATA_LENGTH;
use squads_multisig::{
    solana_rpc_client::nonblocking::rpc_client::RpcClient,
    solana_rpc_client_api::config::RpcSendTransactionConfig,
};

const PROGRAM_EXTENSION_INCREMENT: usize = 10_240;

#[derive(Serialize)]
pub struct ProgramExtensionReceipt {
    pub program: Pubkey,
    pub previous_capacity_bytes: usize,
    pub additional_bytes: u32,
    pub program_capacity_bytes: usize,
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

// Preserve the signed transaction identifier before submission and wait for
// confirmed status before the next operation.
pub(crate) enum ProgramTransaction {
    Extension,
    Upgrade,
}

pub(crate) async fn send_and_confirm(
    rpc: &RpcClient,
    authority: &Keypair,
    instruction: Instruction,
    operation: ProgramTransaction,
    output_dir: &Path,
) -> Result<Signature> {
    let (operation, signature_file) = match operation {
        ProgramTransaction::Extension => ("Program expansion", "extension-signature.txt"),
        ProgramTransaction::Upgrade => ("Upgrade", "transaction-signature.txt"),
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
    eprintln!("Submitting {operation} {signature}");
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
