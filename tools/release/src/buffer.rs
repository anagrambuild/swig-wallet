use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

use anyhow::{anyhow, ensure, Context, Result};
use serde::Serialize;
use solana_loader_v3_interface::instruction;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    hash::Hash,
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use squads_multisig::{
    solana_rpc_client::nonblocking::rpc_client::RpcClient,
    solana_rpc_client_api::config::RpcSendTransactionConfig,
};
use zeroize::Zeroizing;

use crate::{
    accounts::validate_buffer_authority,
    devnet::DEVNET_GENESIS_HASH,
    ottersec::{Cluster, MAINNET_GENESIS_HASH},
};

#[serde_with::serde_as]
#[derive(Serialize)]
pub struct BufferCloseReceipt {
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub buffer: Pubkey,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub authority_and_recipient: Pubkey,
    pub genesis_hash: String,
    /// Observed before submission; the loader refunds the entire balance at
    /// execution. The authority also pays the transaction fee.
    pub lamports_before_close: u64,
    pub signature: String,
}

/// Close one signer-controlled buffer. Never accepts a separate refund
/// recipient or closes program accounts, even if the signer controls them.
pub async fn close_buffer(
    rpc: &RpcClient,
    cluster: Cluster,
    buffer: Pubkey,
    authority: &Keypair,
    output_dir: &Path,
) -> Result<BufferCloseReceipt> {
    ensure!(
        buffer != authority.pubkey(),
        "Buffer cannot be the refund recipient"
    );
    fs::create_dir(output_dir)
        .context("Output directory must be new; inspect any earlier attempt before retrying")?;
    let expected_genesis = match cluster {
        Cluster::Mainnet => MAINNET_GENESIS_HASH,
        Cluster::Devnet => DEVNET_GENESIS_HASH,
    };
    let genesis = rpc
        .get_genesis_hash()
        .await
        .map_err(|_| anyhow!("Could not read cluster genesis hash"))?;
    ensure!(
        genesis == expected_genesis.parse::<Hash>()?,
        "RPC network does not match selected cluster"
    );
    let account = rpc
        .get_account_with_commitment(&buffer, CommitmentConfig::confirmed())
        .await
        .map_err(|_| anyhow!("Could not read buffer account"))?
        .value
        .context("Buffer does not exist or is already closed")?;
    validate_buffer_authority(&account, authority.pubkey())?;
    ensure!(account.lamports > 0, "Buffer is already drained");
    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|_| anyhow!("Could not fetch a recent blockhash"))?;
    let instruction = instruction::close(&buffer, &authority.pubkey(), &authority.pubkey());
    let message =
        Message::new_with_blockhash(&[instruction], Some(&authority.pubkey()), &blockhash);
    let mut transaction = Transaction::new_unsigned(message);
    transaction.try_sign(&[authority], blockhash)?;
    let signature = *transaction
        .signatures
        .first()
        .context("Missing transaction signature")?;
    let receipt = BufferCloseReceipt {
        buffer,
        authority_and_recipient: authority.pubkey(),
        genesis_hash: genesis.to_string(),
        lamports_before_close: account.lamports,
        signature: signature.to_string(),
    };
    let json = serde_json::to_vec_pretty(&receipt)?;
    // Preserve the exact public transaction identifier even if submission or
    // confirmation fails. A submission file is not proof of confirmation.
    fs::write(output_dir.join("buffer-close-submission.json"), &json)
        .context("Could not save buffer close submission")?;
    eprintln!(
        "Closing buffer {buffer}; recipient={} signature={signature}",
        authority.pubkey()
    );
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
        .map_err(|_| anyhow!(
            "Buffer close submission failed or is uncertain; inspect transaction {signature} before retrying"
        ))?;
    ensure!(
        returned == signature,
        "RPC returned an unexpected signature; inspect {signature}"
    );
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            match rpc
                .get_signature_status_with_commitment_and_history(
                    &signature,
                    CommitmentConfig::confirmed(),
                    true,
                )
                .await
                .map_err(|_| {
                    anyhow!(
                    "Buffer close confirmation is uncertain; inspect {signature} before retrying"
                )
                })? {
                Some(Ok(())) => break Ok(()),
                Some(Err(_)) => anyhow::bail!(
                    "Buffer close failed on-chain; inspect {signature} before retrying"
                ),
                None => tokio::time::sleep(Duration::from_secs(2)).await,
            }
        }
    })
    .await
    .map_err(|_| {
        anyhow!("Buffer close confirmation timed out; inspect {signature} before retrying")
    })??;
    let remaining = rpc
        .get_account_with_commitment(&buffer, CommitmentConfig::confirmed())
        .await
        .map_err(|_| {
            anyhow!("Could not verify buffer closure; inspect {signature} before retrying")
        })?
        .value;
    ensure!(
        remaining.is_none_or(|account| account.lamports == 0),
        "Buffer still has lamports after confirmation; inspect {signature} before retrying"
    );
    fs::write(output_dir.join("buffer-close-receipt.json"), json).context(
        "Buffer close confirmed, but could not save its receipt; inspect the logged signature",
    )?;
    Ok(receipt)
}

#[derive(Clone, Copy)]
pub enum UploadProfile {
    Mainnet,
    Devnet,
}

/// Upload the already-validated bytes using the pinned Solana CLI. Only the
/// public buffer address survives; temporary key files are removed on return.
pub fn upload_buffer(
    rpc_url: &str,
    profile: UploadProfile,
    authority: &Keypair,
    binary: &[u8],
    solana_cli: &Path,
    output_dir: &Path,
) -> Result<Pubkey> {
    let private = tempfile::tempdir().context("Could not create private upload directory")?;
    let mut authority_file = tempfile::NamedTempFile::new_in(private.path())?;
    let mut buffer_file = tempfile::NamedTempFile::new_in(private.path())?;
    let buffer = Keypair::new();
    authority_file.write_all(&Zeroizing::new(serde_json::to_vec(
        &authority.to_bytes().as_slice(),
    )?))?;
    buffer_file.write_all(&Zeroizing::new(serde_json::to_vec(
        &buffer.to_bytes().as_slice(),
    )?))?;
    // Upload exactly the bytes checked in memory, even if the input file changes.
    let binary_path = private.path().join("swig.so");
    fs::write(&binary_path, binary)?;
    let address = buffer.pubkey();
    let mut recovery = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_dir.join("buffer-address.txt"))?;
    writeln!(recovery, "{address}")?;
    eprintln!("Uploading buffer: address={address} bytes={}", binary.len());
    // Raw uploader output can contain the credential-bearing RPC URL. Emit our
    // own progress/errors; never forward or save that output.
    let mut command = Command::new(solana_cli);
    command
        .args(["program", "write-buffer"])
        .arg(&binary_path)
        .args(["--url", rpc_url, "--max-len", &binary.len().to_string()]);
    match profile {
        UploadProfile::Mainnet => command.args([
            "--commitment",
            "confirmed",
            "--use-rpc",
            "--max-sign-attempts",
            "3",
        ]),
        UploadProfile::Devnet => command.args([
            "--commitment",
            "confirmed",
            "--with-compute-unit-price",
            "100",
            "--max-sign-attempts",
            "100",
            "--use-tpu-client",
        ]),
    };
    let status = command
        .arg("--keypair")
        .arg(authority_file.path())
        .arg("--buffer")
        .arg(buffer_file.path())
        .env_remove("PROPOSER_KEYPAIR")
        .env_remove("PROGRAM_AUTHORITY_KEYPAIR")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Could not start Solana CLI; install the pinned version or set --solana-cli")?;
    ensure!(
        status.success(),
        "Buffer upload failed ({status}); inspect buffer {address}. The signer retains \
         authority for recovery"
    );
    eprintln!("Buffer upload complete: address={address}");
    Ok(address)
}
