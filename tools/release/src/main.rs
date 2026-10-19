use std::{fs, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use solana_sdk::commitment_config::CommitmentConfig;
use squads_multisig::solana_rpc_client::nonblocking::rpc_client::RpcClient;
use swig_release::{
    buffer::{upload_buffer, UploadProfile},
    config::{load_program_authority, load_proposer, DevnetConfig, ReleaseConfig},
    devnet::{self, DeploymentRequest, DevnetCheckReceipt},
    proposal::validate_release_identity,
    release::{check, propose, read_binary, validate_preflight, CheckReceipt, ProposalRequest},
    verification::VerificationManifest,
};

#[derive(Parser)]
#[command(
    name = "swig-release",
    about = "Propose Swig upgrades through Squads or deploy directly to devnet"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read-only preflight. Configuration comes exclusively from environment
    /// variables.
    Check {
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        verification: PathBuf,
    },
    /// Upload the binary and create an active proposal; never votes or
    /// executes.
    Propose {
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        verification: PathBuf,
        #[arg(long)]
        preflight: PathBuf,
        #[arg(long)]
        source_commit: String,
        #[arg(long)]
        tag: String,
        /// New directory for public recovery information and the verified
        /// receipt.
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value = "solana")]
        solana_cli: PathBuf,
    },
    /// Read-only preflight for a devnet program controlled by a keypair.
    CheckDevnet {
        #[arg(long)]
        binary: PathBuf,
    },
    /// Expand ProgramData if needed, upload, and execute a direct devnet
    /// upgrade.
    DeployDevnet {
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        preflight: PathBuf,
        #[arg(long)]
        source_commit: String,
        #[arg(long)]
        tag: String,
        /// New directory for public recovery information and the verified
        /// receipt.
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value = "solana")]
        solana_cli: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Check {
            binary,
            verification,
        } => {
            let config = ReleaseConfig::from_env()?;
            let proposer = load_proposer()?;
            let rpc = RpcClient::new_with_timeout_and_commitment(
                config.rpc_url.clone(),
                Duration::from_secs(30),
                CommitmentConfig::confirmed(),
            );
            let binary = read_binary(&binary)?;
            let manifest: VerificationManifest = serde_json::from_slice(
                &fs::read(verification).context("Could not read verification manifest")?,
            )?;
            let receipt = check(&rpc, &config, &proposer, &binary, &manifest).await?;
            eprintln!(
                "Preflight passed: bytes={} capacity={} transaction_index={}",
                receipt.binary_bytes, receipt.program_capacity_bytes, receipt.transaction_index
            );
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        },
        Command::Propose {
            binary,
            verification,
            preflight,
            source_commit,
            tag,
            output_dir,
            solana_cli,
        } => {
            let config = ReleaseConfig::from_env()?;
            let proposer = load_proposer()?;
            let rpc = RpcClient::new_with_timeout_and_commitment(
                config.rpc_url.clone(),
                Duration::from_secs(30),
                CommitmentConfig::confirmed(),
            );
            validate_release_identity(&source_commit, &tag)?;
            let binary = read_binary(&binary)?;
            let saved: CheckReceipt = serde_json::from_slice(
                &fs::read(preflight).context("Could not read preflight receipt")?,
            )
            .context("Malformed preflight receipt")?;
            let manifest: VerificationManifest = serde_json::from_slice(
                &fs::read(verification).context("Could not read verification manifest")?,
            )?;
            manifest.validate(&binary, &source_commit)?;
            let current = check(&rpc, &config, &proposer, &binary, &manifest).await?;
            validate_preflight(&saved, &current)?;
            // An existing directory may contain an earlier submission. Never
            // overwrite its recovery evidence or silently start another attempt.
            fs::create_dir(&output_dir).context(
                "Output directory must be new; inspect any earlier attempt before retrying",
            )?;
            let buffer = upload_buffer(
                &config.rpc_url,
                UploadProfile::Mainnet,
                &proposer,
                &binary,
                &solana_cli,
                &output_dir,
            )?;
            let receipt = propose(
                &rpc,
                &config,
                &proposer,
                &binary,
                ProposalRequest {
                    buffer,
                    transaction_index: saved.transaction_index,
                    verification: manifest,
                    verification_instruction_sha256: saved.verification_instruction_sha256,
                    source_commit,
                    tag,
                },
            )
            .await?;
            let json = serde_json::to_string_pretty(&receipt)?;
            fs::write(output_dir.join("proposal-receipt.json"), &json).context(
                "Proposal confirmed, but could not save its receipt; inspect the logged signature",
            )?;
            eprintln!(
                "Proposal confirmed: proposal={} signature={}",
                receipt.proposal, receipt.signature
            );
            println!("{json}");
        },
        Command::CheckDevnet { binary } => {
            let config = DevnetConfig::from_env()?;
            let authority = load_program_authority()?;
            let binary = read_binary(&binary)?;
            let rpc = RpcClient::new_with_timeout_and_commitment(
                config.rpc_url.clone(),
                Duration::from_secs(30),
                CommitmentConfig::confirmed(),
            );
            let receipt = devnet::check(&rpc, &config, &authority, &binary).await?;
            eprintln!(
                "Devnet preflight passed: bytes={} capacity={} additional={} authority={}",
                receipt.binary_bytes,
                receipt.program_capacity_bytes,
                receipt.additional_program_bytes,
                receipt.authority
            );
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        },
        Command::DeployDevnet {
            binary,
            preflight,
            source_commit,
            tag,
            output_dir,
            solana_cli,
        } => {
            let config = DevnetConfig::from_env()?;
            let authority = load_program_authority()?;
            validate_release_identity(&source_commit, &tag)?;
            let binary = read_binary(&binary)?;
            let saved: DevnetCheckReceipt = serde_json::from_slice(
                &fs::read(preflight).context("Could not read devnet preflight receipt")?,
            )
            .context("Malformed devnet preflight receipt")?;
            let rpc = RpcClient::new_with_timeout_and_commitment(
                config.rpc_url.clone(),
                Duration::from_secs(30),
                CommitmentConfig::confirmed(),
            );
            fs::create_dir(&output_dir).context(
                "Output directory must be new; inspect any earlier attempt before retrying",
            )?;
            if let Some(extension) =
                devnet::ensure_capacity(&rpc, &config, &authority, &binary, &saved, &output_dir)
                    .await?
            {
                fs::write(
                    output_dir.join("extension-receipt.json"),
                    serde_json::to_string_pretty(&extension)?,
                )
                .context("Program expansion confirmed, but could not save its receipt")?;
            }
            let buffer = upload_buffer(
                &config.rpc_url,
                UploadProfile::Devnet,
                &authority,
                &binary,
                &solana_cli,
                &output_dir,
            )?;
            let receipt = devnet::deploy(
                &rpc,
                &config,
                &authority,
                &binary,
                DeploymentRequest {
                    buffer,
                    source_commit,
                    tag,
                },
                &output_dir,
            )
            .await?;
            let json = serde_json::to_string_pretty(&receipt)?;
            fs::write(output_dir.join("deployment-receipt.json"), &json).context(
                "Upgrade confirmed, but could not save its receipt; inspect the logged signature",
            )?;
            eprintln!(
                "Devnet upgrade confirmed: program={} signature={}",
                receipt.program, receipt.signature
            );
            println!("{json}");
        },
    }
    Ok(())
}
