use std::{fs, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use solana_sdk::commitment_config::CommitmentConfig;
use squads_multisig::solana_rpc_client::nonblocking::rpc_client::RpcClient;
use swig_release::{
    buffer::upload_buffer,
    config::{load_program_authority, load_proposer, DevnetConfig, ReleaseConfig},
    devnet::{self, DeploymentRequest, DevnetCheckReceipt},
    proposal::validate_release_identity,
    release::{check, propose, read_binary, validate_preflight, CheckReceipt, ProposalRequest},
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
    },
    /// Upload the binary and create an active proposal; never votes or
    /// executes.
    Propose {
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
    /// Read-only preflight for a devnet program controlled by a keypair.
    CheckDevnet {
        #[arg(long)]
        binary: PathBuf,
    },
    /// Upload and execute a direct devnet upgrade with the program authority.
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
        Command::Check { binary } => {
            let config = ReleaseConfig::from_env()?;
            let proposer = load_proposer()?;
            let rpc = RpcClient::new_with_timeout_and_commitment(
                config.rpc_url.clone(),
                Duration::from_secs(30),
                CommitmentConfig::confirmed(),
            );
            let binary = read_binary(&binary)?;
            let receipt = check(&rpc, &config, &proposer, &binary).await?;
            eprintln!(
                "Preflight passed: bytes={} capacity={} transaction_index={}",
                receipt.binary_bytes, receipt.program_capacity_bytes, receipt.transaction_index
            );
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        },
        Command::Propose {
            binary,
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
            let current = check(&rpc, &config, &proposer, &binary).await?;
            validate_preflight(&saved, &current)?;
            // An existing directory may contain an earlier submission. Never
            // overwrite its recovery evidence or silently start another attempt.
            fs::create_dir(&output_dir).context(
                "Output directory must be new; inspect any earlier attempt before retrying",
            )?;
            let buffer = upload_buffer(
                &config.rpc_url,
                CommitmentConfig::confirmed(),
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
                CommitmentConfig::finalized(),
            );
            let receipt = devnet::check(&rpc, &config, &authority, &binary).await?;
            eprintln!(
                "Devnet preflight passed: bytes={} capacity={} authority={}",
                receipt.binary_bytes, receipt.program_capacity_bytes, receipt.authority
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
                CommitmentConfig::finalized(),
            );
            let current = devnet::check(&rpc, &config, &authority, &binary).await?;
            devnet::validate_preflight(&saved, &current)?;
            fs::create_dir(&output_dir).context(
                "Output directory must be new; inspect any earlier attempt before retrying",
            )?;
            let buffer = upload_buffer(
                &config.rpc_url,
                CommitmentConfig::finalized(),
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
                "Upgrade finalized, but could not save its receipt; inspect the logged signature",
            )?;
            eprintln!(
                "Devnet upgrade finalized: program={} signature={}",
                receipt.program, receipt.signature
            );
            println!("{json}");
        },
    }
    Ok(())
}
