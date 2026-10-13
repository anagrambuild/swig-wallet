use std::{path::PathBuf, time::Duration};

use anyhow::Result;
use clap::{Parser, Subcommand};
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};
use squads_multisig::solana_rpc_client::nonblocking::rpc_client::RpcClient;
use swig_release::{
    config::{load_proposer, ReleaseConfig},
    release::{check, propose, read_binary, ProposalRequest},
};

#[derive(Parser)]
#[command(
    name = "swig-release",
    about = "Validate and propose Swig program upgrades through Squads"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read-only preflight. Configuration comes exclusively from environment variables.
    Check {
        #[arg(long)]
        binary: PathBuf,
    },
    /// Atomically hand off the buffer and create an active proposal; never votes or executes.
    Propose {
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        buffer: Pubkey,
        /// Use the index returned by check; an occupied or stale index is rejected.
        #[arg(long)]
        transaction_index: u64,
        #[arg(long)]
        source_commit: String,
        #[arg(long)]
        tag: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = ReleaseConfig::from_env()?;
    let proposer = load_proposer()?;
    let rpc = RpcClient::new_with_timeout_and_commitment(
        config.rpc_url.clone(),
        Duration::from_secs(30),
        CommitmentConfig::confirmed(),
    );
    match cli.command {
        Command::Check { binary } => {
            let binary = read_binary(&binary)?;
            let receipt = check(&rpc, &config, &proposer, &binary).await?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        },
        Command::Propose {
            binary,
            buffer,
            transaction_index,
            source_commit,
            tag,
        } => {
            let binary = read_binary(&binary)?;
            let receipt = propose(
                &rpc,
                &config,
                &proposer,
                &binary,
                ProposalRequest {
                    buffer,
                    transaction_index,
                    source_commit,
                    tag,
                },
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        },
    }
    Ok(())
}
