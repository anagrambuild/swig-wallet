use std::{fs, path::Path, process::Stdio, time::Duration};

use anyhow::{anyhow, ensure, Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_sdk::{hash::Hash, pubkey::Pubkey};
use solana_sdk_ids::bpf_loader_upgradeable;
use squads_multisig::solana_rpc_client::nonblocking::rpc_client::RpcClient;

use crate::{
    accounts::validate_program,
    build::solana_verify_command,
    devnet::DEVNET_GENESIS_HASH,
    verification::{
        executable_hash, validate_published_metadata, VerificationManifest, VERIFY_PROGRAM,
    },
};

pub const OTTERSEC_URL: &str = "https://verify.osec.io";
pub const MAINNET_GENESIS_HASH: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";

#[derive(Clone, Copy, ValueEnum)]
pub enum Cluster {
    Mainnet,
    Devnet,
}

#[serde_with::serde_as]
#[derive(Serialize)]
pub struct DeployedRelease {
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub program: Pubkey,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub authority: Pubkey,
    pub slot: u64,
    pub executable_hash: String,
}

#[serde_with::serde_as]
#[derive(Deserialize)]
pub struct SubmissionReceipt {
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub program: Pubkey,
    pub source_commit: String,
    pub verification_observed_deploy_slot: u64,
}

impl SubmissionReceipt {
    pub fn validate(
        &self,
        deployed: &DeployedRelease,
        manifest: &VerificationManifest,
    ) -> Result<()> {
        ensure!(
            self.program == deployed.program
                && self.source_commit == manifest.commit
                && self.verification_observed_deploy_slot > 0
                && deployed.slot > self.verification_observed_deploy_slot,
            "Proposal receipt does not match an executed upgrade of this release"
        );
        Ok(())
    }
}

pub async fn check_deployed_release(
    rpc: &RpcClient,
    program: Pubkey,
    cluster: Cluster,
    manifest: &VerificationManifest,
) -> Result<DeployedRelease> {
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
        "RPC network does not match the selected cluster"
    );
    let program_data =
        Pubkey::find_program_address(&[program.as_ref()], &bpf_loader_upgradeable::id()).0;
    let fetched = rpc
        .get_multiple_accounts(&[program, program_data])
        .await
        .map_err(|_| anyhow!("Could not read the deployed program"))?;
    let mut fetched = fetched.into_iter();
    let program_account = fetched
        .next()
        .flatten()
        .context("Program account is missing")?;
    let data = fetched
        .next()
        .flatten()
        .context("ProgramData account is missing")?;
    let metadata_size = UpgradeableLoaderState::size_of_programdata_metadata();
    let state: UpgradeableLoaderState = bincode::deserialize(
        data.data
            .get(..metadata_size)
            .context("Truncated ProgramData")?,
    )?;
    let UpgradeableLoaderState::ProgramData {
        slot,
        upgrade_authority_address: Some(authority),
    } = state
    else {
        anyhow::bail!("ProgramData must have an upgrade authority")
    };
    validate_program(program, &program_account, &data, authority)?;
    let hash = executable_hash(
        data.data
            .get(metadata_size..)
            .context("Missing program executable")?,
    );
    ensure!(
        hash == manifest.executable_hash,
        "Deployed program does not match this release"
    );
    Ok(DeployedRelease {
        program,
        authority,
        slot,
        executable_hash: hash,
    })
}

#[serde_with::serde_as]
#[derive(Deserialize, Serialize)]
pub struct VerifiedBuild {
    // The API includes unsigned historical builds, but always returns this field.
    #[serde_as(as = "Option<serde_with::DisplayFromStr>", no_default)]
    pub signer: Option<Pubkey>,
    pub commit: String,
    pub is_verified: bool,
    pub repo_url: String,
    pub executable_hash: String,
    pub on_chain_hash: String,
}

/// Decode and correlate the public status endpoint before accepting its attestation.
pub fn decode_attestation(
    status: u16,
    body: &[u8],
    authority: Pubkey,
    manifest: &VerificationManifest,
) -> Result<VerifiedBuild> {
    ensure!(
        (200..300).contains(&status),
        "OtterSec status request failed with HTTP {status}"
    );
    let statuses: Vec<VerifiedBuild> = serde_json::from_slice(body)
        .map_err(|_| anyhow!("Malformed OtterSec verification status"))?;
    statuses
        .into_iter()
        .find(|status| {
            status.signer == Some(authority)
                && status.is_verified
                && status.commit == manifest.commit
                && status.repo_url == format!("{}/tree/{}", manifest.repository, manifest.commit)
                && status.executable_hash == manifest.executable_hash
                && status.on_chain_hash == manifest.executable_hash
        })
        .context("OtterSec has no matching verified attestation for this release")
}

pub async fn submit_ottersec(
    rpc: &RpcClient,
    program: Pubkey,
    manifest: &VerificationManifest,
    receipt: &SubmissionReceipt,
    verify_cli: &Path,
    output_dir: &Path,
) -> Result<VerifiedBuild> {
    // Mainnet is enforced here even when a caller bypasses the CLI argument checks.
    let deployed = check_deployed_release(rpc, program, Cluster::Mainnet, manifest).await?;
    receipt.validate(&deployed, manifest)?;
    let address = Pubkey::find_program_address(
        &[
            b"otter_verify",
            deployed.authority.as_ref(),
            program.as_ref(),
        ],
        &VERIFY_PROGRAM,
    )
    .0;
    let metadata = rpc
        .get_account(&address)
        .await
        .map_err(|_| anyhow!("Could not read published verification metadata"))?;
    validate_published_metadata(
        &metadata,
        program,
        deployed.authority,
        manifest,
        receipt.verification_observed_deploy_slot,
    )?;
    fs::write(
        output_dir.join("deployed-release.json"),
        serde_json::to_vec_pretty(&deployed)?,
    )?;
    eprintln!(
        "Submitting release {} to OtterSec for program {program}",
        manifest.commit
    );
    // The pinned CLI owns job submission and polling. Never forward its raw output:
    // it can contain RPC credentials or untrusted remote response bodies.
    let status = solana_verify_command(verify_cli)?
        .args([
            "remote",
            "submit-job",
            "--url",
            &rpc.url(),
            "--program-id",
            &program.to_string(),
            "--uploader",
            &deployed.authority.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Could not start OtterSec submission")?;
    ensure!(status.success(), "OtterSec submission failed ({status}); inspect the program's remote status before retrying");
    // solana-verify 0.5.2 also exits zero for failed jobs and HTTP 409. Only an
    // independently fetched, matching signer/source/hash attestation is success.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|_| anyhow!("Could not initialize OtterSec status connection"))?;
    let response = client
        .get(format!("{OTTERSEC_URL}/status-all/{program}"))
        .send()
        .await
        .map_err(|_| anyhow!("Could not fetch OtterSec verification status"))?;
    let status = response.status().as_u16();
    let body = response
        .bytes()
        .await
        .map_err(|_| anyhow!("Could not read OtterSec verification status"))?;
    let attestation = decode_attestation(status, &body, deployed.authority, manifest)?;
    let current = check_deployed_release(rpc, program, Cluster::Mainnet, manifest).await?;
    ensure!(
        current.authority == deployed.authority && current.slot == deployed.slot,
        "Program changed during remote verification; check the current release before retrying"
    );
    fs::write(
        output_dir.join("remote-status.json"),
        serde_json::to_vec_pretty(&attestation)?,
    )?;
    Ok(attestation)
}
