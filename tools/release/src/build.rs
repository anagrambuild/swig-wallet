use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
};

use anyhow::{ensure, Context, Result};

use crate::{
    release::read_binary,
    verification::{executable_hash, VerificationManifest, BUILD_ARGS, REPOSITORY, VERIFY_VERSION},
};

/// Pin the external builder and keep unrelated credentials out of child tools.
pub fn solana_verify_command(path: &Path) -> Result<Command> {
    let mut command = Command::new(path);
    command
        .env_remove("PROPOSER_KEYPAIR")
        .env_remove("PROGRAM_AUTHORITY_KEYPAIR")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .env_remove("SOLANA_RPC_URL")
        .stdin(Stdio::null());
    let version = command
        .arg("--version")
        .output()
        .context("Could not start solana-verify")?;
    ensure!(
        version.status.success()
            && String::from_utf8_lossy(&version.stdout).trim()
                == format!("solana-verify {VERIFY_VERSION}"),
        "Install the pinned solana-verify {VERIFY_VERSION}"
    );
    let mut command = Command::new(path);
    command
        .env_remove("PROPOSER_KEYPAIR")
        .env_remove("PROGRAM_AUTHORITY_KEYPAIR")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .env_remove("SOLANA_RPC_URL")
        .stdin(Stdio::null());
    Ok(command)
}

pub fn build_release(
    source_commit: &str,
    output_dir: &Path,
    verify_cli: &Path,
) -> Result<VerificationManifest> {
    ensure!(
        source_commit.len() == 40 && source_commit.bytes().all(|b| b.is_ascii_hexdigit()),
        "source-commit must be a full Git commit SHA"
    );
    let checkout = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .context("Could not resolve the checked-out source")?;
    ensure!(
        checkout.status.success()
            && String::from_utf8_lossy(&checkout.stdout).trim() == source_commit,
        "Checked-out source does not match source-commit"
    );
    let changes = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=normal"])
        .output()
        .context("Could not inspect the build checkout")?;
    ensure!(
        changes.status.success() && changes.stdout.is_empty(),
        "Build requires a clean checkout so the binary matches source-commit"
    );
    let status = solana_verify_command(verify_cli)?
        .arg("build")
        .args(BUILD_ARGS)
        .status()
        .context("Could not start the verifiable build")?;
    ensure!(status.success(), "Verifiable build failed ({status})");
    let binary = read_binary(Path::new("target/deploy/swig.so"))?;
    let manifest = VerificationManifest {
        repository: REPOSITORY.into(),
        commit: source_commit.into(),
        cli_version: VERIFY_VERSION.into(),
        build_args: BUILD_ARGS.map(str::to_owned).to_vec(),
        executable_hash: executable_hash(&binary),
    };
    manifest.validate(&binary, source_commit)?;
    fs::create_dir_all(output_dir).context("Could not create release artifact directory")?;
    fs::write(output_dir.join("swig.so"), binary)?;
    fs::write(
        output_dir.join("verification.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(manifest)
}
