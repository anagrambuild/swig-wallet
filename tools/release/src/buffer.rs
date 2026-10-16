use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use anyhow::{ensure, Context, Result};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use zeroize::Zeroizing;

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
            "finalized",
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
