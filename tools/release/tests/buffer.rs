#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt};

use anyhow::{Context, Result};
use solana_sdk::{pubkey::Pubkey, signature::Keypair};
use swig_release::buffer::{upload_buffer, UploadProfile};

#[test]
fn upload_owns_exact_bytes_private_files_cleanup_and_public_recovery() -> Result<()> {
    for (profile, commitment, transport, attempts, price, exit_code) in [
        (UploadProfile::Mainnet, "confirmed", "rpc", 3, "none", 0),
        (UploadProfile::Mainnet, "confirmed", "rpc", 3, "none", 9),
        (UploadProfile::Devnet, "confirmed", "tpu", 100, "100", 0),
        (UploadProfile::Devnet, "confirmed", "tpu", 100, "100", 9),
    ] {
        let directory = tempfile::tempdir()?;
        let script = directory.path().join("solana with spaces");
        // The subprocess observes actual arguments and files. Neither fake
        // uploader output nor inherited signing credentials may escape.
        fs::write(
            &script,
            format!(
                r##"#!/bin/sh
set -eu
test "$1" = program
test "$2" = write-buffer
binary=$3
shift 3
test -z "${{PROPOSER_KEYPAIR:-}}"
test -z "${{PROGRAM_AUTHORITY_KEYPAIR:-}}"
test -z "${{GH_TOKEN:-}}"
test -z "${{GITHUB_TOKEN:-}}"
observed_commitment=none
observed_transport=none
observed_attempts=none
observed_price=none
while [ "$#" -gt 0 ]; do
    case "$1" in
        --keypair) payer=$2; shift 2 ;;
        --buffer) buffer=$2; shift 2 ;;
        --max-len) size=$2; shift 2 ;;
        --url) test "$2" = https://rpc.invalid/private-rpc-credential; shift 2 ;;
        --commitment) observed_commitment=$2; shift 2 ;;
        --max-sign-attempts) observed_attempts=$2; shift 2 ;;
        --with-compute-unit-price) observed_price=$2; shift 2 ;;
        --use-rpc) test "$observed_transport" = none; observed_transport=rpc; shift ;;
        --use-tpu-client) test "$observed_transport" = none; observed_transport=tpu; shift ;;
        *) exit 99 ;;
    esac
done
test "$observed_commitment" = {commitment}
test "$observed_transport" = {transport}
test "$observed_attempts" = {attempts}
test "$observed_price" = {price}
test -s "$payer"
test -s "$buffer"
test "$size" = 7
cmp "$binary" "${{0%/*}}/expected.so"
printf '%s\n' "$binary" "$payer" "$buffer" > "${{0%/*}}/observed-paths"
echo private-rpc-credential >&2
exit {exit_code}
"##,
            ),
        )?;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
        let binary = b"\x7fELFabc";
        fs::write(directory.path().join("expected.so"), binary)?;
        let output = directory.path().join("public");
        fs::create_dir(&output)?;
        let result = upload_buffer(
            "https://rpc.invalid/private-rpc-credential",
            profile,
            &Keypair::new(),
            binary,
            &script,
            &output,
        );
        let address: Pubkey = fs::read_to_string(output.join("buffer-address.txt"))?
            .trim()
            .parse()?;
        if exit_code == 0 {
            assert_eq!(result?, address);
        } else {
            let error = result
                .err()
                .context("Expected uploader failure")?
                .to_string();
            assert!(error.contains("Buffer upload failed"));
            assert!(error.contains(&address.to_string()));
            assert!(!error.contains("private-rpc-credential"));
        }
        for path in fs::read_to_string(directory.path().join("observed-paths"))?.lines() {
            assert!(
                !std::path::Path::new(path).exists(),
                "Upload temporary file leaked"
            );
        }
        assert_eq!(
            fs::read_dir(&output)?.count(),
            1,
            "Only public recovery information may survive"
        );
    }
    Ok(())
}

#[test]
fn upload_failure_reports_safe_diagnostics_without_raw_output() -> Result<()> {
    for (message, expected) in [
        (
            "Error: Data writes to account failed: Custom error: Max retries exceeded",
            "data writes failed; retry limit exceeded",
        ),
        (
            "Error: Account allocation failed: HTTP status client error (429 Too Many Requests)",
            "buffer allocation failed; HTTP 429",
        ),
        (
            "Error: error sending request: operation timed out",
            "RPC request failed; request timed out",
        ),
        (
            "Error: unknown provider response with signing-canary",
            "unrecognized or empty CLI error; raw output withheld",
        ),
    ] {
        let directory = tempfile::tempdir()?;
        let script = directory.path().join("solana");
        fs::write(
            &script,
            format!(
                r##"#!/bin/sh
echo 'stdout-canary'
echo 'https://rpc-user:rpc-password@rpc.invalid/path-canary?api-key=query-canary' >&2
echo 'Authorization: Bearer token-canary; signing-canary; [1,2,3,4]' >&2
echo '{message}' >&2
exit 1
"##
            ),
        )?;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
        let output = directory.path().join("public");
        fs::create_dir(&output)?;
        let error = upload_buffer(
            "https://rpc-user:rpc-password@rpc.invalid/path-canary?api-key=query-canary",
            UploadProfile::Mainnet,
            &Keypair::new(),
            b"\x7fELFabc",
            &script,
            &output,
        )
        .err()
        .context("Expected uploader failure")?
        .to_string();
        assert!(error.ends_with(expected), "{error}");
        for secret in [
            "rpc-user",
            "rpc-password",
            "rpc.invalid",
            "path-canary",
            "query-canary",
            "token-canary",
            "signing-canary",
            "stdout-canary",
            "[1,2,3,4]",
        ] {
            assert!(!error.contains(secret), "CLI output must stay private");
        }
        assert_eq!(fs::read_dir(&output)?.count(), 1);
    }
    Ok(())
}

#[test]
fn upload_drains_large_output_and_inspects_only_the_bounded_tail() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let script = directory.path().join("solana");
    fs::write(
        &script,
        r##"#!/bin/sh
echo '401 Unauthorized prefix-secret' >&2
dd if=/dev/zero bs=1024 count=256 2>/dev/null
dd if=/dev/zero bs=1024 count=256 2>/dev/null | tr '\000' x >&2
echo 'Data writes to account failed: Max retries exceeded tail-secret' >&2
exit 1
"##,
    )?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
    let output = directory.path().join("public");
    fs::create_dir(&output)?;
    let error = upload_buffer(
        "https://rpc.invalid/private-rpc-credential",
        UploadProfile::Mainnet,
        &Keypair::new(),
        b"\x7fELFabc",
        &script,
        &output,
    )
    .err()
    .context("Expected uploader failure")?
    .to_string();
    assert!(error.ends_with(
        "data writes failed; retry limit exceeded; only the final 16 KiB of stderr inspected"
    ));
    assert!(!error.contains("HTTP 401"));
    assert!(!error.contains("prefix-secret") && !error.contains("tail-secret"));
    assert!(error.len() < 512);
    assert_eq!(fs::read_dir(&output)?.count(), 1);
    Ok(())
}
