#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt};

use anyhow::{Context, Result};
use solana_sdk::{pubkey::Pubkey, signature::Keypair};
use swig_release::{buffer::upload_buffer, config::ReleaseConfig};

#[test]
fn upload_owns_exact_bytes_private_files_cleanup_and_public_recovery() -> Result<()> {
    for exit_code in [0, 9] {
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
test -z "${{GH_TOKEN:-}}"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --keypair) payer=$2; shift 2 ;;
        --buffer) buffer=$2; shift 2 ;;
        --max-len) size=$2; shift 2 ;;
        --use-rpc) shift ;;
        *) shift 2 ;;
    esac
done
test -s "$payer"
test -s "$buffer"
test "$size" = 7
cmp "$binary" "${{0%/*}}/expected.so"
printf '%s\n' "$binary" "$payer" "$buffer" > "${{0%/*}}/observed-paths"
echo private-rpc-credential >&2
exit {exit_code}
"##
            ),
        )?;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
        let binary = b"\x7fELFabc";
        fs::write(directory.path().join("expected.so"), binary)?;
        let output = directory.path().join("public");
        fs::create_dir(&output)?;
        let config = ReleaseConfig {
            rpc_url: "https://rpc.invalid/private-rpc-credential".into(),
            program: Pubkey::new_unique(),
            squads_program: Pubkey::new_unique(),
            multisig: Pubkey::new_unique(),
            vault_index: 3,
        };
        let result = upload_buffer(&config, &Keypair::new(), binary, &script, &output);
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
