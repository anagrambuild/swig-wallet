use std::process::Command;

use anyhow::Result;

#[test]
fn missing_configuration_fails_before_reading_binary_or_sending_requests() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_swig-release"))
        .env_clear()
        .args(["check", "--binary", "/does-not-exist/swig.so"])
        .output()?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)?.contains("SOLANA_RPC_URL is required"));
    Ok(())
}

#[test]
fn invalid_rpc_error_does_not_expose_credentials() -> Result<()> {
    let sentinel = "private-rpc-credential";
    let output = Command::new(env!("CARGO_BIN_EXE_swig-release"))
        .env_clear()
        .env("SOLANA_RPC_URL", sentinel)
        .args(["check", "--binary", "/does-not-exist/swig.so"])
        .output()?;
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr)?;
    assert!(error.contains("SOLANA_RPC_URL must be an HTTP(S) URL"));
    assert!(!error.contains(sentinel));
    Ok(())
}
