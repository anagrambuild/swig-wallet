use std::process::Command;

use anyhow::Result;

#[test]
fn help_does_not_require_secrets() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_swig-release"))
        .env_clear()
        .arg("--help")
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("check"));
    assert!(help.contains("propose"));
    Ok(())
}

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

#[test]
fn proposal_requires_the_saved_preflight_and_receipt_directory() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_swig-release"))
        .env_clear()
        .args(["propose", "--binary", "swig.so"])
        .output()?;
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr)?;
    assert!(error.contains("--preflight"));
    assert!(error.contains("--output-dir"));
    Ok(())
}
