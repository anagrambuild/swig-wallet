use std::process::Command;

use anyhow::Result;
use solana_sdk::signature::Keypair;

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
fn devnet_commands_require_only_devnet_configuration() -> Result<()> {
    let keypair = serde_json::to_string(&Keypair::new().to_bytes().to_vec())?;
    for command in ["check-devnet", "deploy-devnet"] {
        let mut invocation = Command::new(env!("CARGO_BIN_EXE_swig-release"));
        invocation
            .env_clear()
            .env("SOLANA_RPC_URL", "https://rpc.invalid")
            .env(
                "SWIG_PROGRAM_ID",
                "swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB",
            )
            .env("PROGRAM_AUTHORITY_KEYPAIR", &keypair)
            .args([command, "--binary", "/does-not-exist/swig.so"]);
        if command == "deploy-devnet" {
            invocation.args([
                "--preflight",
                "/does-not-exist/preflight.json",
                "--source-commit",
                &"a".repeat(40),
                "--tag",
                "devnet-upgrade-1-aaaaaaaaaaaa",
                "--output-dir",
                "/does-not-exist/deployment",
            ]);
        }
        let output = invocation.output()?;
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr)?;
        assert!(error.contains("Could not read program binary"), "{error}");
        assert!(!error.contains("SQUADS") && !error.contains("PROPOSER"));
    }
    Ok(())
}

#[test]
fn devnet_rejects_missing_invalid_keys_and_wrong_program_before_rpc() -> Result<()> {
    for (key, program, expected) in [
        (
            None,
            "swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB",
            "PROGRAM_AUTHORITY_KEYPAIR is required",
        ),
        (
            Some("private-key-sentinel"),
            "swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB",
            "must be a Solana keypair JSON array",
        ),
        (
            Some("[1,2,3]"),
            "swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB",
            "must contain a valid 64-byte Solana keypair",
        ),
        (
            None,
            "11111111111111111111111111111111",
            "must match the program ID declared by the Swig binary",
        ),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_swig-release"));
        command
            .env_clear()
            .env("SOLANA_RPC_URL", "https://rpc.invalid")
            .env("SWIG_PROGRAM_ID", program)
            .args(["check-devnet", "--binary", "/does-not-exist/swig.so"]);
        if let Some(key) = key {
            command.env("PROGRAM_AUTHORITY_KEYPAIR", key);
        }
        let output = command.output()?;
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr)?;
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains("private-key-sentinel"));
        assert!(output.stdout.is_empty());
    }
    Ok(())
}
