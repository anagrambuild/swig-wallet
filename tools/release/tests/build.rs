use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

use anyhow::Result;
use swig_release::verification::{VerificationManifest, BUILD_ARGS};

fn executable(path: &Path, script: &str) -> Result<()> {
    fs::write(path, script)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[test]
fn rust_build_command_pins_recipe_and_writes_exact_binary_and_manifest() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let bin = temp.path().join("bin");
    fs::create_dir(&bin)?;
    executable(
        &bin.join("git"),
        "#!/bin/sh\ncase \"$1\" in\nrev-parse) printf '%s\\n' \"$TEST_CHECKOUT\";;\nstatus) printf '%s' \"$TEST_DIRTY\";;\nesac\n",
    )?;
    executable(
        &bin.join("solana-verify"),
        r#"#!/bin/sh
test -z "$PROPOSER_KEYPAIR$PROGRAM_AUTHORITY_KEYPAIR$GH_TOKEN$GITHUB_TOKEN$SOLANA_RPC_URL" || exit 71
if [ "$1" = --version ]; then
  echo "solana-verify $TEST_VERSION"
else
  printf '%s\n' "$@" > builder-args.txt
  test "$TEST_BUILD_FAIL" != yes || exit 72
  mkdir -p target/deploy
  printf '\177ELFtest-program\000\000' > target/deploy/swig.so
fi
"#,
    )?;
    let commit = "a".repeat(40);
    for (checkout, version, build_fail, dirty, expected) in [
        (&commit, "0.5.2", "no", "", true),
        (&"b".repeat(40), "0.5.2", "no", "", false),
        (&commit, "0.4.11", "no", "", false),
        (&commit, "0.5.2", "yes", "", false),
        (&commit, "0.5.2", "no", " M program/src/lib.rs", false),
    ] {
        let args_file = temp.path().join("builder-args.txt");
        if args_file.exists() {
            fs::remove_file(&args_file)?;
        }
        let output = Command::new(env!("CARGO_BIN_EXE_swig-release"))
            .current_dir(temp.path())
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("TEST_CHECKOUT", checkout)
            .env("TEST_VERSION", version)
            .env("TEST_BUILD_FAIL", build_fail)
            .env("TEST_DIRTY", dirty)
            .env("PROPOSER_KEYPAIR", "secret")
            .env("PROGRAM_AUTHORITY_KEYPAIR", "secret")
            .env("GH_TOKEN", "secret")
            .env("GITHUB_TOKEN", "secret")
            .env("SOLANA_RPC_URL", "secret")
            .args([
                "build",
                "--source-commit",
                &commit,
                "--output-dir",
                "release",
            ])
            .output()?;
        assert_eq!(
            output.status.success(),
            expected,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if expected {
            let manifest =
                VerificationManifest::read_release(&temp.path().join("release"), &commit)?;
            assert_eq!(manifest.build_args, BUILD_ARGS);
            assert_eq!(
                fs::read_to_string(&args_file)?.lines().collect::<Vec<_>>(),
                std::iter::once("build")
                    .chain(BUILD_ARGS)
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                fs::read(temp.path().join("release/swig.so"))?,
                fs::read(temp.path().join("target/deploy/swig.so"))?
            );
        } else if checkout != &commit || version != "0.5.2" || !dirty.is_empty() {
            assert!(!args_file.exists(), "Invalid input reached the builder");
        }
    }
    Ok(())
}

#[test]
fn release_input_rejects_changed_binary_and_manifest_before_network_access() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let binary = b"\x7fELFtest\0\0";
    let mut manifest: VerificationManifest =
        serde_json::from_str(include_str!("fixtures/verification.json"))?;
    manifest.executable_hash = swig_release::verification::executable_hash(binary);
    fs::write(temp.path().join("swig.so"), binary)?;
    fs::write(
        temp.path().join("verification.json"),
        serde_json::to_vec(&manifest)?,
    )?;
    VerificationManifest::read_release(temp.path(), &manifest.commit)?;
    fs::write(temp.path().join("swig.so"), b"\x7fELFdifferent")?;
    for name in ["check-release", "submit-ottersec"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_swig-release"));
        command
            .env_clear()
            .args([name, "--source-commit", &manifest.commit, "--directory"])
            .arg(temp.path());
        if name == "check-release" {
            command.args(["--cluster", "devnet"]);
        }
        let output = command.output()?;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("executable hash does not match"));
    }
    assert!(VerificationManifest::read_release(temp.path(), &manifest.commit).is_err());
    fs::write(temp.path().join("swig.so"), binary)?;
    assert!(VerificationManifest::read_release(temp.path(), &"b".repeat(40)).is_err());
    Ok(())
}
