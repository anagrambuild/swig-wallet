use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use solana_sdk::{account::Account, pubkey::Pubkey, transaction::Transaction};
use solana_sdk_ids::system_program;
use swig_release::verification::{
    build_verification_instruction, VerificationManifest, VERIFY_PROGRAM,
};

#[test]
fn metadata_matches_native_cli_export_from_devnet() -> Result<()> {
    // Captured from solana-verify 0.5.2 export-pda-tx against public devnet.
    // Unsigned transaction only; no network or keypair is required by this test.
    let native: Transaction =
        bincode::deserialize(include_bytes!("fixtures/devnet-metadata-transaction.bin"))?;
    let [exported] = native.message.instructions.as_slice() else {
        anyhow::bail!("Expected one metadata instruction")
    };
    let program = solana_sdk::pubkey!("swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB");
    let uploader = solana_sdk::pubkey!("yRtJa2jbNRv5KR7qKTi4ZFQ1GGjbkyPHra5C7G4NtPb");
    let mut manifest: VerificationManifest =
        serde_json::from_str(include_str!("fixtures/verification.json"))?;
    manifest.commit = "695f6ecedaa29c572b9a42fc4736f670d874ebaa".into();
    let metadata = build_verification_instruction(program, uploader, &manifest, 511874988, None)?;
    assert_eq!(metadata.instruction.data, exported.data);
    assert_eq!(
        native
            .message
            .account_keys
            .get(usize::from(exported.program_id_index)),
        Some(&VERIFY_PROGRAM)
    );
    for (account, index) in metadata.instruction.accounts.iter().zip(&exported.accounts) {
        let index = usize::from(*index);
        assert_eq!(
            native.message.account_keys.get(index),
            Some(&account.pubkey)
        );
        assert_eq!(native.message.is_signer(index), account.is_signer);
        assert_eq!(
            native.message.is_maybe_writable(index, None),
            account.is_writable
        );
    }
    Ok(())
}

#[test]
fn manifest_binds_exact_source_recipe_and_normalized_binary() -> Result<()> {
    let mut json: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/verification.json"))?;
    let binary = b"\x7fELFtest\0\0";
    json["executable_hash"] = format!("{:x}", Sha256::digest(b"\x7fELFtest")).into();
    let manifest: VerificationManifest = serde_json::from_value(json.clone())?;
    manifest.validate(binary, &manifest.commit)?;
    assert!(manifest
        .validate(b"\x7fELFchanged", &manifest.commit)
        .is_err());
    assert!(manifest.validate(binary, &"b".repeat(40)).is_err());
    for (field, wrong) in [
        (
            "repository",
            serde_json::json!("https://github.com/wrong/repo"),
        ),
        ("commit", serde_json::json!("")),
        ("cli_version", serde_json::json!("0.4.11")),
        ("build_args", serde_json::json!(["--arch", "v1"])),
    ] {
        let mut changed = json.clone();
        changed[field] = wrong;
        let bad: VerificationManifest = serde_json::from_value(changed)?;
        assert!(
            bad.validate(binary, &manifest.commit).is_err(),
            "accepted {field}"
        );
    }
    Ok(())
}

#[test]
fn existing_metadata_binds_owner_discriminator_program_signer_bump_and_layout() -> Result<()> {
    let manifest: VerificationManifest =
        serde_json::from_str(include_str!("fixtures/verification.json"))?;
    let program = Pubkey::new_unique();
    let vault = Pubkey::new_unique();
    let initial = build_verification_instruction(program, vault, &manifest, 123, None)?;
    let bump = Pubkey::find_program_address(
        &[b"otter_verify", vault.as_ref(), program.as_ref()],
        &VERIFY_PROGRAM,
    )
    .1;
    let mut data = Sha256::digest(b"account:BuildParams")[..8].to_vec();
    data.extend(program.as_ref());
    data.extend(vault.as_ref());
    data.extend(
        initial
            .instruction
            .data
            .get(8..)
            .context("Missing metadata payload")?,
    );
    data.push(bump);
    let account = Account {
        lamports: 100_000_000,
        data,
        owner: VERIFY_PROGRAM,
        executable: false,
        rent_epoch: 0,
    };
    let update = build_verification_instruction(program, vault, &manifest, 123, Some(&account))?;
    assert_eq!(
        update.instruction.data.get(..8),
        Some(&Sha256::digest(b"global:update")[..8])
    );
    assert_eq!(
        update.instruction.data.get(8..),
        initial.instruction.data.get(8..)
    );
    assert_eq!(update.account_size, account.data.len());
    for offset in [0, 8, 40, account.data.len() - 1] {
        let mut bad = account.clone();
        *bad.data.get_mut(offset).context("Invalid fixture offset")? ^= 1;
        assert!(
            build_verification_instruction(program, vault, &manifest, 123, Some(&bad)).is_err(),
            "accepted offset {offset}"
        );
    }
    for size in [0, 7, 71, account.data.len() - 1] {
        let mut bad = account.clone();
        bad.data.truncate(size);
        assert!(
            build_verification_instruction(program, vault, &manifest, 123, Some(&bad)).is_err()
        );
    }
    let mut bad = account.clone();
    bad.data.push(0);
    assert!(build_verification_instruction(program, vault, &manifest, 123, Some(&bad)).is_err());
    let mut bad = account.clone();
    bad.owner = system_program::id();
    assert!(build_verification_instruction(program, vault, &manifest, 123, Some(&bad)).is_err());
    let mut bad = account;
    bad.executable = true;
    assert!(build_verification_instruction(program, vault, &manifest, 123, Some(&bad)).is_err());
    let prefunded = Account {
        lamports: 1,
        owner: system_program::id(),
        ..Account::default()
    };
    assert_eq!(
        build_verification_instruction(program, vault, &manifest, 123, Some(&prefunded))?
            .instruction,
        initial.instruction
    );
    Ok(())
}
