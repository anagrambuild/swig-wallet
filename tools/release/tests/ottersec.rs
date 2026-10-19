use anyhow::{Context, Result};
use serde_json::json;
use solana_sdk::pubkey::Pubkey;
use swig_release::{
    ottersec::{decode_attestation, DeployedRelease, SubmissionReceipt},
    verification::VerificationManifest,
};

#[test]
fn submission_receipt_binds_program_source_and_later_deployment() -> Result<()> {
    let manifest: VerificationManifest =
        serde_json::from_str(include_str!("fixtures/verification.json"))?;
    let deployed = DeployedRelease {
        program: Pubkey::new_unique(),
        authority: Pubkey::new_unique(),
        slot: 100,
        executable_hash: manifest.executable_hash.clone(),
    };
    let receipt: SubmissionReceipt = serde_json::from_value(json!({
        "program":deployed.program.to_string(), "source_commit":manifest.commit,
        "verification_observed_deploy_slot":90, "signature":"public-signature",
    }))?;
    assert_eq!(receipt.program, deployed.program);
    receipt.validate(&deployed, &manifest)?;
    for invalid in ["program", "source", "zero-slot", "same-slot", "future-slot"] {
        let mut receipt = SubmissionReceipt {
            program: deployed.program,
            source_commit: manifest.commit.clone(),
            verification_observed_deploy_slot: 90,
        };
        match invalid {
            "program" => receipt.program = Pubkey::new_unique(),
            "source" => receipt.source_commit = "a".repeat(40),
            "zero-slot" => receipt.verification_observed_deploy_slot = 0,
            "same-slot" => receipt.verification_observed_deploy_slot = 100,
            "future-slot" => receipt.verification_observed_deploy_slot = 101,
            _ => {},
        }
        let error = receipt
            .validate(&deployed, &manifest)
            .err()
            .context("Accepted invalid receipt")?;
        assert!(
            error
                .to_string()
                .contains("does not match an executed upgrade"),
            "{invalid}: {error}"
        );
    }
    Ok(())
}

#[test]
fn remote_success_requires_exact_signer_source_and_both_hashes() -> Result<()> {
    let authority = Pubkey::new_unique();
    let manifest: VerificationManifest =
        serde_json::from_str(include_str!("fixtures/verification.json"))?;
    let status = json!({"signer":authority.to_string(),"commit":manifest.commit,
        "is_verified":true,"repo_url":format!("{}/tree/{}",manifest.repository,manifest.commit),
        "executable_hash":manifest.executable_hash,"on_chain_hash":manifest.executable_hash});
    decode_attestation(
        200,
        &serde_json::to_vec(&vec![status.clone()])?,
        authority,
        &manifest,
    )?;
    let mut unsigned = status.clone();
    unsigned["signer"] = json!(null);
    let matched = decode_attestation(
        200,
        &serde_json::to_vec(&vec![unsigned.clone(), status.clone()])?,
        authority,
        &manifest,
    )?;
    assert_eq!(matched.signer, Some(authority));
    assert!(decode_attestation(
        200,
        &serde_json::to_vec(&vec![unsigned.clone()])?,
        authority,
        &manifest,
    )
    .err()
    .context("Accepted unsigned attestation")?
    .to_string()
    .contains("no matching verified attestation"));
    unsigned
        .as_object_mut()
        .context("Expected object")?
        .remove("signer");
    assert!(decode_attestation(
        200,
        &serde_json::to_vec(&vec![unsigned, status.clone()])?,
        authority,
        &manifest,
    )
    .err()
    .context("Accepted missing signer field")?
    .to_string()
    .contains("Malformed OtterSec verification status"));
    for (field, wrong) in [
        ("signer", json!(Pubkey::new_unique().to_string())),
        ("commit", json!("b".repeat(40))),
        ("is_verified", json!(false)),
        ("repo_url", json!(manifest.repository)),
        ("executable_hash", json!("b".repeat(64))),
        ("on_chain_hash", json!("b".repeat(64))),
    ] {
        let mut changed = status.clone();
        changed[field] = wrong;
        assert!(
            decode_attestation(
                200,
                &serde_json::to_vec(&vec![changed.clone()])?,
                authority,
                &manifest
            )
            .is_err(),
            "accepted {field}"
        );
        changed
            .as_object_mut()
            .context("Expected object")?
            .remove(field);
        assert!(
            decode_attestation(
                200,
                &serde_json::to_vec(&vec![changed])?,
                authority,
                &manifest
            )
            .is_err(),
            "accepted missing {field}"
        );
    }
    for (code, body) in [
        (500, b"private-upstream-body".as_slice()),
        (200, b"private-upstream-body".as_slice()),
        (200, b"[]".as_slice()),
    ] {
        let error = decode_attestation(code, body, authority, &manifest)
            .err()
            .context("Accepted failed response")?;
        assert!(!error.to_string().contains("private-upstream-body"));
    }
    Ok(())
}
