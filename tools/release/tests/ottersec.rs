use std::path::Path;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_sdk::{account::Account, pubkey::Pubkey};
use solana_sdk_ids::bpf_loader_upgradeable;
use squads_multisig::solana_rpc_client::{mock_sender::Mocks, nonblocking::rpc_client::RpcClient};
use squads_multisig::solana_rpc_client_api::request::RpcRequest;
use swig_release::{
    devnet::DEVNET_GENESIS_HASH,
    ottersec::{
        check_deployed_release, decode_attestation, submit_ottersec, Cluster, SubmissionReceipt,
        MAINNET_GENESIS_HASH,
    },
    verification::{
        build_verification_instruction, executable_hash, VerificationManifest, VERIFY_PROGRAM,
    },
};

fn rpc_account(account: &Account) -> Value {
    json!({"lamports":account.lamports,"owner":account.owner.to_string(),"executable":account.executable,
        "rentEpoch":0,"data":[STANDARD.encode(&account.data),"base64"]})
}

struct Fixture {
    program: Pubkey,
    authority: Pubkey,
    manifest: VerificationManifest,
    program_account: Account,
    data_account: Account,
    metadata_account: Account,
}

impl Fixture {
    fn new() -> Result<Self> {
        let program = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let binary = b"\x7fELFfixture\0\0";
        let mut manifest: VerificationManifest =
            serde_json::from_str(include_str!("fixtures/verification.json"))?;
        manifest.executable_hash = executable_hash(binary);
        let program_data =
            Pubkey::find_program_address(&[program.as_ref()], &bpf_loader_upgradeable::id()).0;
        let program_account = Account {
            lamports: 10_000_000,
            owner: bpf_loader_upgradeable::id(),
            executable: true,
            data: bincode::serialize(&UpgradeableLoaderState::Program {
                programdata_address: program_data,
            })?,
            rent_epoch: 0,
        };
        let mut data = bincode::serialize(&UpgradeableLoaderState::ProgramData {
            slot: 100,
            upgrade_authority_address: Some(authority),
        })?;
        data.resize(UpgradeableLoaderState::size_of_programdata_metadata(), 0);
        data.extend(binary);
        let data_account = Account {
            lamports: 10_000_000,
            owner: bpf_loader_upgradeable::id(),
            data,
            ..Account::default()
        };
        let metadata = build_verification_instruction(program, authority, &manifest, 90, None)?;
        let mut data = Sha256::digest(b"account:BuildParams")[..8].to_vec();
        data.extend(program.as_ref());
        data.extend(authority.as_ref());
        data.extend(
            metadata
                .instruction
                .data
                .get(8..)
                .context("Missing metadata payload")?,
        );
        data.push(
            Pubkey::find_program_address(
                &[b"otter_verify", authority.as_ref(), program.as_ref()],
                &VERIFY_PROGRAM,
            )
            .1,
        );
        let metadata_account = Account {
            lamports: 10_000_000,
            owner: VERIFY_PROGRAM,
            data,
            ..Account::default()
        };
        Ok(Self {
            program,
            authority,
            manifest,
            program_account,
            data_account,
            metadata_account,
        })
    }

    fn rpc(&self, genesis: &str) -> RpcClient {
        let mut mocks = Mocks::default();
        mocks.insert(RpcRequest::GetGenesisHash, json!(genesis));
        mocks.insert(RpcRequest::GetMultipleAccounts,
            json!({"context":{"slot":110},"value":[rpc_account(&self.program_account),rpc_account(&self.data_account)]}));
        mocks.insert(
            RpcRequest::GetAccountInfo,
            json!({"context":{"slot":110},"value":rpc_account(&self.metadata_account)}),
        );
        RpcClient::new_mock_with_mocks("succeeds".into(), mocks)
    }
}

#[tokio::test]
async fn deployed_release_checks_network_hash_and_program_contract() -> Result<()> {
    let mut fixture = Fixture::new()?;
    for (cluster, genesis) in [
        (Cluster::Mainnet, MAINNET_GENESIS_HASH),
        (Cluster::Devnet, DEVNET_GENESIS_HASH),
    ] {
        let deployed = check_deployed_release(
            &fixture.rpc(genesis),
            fixture.program,
            cluster,
            &fixture.manifest,
        )
        .await?;
        assert_eq!(deployed.authority, fixture.authority);
        assert_eq!(deployed.slot, 100);
        assert_eq!(deployed.executable_hash, fixture.manifest.executable_hash);
    }
    assert!(check_deployed_release(
        &fixture.rpc(DEVNET_GENESIS_HASH),
        fixture.program,
        Cluster::Mainnet,
        &fixture.manifest
    )
    .await
    .is_err());
    fixture.manifest.executable_hash = "a".repeat(64);
    assert!(check_deployed_release(
        &fixture.rpc(MAINNET_GENESIS_HASH),
        fixture.program,
        Cluster::Mainnet,
        &fixture.manifest
    )
    .await
    .is_err());
    fixture = Fixture::new()?;
    fixture.program_account.executable = false;
    assert!(check_deployed_release(
        &fixture.rpc(MAINNET_GENESIS_HASH),
        fixture.program,
        Cluster::Mainnet,
        &fixture.manifest
    )
    .await
    .is_err());
    fixture = Fixture::new()?;
    fixture.data_account.owner = Pubkey::new_unique();
    assert!(check_deployed_release(
        &fixture.rpc(MAINNET_GENESIS_HASH),
        fixture.program,
        Cluster::Mainnet,
        &fixture.manifest
    )
    .await
    .is_err());
    Ok(())
}

#[tokio::test]
async fn receipt_and_metadata_rejections_happen_before_remote_submission() -> Result<()> {
    let temp = tempfile::tempdir()?;
    for invalid in [
        "commit",
        "program",
        "zero-slot",
        "unexecuted",
        "metadata",
        "metadata-owner",
        "devnet",
    ] {
        let mut fixture = Fixture::new()?;
        let mut receipt = SubmissionReceipt {
            program: fixture.program,
            source_commit: fixture.manifest.commit.clone(),
            verification_observed_deploy_slot: 90,
        };
        match invalid {
            "commit" => receipt.source_commit = "a".repeat(40),
            "program" => receipt.program = Pubkey::new_unique(),
            "zero-slot" => receipt.verification_observed_deploy_slot = 0,
            "unexecuted" => receipt.verification_observed_deploy_slot = 100,
            "metadata" => fixture.metadata_account.data[80] ^= 1,
            "metadata-owner" => fixture.metadata_account.owner = Pubkey::new_unique(),
            _ => {},
        }
        let genesis = if invalid == "devnet" {
            DEVNET_GENESIS_HASH
        } else {
            MAINNET_GENESIS_HASH
        };
        let error = submit_ottersec(
            &fixture.rpc(genesis),
            fixture.program,
            &fixture.manifest,
            &receipt,
            Path::new("/does-not-exist/solana-verify"),
            temp.path(),
        )
        .await
        .err()
        .context("Accepted invalid release")?;
        assert!(
            !error.to_string().contains("Could not start"),
            "{invalid} reached the CLI: {error:#}"
        );
        assert!(
            !temp.path().join("deployed-release.json").exists(),
            "{invalid} passed local validation"
        );
    }
    Ok(())
}

#[test]
fn remote_success_requires_exact_signer_source_and_both_hashes() -> Result<()> {
    let fixture = Fixture::new()?;
    // ProposalReceipt writes public keys as base58 strings, not SDK serde arrays.
    let receipt: SubmissionReceipt = serde_json::from_value(json!({
        "program":fixture.program.to_string(), "source_commit":fixture.manifest.commit,
        "verification_observed_deploy_slot":90, "signature":"public-signature",
    }))?;
    assert_eq!(receipt.program, fixture.program);
    let status = json!({"signer":fixture.authority.to_string(),"commit":fixture.manifest.commit,
        "is_verified":true,"repo_url":format!("{}/tree/{}",fixture.manifest.repository,fixture.manifest.commit),
        "executable_hash":fixture.manifest.executable_hash,"on_chain_hash":fixture.manifest.executable_hash});
    decode_attestation(
        200,
        &serde_json::to_vec(&vec![status.clone()])?,
        fixture.authority,
        &fixture.manifest,
    )?;
    for (field, wrong) in [
        ("signer", json!(Pubkey::new_unique().to_string())),
        ("commit", json!("b".repeat(40))),
        ("is_verified", json!(false)),
        ("repo_url", json!(fixture.manifest.repository)),
        ("executable_hash", json!("b".repeat(64))),
        ("on_chain_hash", json!("b".repeat(64))),
    ] {
        let mut changed = status.clone();
        changed[field] = wrong;
        assert!(
            decode_attestation(
                200,
                &serde_json::to_vec(&vec![changed.clone()])?,
                fixture.authority,
                &fixture.manifest
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
                fixture.authority,
                &fixture.manifest
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
        let error = decode_attestation(code, body, fixture.authority, &fixture.manifest)
            .err()
            .context("Accepted failed response")?;
        assert!(!error.to_string().contains("private-upstream-body"));
    }
    Ok(())
}
