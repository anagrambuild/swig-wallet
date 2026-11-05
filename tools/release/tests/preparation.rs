use std::{
    collections::VecDeque,
    fs,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_loader_v3_interface::{instruction, state::UpgradeableLoaderState};
use solana_sdk::{
    account::Account,
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use solana_sdk_ids::{bpf_loader_upgradeable, system_program};
use squads_multisig::{
    anchor_lang::AccountSerialize,
    pda::{get_multisig_pda, get_vault_pda},
    solana_rpc_client::{
        mock_sender::{MockSender, Mocks},
        nonblocking::rpc_client::RpcClient,
        rpc_client::RpcClientConfig,
        rpc_sender::{RpcSender, RpcTransportStats},
    },
    solana_rpc_client_api::{client_error::Result as RpcResult, request::RpcRequest},
    state::{Member, Multisig, Permission, Permissions},
};
use swig_release::{
    config::ReleaseConfig,
    release,
    verification::{
        build_verification_instruction, executable_hash, VerificationManifest, VERIFY_PROGRAM,
    },
};

struct TestRpc {
    inner: MockSender,
    reads: Mutex<VecDeque<Value>>,
    requests: Arc<Mutex<Vec<(RpcRequest, Value)>>>,
    status: Value,
    fail_on: Option<RpcRequest>,
}

#[async_trait]
impl RpcSender for TestRpc {
    async fn send(&self, request: RpcRequest, params: Value) -> RpcResult<Value> {
        self.requests
            .lock()
            .unwrap()
            .push((request, params.clone()));
        if self.fail_on == Some(request) {
            return Err(std::io::Error::other("private-rpc-credential").into());
        }
        match request {
            RpcRequest::GetMultipleAccounts => Ok(self
                .reads
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected account read")),
            RpcRequest::GetSignatureStatuses => Ok(self.status.clone()),
            _ => self.inner.send(request, params).await,
        }
    }
    fn get_transport_stats(&self) -> RpcTransportStats {
        RpcTransportStats::default()
    }
    fn url(&self) -> String {
        "https://rpc.invalid/private-rpc-credential".into()
    }
}

struct Fixture {
    config: ReleaseConfig,
    proposer: Keypair,
    program: Account,
    data: Account,
    multisig: Account,
    metadata: Account,
    payer: Account,
    binary: Vec<u8>,
    manifest: VerificationManifest,
    requests: Arc<Mutex<Vec<(RpcRequest, Value)>>>,
}

impl Fixture {
    fn new(binary_len: usize, capacity: usize) -> Result<Self> {
        let proposer = Keypair::new();
        let squads_program = Pubkey::new_unique();
        let create_key = Pubkey::new_unique();
        let (multisig, bump) = get_multisig_pda(&create_key, Some(&squads_program));
        let config = ReleaseConfig {
            rpc_url: "https://rpc.invalid/private-rpc-credential".into(),
            squads_program,
            multisig,
            vault_index: 3,
            program: Pubkey::new_unique(),
        };
        let vault = get_vault_pda(&multisig, 3, Some(&squads_program)).0;
        let payer = Account {
            lamports: 1_000_000_000,
            data: vec![],
            owner: system_program::id(),
            executable: false,
            rent_epoch: 0,
        };
        let program = Account {
            owner: bpf_loader_upgradeable::id(),
            executable: true,
            data: bincode::serialize(&UpgradeableLoaderState::Program {
                programdata_address: Pubkey::find_program_address(
                    &[config.program.as_ref()],
                    &bpf_loader_upgradeable::id(),
                )
                .0,
            })?,
            ..payer.clone()
        };
        let mut data = bincode::serialize(&UpgradeableLoaderState::ProgramData {
            slot: 42,
            upgrade_authority_address: Some(vault),
        })?;
        data.resize(UpgradeableLoaderState::size_of_programdata(capacity), 0);
        let data = Account {
            data,
            executable: false,
            ..program.clone()
        };
        let multisig = Multisig {
            create_key,
            config_authority: Pubkey::default(),
            threshold: 1,
            time_lock: 0,
            transaction_index: 7,
            stale_transaction_index: 0,
            rent_collector: None,
            bump,
            members: vec![Member {
                key: proposer.pubkey(),
                permissions: Permissions::from_vec(&[
                    Permission::Initiate,
                    Permission::Vote,
                    Permission::Execute,
                ]),
            }],
        };
        let mut bytes = Vec::new();
        multisig.try_serialize(&mut bytes)?;
        let multisig = Account {
            data: bytes,
            owner: squads_program,
            ..payer.clone()
        };
        let mut binary = b"\x7fELFtest".to_vec();
        binary.resize(binary_len, 0);
        let mut manifest: VerificationManifest =
            serde_json::from_str(include_str!("fixtures/verification.json"))?;
        manifest.executable_hash = executable_hash(&binary);
        let initial = build_verification_instruction(config.program, vault, &manifest, 42, None)?;
        let bump = Pubkey::find_program_address(
            &[b"otter_verify", vault.as_ref(), config.program.as_ref()],
            &VERIFY_PROGRAM,
        )
        .1;
        let mut bytes = Sha256::digest(b"account:BuildParams")[..8].to_vec();
        bytes.extend(config.program.as_ref());
        bytes.extend(vault.as_ref());
        bytes.extend(initial.instruction.data.get(8..).context("metadata")?);
        bytes.push(bump);
        let metadata = Account {
            data: bytes,
            owner: VERIFY_PROGRAM,
            ..payer.clone()
        };
        Ok(Self {
            config,
            proposer,
            program,
            data,
            multisig,
            metadata,
            payer,
            binary,
            manifest,
            requests: Arc::default(),
        })
    }

    fn reads(&self) -> Vec<Value> {
        let executable = Account {
            executable: true,
            ..Account::default()
        };
        let vault = Account {
            lamports: 1_000_000_000,
            ..self.payer.clone()
        };
        vec![
            account_response(&[
                executable.clone(),
                self.metadata.clone(),
                vault,
                self.data.clone(),
            ]),
            account_response(&[
                self.program.clone(),
                self.data.clone(),
                self.multisig.clone(),
                executable,
                self.payer.clone(),
            ]),
        ]
    }

    fn rpc(&self, reads: Vec<Value>, status: Value, fail_on: Option<RpcRequest>) -> RpcClient {
        RpcClient::new_sender(
            TestRpc {
                inner: MockSender::new_with_mocks("succeeds", Mocks::default()),
                reads: Mutex::new(reads.into()),
                requests: self.requests.clone(),
                status,
                fail_on,
            },
            RpcClientConfig::with_commitment(CommitmentConfig::confirmed()),
        )
    }

    fn expand(&mut self, additional: usize) -> Result<()> {
        self.data.data.resize(self.data.data.len() + additional, 0);
        let vault = get_vault_pda(
            &self.config.multisig,
            self.config.vault_index,
            Some(&self.config.squads_program),
        )
        .0;
        let header = bincode::serialize(&UpgradeableLoaderState::ProgramData {
            slot: 50,
            upgrade_authority_address: Some(vault),
        })?;
        self.data.data[..header.len()].copy_from_slice(&header);
        Ok(())
    }
}

fn account_response(accounts: &[Account]) -> Value {
    json!({"context":{"slot":50},"value":accounts.iter().map(|account| json!({
        "lamports":account.lamports,"owner":account.owner.to_string(),"executable":account.executable,
        "rentEpoch":account.rent_epoch,"data":[STANDARD.encode(&account.data),"base64"],
    })).collect::<Vec<_>>()})
}

fn confirmed() -> Value {
    json!({"context":{"slot":50},"value":[{"slot":50,"confirmations":1,"err":null,"status":{"Ok":null},"confirmationStatus":"confirmed"}]})
}

#[tokio::test]
async fn read_only_preflight_budgets_rounded_extension_rent_and_all_remaining_costs() -> Result<()>
{
    for (data_balance, payer_balance, extension_rent, succeeds) in [
        (7, 200_000_073, 13, true),
        (7, 200_000_072, 13, false),
        (20, 200_000_060, 0, true),
        (21, 200_000_060, 0, true),
    ] {
        let mut fixture = Fixture::new(139_276, 100)?;
        fixture.data.lamports = data_balance;
        fixture.payer.lamports = payer_balance;
        let rpc = fixture.rpc(fixture.reads(), confirmed(), None);
        let result = release::check(
            &rpc,
            &fixture.config,
            &fixture.proposer,
            &fixture.binary,
            &fixture.manifest,
        )
        .await;
        if succeeds {
            let receipt = result?;
            assert_eq!(receipt.additional_bytes_required, 139_176);
            assert_eq!(receipt.program_extension_bytes, 143_360);
            assert_eq!(receipt.program_extension_rent_lamports, extension_rent);
            assert_eq!(receipt.extension_fee_reserve_lamports, 100_000_000);
            assert_eq!(
                receipt.minimum_proposer_balance_lamports,
                200_000_060 + extension_rent
            );
        } else {
            assert!(result
                .err()
                .context("expected rejection")?
                .to_string()
                .starts_with("Proposer needs at least 200000073 lamports"));
        }
        let requests = fixture.requests.lock().unwrap();
        assert!(requests.iter().any(|(request, params)| *request
            == RpcRequest::GetMinimumBalanceForRentExemption
            && params[0] == json!(UpgradeableLoaderState::size_of_programdata(143_460))));
        assert!(!requests
            .iter()
            .any(|(request, _)| *request == RpcRequest::SendTransaction));
    }
    Ok(())
}

#[tokio::test]
async fn preparation_extends_with_proposer_and_refreshes_slot_bound_preflight() -> Result<()> {
    let mut fixture = Fixture::new(110, 100)?;
    let before = fixture.reads();
    let before_rpc = fixture.rpc(before.clone(), confirmed(), None);
    let saved = release::check(
        &before_rpc,
        &fixture.config,
        &fixture.proposer,
        &fixture.binary,
        &fixture.manifest,
    )
    .await?;
    fixture.requests.lock().unwrap().clear();
    fixture.expand(10_240)?;
    let mut reads = before;
    reads.extend(fixture.reads());
    let rpc = fixture.rpc(reads, confirmed(), None);
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("preparation");
    let receipt = release::prepare(
        &rpc,
        &fixture.config,
        &fixture.proposer,
        &fixture.binary,
        &fixture.manifest,
        &output,
    )
    .await?;
    assert_eq!(receipt.program_capacity_bytes, 10_340);
    assert_eq!(receipt.program_extension_bytes, 0);
    assert_eq!(receipt.additional_bytes_required, 0);
    assert_eq!(receipt.program_extension_rent_lamports, 0);
    assert_eq!(receipt.minimum_proposer_balance_lamports, 100_000_060);
    assert_ne!(
        receipt.verification_instruction_sha256,
        saved.verification_instruction_sha256
    );
    let fresh_rpc = fixture.rpc(fixture.reads(), confirmed(), None);
    let fresh = release::check(
        &fresh_rpc,
        &fixture.config,
        &fixture.proposer,
        &fixture.binary,
        &fixture.manifest,
    )
    .await?;
    release::validate_preflight(&receipt, &fresh)?;
    let extension: Value =
        serde_json::from_slice(&fs::read(output.join("extension-receipt.json"))?)?;
    assert_eq!(extension["previous_capacity_bytes"], 100);
    assert_eq!(extension["additional_bytes"], 10_240);
    assert_eq!(extension["program_capacity_bytes"], 10_340);
    assert_eq!(
        fs::read_to_string(output.join("extension-signature.txt"))?.trim(),
        extension["signature"].as_str().context("signature")?
    );
    let requests = fixture.requests.lock().unwrap();
    let sends: Vec<_> = requests
        .iter()
        .filter(|(request, _)| *request == RpcRequest::SendTransaction)
        .collect();
    assert_eq!(sends.len(), 1);
    let params = &sends[0].1;
    let tx: Transaction =
        bincode::deserialize(&STANDARD.decode(params[0].as_str().context("transaction")?)?)?;
    tx.verify()?;
    assert_eq!(
        tx.message,
        solana_sdk::message::Message::new_with_blockhash(
            &[instruction::extend_program(
                &fixture.config.program,
                Some(&fixture.proposer.pubkey()),
                10_240
            )],
            Some(&fixture.proposer.pubkey()),
            &tx.message.recent_blockhash
        )
    );
    assert_eq!(tx.signatures.len(), 1);
    assert_eq!(params[1]["skipPreflight"], false);
    assert_eq!(params[1]["preflightCommitment"], "confirmed");
    assert_eq!(params[1]["maxRetries"], 0);
    let confirmation = requests
        .iter()
        .position(|(request, _)| *request == RpcRequest::GetSignatureStatuses)
        .context("confirmation")?;
    let post_reads = requests
        .iter()
        .enumerate()
        .filter(|(i, (request, _))| {
            *i > confirmation && *request == RpcRequest::GetMultipleAccounts
        })
        .count();
    assert_eq!(post_reads, 4); // refreshed preflight plus independent proposal preflight
    Ok(())
}

#[tokio::test]
async fn preparation_is_a_noop_when_live_capacity_is_sufficient() -> Result<()> {
    for capacity in [100, 10_340] {
        let fixture = Fixture::new(100, capacity)?;
        let rpc = fixture.rpc(fixture.reads(), confirmed(), None);
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("preparation");
        let receipt = release::prepare(
            &rpc,
            &fixture.config,
            &fixture.proposer,
            &fixture.binary,
            &fixture.manifest,
            &output,
        )
        .await?;
        assert_eq!(receipt.program_extension_bytes, 0);
        assert_eq!(receipt.extension_fee_reserve_lamports, 0);
        assert_eq!(receipt.minimum_proposer_balance_lamports, 100_000_060);
        assert_eq!(fs::read_dir(output)?.count(), 0);
        assert!(!fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|(request, _)| *request == RpcRequest::SendTransaction));
    }
    Ok(())
}

#[tokio::test]
async fn preparation_validates_funding_authority_and_metadata_before_submission() -> Result<()> {
    for scenario in [
        "funding",
        "authority",
        "program-owner",
        "metadata-owner",
        "manifest",
        "existing-output",
    ] {
        let mut fixture = Fixture::new(110, 100)?;
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("preparation");
        let expected = match scenario {
            "funding" => {
                fixture.payer.lamports = 200_000_059;
                "Proposer needs at least 200000060 lamports"
            },
            "authority" => {
                let header = bincode::serialize(&UpgradeableLoaderState::ProgramData {
                    slot: 42,
                    upgrade_authority_address: Some(fixture.proposer.pubkey()),
                })?;
                fixture.data.data[..header.len()].copy_from_slice(&header);
                "Verification signer must be the program upgrade authority"
            },
            "program-owner" => {
                fixture.program.owner = system_program::id();
                "SWIG_PROGRAM_ID must be an executable loader-v3 program"
            },
            "metadata-owner" => {
                fixture.metadata.owner = system_program::id();
                "Verification PDA has an incorrect owner or executable flag"
            },
            "manifest" => {
                fixture.manifest.executable_hash = "bad".into();
                "Verification manifest executable hash does not match the binary"
            },
            _ => {
                fs::create_dir(&output)?;
                fs::write(output.join("extension-signature.txt"), "old-signature")?;
                "Output directory must be new"
            },
        };
        let rpc = fixture.rpc(fixture.reads(), confirmed(), None);
        let error = release::prepare(
            &rpc,
            &fixture.config,
            &fixture.proposer,
            &fixture.binary,
            &fixture.manifest,
            &output,
        )
        .await
        .err()
        .context("expected rejection")?
        .to_string();
        assert!(error.starts_with(expected), "{scenario}: {error}");
        assert!(!fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|(request, _)| *request == RpcRequest::SendTransaction));
        if scenario == "existing-output" {
            assert!(fixture.requests.lock().unwrap().is_empty());
            assert_eq!(
                fs::read_to_string(output.join("extension-signature.txt"))?,
                "old-signature"
            );
        } else {
            assert_eq!(fs::read_dir(output)?.count(), 0);
        }
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn failed_uncertain_or_unverified_extension_keeps_recovery_signature_and_stops() -> Result<()>
{
    for scenario in [
        "send-failure",
        "onchain-failure",
        "timeout",
        "processed-only",
        "unchanged-capacity",
        "spent-funds",
        "changed-authority",
    ] {
        let mut fixture = Fixture::new(110, 100)?;
        let mut reads = fixture.reads();
        fixture.expand(10_240)?;
        let mut status = confirmed();
        let mut fail_on = None;
        let expected = match scenario {
            "send-failure" => {
                fail_on = Some(RpcRequest::SendTransaction);
                "submission failed or is uncertain"
            },
            "onchain-failure" => {
                status["value"][0]["err"] = json!("AccountNotFound");
                status["value"][0]["status"] = json!({"Err":"AccountNotFound"});
                "failed on-chain"
            },
            "timeout" => {
                status["value"][0] = Value::Null;
                "confirmation timed out"
            },
            "processed-only" => {
                status["value"][0]["confirmationStatus"] = json!("processed");
                status["value"][0]["confirmations"] = json!(0);
                "confirmation timed out"
            },
            "unchanged-capacity" => {
                fixture
                    .data
                    .data
                    .truncate(UpgradeableLoaderState::size_of_programdata(100));
                "allocated capacity is below the target"
            },
            "spent-funds" => {
                fixture.payer.lamports = 100_000_059;
                "Proposer needs at least 100000060 lamports"
            },
            _ => {
                let header = bincode::serialize(&UpgradeableLoaderState::ProgramData {
                    slot: 50,
                    upgrade_authority_address: Some(Pubkey::new_unique()),
                })?;
                fixture.data.data[..header.len()].copy_from_slice(&header);
                "Verification signer must be the program upgrade authority"
            },
        };
        reads.extend(fixture.reads());
        let rpc = fixture.rpc(reads, status, fail_on);
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("preparation");
        let error = release::prepare(
            &rpc,
            &fixture.config,
            &fixture.proposer,
            &fixture.binary,
            &fixture.manifest,
            &output,
        )
        .await
        .err()
        .context("expected rejection")?
        .to_string();
        assert!(error.contains(expected), "{scenario}: {error}");
        assert!(!error.contains("private-rpc-credential"));
        assert!(output.join("extension-signature.txt").exists());
        assert_eq!(fs::read_dir(output)?.count(), 1);
        let requests = fixture.requests.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|(request, _)| *request == RpcRequest::SendTransaction)
                .count(),
            1
        );
        if matches!(
            scenario,
            "send-failure" | "onchain-failure" | "timeout" | "processed-only"
        ) {
            assert_eq!(
                requests
                    .iter()
                    .filter(|(request, _)| *request == RpcRequest::GetMultipleAccounts)
                    .count(),
                2
            );
        }
    }
    Ok(())
}
