use std::{
    collections::VecDeque,
    fs,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
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
    solana_rpc_client::{
        mock_sender::{MockSender, Mocks},
        nonblocking::rpc_client::RpcClient,
        rpc_client::RpcClientConfig,
        rpc_sender::{RpcSender, RpcTransportStats},
    },
    solana_rpc_client_api::{client_error::Result as RpcResult, request::RpcRequest},
};
use swig_release::{
    config::DevnetConfig,
    devnet::{self, DeploymentRequest, DevnetCheckReceipt, DEVNET_GENESIS_HASH},
};

struct TestRpc {
    inner: MockSender,
    genesis_hash: Value,
    account_reads: Mutex<VecDeque<Value>>,
    requests: Arc<Mutex<Vec<(RpcRequest, Value)>>>,
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
        if request == RpcRequest::GetGenesisHash {
            return Ok(self.genesis_hash.clone());
        }
        if request == RpcRequest::GetMultipleAccounts {
            return Ok(self
                .account_reads
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected account read"));
        }
        self.inner.send(request, params).await
    }

    fn get_transport_stats(&self) -> RpcTransportStats {
        RpcTransportStats::default()
    }
    fn url(&self) -> String {
        "https://rpc.invalid/private-rpc-credential".into()
    }
}

struct Fixture {
    config: DevnetConfig,
    authority: Keypair,
    buffer_key: Pubkey,
    program: Account,
    data: Account,
    buffer: Account,
    payer: Account,
    binary: Vec<u8>,
    requests: Arc<Mutex<Vec<(RpcRequest, Value)>>>,
}

impl Fixture {
    fn new() -> Result<Self> {
        let config = DevnetConfig {
            rpc_url: "https://rpc.invalid/private-rpc-credential".into(),
            program: solana_sdk::pubkey!("swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB"),
        };
        let authority = Keypair::new();
        let binary = b"\x7fELFdevnet".to_vec();
        let data_address =
            Pubkey::find_program_address(&[config.program.as_ref()], &bpf_loader_upgradeable::id())
                .0;
        let program = Account {
            lamports: 1_000_000_000,
            owner: bpf_loader_upgradeable::id(),
            executable: true,
            rent_epoch: 0,
            data: bincode::serialize(&UpgradeableLoaderState::Program {
                programdata_address: data_address,
            })?,
        };
        let mut data = bincode::serialize(&UpgradeableLoaderState::ProgramData {
            slot: 42,
            upgrade_authority_address: Some(authority.pubkey()),
        })?;
        data.resize(
            UpgradeableLoaderState::size_of_programdata(binary.len() + 8),
            0,
        );
        let data = Account {
            data,
            executable: false,
            ..program.clone()
        };
        let mut buffer_data = bincode::serialize(&UpgradeableLoaderState::Buffer {
            authority_address: Some(authority.pubkey()),
        })?;
        buffer_data.extend_from_slice(&binary);
        let buffer = Account {
            data: buffer_data,
            executable: false,
            ..program.clone()
        };
        let payer = Account {
            lamports: 1_000_000_000,
            data: vec![],
            owner: system_program::id(),
            executable: false,
            rent_epoch: 0,
        };
        Ok(Self {
            config,
            authority,
            buffer_key: Pubkey::new_unique(),
            program,
            data,
            buffer,
            payer,
            binary,
            requests: Arc::default(),
        })
    }

    fn rpc(
        &self,
        account_reads: Vec<Value>,
        mut mocks: Mocks,
        fail_on: Option<RpcRequest>,
    ) -> RpcClient {
        let genesis_hash = mocks
            .remove(&RpcRequest::GetGenesisHash)
            .unwrap_or(json!(DEVNET_GENESIS_HASH));
        RpcClient::new_sender(
            TestRpc {
                inner: MockSender::new_with_mocks("succeeds", mocks),
                genesis_hash,
                account_reads: Mutex::new(account_reads.into()),
                requests: self.requests.clone(),
                fail_on,
            },
            RpcClientConfig::with_commitment(CommitmentConfig::finalized()),
        )
    }

    fn request(&self) -> DeploymentRequest {
        DeploymentRequest {
            buffer: self.buffer_key,
            source_commit: "a".repeat(40),
            tag: "devnet-upgrade-1-aaaaaaaaaaaa".into(),
        }
    }

    fn deployed_data(&self) -> Account {
        let mut data = self.data.clone();
        let offset = UpgradeableLoaderState::size_of_programdata_metadata();
        data.data[offset..offset + self.binary.len()].copy_from_slice(&self.binary);
        data
    }
}

fn account_response(accounts: &[Account]) -> Value {
    json!({"context": {"slot": 50}, "value": accounts.iter().map(|account| json!({
        "lamports": account.lamports, "owner": account.owner.to_string(), "executable": account.executable,
        "rentEpoch": account.rent_epoch, "data": [STANDARD.encode(&account.data), "base64"],
    })).collect::<Vec<_>>()})
}

#[tokio::test]
async fn preflight_checks_devnet_program_authority_capacity_and_funding() -> Result<()> {
    let fixture = Fixture::new()?;
    let rpc = fixture.rpc(
        vec![account_response(&[
            fixture.program.clone(),
            fixture.data.clone(),
            fixture.payer.clone(),
        ])],
        Mocks::default(),
        None,
    );
    let receipt = devnet::check(&rpc, &fixture.config, &fixture.authority, &fixture.binary).await?;
    assert_eq!(receipt.program, fixture.config.program);
    assert_eq!(receipt.authority, fixture.authority.pubkey());
    assert_eq!(receipt.program_capacity_bytes, fixture.binary.len() + 8);
    assert_eq!(receipt.additional_program_bytes, 0);
    assert_eq!(receipt.program_extension_rent_lamports, 0);
    assert_eq!(receipt.minimum_authority_balance_lamports, 100_000_020);
    assert!(!fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|(request, _)| *request == RpcRequest::SendTransaction));
    Ok(())
}

#[tokio::test]
async fn preflight_rejects_wrong_cluster_before_account_reads() -> Result<()> {
    let fixture = Fixture::new()?;
    let rpc = fixture.rpc(
        vec![],
        Mocks::from([(
            RpcRequest::GetGenesisHash,
            json!(Pubkey::new_unique().to_string()),
        )]),
        None,
    );
    let error = devnet::check(&rpc, &fixture.config, &fixture.authority, &fixture.binary)
        .await
        .err()
        .context("expected rejection")?;
    assert_eq!(
        error.to_string(),
        "SOLANA_RPC_URL must point to Solana devnet"
    );
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    Ok(())
}

#[tokio::test]
async fn preflight_rejects_invalid_authority_and_funding() -> Result<()> {
    for scenario in ["authority", "payer-owner", "payer-balance"] {
        let mut fixture = Fixture::new()?;
        let expected = match scenario {
            "authority" => {
                fixture.authority = Keypair::new();
                "Program upgrade authority does not match the expected authority"
            },
            "payer-owner" => {
                fixture.payer.owner = Pubkey::new_unique();
                "Program authority must be a funded System account"
            },
            _ => {
                fixture.payer.lamports = 0;
                "Program authority needs at least 100000020 lamports"
            },
        };
        let rpc = fixture.rpc(
            vec![account_response(&[
                fixture.program.clone(),
                fixture.data.clone(),
                fixture.payer.clone(),
            ])],
            Mocks::default(),
            None,
        );
        let error = devnet::check(&rpc, &fixture.config, &fixture.authority, &fixture.binary)
            .await
            .err()
            .context("expected rejection")?;
        assert!(error.to_string().starts_with(expected), "{error}");
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
async fn saved_preflight_binds_program_signer_binary_and_capacity() -> Result<()> {
    let fixture = Fixture::new()?;
    let rpc = fixture.rpc(
        vec![account_response(&[
            fixture.program.clone(),
            fixture.data.clone(),
            fixture.payer.clone(),
        ])],
        Mocks::default(),
        None,
    );
    let receipt = devnet::check(&rpc, &fixture.config, &fixture.authority, &fixture.binary).await?;
    devnet::validate_preflight(&receipt, &receipt)?;
    for (field, value, expected) in [
        (
            "program",
            json!(Pubkey::new_unique()),
            "Preflight deployment or authority",
        ),
        (
            "authority",
            json!(Pubkey::new_unique()),
            "Preflight deployment or authority",
        ),
        ("binary_bytes", json!(1), "Preflight binary"),
        ("binary_sha256", json!("wrong-hash"), "Preflight binary"),
        (
            "program_capacity_bytes",
            json!(1),
            "Program capacity changed",
        ),
    ] {
        let mut changed = serde_json::to_value(&receipt)?;
        changed[field] = value;
        let changed: DevnetCheckReceipt = serde_json::from_value(changed)?;
        let error = devnet::validate_preflight(&receipt, &changed)
            .err()
            .context("expected rejection")?;
        assert!(error.to_string().starts_with(expected));
    }
    Ok(())
}

#[tokio::test]
async fn deploy_signs_upgrade_directly_and_verifies_finalized_bytes() -> Result<()> {
    let fixture = Fixture::new()?;
    let output = tempfile::tempdir()?;
    let rpc = fixture.rpc(
        vec![
            account_response(&[
                fixture.program.clone(),
                fixture.data.clone(),
                fixture.buffer.clone(),
            ]),
            account_response(&[fixture.program.clone(), fixture.deployed_data()]),
        ],
        Mocks::default(),
        None,
    );
    let receipt = devnet::deploy(
        &rpc,
        &fixture.config,
        &fixture.authority,
        &fixture.binary,
        fixture.request(),
        output.path(),
    )
    .await?;
    assert_eq!(receipt.authority, fixture.authority.pubkey());
    assert_eq!(receipt.program, fixture.config.program);
    assert_eq!(receipt.genesis_hash, DEVNET_GENESIS_HASH);
    assert_eq!(
        fs::read_to_string(output.path().join("transaction-signature.txt"))?.trim(),
        receipt.signature
    );
    let requests = fixture.requests.lock().unwrap();
    let (_, params) = requests
        .iter()
        .find(|(request, _)| *request == RpcRequest::SendTransaction)
        .context("missing transaction")?;
    let encoded = params
        .get(0)
        .and_then(Value::as_str)
        .context("missing encoded transaction")?;
    let transaction: Transaction = bincode::deserialize(&STANDARD.decode(encoded)?)?;
    transaction.verify()?;
    let upgrade = instruction::upgrade(
        &fixture.config.program,
        &fixture.buffer_key,
        &fixture.authority.pubkey(),
        &fixture.authority.pubkey(),
    );
    assert_eq!(
        transaction.message,
        solana_sdk::message::Message::new_with_blockhash(
            &[upgrade],
            Some(&fixture.authority.pubkey()),
            &transaction.message.recent_blockhash
        )
    );
    assert_eq!(transaction.signatures.len(), 1);
    assert_eq!(params[1]["skipPreflight"], false);
    assert_eq!(params[1]["preflightCommitment"], "finalized");
    assert!(requests
        .iter()
        .filter(|(request, _)| *request == RpcRequest::GetMultipleAccounts)
        .all(|(_, params)| params[1]["commitment"] == "finalized"));
    Ok(())
}

#[tokio::test]
async fn deploy_revalidates_cluster_authority_and_buffer_before_submission() -> Result<()> {
    for scenario in ["cluster", "authority", "buffer-bytes", "buffer-rent"] {
        let mut fixture = Fixture::new()?;
        let mut mocks = Mocks::default();
        let expected = match scenario {
            "cluster" => {
                mocks.insert(
                    RpcRequest::GetGenesisHash,
                    json!(Pubkey::new_unique().to_string()),
                );
                "SOLANA_RPC_URL must point to Solana devnet"
            },
            "authority" => {
                fixture.authority = Keypair::new();
                "Program upgrade authority does not match the expected authority"
            },
            "buffer-bytes" => {
                *fixture
                    .buffer
                    .data
                    .last_mut()
                    .context("missing buffer payload")? ^= 1;
                "Uploaded buffer contents do not match the built binary"
            },
            _ => {
                fixture.buffer.lamports = 0;
                "Buffer must be rent exempt"
            },
        };
        let rpc = fixture.rpc(
            vec![account_response(&[
                fixture.program.clone(),
                fixture.data.clone(),
                fixture.buffer.clone(),
            ])],
            mocks,
            None,
        );
        let output = tempfile::tempdir()?;
        let error = devnet::deploy(
            &rpc,
            &fixture.config,
            &fixture.authority,
            &fixture.binary,
            fixture.request(),
            output.path(),
        )
        .await
        .err()
        .context("expected rejection")?;
        assert_eq!(error.to_string(), expected);
        assert!(!fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|(request, _)| *request == RpcRequest::SendTransaction));
        assert_eq!(fs::read_dir(output.path())?.count(), 0);
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn failed_uncertain_and_unverified_upgrades_keep_the_transaction_receipt() -> Result<()> {
    for scenario in [
        "send-failure",
        "onchain-failure",
        "confirmation-timeout",
        "wrong-binary",
        "read-failure",
        "changed-authority",
    ] {
        let fixture = Fixture::new()?;
        let mut mocks = Mocks::default();
        let mut deployed_data = fixture.deployed_data();
        let mut fail_on = None;
        let expected = match scenario {
            "send-failure" => {
                fail_on = Some(RpcRequest::SendTransaction);
                "Upgrade submission failed or is uncertain"
            },
            "onchain-failure" => {
                mocks.insert(RpcRequest::GetSignatureStatuses, json!({"context":{"slot":50},"value":[{"slot":50,"confirmations":null,"err":"AccountNotFound","status":{"Err":"AccountNotFound"},"confirmationStatus":"finalized"}]}));
                "failed on-chain"
            },
            "confirmation-timeout" => {
                // Keep every status query pending while Tokio advances the clock.
                "confirmation timed out"
            },
            "changed-authority" => {
                let metadata = bincode::serialize(&UpgradeableLoaderState::ProgramData {
                    slot: 50,
                    upgrade_authority_address: Some(Pubkey::new_unique()),
                })?;
                deployed_data.data[..metadata.len()].copy_from_slice(&metadata);
                "Program upgrade authority does not match"
            },
            "read-failure" => "Could not get accounts",
            _ => {
                *deployed_data.data.last_mut().context("missing padding")? = 1;
                "Deployed program bytes do not match"
            },
        };
        let mut accounts = vec![account_response(&[
            fixture.program.clone(),
            fixture.data.clone(),
            fixture.buffer.clone(),
        ])];
        accounts.push(if scenario == "read-failure" {
            Value::Null
        } else {
            account_response(&[fixture.program.clone(), deployed_data])
        });
        let rpc = if scenario == "confirmation-timeout" {
            RpcClient::new_sender(
                TestRpc {
                    inner: MockSender::new_with_mocks("sig_not_found", mocks),
                    genesis_hash: json!(DEVNET_GENESIS_HASH),
                    account_reads: Mutex::new(accounts.into()),
                    requests: fixture.requests.clone(),
                    fail_on,
                },
                RpcClientConfig::with_commitment(CommitmentConfig::finalized()),
            )
        } else {
            fixture.rpc(accounts, mocks, fail_on)
        };
        let output = tempfile::tempdir()?;
        let error = devnet::deploy(
            &rpc,
            &fixture.config,
            &fixture.authority,
            &fixture.binary,
            fixture.request(),
            output.path(),
        )
        .await
        .err()
        .context("expected rejection")?;
        let error = error.to_string();
        if scenario == "read-failure" {
            assert!(
                error.contains("could not read deployed accounts"),
                "{error}"
            );
        } else {
            assert!(error.contains(expected), "{scenario}: {error}");
        }
        assert!(!error.contains("private-rpc-credential"));
        assert!(output.path().join("transaction-signature.txt").exists());
        assert_eq!(fs::read_dir(output.path())?.count(), 1);
    }
    Ok(())
}

#[test]
fn deployed_binary_requires_exact_bytes_and_only_zero_padding() -> Result<()> {
    let fixture = Fixture::new()?;
    let data = fixture.deployed_data();
    devnet::validate_deployed_binary(&data, &fixture.binary)?;
    for length in [
        0,
        UpgradeableLoaderState::size_of_programdata_metadata(),
        UpgradeableLoaderState::size_of_programdata(fixture.binary.len() - 1),
    ] {
        let mut truncated = data.clone();
        truncated.data.truncate(length);
        assert!(devnet::validate_deployed_binary(&truncated, &fixture.binary).is_err());
    }
    let mut corrupt = data;
    corrupt.data[UpgradeableLoaderState::size_of_programdata_metadata()] ^= 1;
    assert_eq!(
        devnet::validate_deployed_binary(&corrupt, &fixture.binary)
            .err()
            .context("expected rejection")?
            .to_string(),
        "Deployed program bytes do not match the release binary"
    );
    Ok(())
}

#[test]
fn expansion_rounds_the_shortfall_and_respects_the_total_account_limit() -> Result<()> {
    // Capacity excludes the 45-byte ProgramData header; round the shortfall,
    // not the binary size or the existing allocation.
    for (binary, capacity, additional) in [
        (0, 17, 0),
        (16, 17, 0),
        (17, 17, 0),
        (18, 17, 10_240),
        (10_257, 17, 10_240),
        (10_258, 17, 20_480),
        (10_485_715, 10_485_715, 0),
        (10_485_715, 10_475_475, 10_240),
    ] {
        assert_eq!(
            devnet::required_program_extension(binary, capacity)?,
            additional
        );
    }
    for (binary, capacity) in [
        (10_485_715, 10_485_714), // Rounded extension would exceed the limit.
        (10_485_716, 0),          // Header also counts toward the account limit.
        (1, 10_485_716),
        (usize::MAX, 17),
        (17, usize::MAX),
    ] {
        assert!(devnet::required_program_extension(binary, capacity).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn preflight_budgets_expansion_rent_before_any_mutation() -> Result<()> {
    for (data_balance, payer_balance, extension_rent, succeeds) in [
        (7, 200_000_033, 13, true),
        (7, 200_000_032, 13, false),
        (20, 200_000_020, 0, true),
        (21, 200_000_020, 0, true),
    ] {
        let mut fixture = Fixture::new()?;
        let capacity = fixture.binary.len() + 8;
        fixture.binary.resize(capacity + 1, 0);
        fixture.data.lamports = data_balance;
        fixture.payer.lamports = payer_balance;
        let rpc = fixture.rpc(
            vec![account_response(&[
                fixture.program.clone(),
                fixture.data.clone(),
                fixture.payer.clone(),
            ])],
            Mocks::default(),
            None,
        );
        let result =
            devnet::check(&rpc, &fixture.config, &fixture.authority, &fixture.binary).await;
        if succeeds {
            let receipt = result?;
            assert_eq!(receipt.program_capacity_bytes, capacity);
            assert_eq!(receipt.additional_program_bytes, 10_240);
            assert_eq!(receipt.program_extension_rent_lamports, extension_rent);
            assert_eq!(
                receipt.minimum_authority_balance_lamports,
                200_000_020 + extension_rent
            );
        } else {
            assert!(result
                .err()
                .context("expected rejection")?
                .to_string()
                .contains("200000033 lamports"));
        }
        let requests = fixture.requests.lock().unwrap();
        let rent_sizes: Vec<_> = requests
            .iter()
            .filter(|(request, _)| *request == RpcRequest::GetMinimumBalanceForRentExemption)
            .map(|(_, params)| params[0].clone())
            .collect();
        assert_eq!(
            rent_sizes,
            vec![
                json!(UpgradeableLoaderState::size_of_buffer(fixture.binary.len())),
                json!(UpgradeableLoaderState::size_of_programdata(
                    capacity + 10_240
                )),
            ]
        );
        assert!(!requests
            .iter()
            .any(|(request, _)| *request == RpcRequest::SendTransaction));
    }
    Ok(())
}

#[tokio::test]
async fn expansion_signs_rounded_extend_and_verifies_finalized_capacity() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let capacity = fixture.binary.len() + 8;
    fixture.binary.resize(capacity + 10_241, 0);
    let before = account_response(&[
        fixture.program.clone(),
        fixture.data.clone(),
        fixture.payer.clone(),
    ]);
    let mut expanded = fixture.data.clone();
    expanded.data.resize(
        UpgradeableLoaderState::size_of_programdata(capacity + 20_480),
        0,
    );
    let rpc = fixture.rpc(
        vec![
            before.clone(),
            before,
            account_response(&[fixture.program.clone(), expanded, fixture.payer.clone()]),
        ],
        Mocks::default(),
        None,
    );
    let saved = devnet::check(&rpc, &fixture.config, &fixture.authority, &fixture.binary).await?;
    let output = tempfile::tempdir()?;
    let receipt = devnet::ensure_capacity(
        &rpc,
        &fixture.config,
        &fixture.authority,
        &fixture.binary,
        &saved,
        output.path(),
    )
    .await?
    .context("expected expansion")?;
    assert_eq!(receipt.program, fixture.config.program);
    assert_eq!(receipt.previous_capacity_bytes, capacity);
    assert_eq!(receipt.additional_bytes, 20_480);
    assert_eq!(receipt.program_capacity_bytes, capacity + 20_480);
    assert_eq!(
        fs::read_to_string(output.path().join("extension-signature.txt"))?.trim(),
        receipt.signature
    );
    let requests = fixture.requests.lock().unwrap();
    let sends: Vec<_> = requests
        .iter()
        .filter(|(request, _)| *request == RpcRequest::SendTransaction)
        .collect();
    assert_eq!(sends.len(), 1);
    let params = &sends[0].1;
    let transaction: Transaction =
        bincode::deserialize(&STANDARD.decode(params[0].as_str().context("transaction")?)?)?;
    transaction.verify()?;
    assert_eq!(
        transaction.message,
        solana_sdk::message::Message::new_with_blockhash(
            &[instruction::extend_program(
                &fixture.config.program,
                Some(&fixture.authority.pubkey()),
                20_480
            )],
            Some(&fixture.authority.pubkey()),
            &transaction.message.recent_blockhash,
        )
    );
    assert_eq!(transaction.signatures.len(), 1);
    assert_eq!(params[1]["skipPreflight"], false);
    assert_eq!(params[1]["preflightCommitment"], "finalized");
    assert!(requests
        .iter()
        .filter(|(request, _)| *request == RpcRequest::GetMultipleAccounts)
        .all(|(_, params)| params[1]["commitment"] == "finalized"));
    let send_index = requests
        .iter()
        .position(|(request, _)| *request == RpcRequest::SendTransaction)
        .context("submission")?;
    let confirmation_index = requests
        .iter()
        .rposition(|(request, _)| *request == RpcRequest::GetSignatureStatuses)
        .context("confirmation")?;
    let verification_index = requests
        .iter()
        .rposition(|(request, _)| *request == RpcRequest::GetMultipleAccounts)
        .context("capacity verification")?;
    assert!(send_index < confirmation_index && confirmation_index < verification_index);
    Ok(())
}

#[tokio::test]
async fn sufficient_or_concurrently_expanded_capacity_needs_no_transaction() -> Result<()> {
    for (extra_binary_bytes, concurrent_extension) in [(0, 0), (8, 0), (9, 10_240)] {
        let mut fixture = Fixture::new()?;
        let capacity = fixture.binary.len() + 8;
        fixture
            .binary
            .resize(fixture.binary.len() + extra_binary_bytes, 0);
        let before = account_response(&[
            fixture.program.clone(),
            fixture.data.clone(),
            fixture.payer.clone(),
        ]);
        fixture.data.data.resize(
            UpgradeableLoaderState::size_of_programdata(capacity + concurrent_extension),
            0,
        );
        let rpc = fixture.rpc(
            vec![
                before,
                account_response(&[
                    fixture.program.clone(),
                    fixture.data.clone(),
                    fixture.payer.clone(),
                ]),
            ],
            Mocks::default(),
            None,
        );
        let saved =
            devnet::check(&rpc, &fixture.config, &fixture.authority, &fixture.binary).await?;
        let output = tempfile::tempdir()?;
        assert!(devnet::ensure_capacity(
            &rpc,
            &fixture.config,
            &fixture.authority,
            &fixture.binary,
            &saved,
            output.path()
        )
        .await?
        .is_none());
        assert_eq!(fs::read_dir(output.path())?.count(), 0);
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
async fn expansion_rechecks_authority_funding_and_preflight_before_submission() -> Result<()> {
    for scenario in ["authority", "funding", "binary", "cluster"] {
        let mut fixture = Fixture::new()?;
        fixture.binary.resize(fixture.binary.len() + 9, 0);
        let rpc = fixture.rpc(
            vec![account_response(&[
                fixture.program.clone(),
                fixture.data.clone(),
                fixture.payer.clone(),
            ])],
            Mocks::default(),
            None,
        );
        let saved =
            devnet::check(&rpc, &fixture.config, &fixture.authority, &fixture.binary).await?;
        let mut mocks = Mocks::default();
        let expected = match scenario {
            "authority" => {
                fixture.authority = Keypair::new();
                "Program upgrade authority does not match"
            },
            "funding" => {
                fixture.payer.lamports = 0;
                "Program authority needs at least"
            },
            "binary" => {
                fixture.binary.push(1);
                "Preflight binary does not match"
            },
            _ => {
                mocks.insert(
                    RpcRequest::GetGenesisHash,
                    json!(Pubkey::new_unique().to_string()),
                );
                "SOLANA_RPC_URL must point to Solana devnet"
            },
        };
        let rpc = fixture.rpc(
            vec![account_response(&[
                fixture.program.clone(),
                fixture.data.clone(),
                fixture.payer.clone(),
            ])],
            mocks,
            None,
        );
        let output = tempfile::tempdir()?;
        let error = devnet::ensure_capacity(
            &rpc,
            &fixture.config,
            &fixture.authority,
            &fixture.binary,
            &saved,
            output.path(),
        )
        .await
        .err()
        .context("expected rejection")?;
        assert!(
            error.to_string().starts_with(expected),
            "{scenario}: {error}"
        );
        assert_eq!(fs::read_dir(output.path())?.count(), 0);
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
async fn failed_or_unverified_expansion_preserves_its_signature_and_stops() -> Result<()> {
    for scenario in [
        "send-failure",
        "onchain-failure",
        "unchanged-capacity",
        "changed-authority",
        "spent-funds",
    ] {
        let mut fixture = Fixture::new()?;
        fixture.binary.resize(fixture.binary.len() + 9, 0);
        let before = account_response(&[
            fixture.program.clone(),
            fixture.data.clone(),
            fixture.payer.clone(),
        ]);
        let mut expanded = fixture.data.clone();
        expanded.data.resize(expanded.data.len() + 10_240, 0);
        let mut mocks = Mocks::default();
        let mut fail_on = None;
        let expected = match scenario {
            "send-failure" => {
                fail_on = Some(RpcRequest::SendTransaction);
                "Program expansion submission failed or is uncertain"
            },
            "onchain-failure" => {
                mocks.insert(RpcRequest::GetSignatureStatuses, json!({"context":{"slot":50},"value":[{"slot":50,"confirmations":null,"err":"AccountNotFound","status":{"Err":"AccountNotFound"},"confirmationStatus":"finalized"}]}));
                "failed on-chain"
            },
            "changed-authority" => {
                let metadata = bincode::serialize(&UpgradeableLoaderState::ProgramData {
                    slot: 50,
                    upgrade_authority_address: Some(Pubkey::new_unique()),
                })?;
                expanded.data[..metadata.len()].copy_from_slice(&metadata);
                "Program upgrade authority does not match"
            },
            "spent-funds" => {
                fixture.payer.lamports = 0;
                "Program authority needs at least"
            },
            _ => {
                expanded = fixture.data.clone();
                "allocated capacity is below the target"
            },
        };
        let rpc = fixture.rpc(
            vec![
                before.clone(),
                before,
                account_response(&[fixture.program.clone(), expanded, fixture.payer.clone()]),
            ],
            mocks,
            fail_on,
        );
        let saved =
            devnet::check(&rpc, &fixture.config, &fixture.authority, &fixture.binary).await?;
        let output = tempfile::tempdir()?;
        let error = devnet::ensure_capacity(
            &rpc,
            &fixture.config,
            &fixture.authority,
            &fixture.binary,
            &saved,
            output.path(),
        )
        .await
        .err()
        .context("expected rejection")?
        .to_string();
        assert!(error.contains(expected), "{scenario}: {error}");
        assert!(!error.contains("private-rpc-credential"));
        assert!(output.path().join("extension-signature.txt").exists());
        assert_eq!(fs::read_dir(output.path())?.count(), 1);
        assert_eq!(
            fixture
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|(request, _)| *request == RpcRequest::SendTransaction)
                .count(),
            1
        );
    }
    Ok(())
}
