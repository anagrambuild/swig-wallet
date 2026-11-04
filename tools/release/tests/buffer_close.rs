use std::{
    collections::VecDeque,
    fs,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use solana_loader_v3_interface::{
    instruction::UpgradeableLoaderInstruction, state::UpgradeableLoaderState,
};
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
    buffer::close_buffer,
    devnet::DEVNET_GENESIS_HASH,
    ottersec::{Cluster, MAINNET_GENESIS_HASH},
};

struct TestRpc {
    inner: MockSender,
    genesis: Value,
    status: Value,
    previous_statuses: Mutex<VecDeque<Value>>,
    accounts: Mutex<VecDeque<Option<Account>>>,
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
        match request {
            RpcRequest::GetGenesisHash => Ok(self.genesis.clone()),
            RpcRequest::GetSignatureStatuses => Ok(self
                .previous_statuses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| self.status.clone())),
            RpcRequest::GetAccountInfo => {
                let account = self
                    .accounts
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected account read");
                Ok(
                    json!({"context":{"slot":50},"value":account.map(|account| json!({
                        "lamports":account.lamports,"owner":account.owner.to_string(),
                        "executable":account.executable,"rentEpoch":0,
                        "data":[STANDARD.encode(account.data),"base64"]
                    }))}),
                )
            },
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
    authority: Keypair,
    buffer: Pubkey,
    account: Account,
    requests: Arc<Mutex<Vec<(RpcRequest, Value)>>>,
}

impl Fixture {
    fn new() -> Result<Self> {
        let authority = Keypair::new();
        let mut data = bincode::serialize(&UpgradeableLoaderState::Buffer {
            authority_address: Some(authority.pubkey()),
        })?;
        // Incomplete uploads are deliberately recoverable.
        data.extend_from_slice(&[0; 128]);
        Ok(Self {
            authority,
            buffer: Pubkey::new_unique(),
            account: Account {
                lamports: 1_492_407_480,
                data,
                owner: bpf_loader_upgradeable::id(),
                executable: false,
                rent_epoch: 0,
            },
            requests: Arc::default(),
        })
    }

    fn rpc(
        &self,
        accounts: Vec<Option<Account>>,
        mut mocks: Mocks,
        fail_on: Option<RpcRequest>,
    ) -> RpcClient {
        let genesis = mocks
            .remove(&RpcRequest::GetGenesisHash)
            .unwrap_or(json!(DEVNET_GENESIS_HASH));
        let status = mocks
            .remove(&RpcRequest::GetSignatureStatuses)
            .unwrap_or(json!({
                "context":{"slot":50},"value":[{"slot":50,"confirmations":1,"err":null,
                "status":{"Ok":null},"confirmationStatus":"confirmed"}]
            }));
        RpcClient::new_sender(
            TestRpc {
                inner: MockSender::new_with_mocks("succeeds", mocks),
                genesis,
                status,
                previous_statuses: Mutex::default(),
                accounts: Mutex::new(accounts.into()),
                requests: self.requests.clone(),
                fail_on,
            },
            RpcClientConfig::with_commitment(CommitmentConfig::confirmed()),
        )
    }
}

#[tokio::test(start_paused = true)]
async fn processed_success_then_confirmed_failure_cannot_issue_a_success_receipt() -> Result<()> {
    let fixture = Fixture::new()?;
    let rpc = RpcClient::new_sender(
        TestRpc {
            inner: MockSender::new("succeeds"),
            genesis: json!(DEVNET_GENESIS_HASH),
            previous_statuses: Mutex::new(VecDeque::from([json!({
                "context":{"slot":50},"value":[{"slot":50,"confirmations":0,"err":null,
                "status":{"Ok":null},"confirmationStatus":"processed"}]
            })])),
            status: json!({"context":{"slot":51},"value":[{"slot":51,"confirmations":1,
                "err":"AccountNotFound","status":{"Err":"AccountNotFound"},"confirmationStatus":"confirmed"}]}),
            // A concurrent close can drain the account even though our transaction fails.
            accounts: Mutex::new(VecDeque::from([Some(fixture.account.clone()), None])),
            requests: fixture.requests.clone(),
            fail_on: None,
        },
        RpcClientConfig::with_commitment(CommitmentConfig::confirmed()),
    );
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("close");
    let result = close_buffer(
        &rpc,
        Cluster::Devnet,
        fixture.buffer,
        &fixture.authority,
        &output,
    )
    .await;
    assert!(
        result.is_err(),
        "A confirmed failure must not become a successful close receipt"
    );
    assert!(output.join("buffer-close-submission.json").exists());
    assert!(!output.join("buffer-close-receipt.json").exists());
    Ok(())
}

#[tokio::test]
async fn closes_one_partial_buffer_to_its_signer_on_each_network() -> Result<()> {
    for (cluster, genesis) in [
        (Cluster::Devnet, DEVNET_GENESIS_HASH),
        (Cluster::Mainnet, MAINNET_GENESIS_HASH),
    ] {
        let fixture = Fixture::new()?;
        let rpc = fixture.rpc(
            vec![Some(fixture.account.clone()), None],
            Mocks::from([(RpcRequest::GetGenesisHash, json!(genesis))]),
            None,
        );
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("close");
        let receipt =
            close_buffer(&rpc, cluster, fixture.buffer, &fixture.authority, &output).await?;
        assert_eq!(receipt.buffer, fixture.buffer);
        assert_eq!(receipt.authority_and_recipient, fixture.authority.pubkey());
        assert_eq!(receipt.genesis_hash, genesis);
        assert_eq!(receipt.lamports_before_close, fixture.account.lamports);
        let submission: Value =
            serde_json::from_slice(&fs::read(output.join("buffer-close-submission.json"))?)?;
        let confirmed: Value =
            serde_json::from_slice(&fs::read(output.join("buffer-close-receipt.json"))?)?;
        assert_eq!(submission, confirmed);
        assert_eq!(confirmed["buffer"], fixture.buffer.to_string());
        let requests = fixture.requests.lock().unwrap();
        let sends: Vec<_> = requests
            .iter()
            .filter(|(request, _)| *request == RpcRequest::SendTransaction)
            .collect();
        assert_eq!(sends.len(), 1);
        let params = &sends[0].1;
        assert_eq!(params[1]["skipPreflight"], false);
        assert_eq!(params[1]["maxRetries"], 0);
        assert_eq!(params[1]["preflightCommitment"], "confirmed");
        let transaction: Transaction = bincode::deserialize(
            &STANDARD.decode(params[0].as_str().context("missing transaction")?)?,
        )?;
        transaction.verify()?;
        assert_eq!(transaction.signatures.len(), 1);
        assert_eq!(transaction.signatures[0].to_string(), receipt.signature);
        assert_eq!(
            transaction.message.account_keys,
            vec![
                fixture.authority.pubkey(),
                fixture.buffer,
                bpf_loader_upgradeable::id()
            ]
        );
        assert_eq!(transaction.message.header.num_required_signatures, 1);
        assert_eq!(transaction.message.header.num_readonly_signed_accounts, 0);
        assert_eq!(transaction.message.header.num_readonly_unsigned_accounts, 1);
        assert_eq!(transaction.message.instructions.len(), 1);
        let instruction = &transaction.message.instructions[0];
        assert_eq!(instruction.program_id_index, 2);
        assert_eq!(instruction.accounts, vec![1, 0, 0]);
        assert!(matches!(
            bincode::deserialize::<UpgradeableLoaderInstruction>(&instruction.data)?,
            UpgradeableLoaderInstruction::Close
        ));
    }
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_accounts_without_sending() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut accounts = vec![None];
    let mut wrong_owner = fixture.account.clone();
    wrong_owner.owner = system_program::id();
    accounts.push(Some(wrong_owner));
    let mut executable = fixture.account.clone();
    executable.executable = true;
    accounts.push(Some(executable));
    let mut drained = fixture.account.clone();
    drained.lamports = 0;
    accounts.push(Some(drained));
    for state in [
        UpgradeableLoaderState::Uninitialized,
        UpgradeableLoaderState::Program {
            programdata_address: Pubkey::new_unique(),
        },
        UpgradeableLoaderState::ProgramData {
            slot: 1,
            upgrade_authority_address: Some(fixture.authority.pubkey()),
        },
        UpgradeableLoaderState::Buffer {
            authority_address: None,
        },
        UpgradeableLoaderState::Buffer {
            authority_address: Some(Pubkey::new_unique()),
        },
    ] {
        let mut account = fixture.account.clone();
        account.data = bincode::serialize(&state)?;
        account.data.resize(200, 0);
        accounts.push(Some(account));
    }
    for data in [vec![0xff; 37], fixture.account.data[..36].to_vec()] {
        accounts.push(Some(Account {
            data,
            ..fixture.account.clone()
        }));
    }
    for account in accounts {
        let rpc = fixture.rpc(vec![account], Mocks::default(), None);
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("close");
        assert!(close_buffer(
            &rpc,
            Cluster::Devnet,
            fixture.buffer,
            &fixture.authority,
            &output
        )
        .await
        .is_err());
        assert!(!output.join("buffer-close-submission.json").exists());
    }
    assert!(!fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|(request, _)| *request == RpcRequest::SendTransaction));
    Ok(())
}

#[tokio::test]
async fn rejects_wrong_network_alias_and_existing_recovery_directory() -> Result<()> {
    let fixture = Fixture::new()?;
    for (cluster, genesis) in [
        (Cluster::Devnet, MAINNET_GENESIS_HASH),
        (Cluster::Mainnet, DEVNET_GENESIS_HASH),
    ] {
        let rpc = fixture.rpc(
            vec![],
            Mocks::from([(RpcRequest::GetGenesisHash, json!(genesis))]),
            None,
        );
        let directory = tempfile::tempdir()?;
        let error = close_buffer(
            &rpc,
            cluster,
            fixture.buffer,
            &fixture.authority,
            &directory.path().join("close"),
        )
        .await
        .err()
        .context("expected rejection")?;
        assert!(error.to_string().contains("network does not match"));
    }
    let rpc = fixture.rpc(vec![], Mocks::default(), None);
    let directory = tempfile::tempdir()?;
    let error = close_buffer(
        &rpc,
        Cluster::Devnet,
        fixture.authority.pubkey(),
        &fixture.authority,
        &directory.path().join("close"),
    )
    .await
    .err()
    .context("expected alias rejection")?;
    assert!(error.to_string().contains("refund recipient"));
    fs::write(
        directory.path().join("buffer-close-submission.json"),
        "previous attempt",
    )?;
    let error = close_buffer(
        &rpc,
        Cluster::Devnet,
        fixture.buffer,
        &fixture.authority,
        directory.path(),
    )
    .await
    .err()
    .context("expected directory rejection")?;
    assert!(error.to_string().contains("Output directory must be new"));
    assert_eq!(
        fs::read_to_string(directory.path().join("buffer-close-submission.json"))?,
        "previous attempt"
    );
    assert!(fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|(request, _)| *request == RpcRequest::GetGenesisHash));
    Ok(())
}

#[tokio::test]
async fn rpc_failures_are_redacted_and_preserve_submission_when_applicable() -> Result<()> {
    for request in [
        RpcRequest::GetGenesisHash,
        RpcRequest::GetAccountInfo,
        RpcRequest::GetLatestBlockhash,
        RpcRequest::SendTransaction,
        RpcRequest::GetSignatureStatuses,
    ] {
        let fixture = Fixture::new()?;
        let rpc = fixture.rpc(
            vec![Some(fixture.account.clone())],
            Mocks::default(),
            Some(request),
        );
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("close");
        let error = close_buffer(
            &rpc,
            Cluster::Devnet,
            fixture.buffer,
            &fixture.authority,
            &output,
        )
        .await
        .err()
        .context("expected RPC failure")?;
        assert!(!format!("{error:#}").contains("private-rpc-credential"));
        assert!(!output.join("buffer-close-receipt.json").exists());
        let submitted = matches!(
            request,
            RpcRequest::SendTransaction | RpcRequest::GetSignatureStatuses
        );
        assert_eq!(
            output.join("buffer-close-submission.json").exists(),
            submitted
        );
        if submitted {
            let receipt: Value =
                serde_json::from_slice(&fs::read(output.join("buffer-close-submission.json"))?)?;
            assert!(error
                .to_string()
                .contains(receipt["signature"].as_str().context("missing signature")?));
        }
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn failed_unconfirmed_or_mismatched_transactions_never_get_success_receipts() -> Result<()> {
    for mocks in [
        Mocks::from([(
            RpcRequest::GetSignatureStatuses,
            json!({"context":{"slot":50},"value":[{
                "slot":50,"confirmations":1,"err":"AccountNotFound","status":{"Err":"AccountNotFound"},"confirmationStatus":"confirmed"
            }]}),
        )]),
        Mocks::from([(
            RpcRequest::GetSignatureStatuses,
            json!({"context":{"slot":50},"value":[null]}),
        )]),
        Mocks::from([(
            RpcRequest::SendTransaction,
            json!(solana_sdk::signature::Signature::new_unique().to_string()),
        )]),
    ] {
        let fixture = Fixture::new()?;
        let rpc = fixture.rpc(vec![Some(fixture.account.clone())], mocks, None);
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("close");
        assert!(close_buffer(
            &rpc,
            Cluster::Devnet,
            fixture.buffer,
            &fixture.authority,
            &output
        )
        .await
        .is_err());
        assert!(output.join("buffer-close-submission.json").exists());
        assert!(!output.join("buffer-close-receipt.json").exists());
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

#[tokio::test]
async fn requires_a_drained_or_absent_account_after_confirmation() -> Result<()> {
    for drained in [false, true] {
        let fixture = Fixture::new()?;
        let mut remaining = fixture.account.clone();
        if drained {
            remaining.lamports = 0;
        }
        let rpc = fixture.rpc(
            vec![Some(fixture.account.clone()), Some(remaining)],
            Mocks::default(),
            None,
        );
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("close");
        let result = close_buffer(
            &rpc,
            Cluster::Devnet,
            fixture.buffer,
            &fixture.authority,
            &output,
        )
        .await;
        assert_eq!(result.is_ok(), drained);
        assert_eq!(output.join("buffer-close-receipt.json").exists(), drained);
    }
    Ok(())
}
