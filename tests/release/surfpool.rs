//! Explicit local E2E suite; normal cargo test leaves it ignored.
//! Build Swig and the pinned Squads program first, then run:
//! SWIG_TEST_BINARY=/path/swig.so SQUADS_TEST_BINARY=/path/squads_multisig_program.so \
//! cargo test --manifest-path tools/release/Cargo.toml --test surfpool -- --ignored --nocapture
//! SOLANA_TEST_CLI optionally selects the workflow's pinned Solana CLI executable.

mod fixture;

use fixture::{Fixture, SOURCE_COMMIT};

use std::{
    env, fs,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_sdk::{
    account::Account,
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Signer,
    transaction::Transaction,
};
use solana_sdk_ids::bpf_loader_upgradeable;
use squads_multisig::{
    anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas},
    pda::{get_proposal_pda, get_transaction_pda, get_vault_pda},
    solana_rpc_client::{
        http_sender::HttpSender,
        nonblocking::rpc_client::RpcClient,
        rpc_client::RpcClientConfig,
        rpc_sender::{RpcSender, RpcTransportStats},
    },
    solana_rpc_client_api::{
        client_error::{ErrorKind, Result as RpcResult},
        config::RpcSendTransactionConfig,
        request::RpcRequest,
    },
    squads_multisig_program::{
        self as squads, Proposal, ProposalStatus, VaultTransaction, VaultTransactionMessage,
    },
};
use swig_release::{
    accounts::validate_buffer,
    proposal::build_proposal,
    release::{propose, ProposalRequest},
};

#[tokio::test]
#[ignore = "explicit local Surfpool E2E; requires built Swig and Squads binaries and Solana CLI"]
async fn release_cli_on_surfpool() -> Result<()> {
    let fixture = Fixture::start().await?;
    let check = fixture
        .cli()?
        .args(["check", "--binary"])
        .arg(&fixture.binary_path)
        .output()?;
    ensure!(
        check.status.success(),
        "Preflight failed: {}",
        String::from_utf8_lossy(&check.stderr)
    );
    let receipt: Value = serde_json::from_slice(&check.stdout)?;
    assert_eq!(receipt["binary_bytes"], fixture.binary.len());
    assert_eq!(
        receipt["binary_sha256"],
        format!("{:x}", Sha256::digest(&fixture.binary))
    );
    assert_eq!(receipt["transaction_index"], 1);
    assert_eq!(receipt["program_capacity_bytes"], fixture.binary.len());
    let preflight = fixture.directory.path().join("preflight.json");
    fs::write(&preflight, &check.stdout)?;
    println!(
        "PASS read-only preflight: {}",
        String::from_utf8(check.stdout)?
    );
    let buffer = fixture.upload_buffer()?;
    let uploaded = fixture.rpc.get_account(&buffer).await?;
    validate_buffer(&uploaded, &fixture.binary, fixture.proposer.pubkey())?;
    assert_atomic_rollback(&fixture, buffer, &uploaded).await?;
    let proposal_address = get_proposal_pda(
        &fixture.config.multisig,
        1,
        Some(&fixture.config.squads_program),
    )
    .0;

    let program_data = Pubkey::find_program_address(
        &[fixture.config.program.as_ref()],
        &bpf_loader_upgradeable::id(),
    )
    .0;
    let before = fixture.rpc.get_account(&program_data).await?;
    let output_dir = fixture.directory.path().join("proposal");
    let mut command = fixture.cli()?;
    command
        .args(["propose", "--binary"])
        .arg(&fixture.binary_path)
        .arg("--preflight")
        .arg(&preflight)
        .args([
            "--source-commit",
            SOURCE_COMMIT,
            "--tag",
            "upgrade-surfpool-test",
        ])
        .arg("--output-dir")
        .arg(&output_dir)
        .arg("--solana-cli")
        .arg(env::var("SOLANA_TEST_CLI").unwrap_or_else(|_| "solana".into()));
    let output = command.output()?;
    ensure!(
        output.status.success(),
        "Proposal failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(receipt["transaction_index"], 1);
    assert_eq!(
        receipt["binary_sha256"],
        format!("{:x}", Sha256::digest(&fixture.binary))
    );
    assert_eq!(receipt["source_commit"], SOURCE_COMMIT);
    let buffer: Pubkey = receipt["buffer"]
        .as_str()
        .context("Missing buffer address")?
        .parse()?;
    assert_eq!(
        fs::read_to_string(output_dir.join("buffer-address.txt"))?.trim(),
        buffer.to_string()
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(output_dir.join("proposal-receipt.json"))?)?,
        receipt
    );
    let vault = get_vault_pda(
        &fixture.config.multisig,
        fixture.config.vault_index,
        Some(&fixture.config.squads_program),
    )
    .0;
    validate_buffer(
        &fixture.rpc.get_account(&buffer).await?,
        &fixture.binary,
        vault,
    )?;
    assert_eq!(
        fixture.rpc.get_account(&program_data).await?,
        before,
        "CLI executed the upgrade"
    );
    let proposal_account = fixture.rpc.get_account(&proposal_address).await?;
    let proposal = Proposal::try_deserialize(&mut proposal_account.data.as_slice())?;
    assert!(matches!(proposal.status, ProposalStatus::Active { .. }));
    assert!(proposal.approved.is_empty(), "CLI cast a vote");
    println!(
        "PASS active proposal, no votes or execution: {}",
        String::from_utf8(output.stdout)?
    );
    // Reusing the saved preflight must stop before a second upload or submission.
    let signatures = fixture
        .rpc
        .get_signatures_for_address(&fixture.proposer.pubkey())
        .await?;
    let retry = command.output()?;
    assert!(!retry.status.success());
    assert!(retry.stdout.is_empty());
    assert!(String::from_utf8(retry.stderr)?.contains("Preflight transaction index is stale"));
    assert_eq!(
        fixture
            .rpc
            .get_signatures_for_address(&fixture.proposer.pubkey())
            .await?
            .len(),
        signatures.len()
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(output_dir.join("proposal-receipt.json"))?)?,
        receipt
    );

    execute_as_separate_member(&fixture, buffer, &receipt).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "explicit local Surfpool E2E; drops the response after a real submission"]
async fn lost_submission_reply_does_not_retry_or_report_success() -> Result<()> {
    let fixture = Fixture::start().await?;
    let buffer = fixture.upload_buffer()?;
    let submissions = Arc::new(AtomicUsize::new(0));
    let rpc = RpcClient::new_sender(
        LostSubmissionReply {
            inner: HttpSender::new(&fixture.config.rpc_url),
            submissions: Arc::clone(&submissions),
        },
        RpcClientConfig::with_commitment(CommitmentConfig::confirmed()),
    );
    let result = propose(
        &rpc,
        &fixture.config,
        &fixture.proposer,
        &fixture.binary,
        ProposalRequest {
            buffer,
            transaction_index: 1,
            source_commit: SOURCE_COMMIT.into(),
            tag: "surfpool-lost-reply".into(),
        },
    )
    .await;
    let error = result
        .err()
        .context("Uncertain submission emitted a success receipt")?;
    assert!(error
        .to_string()
        .contains("Submission failed or is uncertain"));
    assert_eq!(
        submissions.load(Ordering::SeqCst),
        1,
        "Resubmitted after a lost response"
    );

    // The client must report uncertainty even when the real chain accepted it.
    let address = get_proposal_pda(
        &fixture.config.multisig,
        1,
        Some(&fixture.config.squads_program),
    )
    .0;
    let mut active = false;
    for _ in 0..100 {
        if let Some(account) = fixture
            .rpc
            .get_multiple_accounts(&[address])
            .await?
            .remove(0)
        {
            active = matches!(
                Proposal::try_deserialize(&mut account.data.as_slice())?.status,
                ProposalStatus::Active { .. }
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        active,
        "The injected error did not follow an accepted proposal"
    );
    println!("PASS lost submission reply: real active proposal, no success receipt, no retry");
    Ok(())
}

// One transport failure at the irreversible boundary; all other RPCs are real.
struct LostSubmissionReply {
    inner: HttpSender,
    submissions: Arc<AtomicUsize>,
}

#[async_trait]
impl RpcSender for LostSubmissionReply {
    async fn send(&self, request: RpcRequest, params: Value) -> RpcResult<Value> {
        if request == RpcRequest::SendTransaction {
            self.submissions.fetch_add(1, Ordering::SeqCst);
            self.inner.send(request, params).await?;
            return Err(ErrorKind::Custom("Lost reply after successful submission".into()).into());
        }
        self.inner.send(request, params).await
    }

    fn get_transport_stats(&self) -> RpcTransportStats {
        self.inner.get_transport_stats()
    }

    fn url(&self) -> String {
        self.inner.url()
    }
}

async fn assert_atomic_rollback(
    fixture: &Fixture,
    buffer: Pubkey,
    uploaded: &Account,
) -> Result<()> {
    let multisig_before = fixture.rpc.get_account(&fixture.config.multisig).await?;
    // Force the LAST instruction to fail at runtime, after buffer handoff and
    // transaction creation. Bypass simulation only for this rollback test.
    let mut failed_proposal = build_proposal(
        &fixture.config,
        fixture.proposer.pubkey(),
        buffer,
        1,
        2,
        "rollback-test".into(),
    )?;
    failed_proposal
        .instructions
        .last_mut()
        .context("Missing proposal instruction")?
        .data = squads::instruction::ProposalCreate {
        args: squads::ProposalCreateArgs {
            transaction_index: 2,
            draft: false,
        },
    }
    .data();
    let blockhash = fixture.rpc.get_latest_blockhash().await?;
    let failed = Transaction::new_signed_with_payer(
        &failed_proposal.instructions,
        Some(&fixture.proposer.pubkey()),
        &[&fixture.proposer],
        blockhash,
    );
    let signature = fixture
        .rpc
        .send_transaction_with_config(
            &failed,
            RpcSendTransactionConfig {
                skip_preflight: true,
                max_retries: Some(0),
                ..Default::default()
            },
        )
        .await?;
    let mut status = None;
    for _ in 0..100 {
        status = fixture
            .rpc
            .get_signature_status_with_commitment_and_history(
                &signature,
                CommitmentConfig::confirmed(),
                true,
            )
            .await?;
        if status.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        matches!(
            status,
            Some(Err(
                solana_sdk::transaction::TransactionError::InstructionError(2, _)
            ))
        ),
        "Expected instruction 2 runtime failure, got {status:?}"
    );
    assert_eq!(
        fixture.rpc.get_account(&buffer).await?,
        *uploaded,
        "Failed proposal stranded the buffer"
    );
    let accounts = fixture
        .rpc
        .get_multiple_accounts(&[
            failed_proposal.transaction_address,
            failed_proposal.proposal_address,
        ])
        .await?;
    assert!(
        accounts.iter().all(Option::is_none),
        "Failed proposal left created accounts"
    );
    assert_eq!(
        fixture.rpc.get_account(&fixture.config.multisig).await?,
        multisig_before,
        "Failed proposal mutated the multisig"
    );
    println!("PASS runtime rollback at instruction 2: {signature}");

    Ok(())
}

async fn execute_as_separate_member(
    fixture: &Fixture,
    buffer: Pubkey,
    receipt: &Value,
) -> Result<()> {
    let program_data = Pubkey::find_program_address(
        &[fixture.config.program.as_ref()],
        &bpf_loader_upgradeable::id(),
    )
    .0;
    let before = fixture.rpc.get_account(&program_data).await?;
    let vault = get_vault_pda(
        &fixture.config.multisig,
        fixture.config.vault_index,
        Some(&fixture.config.squads_program),
    )
    .0;
    let proposal_address = get_proposal_pda(
        &fixture.config.multisig,
        1,
        Some(&fixture.config.squads_program),
    )
    .0;
    let transaction_address = get_transaction_pda(
        &fixture.config.multisig,
        1,
        Some(&fixture.config.squads_program),
    )
    .0;
    // The CLI stops at Active. Only this distinct local test member votes and
    // executes, proving that the stored upgrade is actually executable.
    let approve = Instruction {
        program_id: fixture.config.squads_program,
        accounts: squads::accounts::ProposalVote {
            multisig: fixture.config.multisig,
            proposal: proposal_address,
            member: fixture.voter.pubkey(),
        }
        .to_account_metas(None),
        data: squads::instruction::ProposalApprove {
            args: squads::ProposalVoteArgs { memo: None },
        }
        .data(),
    };
    let approval = Transaction::new_signed_with_payer(
        &[approve],
        Some(&fixture.voter.pubkey()),
        &[&fixture.voter],
        fixture.rpc.get_latest_blockhash().await?,
    );
    fixture.rpc.send_and_confirm_transaction(&approval).await?;
    let stored = fixture.rpc.get_account(&transaction_address).await?;
    let stored = VaultTransaction::try_deserialize(&mut stored.data.as_slice())?;
    assert!(stored.message.address_table_lookups.is_empty());
    let mut accounts = squads::accounts::VaultTransactionExecute {
        multisig: fixture.config.multisig,
        proposal: proposal_address,
        transaction: transaction_address,
        member: fixture.voter.pubkey(),
    }
    .to_account_metas(None);
    for (index, key) in stored.message.account_keys.iter().enumerate() {
        accounts.push(AccountMeta {
            pubkey: *key,
            is_signer: VaultTransactionMessage::is_signer_index(&stored.message, index)
                && *key != vault,
            is_writable: VaultTransactionMessage::is_static_writable_index(&stored.message, index),
        });
    }
    let execute = Instruction {
        program_id: fixture.config.squads_program,
        accounts,
        data: squads::instruction::VaultTransactionExecute {}.data(),
    };
    let execution = Transaction::new_signed_with_payer(
        &[execute],
        Some(&fixture.voter.pubkey()),
        &[&fixture.voter],
        fixture.rpc.get_latest_blockhash().await?,
    );
    let vault_before = fixture.rpc.get_balance(&vault).await?;
    let buffer_balance = fixture.rpc.get_balance(&buffer).await?;
    let signature = fixture
        .rpc
        .send_and_confirm_transaction(&execution)
        .await
        .context("Execute proposed upgrade with separate voter")?;
    let after = fixture.rpc.get_account(&program_data).await?;
    assert_eq!(
        &after.data[UpgradeableLoaderState::size_of_programdata_metadata()..],
        fixture.binary
    );
    assert_ne!(
        after.data, before.data,
        "Upgrade did not update the deployment slot"
    );
    assert_eq!(
        fixture.rpc.get_balance(&vault).await?,
        vault_before + buffer_balance,
        "Buffer rent did not return to vault"
    );
    assert!(fixture
        .rpc
        .get_multiple_accounts(&[buffer])
        .await?
        .iter()
        .all(Option::is_none));
    let completed = fixture.rpc.get_account(&proposal_address).await?;
    assert!(matches!(
        Proposal::try_deserialize(&mut completed.data.as_slice())?.status,
        ProposalStatus::Executed { .. }
    ));
    let transaction: Value = fixture.rpc.send(RpcRequest::GetTransaction, json!([receipt["signature"], {"encoding":"json", "commitment":"confirmed", "maxSupportedTransactionVersion":0}])).await?;
    ensure!(
        transaction["meta"]["computeUnitsConsumed"]
            .as_u64()
            .is_some(),
        "Missing measured proposal CU"
    );
    println!(
        "PASS member execution and vault rent refund: {signature}; proposal CU={}",
        transaction["meta"]["computeUnitsConsumed"]
    );
    Ok(())
}
