//! Explicit local E2E suite; normal cargo test leaves it ignored.
//! Build Swig and the pinned Squads program first, then run:
//! SWIG_TEST_BINARY=/path/swig.so SQUADS_TEST_BINARY=/path/squads_multisig_program.so \
//! cargo test --manifest-path tools/release/Cargo.toml --test surfpool -- --ignored --nocapture
//! SOLANA_TEST_CLI optionally selects the workflow's pinned Solana CLI executable.

mod fixture;
mod rpc_faults;

use fixture::{Fixture, SOURCE_COMMIT};

use std::{
    fs,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{ensure, Context, Result};
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
use solana_sdk_ids::{bpf_loader_upgradeable, system_program};
use squads_multisig::{
    anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas},
    pda::{get_proposal_pda, get_transaction_pda, get_vault_pda},
    solana_rpc_client::{
        http_sender::HttpSender, nonblocking::rpc_client::RpcClient, rpc_client::RpcClientConfig,
    },
    solana_rpc_client_api::{config::RpcSendTransactionConfig, request::RpcRequest},
    squads_multisig_program::{
        self as squads, Multisig, Proposal, ProposalStatus, VaultTransaction,
        VaultTransactionMessage,
    },
};
use swig_release::{
    accounts::validate_buffer,
    proposal::build_proposal,
    release::{propose, ProposalRequest},
};

use rpc_faults::{Fault, FaultySurfpool};

#[tokio::test]
#[ignore = "explicit local Surfpool E2E; requires built Swig and Squads binaries and Solana CLI"]
async fn release_cli_on_surfpool() -> Result<()> {
    let fixture = Fixture::start().await?;
    let check = fixture.cli("check", &fixture.binary_path, None, 0)?;
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
    println!(
        "PASS read-only preflight: {}",
        String::from_utf8(check.stdout)?
    );
    let buffer = fixture.upload_buffer()?;
    let uploaded = fixture.rpc.get_account(&buffer).await?;
    validate_buffer(&uploaded, &fixture.binary, fixture.proposer.pubkey())?;
    assert_preflight_rejections(&fixture, buffer, &uploaded).await?;
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
    let output = fixture.cli("propose", &fixture.binary_path, Some(buffer), 1)?;
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
    assert_eq!(receipt["buffer"], buffer.to_string());
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
    fixture
        .assert_rejected_without_mutation(
            "propose",
            &fixture.binary_path,
            buffer,
            1,
            "Expected unused transaction index 2",
        )
        .await?;

    execute_as_separate_member(&fixture, buffer, &receipt).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "explicit local Surfpool E2E with RPC fault injection after real submission"]
async fn uncertain_or_unverified_proposals_never_report_success_or_resubmit() -> Result<()> {
    let fixture = Fixture::start().await?;
    for (case, expected) in [
        (
            Fault::LostSubmissionReply,
            "Submission failed or is uncertain",
        ),
        (Fault::ConfirmationUnavailable, "Confirmation is uncertain"),
        (
            Fault::MissingBuffer,
            "Confirmed transaction buffer is missing",
        ),
        (
            Fault::MissingTransaction,
            "Confirmed vault transaction is missing",
        ),
        (Fault::MissingProposal, "Confirmed proposal is missing"),
        (
            Fault::WrongOwner,
            "Confirmed Squads accounts have incorrect owners",
        ),
        (
            Fault::ChangedBuffer,
            "Uploaded buffer contents do not match the built binary",
        ),
        (
            Fault::ChangedBufferAuthority,
            "Buffer authority does not match the expected signer",
        ),
        (
            Fault::ChangedMessage,
            "Confirmed vault transaction does not match the intended upgrade",
        ),
        (
            Fault::InactiveProposal,
            "Confirmed proposal is not active for this upgrade",
        ),
    ] {
        let multisig = fixture.rpc.get_account(&fixture.config.multisig).await?;
        let index = Multisig::try_deserialize(&mut multisig.data.as_slice())?.transaction_index + 1;
        let buffer = fixture.upload_buffer()?;
        let submissions = Arc::new(AtomicUsize::new(0));
        let injections = Arc::new(AtomicUsize::new(0));
        let rpc = RpcClient::new_sender(
            FaultySurfpool {
                inner: HttpSender::new(&fixture.config.rpc_url),
                fault: case,
                submissions: Arc::clone(&submissions),
                injections: Arc::clone(&injections),
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
                transaction_index: index,
                source_commit: SOURCE_COMMIT.into(),
                tag: "surfpool-rpc-fault".into(),
            },
        )
        .await;
        assert!(
            result.is_err(),
            "Fault {case:?} produced a successful receipt"
        );
        let error = result.err().context("Expected fault error")?.to_string();
        assert!(
            error.contains(expected),
            "Fault {case:?}: expected {expected}, got {error}"
        );
        assert_eq!(
            submissions.load(Ordering::SeqCst),
            1,
            "Fault {case:?} resubmitted"
        );
        assert_eq!(
            injections.load(Ordering::SeqCst),
            1,
            "Fault did not reach expected boundary"
        );
        // An ambiguous client result can coexist with a successful chain effect.
        // Prove the real chain accepted exactly the one intended proposal.
        let address = get_proposal_pda(
            &fixture.config.multisig,
            index,
            Some(&fixture.config.squads_program),
        )
        .0;
        let mut active = false;
        for _ in 0..100 {
            if let Some(account) = fixture
                .rpc
                .get_multiple_accounts(&[address])
                .await?
                .into_iter()
                .next()
                .flatten()
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
            "Fault {case:?} did not follow a real successful submission"
        );
        println!("PASS {case:?}: one real submission, no success receipt, no retry");
    }
    Ok(())
}

async fn assert_preflight_rejections(
    fixture: &Fixture,
    buffer: Pubkey,
    uploaded: &Account,
) -> Result<()> {
    let mut oversized = fixture.binary.clone();
    oversized.push(0);
    let oversized_path = fixture.directory.path().join("oversized.so");
    fs::write(&oversized_path, &oversized)?;
    fixture
        .assert_rejected_without_mutation(
            "check",
            &oversized_path,
            buffer,
            1,
            "Program needs 1 additional bytes",
        )
        .await?;
    fixture
        .assert_rejected_without_mutation(
            "propose",
            &oversized_path,
            buffer,
            1,
            "additional bytes required",
        )
        .await?;
    fixture
        .assert_rejected_without_mutation(
            "propose",
            &fixture.binary_path,
            buffer,
            2,
            "Expected unused transaction index 1",
        )
        .await?;

    for (case, expected) in [
        ("short", "Buffer payload size does not match the binary"),
        ("long", "Buffer payload size does not match the binary"),
        (
            "content",
            "Uploaded buffer contents do not match the built binary",
        ),
        (
            "authority",
            "Buffer authority does not match the expected signer",
        ),
        ("owner", "Buffer has an incorrect owner or executable flag"),
    ] {
        let mut invalid = uploaded.clone();
        match case {
            "short" => {
                invalid.data.pop();
            },
            "long" => invalid.data.push(0),
            "content" => {
                *invalid.data.last_mut().context("Empty buffer")? ^= 1;
            },
            "authority" => {
                let metadata = bincode::serialize(&UpgradeableLoaderState::Buffer {
                    authority_address: Some(fixture.voter.pubkey()),
                })?;
                invalid
                    .data
                    .get_mut(..metadata.len())
                    .context("Short buffer")?
                    .copy_from_slice(&metadata);
            },
            "owner" => invalid.owner = system_program::id(),
            _ => anyhow::bail!("Unknown buffer case"),
        }
        fixture.set_account(buffer, &invalid).await?;
        fixture
            .assert_rejected_without_mutation("propose", &fixture.binary_path, buffer, 1, expected)
            .await?;
        fixture.set_account(buffer, uploaded).await?;
    }
    let funded = fixture.rpc.get_account(&fixture.proposer.pubkey()).await?;
    let mut poor = funded.clone();
    poor.lamports = 1_000_000;
    fixture
        .set_account(fixture.proposer.pubkey(), &poor)
        .await?;
    fixture
        .assert_rejected_without_mutation(
            "check",
            &fixture.binary_path,
            buffer,
            1,
            "Proposer needs at least",
        )
        .await?;
    fixture
        .assert_rejected_without_mutation(
            "propose",
            &fixture.binary_path,
            buffer,
            1,
            "Proposer needs",
        )
        .await?;
    fixture
        .set_account(fixture.proposer.pubkey(), &funded)
        .await?;

    Ok(())
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
