//! Optional runtime proof using public devnet program binaries on an isolated
//! local validator. Set VERIFY_PROGRAM_SO, SQUADS_PROGRAM_SO and SWIG_PROGRAM_SO,
//! then run this test with --ignored. No public-chain transaction is submitted.
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_sdk::{
    account::Account,
    commitment_config::CommitmentConfig,
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use solana_sdk_ids::{bpf_loader_upgradeable, system_program};
use squads_multisig::{
    anchor_lang::{AccountSerialize, AnchorDeserialize},
    client::{
        proposal_approve, vault_transaction_execute, ProposalVoteAccounts, ProposalVoteArgs,
        VaultTransactionExecuteAccounts,
    },
    pda::{get_multisig_pda, get_vault_pda},
    solana_rpc_client::nonblocking::rpc_client::RpcClient,
    state::{Member, Multisig, Permission, Permissions, TransactionMessage},
};
use std::{
    fs,
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::Duration,
};
use swig_release::{
    config::ReleaseConfig,
    proposal::build_proposal,
    release::{check, propose, ProposalRequest},
    transactions::prepare_proposal_transaction,
    verification::{
        build_verification_instruction, read_verification_instruction, VerificationManifest,
        VERIFY_PROGRAM,
    },
};

struct Validator(Child);
impl Drop for Validator {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn genesis_account(directory: &std::path::Path, address: Pubkey, account: Account) -> Result<()> {
    fs::write(
        directory.join(format!("{address}.json")),
        serde_json::to_vec(
            &serde_json::json!({"pubkey":address.to_string(), "account":{"lamports":account.lamports,"data":[STANDARD.encode(account.data),"base64"],"owner":account.owner.to_string(),"executable":account.executable,"rentEpoch":0}}),
        )?,
    )?;
    Ok(())
}

async fn send(rpc: &RpcClient, payer: &Keypair, instructions: &[Instruction]) -> Result<()> {
    let hash = rpc.get_latest_blockhash().await?;
    let transaction =
        Transaction::new_signed_with_payer(instructions, Some(&payer.pubkey()), &[payer], hash);
    rpc.send_and_confirm_transaction(&transaction).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires solana-test-validator and explicitly supplied public program binaries"]
async fn one_squads_proposal_upgrades_and_initializes_or_updates_metadata_atomically() -> Result<()>
{
    let verify_so = std::env::var("VERIFY_PROGRAM_SO")?;
    let squads_so = std::env::var("SQUADS_PROGRAM_SO")?;
    let swig_so = std::env::var("SWIG_PROGRAM_SO")?;
    let binary = fs::read(&swig_so)?;
    let dir = tempfile::tempdir()?;
    let accounts = dir.path().join("accounts");
    fs::create_dir(&accounts)?;
    let member = Keypair::new();
    let squads = solana_sdk::pubkey!("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf");
    let program = solana_sdk::pubkey!("swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB");
    let create_key = Pubkey::new_unique();
    let (multisig, bump) = get_multisig_pda(&create_key, Some(&squads));
    let vault = get_vault_pda(&multisig, 0, Some(&squads)).0;
    let state = Multisig {
        create_key,
        config_authority: Pubkey::default(),
        threshold: 1,
        time_lock: 0,
        transaction_index: 0,
        stale_transaction_index: 0,
        rent_collector: None,
        bump,
        members: vec![Member {
            key: member.pubkey(),
            permissions: Permissions::from_vec(&[
                Permission::Initiate,
                Permission::Vote,
                Permission::Execute,
            ]),
        }],
    };
    let mut data = Vec::new();
    state.try_serialize(&mut data)?;
    genesis_account(
        &accounts,
        multisig,
        Account {
            lamports: 1_000_000_000,
            data,
            owner: squads,
            ..Account::default()
        },
    )?;
    let manifest: VerificationManifest =
        serde_json::from_str(include_str!("fixtures/verification.json"))?;
    let metadata_rent = solana_sdk::rent::Rent::default().minimum_balance(
        build_verification_instruction(program, vault, &manifest, 0, None)?.account_size,
    );
    for (key, lamports) in [
        (member.pubkey(), 100_000_000_000),
        (vault, metadata_rent + 1),
    ] {
        genesis_account(
            &accounts,
            key,
            Account {
                lamports,
                owner: system_program::id(),
                ..Account::default()
            },
        )?;
    }
    let buffers = [
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
    ];
    for buffer in buffers {
        let mut data = bincode::serialize(&UpgradeableLoaderState::Buffer {
            authority_address: Some(member.pubkey()),
        })?;
        data.resize(UpgradeableLoaderState::size_of_buffer_metadata(), 0);
        data.extend(&binary);
        genesis_account(
            &accounts,
            buffer,
            Account {
                lamports: 10_000_000_000,
                data,
                owner: bpf_loader_upgradeable::id(),
                ..Account::default()
            },
        )?;
    }
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let faucet = TcpListener::bind("127.0.0.1:0")?;
    let faucet_port = faucet.local_addr()?.port();
    drop(faucet);
    let output = fs::File::create(dir.path().join("validator.log"))?;
    let mut validator = Validator(
        Command::new("solana-test-validator")
            .args([
                "--reset",
                "--quiet",
                "--bind-address",
                "127.0.0.1",
                "--rpc-port",
                &port.to_string(),
                "--faucet-port",
                &faucet_port.to_string(),
                "--ledger",
            ])
            .arg(dir.path().join("ledger"))
            .arg("--account-dir")
            .arg(&accounts)
            .args([
                "--upgradeable-program",
                &VERIFY_PROGRAM.to_string(),
                &verify_so,
                &vault.to_string(),
                "--upgradeable-program",
                &squads.to_string(),
                &squads_so,
                &vault.to_string(),
                "--upgradeable-program",
                &program.to_string(),
                &swig_so,
                &vault.to_string(),
            ])
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(output))
            .spawn()?,
    );
    let config = ReleaseConfig {
        rpc_url: format!("http://127.0.0.1:{port}"),
        squads_program: squads,
        multisig,
        vault_index: 0,
        program,
    };
    let rpc = RpcClient::new_with_timeout_and_commitment(
        config.rpc_url.clone(),
        Duration::from_secs(2),
        CommitmentConfig::confirmed(),
    );
    let mut ready = false;
    for _ in 0..60 {
        if rpc.get_slot().await.is_ok_and(|slot| slot > 2) {
            ready = true;
            break;
        }
        if let Some(status) = validator.0.try_wait()? {
            anyhow::bail!(
                "Validator exited {status}: {}",
                fs::read_to_string(dir.path().join("validator.log"))?
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::ensure!(ready, "Validator startup timed out");
    let program_data =
        Pubkey::find_program_address(&[program.as_ref()], &bpf_loader_upgradeable::id()).0;
    for (index, buffer) in buffers.into_iter().enumerate() {
        let mut manifest: VerificationManifest =
            serde_json::from_str(include_str!("fixtures/verification.json"))?;
        let end = binary
            .iter()
            .rposition(|b| *b != 0)
            .context("Empty binary")?
            + 1;
        manifest.executable_hash = format!("{:x}", Sha256::digest(&binary[..end]));
        manifest.commit = format!("{:040x}", index + 1);
        manifest.validate(&binary, &manifest.commit)?;
        if index == 0 {
            let error = check(&rpc, &config, &member, &binary, &manifest)
                .await
                .err()
                .context("Accepted vault balance that would leave one lamport")?;
            assert!(error.to_string().contains("own rent reserve"), "{error:#}");
            send(
                &rpc,
                &member,
                &[solana_system_interface::instruction::transfer(
                    &member.pubkey(),
                    &vault,
                    10_000_000,
                )],
            )
            .await?;
            println!("Vault with metadata rent plus one lamport rejected before upload");
        }
        let metadata = read_verification_instruction(&rpc, &config, &manifest).await?;
        let expected_payload = metadata
            .instruction
            .data
            .get(8..)
            .context("Missing metadata bytes")?
            .to_vec();
        let mut instruction = metadata.instruction;
        if index == 2 {
            *instruction
                .data
                .first_mut()
                .context("Missing discriminator")? ^= 1;
        }
        let proposal = build_proposal(
            &config,
            member.pubkey(),
            buffer,
            (index + 1) as u64,
            1,
            instruction,
        )?;
        if index < 2 {
            let preflight = check(&rpc, &config, &member, &binary, &manifest).await?;
            let receipt = propose(
                &rpc,
                &config,
                &member,
                &binary,
                ProposalRequest {
                    buffer,
                    transaction_index: preflight.transaction_index,
                    source_commit: manifest.commit.clone(),
                    tag: format!("upgrade-{}", index + 1),
                    verification: manifest.clone(),
                    verification_instruction_sha256: preflight
                        .verification_instruction_sha256
                        .clone(),
                },
            )
            .await?;
            assert_eq!(receipt.proposal, proposal.proposal_address.to_string());
            assert_eq!(receipt.verification_pda, metadata.address.to_string());
            assert_eq!(
                receipt.verification_observed_deploy_slot,
                metadata.observed_deploy_slot
            );
            if index == 0 {
                let error = check(&rpc, &config, &member, &binary, &manifest)
                    .await
                    .err()
                    .context("Accepted a second pending initializer")?;
                assert!(
                    error.to_string().contains("already initializes"),
                    "{error:#}"
                );
                let next_buffer = buffers[1];
                let before = rpc.get_account(&next_buffer).await?;
                let error = propose(
                    &rpc,
                    &config,
                    &member,
                    &binary,
                    ProposalRequest {
                        buffer: next_buffer,
                        transaction_index: 2,
                        source_commit: manifest.commit.clone(),
                        tag: "overlapping-release".into(),
                        verification: manifest.clone(),
                        verification_instruction_sha256: preflight.verification_instruction_sha256,
                    },
                )
                .await
                .err()
                .context("Submitted a second pending initializer")?;
                assert!(
                    error.to_string().contains("already initializes"),
                    "{error:#}"
                );
                assert_eq!(
                    before,
                    rpc.get_account(&next_buffer).await?,
                    "Rejected proposal changed the buffer"
                );
                println!("Second initializer rejected by preflight and proposal submission while first is active");
            }
        } else {
            // Prove a real Squads proposal can cross the old 1,232-byte ceiling.
            let mut instructions = proposal.instructions.clone();
            instructions.extend(vec![
                solana_system_interface::instruction::transfer(
                    &member.pubkey(),
                    &vault,
                    1
                );
                12
            ]);
            let transaction = prepare_proposal_transaction(&rpc, &member, &instructions).await?;
            assert!(transaction.wire_bytes > 1232 && transaction.wire_bytes <= 4096);
            let signature: String = rpc.send(squads_multisig::solana_rpc_client_api::request::RpcRequest::SendTransaction,
                serde_json::json!([transaction.encoded, {"encoding":"base64", "skipPreflight":false, "preflightCommitment":"confirmed"}])).await?;
            assert_eq!(signature, transaction.signature.to_string());
            let mut confirmed = false;
            for _ in 0..30 {
                if let Some(status) = rpc.get_signature_status(&transaction.signature).await? {
                    status?;
                    confirmed = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            assert!(confirmed, "Oversize v1 proposal was not confirmed");
            println!(
                "Squads v1 proposal confirmed: {} bytes, above the legacy/v0 limit",
                transaction.wire_bytes
            );
        }
        send(
            &rpc,
            &member,
            &[proposal_approve(
                ProposalVoteAccounts {
                    multisig,
                    proposal: proposal.proposal_address,
                    member: member.pubkey(),
                },
                ProposalVoteArgs { memo: None },
                Some(squads),
            )],
        )
        .await?;
        if index == 0 {
            let error = check(&rpc, &config, &member, &binary, &manifest)
                .await
                .err()
                .context("Accepted second initializer while first is approved")?;
            assert!(
                error.to_string().contains("already initializes"),
                "{error:#}"
            );
        }
        let message = TransactionMessage::deserialize(&mut proposal.vault_message.as_slice())?;
        let execute = vault_transaction_execute(
            VaultTransactionExecuteAccounts {
                multisig,
                member: member.pubkey(),
                proposal: proposal.proposal_address,
                transaction: proposal.transaction_address,
            },
            0,
            0,
            &message,
            &[],
            Some(squads),
        )?;
        let before = rpc
            .get_multiple_accounts(&[
                program_data,
                buffer,
                metadata.address,
                vault,
                proposal.proposal_address,
            ])
            .await?;
        if index == 2 {
            // Exercise the real on-chain rollback, not only RPC preflight.
            let hash = rpc.get_latest_blockhash().await?;
            let tx = Transaction::new_signed_with_payer(
                &[execute],
                Some(&member.pubkey()),
                &[&member],
                hash,
            );
            let result = rpc.simulate_transaction(&tx).await?;
            let logs = result.value.logs.context("Missing failed execution logs")?;
            assert!(
                logs.iter().any(|line| line.contains("Upgraded program")),
                "upgrade was not reached: {logs:?}"
            );
            assert!(
                logs.iter()
                    .any(|line| line.contains("InstructionFallbackNotFound")),
                "metadata rejection was not reached: {logs:?}"
            );
            let signature = rpc
                .send_transaction_with_config(
                    &tx,
                    squads_multisig::solana_rpc_client_api::config::RpcSendTransactionConfig {
                        skip_preflight: true,
                        ..Default::default()
                    },
                )
                .await?;
            let mut failed = false;
            for _ in 0..30 {
                if let Some(status) = rpc.get_signature_status(&signature).await? {
                    assert!(status.is_err());
                    failed = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            assert!(failed, "failed execution was not confirmed");
            let after = rpc
                .get_multiple_accounts(&[
                    program_data,
                    buffer,
                    metadata.address,
                    vault,
                    proposal.proposal_address,
                ])
                .await?;
            assert_eq!(
                before, after,
                "failed metadata instruction did not roll back the whole upgrade"
            );
            println!("Metadata failure: upgrade reached, full state rollback confirmed");
        } else {
            send(&rpc, &member, &[execute]).await?;
            let after = rpc.get_account(&program_data).await?;
            assert_ne!(
                before.first().and_then(Option::as_ref).map(|a| &a.data),
                Some(&after.data)
            );
            assert_eq!(
                after
                    .data
                    .get(UpgradeableLoaderState::size_of_programdata_metadata()..),
                Some(binary.as_slice())
            );
            let stored = rpc.get_account(&metadata.address).await?;
            assert_eq!(
                stored.data.get(72..stored.data.len() - 1),
                Some(expected_payload.as_slice())
            );
            assert_eq!(stored.owner, VERIFY_PROGRAM);
            println!(
                "One proposal executed upgrade + metadata {}",
                if index == 0 { "initialize" } else { "update" }
            );
        }
    }
    Ok(())
}
