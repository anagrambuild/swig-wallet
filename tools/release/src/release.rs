use std::{fs, path::Path, time::Duration};

use anyhow::{anyhow, ensure, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use squads_multisig::{
    anchor_lang::{AccountDeserialize, AnchorSerialize},
    solana_rpc_client::nonblocking::rpc_client::RpcClient,
    solana_rpc_client_api::config::RpcSendTransactionConfig,
    squads_multisig_program::{
        Proposal, ProposalStatus, TransactionMessage, VaultTransaction, VaultTransactionMessage,
    },
};

use crate::{
    accounts::{read_upgrade_accounts, validate_buffer, validate_capacity},
    config::ReleaseConfig,
    proposal::{
        build_proposal, confirmation_complete, require_next_index, validate_release_identity,
    },
};

// Conservative reserve for upload transactions and fee changes. It is a balance
// requirement, not a transfer or a priority fee charged to the proposer.
const UPLOAD_FEE_RESERVE: u64 = 100_000_000;

#[derive(Serialize)]
pub struct CheckReceipt {
    pub binary_bytes: usize,
    pub binary_sha256: String,
    pub program_capacity_bytes: usize,
    pub additional_bytes_required: usize,
    pub transaction_index: u64,
    pub buffer_rent_lamports: u64,
    pub proposal_rent_lamports: u64,
    pub upload_fee_reserve_lamports: u64,
    pub minimum_proposer_balance_lamports: u64,
}

#[derive(Serialize)]
pub struct ProposalReceipt {
    pub tag: String,
    pub source_commit: String,
    pub binary_sha256: String,
    pub binary_bytes: usize,
    pub program_capacity_bytes: usize,
    pub buffer: String,
    pub vault_transaction: String,
    pub proposal: String,
    pub transaction_index: u64,
    pub signature: String,
}

pub fn read_binary(path: &Path) -> Result<Vec<u8>> {
    let binary = fs::read(path).context("Could not read program binary")?;
    ensure!(
        binary.get(..4) == Some(b"\x7fELF"),
        "Program binary must be an ELF file"
    );
    ensure!(
        binary.len() <= 10 * 1024 * 1024 - UpgradeableLoaderState::size_of_programdata_metadata(),
        "Program binary exceeds the loader-v3 account size limit"
    );
    Ok(binary)
}

pub async fn check(
    rpc: &RpcClient,
    config: &ReleaseConfig,
    proposer: &Keypair,
    binary: &[u8],
) -> Result<CheckReceipt> {
    let accounts = read_upgrade_accounts(rpc, config, proposer.pubkey()).await?;
    if binary.len() > accounts.program_capacity {
        let rent = rpc
            .get_minimum_balance_for_rent_exemption(UpgradeableLoaderState::size_of_programdata(
                binary.len(),
            ))
            .await
            .map_err(|_| anyhow!("Program is too small; could not calculate extension rent"))?;
        anyhow::bail!(
            "Program needs {} additional bytes and {} additional rent lamports; extend it through an approved operation before retrying",
            binary.len() - accounts.program_capacity,
            rent.saturating_sub(accounts.program_data_balance),
        );
    }
    validate_capacity(binary.len(), accounts.program_capacity)?;
    let transaction_index = accounts
        .multisig
        .transaction_index
        .checked_add(1)
        .context("Multisig transaction index overflow")?;
    // Only the account sizing is needed; the upload buffer is created later.
    let proposal = build_proposal(
        config,
        proposer.pubkey(),
        Keypair::new().pubkey(),
        transaction_index,
        accounts.multisig.members.len(),
        String::new(),
    )?;
    let buffer_rent = rpc
        .get_minimum_balance_for_rent_exemption(UpgradeableLoaderState::size_of_buffer(
            binary.len(),
        ))
        .await
        .map_err(|_| anyhow!("Could not fetch buffer rent"))?;
    let transaction_rent = rpc
        .get_minimum_balance_for_rent_exemption(proposal.transaction_size)
        .await
        .map_err(|_| anyhow!("Could not fetch Squads transaction rent"))?;
    let proposal_rent = rpc
        .get_minimum_balance_for_rent_exemption(proposal.proposal_size)
        .await
        .map_err(|_| anyhow!("Could not fetch proposal rent"))?;
    let combined_rent = transaction_rent
        .checked_add(proposal_rent)
        .context("Rent calculation overflow")?;
    let minimum_balance = buffer_rent
        .checked_add(combined_rent)
        .and_then(|sum| sum.checked_add(UPLOAD_FEE_RESERVE))
        .context("Funding calculation overflow")?;
    ensure!(accounts.proposer_balance >= minimum_balance,
        "Proposer needs at least {minimum_balance} lamports for buffer/proposal rent and upload fee reserve; has {}", accounts.proposer_balance);
    Ok(CheckReceipt {
        binary_bytes: binary.len(),
        binary_sha256: format!("{:x}", Sha256::digest(binary)),
        program_capacity_bytes: accounts.program_capacity,
        additional_bytes_required: 0,
        transaction_index,
        buffer_rent_lamports: buffer_rent,
        proposal_rent_lamports: combined_rent,
        upload_fee_reserve_lamports: UPLOAD_FEE_RESERVE,
        minimum_proposer_balance_lamports: minimum_balance,
    })
}

pub struct ProposalRequest {
    pub buffer: Pubkey,
    pub transaction_index: u64,
    pub source_commit: String,
    pub tag: String,
}

pub async fn propose(
    rpc: &RpcClient,
    config: &ReleaseConfig,
    proposer: &Keypair,
    binary: &[u8],
    request: ProposalRequest,
) -> Result<ProposalReceipt> {
    validate_release_identity(&request.source_commit, &request.tag)?;
    let accounts = read_upgrade_accounts(rpc, config, proposer.pubkey()).await?;
    validate_capacity(binary.len(), accounts.program_capacity)?;
    require_next_index(
        accounts.multisig.transaction_index,
        request.transaction_index,
    )?;
    let buffer = rpc
        .get_account(&request.buffer)
        .await
        .map_err(|_| anyhow!("Could not read the upload buffer"))?;
    validate_buffer(&buffer, binary, proposer.pubkey())?;
    let buffer_rent = rpc
        .get_minimum_balance_for_rent_exemption(buffer.data.len())
        .await
        .map_err(|_| anyhow!("Could not fetch buffer rent"))?;
    ensure!(buffer.lamports >= buffer_rent, "Buffer must be rent exempt");
    let binary_hash = format!("{:x}", Sha256::digest(binary));
    let memo = format!(
        "Swig upgrade {}; commit={}; sha256={binary_hash}",
        request.tag, request.source_commit
    );
    let proposal = build_proposal(
        config,
        proposer.pubkey(),
        request.buffer,
        request.transaction_index,
        accounts.multisig.members.len(),
        memo,
    )?;
    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|_| anyhow!("Could not fetch a recent blockhash"))?;
    let message =
        Message::new_with_blockhash(&proposal.instructions, Some(&proposer.pubkey()), &blockhash);
    let transaction_rent = rpc
        .get_minimum_balance_for_rent_exemption(proposal.transaction_size)
        .await
        .map_err(|_| anyhow!("Could not fetch Squads transaction rent"))?;
    let proposal_rent = rpc
        .get_minimum_balance_for_rent_exemption(proposal.proposal_size)
        .await
        .map_err(|_| anyhow!("Could not fetch proposal rent"))?;
    let fee = rpc
        .get_fee_for_message(&message)
        .await
        .map_err(|_| anyhow!("Could not calculate proposal transaction fee"))?;
    let required = transaction_rent
        .checked_add(proposal_rent)
        .and_then(|rent| rent.checked_add(fee))
        .context("Proposal funding calculation overflow")?;
    ensure!(
        accounts.proposer_balance >= required,
        "Proposer needs {required} lamports for proposal creation"
    );
    let mut transaction = Transaction::new_unsigned(message);
    transaction.try_sign(&[proposer], blockhash)?;
    ensure!(
        bincode::serialize(&transaction)?.len() <= 1232,
        "Proposal transaction exceeds the Solana packet limit"
    );
    let signature = *transaction
        .signatures
        .first()
        .context("Missing transaction signature")?;
    // Print the public transaction identifier before submission so an unknown
    // network outcome can be investigated without constructing a new proposal.
    eprintln!(
        "Submitting proposal transaction {signature}; transaction index {}",
        request.transaction_index
    );
    let returned = rpc.send_transaction_with_config(&transaction, RpcSendTransactionConfig {
        skip_preflight: false, preflight_commitment: Some(CommitmentConfig::confirmed().commitment),
        max_retries: Some(0), ..RpcSendTransactionConfig::default()
    }).await.map_err(|_| anyhow!("Submission failed or is uncertain; inspect transaction {signature} before retrying"))?;
    ensure!(
        returned == signature,
        "RPC returned an unexpected transaction signature; inspect {signature}"
    );
    let mut confirmed = false;
    for _ in 0..60 {
        let status = rpc
            .get_signature_status_with_commitment_and_history(
                &signature,
                CommitmentConfig::confirmed(),
                true,
            )
            .await
            .map_err(|_| {
                anyhow!(
                    "Confirmation is uncertain; inspect transaction {signature} before retrying"
                )
            })?;
        if confirmation_complete(status)? {
            confirmed = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    ensure!(
        confirmed,
        "Confirmation timed out; inspect transaction {signature} before retrying"
    );
    let fetched = rpc.get_multiple_accounts(&[request.buffer, proposal.transaction_address, proposal.proposal_address])
        .await.map_err(|_| anyhow!("Transaction {signature} confirmed, but receipt verification could not read its accounts"))?;
    let mut fetched = fetched.into_iter();
    let buffer = fetched
        .next()
        .flatten()
        .context("Confirmed transaction buffer is missing")?;
    validate_buffer(&buffer, binary, accounts.vault)?;
    let stored_transaction = fetched
        .next()
        .flatten()
        .context("Confirmed vault transaction is missing")?;
    let stored_proposal = fetched
        .next()
        .flatten()
        .context("Confirmed proposal is missing")?;
    ensure!(
        stored_transaction.owner == config.squads_program
            && stored_proposal.owner == config.squads_program,
        "Confirmed Squads accounts have incorrect owners"
    );
    let stored_transaction =
        VaultTransaction::try_deserialize(&mut stored_transaction.data.as_slice())
            .map_err(|_| anyhow!("Malformed confirmed vault transaction"))?;
    let stored_proposal = Proposal::try_deserialize(&mut stored_proposal.data.as_slice())
        .map_err(|_| anyhow!("Malformed confirmed proposal"))?;
    let expected_message: TransactionMessage =
        squads_multisig::anchor_lang::AnchorDeserialize::deserialize(
            &mut proposal.vault_message.as_slice(),
        )?;
    let expected_message = VaultTransactionMessage::try_from(expected_message)
        .map_err(|_| anyhow!("Malformed expected vault message"))?;
    ensure!(
        stored_transaction.multisig == config.multisig
            && stored_transaction.creator == proposer.pubkey()
            && stored_transaction.index == request.transaction_index
            && stored_transaction.vault_index == config.vault_index
            && stored_transaction.ephemeral_signer_bumps.is_empty()
            && stored_transaction.message.try_to_vec()? == expected_message.try_to_vec()?,
        "Confirmed vault transaction does not match the intended upgrade"
    );
    ensure!(
        stored_proposal.multisig == config.multisig
            && stored_proposal.transaction_index == request.transaction_index
            && matches!(stored_proposal.status, ProposalStatus::Active { .. }),
        "Confirmed proposal is not active for this upgrade"
    );
    Ok(ProposalReceipt {
        tag: request.tag,
        source_commit: request.source_commit,
        binary_sha256: binary_hash,
        binary_bytes: binary.len(),
        program_capacity_bytes: accounts.program_capacity,
        buffer: request.buffer.to_string(),
        vault_transaction: proposal.transaction_address.to_string(),
        proposal: proposal.proposal_address.to_string(),
        transaction_index: request.transaction_index,
        signature: signature.to_string(),
    })
}
