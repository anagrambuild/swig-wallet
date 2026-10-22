use anyhow::{anyhow, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::json;
use solana_instruction_v1::{AccountMeta as V1AccountMeta, Instruction as V1Instruction};
use solana_message_v1::{
    v1::{self, TransactionConfig},
    VersionedMessage,
};
use solana_sdk::{
    hash::Hash,
    instruction::Instruction,
    signature::{Keypair, Signature, Signer},
    transaction::TransactionError,
};
use solana_transaction_v1::versioned::VersionedTransaction;
use squads_multisig::{
    solana_rpc_client::nonblocking::rpc_client::RpcClient,
    solana_rpc_client_api::{request::RpcRequest, response::Response},
};

const MAX_COMPUTE_UNITS: u32 = 1_400_000;
const MAX_LOADED_BYTES: u32 = 64 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SimulationResult {
    #[serde(deserialize_with = "Option::deserialize")]
    err: Option<TransactionError>,
    units_consumed: u64,
    loaded_accounts_data_size: u32,
}

pub struct PreparedTransaction {
    pub encoded: String,
    pub signature: Signature,
    pub fee: u64,
    pub wire_bytes: usize,
    pub compute_unit_limit: u32,
    pub loaded_accounts_data_size_limit: u32,
}

/// Squads' SDK 2.x instructions cross into the current SDK only at the outer
/// transaction boundary. Both compilation and v1 wire encoding are SDK-owned.
pub fn build_v1_transaction(
    payer: &Keypair,
    instructions: &[Instruction],
    blockhash: Hash,
    config: TransactionConfig,
) -> Result<VersionedTransaction> {
    ensure!(
        config
            .compute_unit_limit
            .is_some_and(|v| v > 0 && v <= MAX_COMPUTE_UNITS)
            && config
                .loaded_accounts_data_size_limit
                .is_some_and(|v| v > 0 && v <= MAX_LOADED_BYTES),
        "V1 transactions require explicit nonzero compute and loaded-account limits"
    );
    let instructions: Vec<_> = instructions
        .iter()
        .map(|instruction| V1Instruction {
            program_id: instruction.program_id.to_bytes().into(),
            data: instruction.data.clone(),
            accounts: instruction
                .accounts
                .iter()
                .map(|account| V1AccountMeta {
                    pubkey: account.pubkey.to_bytes().into(),
                    is_signer: account.is_signer,
                    is_writable: account.is_writable,
                })
                .collect(),
        })
        .collect();
    let message = v1::Message::try_compile_with_config(
        &payer.pubkey().to_bytes().into(),
        &instructions,
        blockhash.to_bytes().into(),
        config,
    )?;
    ensure!(
        message.header.num_required_signatures == 1,
        "Release transaction must require only the proposer signature"
    );
    let message = VersionedMessage::V1(message);
    let signature = payer.try_sign_message(&wincode::serialize(&message)?)?;
    let transaction = VersionedTransaction {
        message,
        signatures: vec![signature.as_array().to_owned().into()],
    };
    transaction.sanitize()?;
    let size = wincode::serialize(&transaction)?.len();
    ensure!(
        size <= v1::MAX_TRANSACTION_SIZE,
        "Proposal transaction is {size} bytes; v1 permits at most 4,096 bytes"
    );
    Ok(transaction)
}

pub fn measured_limits(units: u64, loaded_bytes: u32) -> Result<TransactionConfig> {
    ensure!(
        units > 0
            && units <= u64::from(MAX_COMPUTE_UNITS)
            && loaded_bytes > 0
            && loaded_bytes <= MAX_LOADED_BYTES,
        "Simulation returned invalid resource measurements"
    );
    // Leave execution headroom and one extra account-data page for accounts that
    // could be funded between simulation and submission.
    let compute = u32::try_from((units * 120 / 100 + 1_000).min(u64::from(MAX_COMPUTE_UNITS)))?;
    let loaded = (loaded_bytes.div_ceil(32_768) * 32_768 + 32_768).min(MAX_LOADED_BYTES);
    Ok(TransactionConfig::empty()
        .with_compute_unit_limit(compute)
        .with_loaded_accounts_data_size_limit(loaded))
}

pub async fn prepare_proposal_transaction(
    rpc: &RpcClient,
    payer: &Keypair,
    instructions: &[Instruction],
) -> Result<PreparedTransaction> {
    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|_| anyhow!("Could not fetch a recent blockhash"))?;
    let trial = build_v1_transaction(
        payer,
        instructions,
        blockhash,
        TransactionConfig::empty()
            .with_compute_unit_limit(MAX_COMPUTE_UNITS)
            .with_loaded_accounts_data_size_limit(MAX_LOADED_BYTES),
    )?;
    // SDK 2.x's send/simulate helpers use the legacy codec. Send the current SDK's
    // encoded bytes through the same RPC connection with explicit base64 encoding.
    let simulation: Response<SimulationResult> = rpc.send(RpcRequest::SimulateTransaction,
        json!([STANDARD.encode(wincode::serialize(&trial)?), {"encoding":"base64", "sigVerify":true, "commitment":"confirmed"}]))
        .await.map_err(|_| anyhow!("V1 proposal simulation failed; use a v1-capable RPC endpoint"))?;
    ensure!(
        simulation.value.err.is_none(),
        "V1 proposal simulation rejected the transaction: {:?}",
        simulation.value.err
    );
    let config = measured_limits(
        simulation.value.units_consumed,
        simulation.value.loaded_accounts_data_size,
    )?;
    let transaction = build_v1_transaction(payer, instructions, blockhash, config)?;
    let fee: Response<Option<u64>> = rpc.send(RpcRequest::GetFeeForMessage,
        json!([STANDARD.encode(wincode::serialize(&transaction.message)?), {"commitment":"confirmed"}]))
        .await.map_err(|_| anyhow!("Could not calculate v1 proposal fee"))?;
    let wire = wincode::serialize(&transaction)?;
    let signature = transaction
        .signatures
        .first()
        .context("Missing proposer signature")?;
    Ok(PreparedTransaction {
        encoded: STANDARD.encode(&wire),
        signature: Signature::from(signature.as_array().to_owned()),
        fee: fee
            .value
            .context("V1 proposal blockhash expired before submission")?,
        wire_bytes: wire.len(),
        compute_unit_limit: config
            .compute_unit_limit
            .context("Missing v1 compute limit")?,
        loaded_accounts_data_size_limit: config
            .loaded_accounts_data_size_limit
            .context("Missing v1 account-data limit")?,
    })
}
