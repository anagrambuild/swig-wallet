//! Fault injection around real Surfpool RPC responses, after real submission.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_sdk_ids::system_program;
use squads_multisig::{
    anchor_lang::{AccountDeserialize, AccountSerialize},
    solana_rpc_client::{
        http_sender::HttpSender,
        rpc_sender::{RpcSender, RpcTransportStats},
    },
    solana_rpc_client_api::{
        client_error::{ErrorKind, Result as RpcResult},
        request::RpcRequest,
    },
    squads_multisig_program::{Proposal, ProposalStatus, VaultTransaction},
};

#[derive(Clone, Copy, Debug)]
pub enum Fault {
    LostSubmissionReply,
    ConfirmationUnavailable,
    MissingBuffer,
    MissingTransaction,
    MissingProposal,
    WrongOwner,
    ChangedBuffer,
    ChangedBufferAuthority,
    ChangedMessage,
    InactiveProposal,
}

pub struct FaultySurfpool {
    pub inner: HttpSender,
    pub fault: Fault,
    pub submissions: Arc<AtomicUsize>,
    pub injections: Arc<AtomicUsize>,
}

#[async_trait]
impl RpcSender for FaultySurfpool {
    async fn send(&self, request: RpcRequest, mut params: Value) -> RpcResult<Value> {
        let sending = request == RpcRequest::SendTransaction;
        if sending {
            self.submissions.fetch_add(1, Ordering::SeqCst);
        }
        if request == RpcRequest::GetSignatureStatuses
            && matches!(self.fault, Fault::ConfirmationUnavailable)
        {
            self.injections.fetch_add(1, Ordering::SeqCst);
            return Err(ErrorKind::Custom("Injected confirmation outage".into()).into());
        }
        let receipt = request == RpcRequest::GetMultipleAccounts
            && params
                .get(0)
                .and_then(Value::as_array)
                .is_some_and(|keys| keys.len() == 3)
            && self.submissions.load(Ordering::SeqCst) > 0;
        if receipt {
            // Ask Surfpool for plain base64 so corruption targets account bytes,
            // not the SDK's default zstd-compressed representation.
            let encoding = params
                .get_mut(1)
                .and_then(|config| config.get_mut("encoding"))
                .ok_or_else(|| ErrorKind::Custom("Missing receipt encoding".into()))?;
            *encoding = json!("base64");
        }
        let mut reply = self.inner.send(request, params).await?;
        if sending && matches!(self.fault, Fault::LostSubmissionReply) {
            self.injections.fetch_add(1, Ordering::SeqCst);
            return Err(ErrorKind::Custom(
                "Injected lost reply after successful submission".into(),
            )
            .into());
        }
        if receipt {
            corrupt_receipt(&mut reply, self.fault)
                .map_err(|error| ErrorKind::Custom(error.to_string()))?;
            self.injections.fetch_add(1, Ordering::SeqCst);
        }
        Ok(reply)
    }

    fn get_transport_stats(&self) -> RpcTransportStats {
        self.inner.get_transport_stats()
    }
    fn url(&self) -> String {
        self.inner.url()
    }
}

fn corrupt_receipt(reply: &mut Value, fault: Fault) -> Result<()> {
    let accounts = reply
        .get_mut("value")
        .and_then(Value::as_array_mut)
        .context("Missing real account response")?;
    let index = match fault {
        Fault::MissingBuffer | Fault::ChangedBuffer | Fault::ChangedBufferAuthority => 0,
        Fault::MissingTransaction | Fault::WrongOwner | Fault::ChangedMessage => 1,
        Fault::MissingProposal | Fault::InactiveProposal => 2,
        _ => anyhow::bail!("Wrong fault phase"),
    };
    let account = accounts
        .get_mut(index)
        .context("Missing response position")?;
    if matches!(
        fault,
        Fault::MissingBuffer | Fault::MissingTransaction | Fault::MissingProposal
    ) {
        *account = Value::Null;
        return Ok(());
    }
    if matches!(fault, Fault::WrongOwner) {
        *account.get_mut("owner").context("Missing account owner")? =
            json!(system_program::id().to_string());
        return Ok(());
    }
    let encoded = account
        .get_mut("data")
        .and_then(Value::as_array_mut)
        .and_then(|data| data.first_mut())
        .context("Missing base64 data")?;
    let mut data = STANDARD.decode(encoded.as_str().context("Non-string account data")?)?;
    match fault {
        Fault::ChangedBuffer => {
            *data.last_mut().context("Empty buffer")? ^= 1;
        },
        Fault::ChangedBufferAuthority => {
            let metadata = bincode::serialize(&UpgradeableLoaderState::Buffer {
                authority_address: Some(system_program::id()),
            })?;
            data.get_mut(..metadata.len())
                .context("Short buffer")?
                .copy_from_slice(&metadata);
        },
        Fault::ChangedMessage => {
            let mut transaction = VaultTransaction::try_deserialize(&mut data.as_slice())?;
            let instruction = transaction
                .message
                .instructions
                .first_mut()
                .context("No stored instruction")?;
            *instruction.data.first_mut().context("No upgrade data")? ^= 1;
            data.clear();
            transaction.try_serialize(&mut data)?;
        },
        Fault::InactiveProposal => {
            let mut proposal = Proposal::try_deserialize(&mut data.as_slice())?;
            proposal.status = ProposalStatus::Draft { timestamp: 0 };
            data.clear();
            proposal.try_serialize(&mut data)?;
        },
        _ => anyhow::bail!("Wrong account corruption phase"),
    }
    *encoded = json!(STANDARD.encode(data));
    Ok(())
}
