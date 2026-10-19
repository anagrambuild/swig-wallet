use anyhow::{anyhow, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
use solana_sdk_ids::{bpf_loader_upgradeable, system_program};
use squads_multisig::{
    anchor_lang::{
        prelude::borsh, AccountDeserialize, AnchorDeserialize, AnchorSerialize, Discriminator,
    },
    pda::{get_proposal_pda, get_transaction_pda, get_vault_pda},
    solana_rpc_client::nonblocking::rpc_client::RpcClient,
    squads_multisig_program::{Multisig, Proposal, ProposalStatus, VaultTransaction},
};

use crate::config::ReleaseConfig;

pub const VERIFY_PROGRAM: Pubkey =
    solana_sdk::pubkey!("verifycLy8mB96wd9wqq3WDXQwM4oU6r42Th37Db9fC");
pub const BUILD_IMAGE: &str = "solanafoundation/solana-verifiable-build@sha256:\
                           12fd4c0a0790f0fc41ef74b0cdb6bccc167ba6137eb1adb749bac649481c86bd";
pub const REPOSITORY: &str = "https://github.com/anagrambuild/swig-wallet";
pub const VERIFY_VERSION: &str = "0.5.2";
pub const BUILD_ARGS: [&str; 6] = [
    "--library-name",
    "swig",
    "--base-image",
    BUILD_IMAGE,
    "--arch",
    "v3",
];

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationManifest {
    pub repository: String,
    pub commit: String,
    pub cli_version: String,
    pub build_args: Vec<String>,
    pub executable_hash: String,
}

impl VerificationManifest {
    pub fn read_release(directory: &std::path::Path, source_commit: &str) -> Result<Self> {
        let binary = crate::release::read_binary(&directory.join("swig.so"))?;
        let manifest: Self = serde_json::from_slice(
            &std::fs::read(directory.join("verification.json"))
                .context("Could not read verification manifest")?,
        )?;
        manifest.validate(&binary, source_commit)?;
        Ok(manifest)
    }

    pub fn validate(&self, binary: &[u8], source_commit: &str) -> Result<()> {
        ensure!(
            self.repository == REPOSITORY
                && self.commit == source_commit
                && self.commit.len() == 40
                && self.commit.bytes().all(|b| b.is_ascii_hexdigit())
                && self.cli_version == VERIFY_VERSION
                && self.build_args == BUILD_ARGS,
            "Verification manifest does not match the release source and pinned build recipe"
        );
        ensure!(
            self.executable_hash == executable_hash(binary),
            "Verification manifest executable hash does not match the binary"
        );
        Ok(())
    }
}

pub fn executable_hash(binary: &[u8]) -> String {
    // solana-verify excludes trailing executable padding from its hash.
    let end = binary.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
    format!("{:x}", Sha256::digest(&binary[..end]))
}

pub fn validate_published_metadata(
    account: &Account,
    program: Pubkey,
    authority: Pubkey,
    manifest: &VerificationManifest,
    observed_slot: u64,
) -> Result<()> {
    let expected =
        build_verification_instruction(program, authority, manifest, observed_slot, Some(account))?;
    // The builder checks the account envelope. Compare its stored parameters to
    // the release recipe, including the slot recorded in the proposal receipt.
    ensure!(
        account.data.get(72..account.data.len().saturating_sub(1))
            == expected.instruction.data.get(8..),
        "Published verification metadata does not match the release proposal"
    );
    Ok(())
}

// Wire format from otter-sec/otter-verify at
// a630c42962872ae9adac924151948bb17d87174d.
#[derive(AnchorSerialize, AnchorDeserialize)]
struct InputParams {
    version: String,
    git_url: String,
    commit: String,
    args: Vec<String>,
    deploy_slot: u64,
}

pub struct VerificationInstruction {
    pub instruction: Instruction,
    pub address: Pubkey,
    pub observed_deploy_slot: u64,
    pub account_size: usize,
}

pub fn build_verification_instruction(
    program: Pubkey,
    vault: Pubkey,
    manifest: &VerificationManifest,
    observed_deploy_slot: u64,
    existing: Option<&Account>,
) -> Result<VerificationInstruction> {
    let (address, bump) = Pubkey::find_program_address(
        &[b"otter_verify", vault.as_ref(), program.as_ref()],
        &VERIFY_PROGRAM,
    );
    let initialize = match existing {
        None => true,
        Some(account)
            if account.owner == system_program::id()
                && account.data.is_empty()
                && !account.executable =>
        {
            true
        },
        Some(account) => {
            ensure!(
                account.owner == VERIFY_PROGRAM && !account.executable,
                "Verification PDA has an incorrect owner or executable flag"
            );
            let mut data = account.data.as_slice();
            let discriminator = <[u8; 8] as AnchorDeserialize>::deserialize(&mut data)?;
            ensure!(
                discriminator.as_slice() == &Sha256::digest(b"account:BuildParams")[..8],
                "Malformed verification PDA discriminator"
            );
            let stored_program = <Pubkey as AnchorDeserialize>::deserialize(&mut data)?;
            let stored_signer = <Pubkey as AnchorDeserialize>::deserialize(&mut data)?;
            let _params = InputParams::deserialize(&mut data)?;
            let stored_bump = <u8 as AnchorDeserialize>::deserialize(&mut data)?;
            ensure!(
                stored_program == program
                    && stored_signer == vault
                    && stored_bump == bump
                    && data.is_empty(),
                "Verification PDA does not match the program and vault"
            );
            false
        },
    };
    // The upcoming execution slot is unknowable at proposal time. Preserve the
    // last observed deployment, just as export-pda-tx does. OtterSec verifies the
    // live executable hash, source and signer; it does not use this advisory slot.
    let params = InputParams {
        version: manifest.cli_version.clone(),
        git_url: manifest.repository.clone(),
        commit: manifest.commit.clone(),
        args: manifest.build_args.clone(),
        deploy_slot: observed_deploy_slot,
    }
    .try_to_vec()?;
    let account_size = 8 + 32 + 32 + params.len() + 1;
    let discriminator = Sha256::digest(if initialize {
        b"global:initialize".as_slice()
    } else {
        b"global:update".as_slice()
    });
    let mut data = discriminator[..8].to_vec();
    data.extend(params);
    Ok(VerificationInstruction {
        instruction: Instruction {
            program_id: VERIFY_PROGRAM,
            accounts: vec![
                AccountMeta::new(address, false),
                AccountMeta::new(vault, true),
                AccountMeta::new_readonly(program, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        },
        address,
        observed_deploy_slot,
        account_size,
    })
}

pub async fn read_verification_instruction(
    rpc: &RpcClient,
    config: &ReleaseConfig,
    manifest: &VerificationManifest,
) -> Result<VerificationInstruction> {
    let vault = get_vault_pda(
        &config.multisig,
        config.vault_index,
        Some(&config.squads_program),
    )
    .0;
    let address = Pubkey::find_program_address(
        &[b"otter_verify", vault.as_ref(), config.program.as_ref()],
        &VERIFY_PROGRAM,
    )
    .0;
    let program_data =
        Pubkey::find_program_address(&[config.program.as_ref()], &bpf_loader_upgradeable::id()).0;
    let fetched = rpc
        .get_multiple_accounts(&[VERIFY_PROGRAM, address, vault, program_data])
        .await
        .map_err(|_| anyhow!("Could not read verification accounts"))?;
    let mut fetched = fetched.into_iter();
    ensure!(
        fetched.next().flatten().is_some_and(|a| a.executable),
        "Otter Verify program is not executable"
    );
    let existing = fetched.next().flatten();
    let vault_account = fetched
        .next()
        .flatten()
        .context("Squads vault must be funded for verification metadata rent")?;
    ensure!(
        vault_account.owner == system_program::id()
            && vault_account.data.is_empty()
            && !vault_account.executable,
        "Squads vault must be a System account"
    );
    let program_data = fetched
        .next()
        .flatten()
        .context("ProgramData account is missing")?;
    ensure!(
        program_data.owner == bpf_loader_upgradeable::id() && !program_data.executable,
        "Invalid verification ProgramData owner"
    );
    let state: UpgradeableLoaderState = bincode::deserialize(
        program_data
            .data
            .get(..UpgradeableLoaderState::size_of_programdata_metadata())
            .context("Truncated verification ProgramData")?,
    )?;
    let UpgradeableLoaderState::ProgramData {
        slot,
        upgrade_authority_address: Some(authority),
    } = state
    else {
        anyhow::bail!("Missing program upgrade authority")
    };
    ensure!(
        authority == vault,
        "Verification signer must be the program upgrade authority"
    );
    let verification =
        build_verification_instruction(config.program, vault, manifest, slot, existing.as_ref())?;
    let rent = rpc
        .get_minimum_balance_for_rent_exemption(verification.account_size)
        .await
        .map_err(|_| anyhow!("Could not calculate verification metadata rent"))?;
    let vault_rent = rpc
        .get_minimum_balance_for_rent_exemption(0)
        .await
        .map_err(|_| anyhow!("Could not calculate Squads vault rent reserve"))?;
    validate_metadata_rent(
        vault_account.lamports,
        existing.as_ref().map_or(0, |a| a.lamports),
        rent,
        vault_rent,
    )?;
    Ok(verification)
}

pub fn validate_metadata_rent(
    vault_balance: u64,
    metadata_balance: u64,
    metadata_rent: u64,
    vault_rent: u64,
) -> Result<()> {
    let required = metadata_rent
        .saturating_sub(metadata_balance)
        .checked_add(vault_rent)
        .context("Verification funding calculation overflow")?;
    ensure!(
        vault_balance >= required,
        "Squads vault needs {required} lamports for verification metadata and its own rent reserve"
    );
    Ok(())
}

pub fn proposal_can_still_execute(proposal: &Proposal, stale_index: u64) -> bool {
    match proposal.status {
        // Squads explicitly permits already-approved proposals to execute after
        // a configuration change makes their transaction index stale.
        ProposalStatus::Approved { .. } => true,
        ProposalStatus::Draft { .. } | ProposalStatus::Active { .. } => {
            proposal.transaction_index > stale_index
        },
        ProposalStatus::Rejected { .. }
        | ProposalStatus::Cancelled { .. }
        | ProposalStatus::Executed { .. } => false,
        _ => true,
    }
}

pub async fn require_no_pending_initializer(
    rpc: &RpcClient,
    config: &ReleaseConfig,
    multisig: &Multisig,
    verification: &VerificationInstruction,
) -> Result<()> {
    let initialize = Sha256::digest(b"global:initialize");
    if verification.instruction.data.get(..8) != Some(&initialize[..8]) {
        return Ok(());
    }
    // This scan only runs before the first metadata initialization. Include old
    // indices: an approved proposal remains executable even when stale.
    let mut next = 1_u64;
    while next <= multisig.transaction_index {
        let last = next.saturating_add(99).min(multisig.transaction_index);
        let addresses: Vec<_> = (next..=last)
            .map(|index| get_proposal_pda(&config.multisig, index, Some(&config.squads_program)).0)
            .collect();
        let accounts = rpc
            .get_multiple_accounts(&addresses)
            .await
            .map_err(|_| anyhow!("Could not inspect outstanding Squads proposals"))?;
        for (address, account) in addresses.iter().zip(accounts) {
            let Some(account) = account else { continue };
            ensure!(
                account.owner == config.squads_program,
                "Invalid Squads proposal owner"
            );
            let proposal = Proposal::try_deserialize(&mut account.data.as_slice())
                .map_err(|_| anyhow!("Malformed Squads proposal"))?;
            if !proposal_can_still_execute(&proposal, multisig.stale_transaction_index) {
                continue;
            }
            let transaction_address = get_transaction_pda(
                &config.multisig,
                proposal.transaction_index,
                Some(&config.squads_program),
            )
            .0;
            let transaction = rpc
                .get_account(&transaction_address)
                .await
                .map_err(|_| anyhow!("Could not inspect pending Squads transaction"))?;
            ensure!(
                transaction.owner == config.squads_program,
                "Invalid Squads transaction owner"
            );
            if transaction.data.get(..8) != Some(VaultTransaction::DISCRIMINATOR) {
                continue; // Configuration transactions and batches are not release proposals.
            }
            let transaction = VaultTransaction::try_deserialize(&mut transaction.data.as_slice())
                .map_err(|_| anyhow!("Malformed Squads vault transaction"))?;
            if transaction.vault_index != config.vault_index {
                continue;
            }
            let message = transaction.message;
            let initializes = message.instructions.iter().any(|instruction| {
                message
                    .account_keys
                    .get(usize::from(instruction.program_id_index))
                    == Some(&VERIFY_PROGRAM)
                    && instruction.data.get(..8) == Some(&initialize[..8])
                    && instruction
                        .account_indexes
                        .first()
                        .and_then(|index| message.account_keys.get(usize::from(*index)))
                        == Some(&verification.address)
            });
            ensure!(!initializes,
                "Squads proposal {address} already initializes verification metadata; resolve it before preparing another release");
        }
        if last == multisig.transaction_index {
            break;
        }
        next = last + 1;
    }
    // A pending initializer may have executed during the scan. Force a fresh
    // preflight instead of freezing another Initialize instruction in that case.
    let account = rpc
        .get_account_with_commitment(&verification.address, rpc.commitment())
        .await
        .map_err(|_| anyhow!("Could not recheck verification metadata state"))?
        .value;
    ensure!(
        account.is_none_or(|a| a.owner == system_program::id() && a.data.is_empty()),
        "Verification metadata changed while checking proposals; rerun preflight"
    );
    Ok(())
}
