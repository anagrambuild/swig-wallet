use anyhow::{anyhow, ensure, Context, Result};
use solana_loader_v3_interface::instruction as bpf_loader_upgradeable;
use solana_sdk::{instruction::Instruction, pubkey::Pubkey, transaction::TransactionError};
use solana_sdk_ids::system_program;
use squads_multisig::{
    anchor_lang::{AnchorSerialize, InstructionData, ToAccountMetas},
    pda::{get_proposal_pda, get_transaction_pda, get_vault_pda},
    squads_multisig_program::{
        self as squads, ProposalCreateArgs, TransactionMessage, VaultTransactionCreateArgs,
    },
    vault_transaction::VaultTransactionMessageExt,
};

use crate::config::ReleaseConfig;

pub struct UpgradeProposal {
    pub instructions: Vec<Instruction>,
    pub transaction_address: Pubkey,
    pub proposal_address: Pubkey,
    pub vault_message: Vec<u8>,
    pub transaction_size: usize,
    pub proposal_size: usize,
}

pub fn validate_release_identity(commit: &str, tag: &str) -> Result<()> {
    ensure!(
        commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "source-commit must be a full 40-character Git commit SHA"
    );
    ensure!(
        !tag.is_empty()
            && tag.len() <= 80
            && tag
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)),
        "tag must contain 1-80 ASCII letters, digits, hyphens, underscores or periods"
    );
    Ok(())
}

pub fn build_proposal(
    config: &ReleaseConfig,
    proposer: Pubkey,
    buffer: Pubkey,
    transaction_index: u64,
    member_count: usize,
    memo: String,
) -> Result<UpgradeProposal> {
    let vault = get_vault_pda(
        &config.multisig,
        config.vault_index,
        Some(&config.squads_program),
    )
    .0;
    let transaction_address = get_transaction_pda(
        &config.multisig,
        transaction_index,
        Some(&config.squads_program),
    )
    .0;
    let proposal_address = get_proposal_pda(
        &config.multisig,
        transaction_index,
        Some(&config.squads_program),
    )
    .0;
    // Reimburse the proposer that funded the buffer when members execute the upgrade.
    let upgrade = bpf_loader_upgradeable::upgrade(&config.program, &buffer, &vault, &proposer);
    let message = TransactionMessage::try_compile(&vault, &[upgrade], &[])?;
    // Squads uses its own message encoding, not a serialized Solana v0 Message.
    let vault_message = message.try_to_vec()?;
    let transaction_size = squads::VaultTransaction::size(0, &vault_message)
        .map_err(|_| anyhow!("Could not calculate Squads transaction account size"))?;
    let proposal_size = squads::Proposal::size(member_count);
    let instructions = vec![
        // Handoff and proposal creation succeed or roll back together. A failed
        // proposal never strands a buffer under the vault's authority.
        bpf_loader_upgradeable::set_buffer_authority(&buffer, &proposer, &vault),
        Instruction {
            program_id: config.squads_program,
            accounts: squads::accounts::VaultTransactionCreate {
                multisig: config.multisig,
                transaction: transaction_address,
                creator: proposer,
                rent_payer: proposer,
                system_program: system_program::id(),
            }
            .to_account_metas(None),
            data: squads::instruction::VaultTransactionCreate {
                args: VaultTransactionCreateArgs {
                    vault_index: config.vault_index,
                    ephemeral_signers: 0,
                    transaction_message: vault_message.clone(),
                    memo: Some(memo),
                },
            }
            .data(),
        },
        Instruction {
            program_id: config.squads_program,
            accounts: squads::accounts::ProposalCreate {
                multisig: config.multisig,
                proposal: proposal_address,
                creator: proposer,
                rent_payer: proposer,
                system_program: system_program::id(),
            }
            .to_account_metas(None),
            data: squads::instruction::ProposalCreate {
                args: ProposalCreateArgs {
                    transaction_index,
                    draft: false,
                },
            }
            .data(),
        },
    ];
    Ok(UpgradeProposal {
        instructions,
        transaction_address,
        proposal_address,
        vault_message,
        transaction_size,
        proposal_size,
    })
}

pub fn require_next_index(current: u64, requested: u64) -> Result<()> {
    let next = current
        .checked_add(1)
        .context("Multisig transaction index overflow")?;
    ensure!(requested == next,
        "Expected unused transaction index {next}, got {requested}; inspect the existing proposal before retrying");
    Ok(())
}

pub fn confirmation_complete(status: Option<Result<(), TransactionError>>) -> Result<bool> {
    match status {
        Some(Ok(())) => Ok(true),
        Some(Err(_)) => Err(anyhow!(
            "Proposal transaction failed on-chain; the buffer handoff was rolled back"
        )),
        None => Ok(false),
    }
}
