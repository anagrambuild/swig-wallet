use anyhow::{anyhow, ensure, Context, Result};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_sdk::{account::Account, pubkey::Pubkey};
use solana_sdk_ids::{bpf_loader_upgradeable, system_program};
use squads_multisig::{
    anchor_lang::AccountDeserialize,
    pda::{get_multisig_pda, get_vault_pda},
    solana_rpc_client::nonblocking::rpc_client::RpcClient,
    state::{Multisig, Permission},
};

use crate::config::ReleaseConfig;

pub struct UpgradeAccounts {
    pub vault: Pubkey,
    pub program_capacity: usize,
    pub multisig: Multisig,
    pub proposer_balance: u64,
    pub program_data_balance: u64,
}

pub fn validate_program(
    program_key: Pubkey,
    program: &Account,
    program_data: &Account,
    vault: Pubkey,
) -> Result<usize> {
    ensure!(
        program.owner == bpf_loader_upgradeable::id() && program.executable,
        "SWIG_PROGRAM_ID must be an executable loader-v3 program"
    );
    let state: UpgradeableLoaderState =
        bincode::deserialize(&program.data).context("Malformed Program account")?;
    let expected_data =
        Pubkey::find_program_address(&[program_key.as_ref()], &bpf_loader_upgradeable::id()).0;
    ensure!(
        matches!(state, UpgradeableLoaderState::Program { programdata_address } if programdata_address == expected_data),
        "Program account does not reference its canonical ProgramData address"
    );
    ensure!(
        program_data.owner == bpf_loader_upgradeable::id() && !program_data.executable,
        "ProgramData has an incorrect owner or executable flag"
    );
    let metadata_size = UpgradeableLoaderState::size_of_programdata_metadata();
    let metadata = program_data
        .data
        .get(..metadata_size)
        .context("Truncated ProgramData account")?;
    let state: UpgradeableLoaderState =
        bincode::deserialize(metadata).context("Malformed ProgramData metadata")?;
    ensure!(
        matches!(state, UpgradeableLoaderState::ProgramData { upgrade_authority_address: Some(authority), .. } if authority == vault),
        "Program upgrade authority must be the configured Squads vault"
    );
    Ok(program_data.data.len() - metadata_size)
}

pub fn validate_capacity(binary_len: usize, capacity: usize) -> Result<()> {
    ensure!(binary_len <= capacity,
        "Program capacity is {capacity} bytes; binary needs {binary_len} bytes ({} additional bytes required)",
        binary_len.saturating_sub(capacity));
    Ok(())
}

pub fn validate_buffer(account: &Account, binary: &[u8], authority: Pubkey) -> Result<()> {
    ensure!(
        account.owner == bpf_loader_upgradeable::id() && !account.executable,
        "Buffer has an incorrect owner or executable flag"
    );
    let metadata_size = UpgradeableLoaderState::size_of_buffer_metadata();
    let metadata = account
        .data
        .get(..metadata_size)
        .context("Truncated Buffer account")?;
    let state: UpgradeableLoaderState =
        bincode::deserialize(metadata).context("Malformed Buffer metadata")?;
    ensure!(
        matches!(state, UpgradeableLoaderState::Buffer { authority_address: Some(key) } if key == authority),
        "Buffer authority does not match the expected signer"
    );
    let payload = account
        .data
        .get(metadata_size..)
        .context("Missing buffer payload")?;
    ensure!(
        payload.len() == binary.len(),
        "Buffer payload size does not match the binary"
    );
    ensure!(
        payload == binary,
        "Uploaded buffer contents do not match the built binary"
    );
    Ok(())
}

pub fn validate_multisig(
    config: &ReleaseConfig,
    account: &Account,
    proposer: Pubkey,
) -> Result<Multisig> {
    ensure!(
        account.owner == config.squads_program && !account.executable,
        "Multisig has an incorrect owner or executable flag"
    );
    let multisig = Multisig::try_deserialize(&mut account.data.as_slice())
        .map_err(|_| anyhow!("Malformed Squads multisig account"))?;
    let (address, bump) = get_multisig_pda(&multisig.create_key, Some(&config.squads_program));
    ensure!(
        address == config.multisig && bump == multisig.bump,
        "Multisig PDA does not match its create key"
    );
    ensure!(
        multisig
            .members
            .windows(2)
            .all(|pair| matches!(pair, [left, right] if left.key < right.key)),
        "Multisig members must be sorted and unique"
    );
    multisig
        .invariant()
        .map_err(|_| anyhow!("Invalid multisig configuration"))?;
    ensure!(
        multisig.member_has_permission(proposer, Permission::Initiate),
        "PROPOSER_KEYPAIR must have Squads Initiate permission"
    );
    Ok(multisig)
}

pub async fn read_upgrade_accounts(
    rpc: &RpcClient,
    config: &ReleaseConfig,
    proposer: Pubkey,
) -> Result<UpgradeAccounts> {
    let vault = get_vault_pda(
        &config.multisig,
        config.vault_index,
        Some(&config.squads_program),
    )
    .0;
    let program_data_address =
        Pubkey::find_program_address(&[config.program.as_ref()], &bpf_loader_upgradeable::id()).0;
    let fetched = rpc
        .get_multiple_accounts(&[
            config.program,
            program_data_address,
            config.multisig,
            config.squads_program,
            proposer,
        ])
        .await
        .map_err(|_| anyhow!("Could not read upgrade accounts from SOLANA_RPC_URL"))?;
    let mut accounts = fetched.into_iter();
    let program = accounts
        .next()
        .flatten()
        .context("Program account does not exist")?;
    let program_data = accounts
        .next()
        .flatten()
        .context("ProgramData account does not exist")?;
    let multisig = accounts
        .next()
        .flatten()
        .context("Multisig account does not exist")?;
    let squads_program = accounts
        .next()
        .flatten()
        .context("Squads program does not exist")?;
    let proposer_account = accounts
        .next()
        .flatten()
        .context("Proposer account is unfunded")?;
    ensure!(
        squads_program.executable,
        "SQUADS_PROGRAM_ID must be executable"
    );
    ensure!(
        proposer_account.owner == system_program::id()
            && proposer_account.data.is_empty()
            && !proposer_account.executable,
        "Proposer must be a funded System account"
    );
    let program_capacity = validate_program(config.program, &program, &program_data, vault)?;
    let multisig = validate_multisig(config, &multisig, proposer)?;
    Ok(UpgradeAccounts {
        vault,
        program_capacity,
        multisig,
        proposer_balance: proposer_account.lamports,
        program_data_balance: program_data.lamports,
    })
}
