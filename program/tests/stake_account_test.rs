#![cfg(feature = "stake_tests")]
// This feature flag ensures these tests are only run when the
// "stake_tests" feature is not enabled.

mod common;
use std::{
    process::{Child, Command},
    str::FromStr,
    sync::{Mutex, MutexGuard},
    thread,
    time::Duration,
};

use bincode;
use once_cell::sync::Lazy;
use solana_client::{
    rpc_client::RpcClient, rpc_config::RpcSendTransactionConfig, rpc_response::RpcVoteAccountInfo,
};
use solana_program::{pubkey::Pubkey as SolanaPubkey, system_instruction};
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    message::{v0, Message, VersionedMessage},
    signature::{Keypair, Signature, Signer},
    stake::{
        instruction::{deactivate_stake, delegate_stake, initialize as stake_initialize, withdraw},
        state::{Authorized, Lockup, StakeState},
    },
    transaction::{Transaction, VersionedTransaction},
    vote::{
        instruction as vote_instruction,
        state::{VoteInit, VoteState},
    },
};
use swig_interface::{AuthorityConfig, ClientAction, SignInstruction};
use swig_state_x::{
    action::{
        all::All, stake_all::StakeAll, stake_limit::StakeLimit,
        stake_recurring_limit::StakeRecurringLimit,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, SwigWithRoles},
    StakeAccountState,
};

// Constants
const LOCALHOST: &str = "http://localhost:8899";
const STAKE_PROGRAM_ID: SolanaPubkey = solana_sdk::stake::program::id();
const VOTE_PROGRAM_ID: SolanaPubkey = solana_sdk::vote::program::id();

// Global static validator process that will be shared across all tests
static GLOBAL_VALIDATOR: Lazy<Mutex<ValidatorProcess>> = Lazy::new(|| {
    let mut validator = ValidatorProcess::new();
    // Start the validator process when first accessed
    if let Err(e) = validator.start() {
        panic!("Failed to start validator process: {}", e);
    }
    Mutex::new(validator)
});

/// Struct to manage the validator process
struct ValidatorProcess {
    process: Option<Child>,
    client: Option<RpcClient>,
    initialized: bool,
}

impl ValidatorProcess {
    fn new() -> Self {
        Self {
            process: None,
            client: None,
            initialized: false,
        }
    }

    fn start(&mut self) -> anyhow::Result<()> {
        // If already initialized, nothing to do
        if self.initialized {
            return Ok(());
        }

        println!("Starting validator process...");

        // Find the project root and the swig.so path
        // The workspace root should be the directory containing the top-level
        // Cargo.toml
        let project_root = find_project_root()?;
        println!("Project root directory: {}", project_root.display());

        // Use the top-level target/deploy directory, not program/target/deploy
        let swig_so_path = project_root.join("target/deploy/swig.so");

        // Check if we need to build the program first
        if !swig_so_path.exists() {
            println!(
                "swig.so not found at {}, attempting build...",
                swig_so_path.display()
            );

            // Run cargo build-sbf from the project root
            let build_status = Command::new("cargo")
                .current_dir(&project_root)
                .arg("build-sbf")
                .status()
                .map_err(|e| anyhow::anyhow!("Failed to run cargo build-sbf: {}", e))?;

            if !build_status.success() {
                return Err(anyhow::anyhow!(
                    "cargo build-sbf failed with status: {}",
                    build_status
                ));
            }

            // Check again if the file exists
            if !swig_so_path.exists() {
                return Err(anyhow::anyhow!(
                    "swig.so still not found at {} after build",
                    swig_so_path.display()
                ));
            }
        }

        println!("Using swig.so at: {}", swig_so_path.display());

        // Start the validator with the correct program
        let process = Command::new("solana-test-validator")
            .current_dir(&project_root) // Run from project root
            .arg("--limit-ledger-size")
            .arg("0")
            .arg("--bind-address")
            .arg("0.0.0.0")
            .arg("--bpf-program")
            .arg("swigDk8JezhiAVde8k6NMwxpZfgGm2NNuMe1KYCmUjP")
            .arg(swig_so_path)
            .arg("-r")  // Reset the ledger
            .arg("--ticks-per-slot")
            .arg("3")
            .arg("--slots-per-epoch")
            .arg("64")
            // Additional logging to diagnose issues
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to start validator: {}", e))?;

        self.process = Some(process);
        self.client = Some(RpcClient::new(LOCALHOST.to_string()));

        println!("Validator process started, waiting for it to be ready...");

        // Wait for the validator to start producing blocks
        self.wait_for_validator_ready()?;

        self.initialized = true;
        println!("Validator is ready and producing blocks");
        Ok(())
    }

    fn wait_for_validator_ready(&self) -> anyhow::Result<()> {
        // Get the client, which should be initialized
        let client = self.client.as_ref().expect("RPC client not initialized");

        // Parameters for waiting
        let timeout_secs = 30;
        let poll_interval_ms = 200;
        let max_attempts = (timeout_secs * 1000) / poll_interval_ms;

        // First, wait for initial connection
        let mut connected = false;
        let mut current_attempt = 0;

        println!("Waiting for initial connection to validator...");
        while !connected && current_attempt < max_attempts {
            match client.get_version() {
                Ok(_) => {
                    connected = true;
                    println!("Successfully connected to validator");
                },
                Err(e) => {
                    if current_attempt % 10 == 0 {
                        println!(
                            "Waiting for validator connection... ({}/{})",
                            current_attempt, max_attempts
                        );
                    }
                    thread::sleep(Duration::from_millis(poll_interval_ms));
                    current_attempt += 1;
                },
            }
        }

        if !connected {
            return Err(anyhow::anyhow!(
                "Timed out waiting for validator connection"
            ));
        }

        // Now wait for block progression
        println!("Waiting for validator to produce blocks...");

        // Get initial slot
        let initial_slot = match client.get_slot() {
            Ok(slot) => {
                println!("Initial slot: {}", slot);
                slot
            },
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to get initial slot: {}", e));
            },
        };

        // Wait for slot to advance
        current_attempt = 0;
        let mut slots_advanced = false;

        while !slots_advanced && current_attempt < max_attempts {
            match client.get_slot() {
                Ok(current_slot) => {
                    if current_slot > initial_slot {
                        slots_advanced = true;
                        println!("Slot advanced from {} to {}", initial_slot, current_slot);
                    } else {
                        if current_attempt % 10 == 0 {
                            println!(
                                "Waiting for slot to advance... (current: {}, initial: {})",
                                current_slot, initial_slot
                            );
                        }
                        thread::sleep(Duration::from_millis(poll_interval_ms));
                        current_attempt += 1;
                    }
                },
                Err(e) => {
                    if current_attempt % 10 == 0 {
                        println!("Error getting slot: {}, retrying...", e);
                    }
                    thread::sleep(Duration::from_millis(poll_interval_ms));
                    current_attempt += 1;
                },
            }
        }

        if !slots_advanced {
            return Err(anyhow::anyhow!(
                "Timed out waiting for validator to advance slots"
            ));
        }

        Ok(())
    }

    fn get_client(&self) -> &RpcClient {
        self.client.as_ref().expect("RPC client not initialized")
    }
}

impl Drop for ValidatorProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.process.take() {
            println!("Stopping validator process...");
            if let Err(e) = child.kill() {
                println!("Error killing validator process: {}", e);
            }

            if let Err(e) = child.wait() {
                println!("Error waiting for validator process to exit: {}", e);
            } else {
                println!("Validator process stopped successfully");
            }
        }
    }
}

/// Find the project root directory by looking for Cargo.toml
fn find_project_root() -> anyhow::Result<std::path::PathBuf> {
    let mut current_dir = std::env::current_dir()
        .map_err(|e| anyhow::anyhow!("Failed to get current directory: {}", e))?;

    println!("Starting directory search from: {}", current_dir.display());

    // Go up the directory tree until we find the workspace root Cargo.toml
    // We want the top-level workspace, not the program directory
    loop {
        // Check if this directory contains a Cargo.toml file
        let cargo_toml_path = current_dir.join("Cargo.toml");
        if cargo_toml_path.exists() {
            println!("Found Cargo.toml at: {}", cargo_toml_path.display());

            // Check if this is the workspace root by looking for the target/deploy
            // directory
            let deploy_dir = current_dir.join("target/deploy");
            if deploy_dir.exists() {
                println!("Found target/deploy at: {}", deploy_dir.display());
                return Ok(current_dir);
            }
        }

        // If we can't go up any further, we've reached the filesystem root
        if !current_dir.pop() {
            return Err(anyhow::anyhow!(
                "Could not find project root with Cargo.toml and target/deploy directory"
            ));
        }
    }
}

/// Structure for test context using real Solana validator
struct TestContext {
    client: RpcClient,
    payer: Keypair,
}

impl TestContext {
    /// Send a transaction with preflight checks skipped and manually confirm it
    fn send_and_confirm_with_preflight_disabled(
        &self,
        transaction: &Transaction,
    ) -> anyhow::Result<Signature> {
        // Configure to skip preflight
        let config = RpcSendTransactionConfig {
            skip_preflight: true,
            ..RpcSendTransactionConfig::default()
        };

        // Send the transaction without preflight checks
        let signature = self
            .client
            .send_transaction_with_config(transaction, config)?;
        println!("Transaction sent: {}", signature);

        // Poll for confirmation
        let mut retries = 20;
        let mut confirmed = false;
        while retries > 0 && !confirmed {
            match self.client.get_signature_status(&signature) {
                Ok(Some(status)) => {
                    if let Ok(_) = status {
                        confirmed = true;
                        println!("Transaction confirmed: {}", signature);
                        break;
                    } else {
                        println!("Transaction failed: {:?}", status);
                        return Err(anyhow::anyhow!("Transaction failed: {:?}", status));
                    }
                },
                Ok(None) => {
                    // Not confirmed yet, wait and retry
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    retries -= 1;
                    println!("Waiting for confirmation... ({} retries left)", retries);
                },
                Err(e) => {
                    // Error checking status, could be transient
                    println!("Error checking status: {:?}", e);
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    retries -= 1;
                },
            }
        }

        if !confirmed {
            return Err(anyhow::anyhow!("Transaction confirmation timed out"));
        }

        Ok(signature)
    }
}

/// Setup the test context with a connected client
fn setup_test_context() -> anyhow::Result<TestContext> {
    // Get the global validator instance
    let validator = GLOBAL_VALIDATOR.lock().unwrap();

    // Create a clone of the validator's RPC client
    let client = RpcClient::new(LOCALHOST.to_string());

    // Verify we can get vote accounts
    let vote_accounts = client
        .get_vote_accounts()
        .map_err(|e| anyhow::anyhow!("Failed to get vote accounts: {}", e))?;

    println!(
        "Found {} current and {} delinquent vote accounts",
        vote_accounts.current.len(),
        vote_accounts.delinquent.len()
    );

    if vote_accounts.current.is_empty() && vote_accounts.delinquent.is_empty() {
        println!("Warning: No vote accounts found. This might cause tests to fail.");
    }

    // Create a new payer account
    let payer = Keypair::new();

    // Request an airdrop for the payer with proper confirmation
    request_airdrop(&client, &payer.pubkey(), 10_000_000_000)?;

    Ok(TestContext { client, payer })
}

/// Helper function to get the validator's vote account
fn get_validator_vote_account(client: &RpcClient) -> anyhow::Result<SolanaPubkey> {
    let max_retries = 5;

    for attempt in 1..=max_retries {
        match client.get_vote_accounts() {
            Ok(vote_accounts) => {
                // Get the first current vote account
                if let Some(account) = vote_accounts.current.first() {
                    let vote_pubkey = SolanaPubkey::from_str(&account.vote_pubkey)?;
                    println!("Using validator vote account: {}", vote_pubkey);
                    return Ok(vote_pubkey);
                }

                // If no current accounts, try delinquent accounts
                if let Some(account) = vote_accounts.delinquent.first() {
                    let vote_pubkey = SolanaPubkey::from_str(&account.vote_pubkey)?;
                    println!("Using delinquent validator vote account: {}", vote_pubkey);
                    return Ok(vote_pubkey);
                }

                // If no accounts found but we haven't reached max retries
                if attempt < max_retries {
                    println!(
                        "No vote accounts found yet, retrying in 3 seconds... (attempt {}/{})",
                        attempt, max_retries
                    );
                    thread::sleep(Duration::from_secs(3));
                } else {
                    return Err(anyhow::anyhow!(
                        "No validator vote accounts found after {} attempts",
                        max_retries
                    ));
                }
            },
            Err(e) => {
                if attempt < max_retries {
                    println!(
                        "Error getting vote accounts: {}, retrying in 3 seconds... (attempt {}/{})",
                        e, attempt, max_retries
                    );
                    thread::sleep(Duration::from_secs(3));
                } else {
                    return Err(anyhow::anyhow!(
                        "Error getting vote accounts after {} attempts: {}",
                        max_retries,
                        e
                    ));
                }
            },
        }
    }

    // We should never reach here due to the error returns above, but just in case
    Err(anyhow::anyhow!("Failed to get validator vote accounts"))
}

/// Helper function to create and initialize a stake account
fn create_stake_account(
    context: &TestContext,
    amount: u64,
    stake_authority: &SolanaPubkey,
    withdraw_authority: &SolanaPubkey,
) -> anyhow::Result<SolanaPubkey> {
    // Create a new stake account with a random keypair
    let stake_account = Keypair::new();
    let stake_account_pubkey = stake_account.pubkey();

    // Calculate minimum rent exemption
    let rent = context
        .client
        .get_minimum_balance_for_rent_exemption(StakeState::size_of())?;

    // Create the stake account
    let create_account_ix = system_instruction::create_account(
        &context.payer.pubkey(),
        &stake_account_pubkey,
        rent + amount, // Include the amount directly in creation
        StakeState::size_of() as u64,
        &STAKE_PROGRAM_ID,
    );

    // Initialize the stake account with explicit instruction
    let init_ix = Instruction {
        program_id: STAKE_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(stake_account_pubkey, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
        ],
        data: stake_initialize(
            &stake_account_pubkey,
            &Authorized {
                staker: *stake_authority,
                withdrawer: *withdraw_authority,
            },
            &Lockup::default(),
        )
        .data
        .clone(),
    };

    // Set higher compute budget for complex transactions
    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_000_000);

    // Create and send the transaction
    let recent_blockhash = context.client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix.clone(), create_account_ix, init_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &stake_account],
        recent_blockhash,
    );

    // Send transaction with preflight disabled and manually confirm
    let signature = context.send_and_confirm_with_preflight_disabled(&transaction)?;

    println!("Created stake account: {}", signature);
    println!("Stake account pubkey: {}", stake_account_pubkey);

    Ok(stake_account_pubkey)
}

/// Helper function to create a vote account
fn create_vote_account(
    context: &TestContext,
    node_keypair: &Keypair,
    vote_keypair: &Keypair,
) -> anyhow::Result<SolanaPubkey> {
    // First, fund the vote keypair
    // request_airdrop(&context.client, &vote_keypair.pubkey(), 1_000_000_000)?;

    // Calculate rent-exempt minimum balance
    let rent = context
        .client
        .get_minimum_balance_for_rent_exemption(VoteState::size_of())?;

    println!("init vote account");
    // Initialize vote account
    let vote_init = VoteInit {
        node_pubkey: node_keypair.pubkey(),
        authorized_voter: vote_keypair.pubkey(),
        authorized_withdrawer: vote_keypair.pubkey(),
        commission: 0,
    };

    // Create vote account using the public create_account_with_config function
    let init_vote_ixs = solana_sdk::vote::instruction::create_account_with_config(
        &context.payer.pubkey(),
        &vote_keypair.pubkey(),
        &vote_init,
        rent,
        solana_sdk::vote::instruction::CreateVoteAccountConfig::default(),
    );

    // Set compute budget to avoid compute limit errors
    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_000_000);

    // Send transaction to create vote account
    let recent_blockhash = context.client.get_latest_blockhash()?;

    // Create a vector with compute budget instruction first, then all vote
    // instructions
    let mut instructions = vec![compute_budget_ix];
    instructions.extend_from_slice(&init_vote_ixs);

    // Include all required signers
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer, vote_keypair, node_keypair],
        recent_blockhash,
    );

    println!("Sending vote account transaction...");
    let signature = context.client.send_and_confirm_transaction(&transaction)?;
    println!("Created vote account: {}", signature);

    Ok(vote_keypair.pubkey())
}

/// Helper function to delegate a stake account
fn delegate_stake_account(
    context: &TestContext,
    stake_account: &SolanaPubkey,
    stake_authority: &Keypair,
    vote_account: &SolanaPubkey,
) -> anyhow::Result<String> {
    let delegate_ix = delegate_stake(stake_account, &stake_authority.pubkey(), vote_account);

    let recent_blockhash = context.client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[delegate_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, stake_authority],
        recent_blockhash,
    );

    let signature = context.client.send_and_confirm_transaction(&transaction)?;
    println!("Delegated stake account: {}", signature);

    Ok(signature.to_string())
}

/// Helper function to deactivate a stake account
fn deactivate_stake_account(
    context: &TestContext,
    stake_account: &SolanaPubkey,
    stake_authority: &Keypair,
) -> anyhow::Result<String> {
    // Create the deactivate stake instruction manually
    let deactivate_ix = Instruction {
        program_id: STAKE_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*stake_account, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
            AccountMeta::new_readonly(stake_authority.pubkey(), true),
        ],
        data: deactivate_stake(stake_account, &stake_authority.pubkey())
            .data
            .clone(),
    };

    // Get recent blockhash
    let recent_blockhash = context.client.get_latest_blockhash()?;

    // Set a higher compute budget
    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_000_000);

    // Create and sign the transaction directly
    let transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix.clone(), deactivate_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, stake_authority],
        recent_blockhash,
    );

    // Send transaction with preflight disabled and manually confirm
    let signature = context.send_and_confirm_with_preflight_disabled(&transaction)?;

    println!("Deactivated stake account: {}", signature);

    Ok(signature.to_string())
}

/// Helper function to withdraw from a stake account
fn withdraw_from_stake_account(
    context: &TestContext,
    stake_account: &SolanaPubkey,
    withdraw_authority: &Keypair,
    recipient: &SolanaPubkey,
    amount: u64,
) -> anyhow::Result<String> {
    // Create the withdraw stake instruction manually
    let withdraw_ix = Instruction {
        program_id: STAKE_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*stake_account, false),
            AccountMeta::new(*recipient, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::stake_history::id(), false),
            AccountMeta::new_readonly(withdraw_authority.pubkey(), true),
        ],
        data: withdraw(
            stake_account,
            &withdraw_authority.pubkey(),
            recipient,
            amount,
            None,
        )
        .data
        .clone(),
    };

    // Get recent blockhash
    let recent_blockhash = context.client.get_latest_blockhash()?;

    // Set a higher compute budget
    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_000_000);

    // Create and sign the transaction directly
    let transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix.clone(), withdraw_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, withdraw_authority],
        recent_blockhash,
    );

    // Send transaction with preflight disabled and manually confirm
    let signature = context.send_and_confirm_with_preflight_disabled(&transaction)?;

    println!("Withdrew from stake account: {}", signature);

    Ok(signature.to_string())
}

/// Helper function to create a Swig wallet with Ed25519 authority
fn create_swig_ed25519(
    context: &TestContext,
    authority: &Keypair,
    id: [u8; 32],
) -> anyhow::Result<SolanaPubkey> {
    // Get program ID
    let program_id = SolanaPubkey::from_str("swigDk8JezhiAVde8k6NMwxpZfgGm2NNuMe1KYCmUjP")?;

    // Calculate PDA for swig account
    let (swig, bump) = SolanaPubkey::find_program_address(
        &swig_account_seeds(&id, &authority.pubkey().to_bytes()),
        &program_id,
    );

    // Create the instruction
    let create_ix = swig_interface::CreateInstruction::new(
        swig,
        bump,
        context.payer.pubkey(),
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {})],
        id,
    )
    .map_err(|e| anyhow::anyhow!("Failed to create instruction: {:?}", e))?;

    // Get recent blockhash
    let recent_blockhash = context.client.get_latest_blockhash()?;

    // Create and sign transaction
    let transaction = Transaction::new_signed_with_payer(
        &[create_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    // Send transaction with preflight disabled and manually confirm
    let signature = context.send_and_confirm_with_preflight_disabled(&transaction)?;

    println!("Created swig wallet: {}", signature);

    // Fund the Swig account with SOL
    request_airdrop(&context.client, &swig, 10_000_000_000)?;

    Ok(swig)
}

/// Helper function to add an authority to a Swig wallet
fn add_authority_with_ed25519_root(
    context: &TestContext,
    swig_pubkey: &SolanaPubkey,
    existing_ed25519_authority: &Keypair,
    new_authority: AuthorityConfig,
    actions: Vec<ClientAction>,
) -> anyhow::Result<String> {
    // Get swig account data
    let swig_account = context.client.get_account(swig_pubkey)?;
    let swig = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig: {:?}", e))?;

    // Get role ID for existing authority
    let role_id = swig
        .lookup_role_id(existing_ed25519_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role ID: {:?}", e))?
        .ok_or(anyhow::anyhow!("Authority not found"))?;

    // Create add authority instruction
    let add_authority_ix = swig_interface::AddAuthorityInstruction::new_with_ed25519_authority(
        *swig_pubkey,
        context.payer.pubkey(),
        existing_ed25519_authority.pubkey(),
        role_id,
        new_authority,
        actions,
    )?;

    // Set a higher compute budget for this transaction
    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_000_000);

    // Create and sign transaction
    let recent_blockhash = context.client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix.clone(), add_authority_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, existing_ed25519_authority],
        recent_blockhash,
    );

    // Send transaction with preflight disabled and manually confirm
    let signature = context.send_and_confirm_with_preflight_disabled(&transaction)?;

    println!("Added authority to swig wallet: {}", signature);

    Ok(signature.to_string())
}

/// Sign an instruction with the swig using the given authority
fn sign_with_swig(
    context: &TestContext,
    swig: &SolanaPubkey,
    authority: &Keypair,
    instruction: Instruction,
    role_id: u32,
) -> anyhow::Result<String> {
    println!("delegate_ix: {:?}", instruction);

    // Create the sign instruction to have the swig program sign the stake
    // instruction
    let sign_ix = SignInstruction::new_ed25519(
        *swig,
        authority.pubkey(),
        authority.pubkey(),
        instruction,
        role_id,
    )
    .map_err(|e| anyhow::anyhow!("Failed to create sign instruction: {:?}", e))?;

    // Get recent blockhash
    let recent_blockhash = context.client.get_latest_blockhash()?;

    // Set higher compute budget for complex transactions
    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_000_000);

    // Create and sign transaction
    let transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix.clone(), sign_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, authority],
        recent_blockhash,
    );

    // Send transaction with preflight disabled and manually confirm
    let signature = context.send_and_confirm_with_preflight_disabled(&transaction)?;

    Ok(signature.to_string())
}

/// Helper function to request an airdrop and confirm it
fn request_airdrop(client: &RpcClient, pubkey: &SolanaPubkey, lamports: u64) -> anyhow::Result<()> {
    // Check if account already has enough balance
    let current_balance = client.get_balance(pubkey)?;
    if current_balance >= lamports {
        println!(
            "Account {} already has {} lamports (requested {})",
            pubkey, current_balance, lamports
        );
        return Ok(());
    }

    // Number of retry attempts
    let max_retries = 5;
    let mut retry_count = 0;

    while retry_count < max_retries {
        // Request airdrop with error handling
        let signature = match client.request_airdrop(pubkey, lamports) {
            Ok(sig) => sig,
            Err(err) => {
                println!("Airdrop request error: {:?}, retrying...", err);
                retry_count += 1;
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            },
        };

        println!("Airdrop requested: {}", signature);

        // Get the latest blockhash for confirmation
        let blockhash = client.get_latest_blockhash()?;

        // Implement a polling mechanism with timeout
        let timeout = std::time::Duration::from_secs(30);
        let start = std::time::Instant::now();
        let mut confirmed = false;

        // Loop until confirmation or timeout
        while !confirmed && start.elapsed() <= timeout {
            if let Ok(status) = client.confirm_transaction(&signature) {
                if status {
                    confirmed = true;
                    println!("Airdrop transaction confirmed");
                    break;
                }
            }

            // Wait a bit before checking again
            std::thread::sleep(std::time::Duration::from_millis(500));
            println!("Waiting for airdrop confirmation...");
        }

        if !confirmed {
            println!("Airdrop confirmation timed out, retrying...");
            retry_count += 1;
            continue;
        }

        // Give the network a moment to process the airdrop
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Verify the balance
        let new_balance = client.get_balance(pubkey)?;
        if new_balance >= lamports {
            println!(
                "Successfully funded account {} with {} lamports (total balance: {})",
                pubkey, lamports, new_balance
            );
            return Ok(());
        } else {
            println!(
                "Airdrop seems to have failed: balance is {} but expected at least {}",
                new_balance, lamports
            );
            retry_count += 1;
        }
    }

    return Err(anyhow::anyhow!(
        "Failed to fund account after {} attempts",
        max_retries
    ));
}

/// A more direct approach to delegate stake with a swig authority
fn delegate_with_swig(
    context: &TestContext,
    stake_account: &SolanaPubkey,
    vote_account: &SolanaPubkey,
    swig_authority: &Keypair,
) -> anyhow::Result<String> {
    // Create the delegate stake instruction
    let delegate_ix = delegate_stake(stake_account, &swig_authority.pubkey(), vote_account);

    println!("delegate_ix: {:?}", delegate_ix);

    // Get recent blockhash
    let recent_blockhash = context.client.get_latest_blockhash()?;

    // Set a higher compute budget
    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_000_000);

    // Create and sign the transaction directly
    let transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix.clone(), delegate_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, swig_authority],
        recent_blockhash,
    );

    // Send transaction with preflight disabled and manually confirm
    let signature = context.send_and_confirm_with_preflight_disabled(&transaction)?;

    println!("Delegated stake account directly: {}", signature);

    Ok(signature.to_string())
}

/// Helper function to print information about a stake account
fn print_stake_account_info(
    client: &RpcClient,
    stake_account: &SolanaPubkey,
) -> anyhow::Result<()> {
    let account = client.get_account(stake_account)?;
    println!("Stake account {} info:", stake_account);
    println!("  Lamports: {}", account.lamports);
    println!("  Owner: {}", account.owner);
    println!("  Executable: {}", account.executable);
    println!("  Rent epoch: {}", account.rent_epoch);
    println!("  Data length: {}", account.data.len());

    if account.owner == STAKE_PROGRAM_ID {
        match bincode::deserialize::<StakeState>(&account.data) {
            Ok(state) => {
                println!("  State: {:?}", state);
                match state {
                    StakeState::Initialized(meta) => {
                        println!("    Rent exempt reserve: {}", meta.rent_exempt_reserve);
                        println!("    Staker: {}", meta.authorized.staker);
                        println!("    Withdrawer: {}", meta.authorized.withdrawer);
                    },
                    StakeState::Stake(meta, stake) => {
                        println!("    Rent exempt reserve: {}", meta.rent_exempt_reserve);
                        println!("    Staker: {}", meta.authorized.staker);
                        println!("    Withdrawer: {}", meta.authorized.withdrawer);
                        println!("    Delegation:");
                        println!("      Voter: {}", stake.delegation.voter_pubkey);
                        println!("      Stake: {}", stake.delegation.stake);
                        println!(
                            "      Activation epoch: {}",
                            stake.delegation.activation_epoch
                        );
                        println!(
                            "      Deactivation epoch: {}",
                            stake.delegation.deactivation_epoch
                        );
                    },
                    _ => {},
                }
            },
            Err(e) => println!("  Error deserializing state: {:?}", e),
        }
    }

    Ok(())
}

#[test]
fn test_stake_with_unlimited_permission() -> anyhow::Result<()> {
    let context = setup_test_context()?;

    // Create the swig wallet with authority
    let swig_authority = Keypair::new();

    // Fund the authority with SOL before using it
    request_airdrop(&context.client, &swig_authority.pubkey(), 10_000_000_000)?;

    // Create a unique ID for the swig wallet
    let id = rand::random::<[u8; 32]>();

    // Create the swig wallet
    let swig = create_swig_ed25519(&context, &swig_authority, id)?;

    println!("Getting validator vote account");

    // Get the validator's vote account dynamically
    let vote_account = get_validator_vote_account(&context.client)?;

    println!("Vote account obtained: {}", vote_account);

    // Create a secondary authority with StakeAll permission
    let secondary_authority = Keypair::new();

    // Fund the secondary authority
    request_airdrop(
        &context.client,
        &secondary_authority.pubkey(),
        10_000_000_000,
    )?;

    println!("Add second authority");

    // Add secondary authority with StakeAll permission
    add_authority_with_ed25519_root(
        &context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        vec![ClientAction::StakeAll(StakeAll {})],
    )?;

    println!("Added second authority");

    // Create a stake account with the swig as the authority
    let stake_account = create_stake_account(
        &context,
        5_000_000_000, // 5 SOL
        &swig,         // Swig is the stake authority
        &swig,         // Swig is the withdraw authority
    )?;

    // Print detailed information about the stake account
    println!("\n=== STAKE ACCOUNT BEFORE DELEGATION ===");
    print_stake_account_info(&context.client, &stake_account)?;

    // Create a stake delegate instruction
    let delegate_ix = delegate_stake(&stake_account, &swig, &vote_account);

    // Create the sign instruction to have the swig program sign the stake
    // instruction
    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        delegate_ix,
        1, // role_id for the secondary authority
    )?;

    println!("Created sign instruction for delegation");

    // Get recent blockhash
    let recent_blockhash = context.client.get_latest_blockhash()?;

    // Set higher compute budget for complex transactions
    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_000_000);

    // Create and sign transaction
    let transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix.clone(), sign_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &secondary_authority],
        recent_blockhash,
    );

    // Send and confirm transaction with preflight disabled
    println!("Sending delegation transaction...");
    let signature = context.send_and_confirm_with_preflight_disabled(&transaction)?;
    println!("Delegation transaction confirmed: {}", signature);

    // Wait a moment to ensure transaction is fully processed
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Print stake account after delegation
    println!("\n=== STAKE ACCOUNT AFTER DELEGATION ===");
    print_stake_account_info(&context.client, &stake_account)?;

    // Now try to deactivate the stake through swig
    let deactivate_ix = deactivate_stake(&stake_account, &swig);

    // Create the sign instruction for deactivation
    let deactivate_sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        deactivate_ix,
        1, // role_id for the secondary authority
    )?;

    // Create and sign transaction for deactivation
    let deactivate_transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix.clone(), deactivate_sign_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &secondary_authority],
        context.client.get_latest_blockhash()?,
    );

    // Send and confirm deactivation transaction with preflight disabled
    println!("Sending deactivation transaction...");
    let deactivate_signature =
        context.send_and_confirm_with_preflight_disabled(&deactivate_transaction)?;
    println!(
        "Deactivation transaction confirmed: {}",
        deactivate_signature
    );

    // Wait a moment to ensure transaction is fully processed
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Print stake account after deactivation
    println!("\n=== STAKE ACCOUNT AFTER DEACTIVATION ===");
    print_stake_account_info(&context.client, &stake_account)?;

    // Try to withdraw some stake through swig
    let withdraw_amount = 1_000_000_000; // 1 SOL
    let withdraw_ix = withdraw(
        &stake_account,
        &swig,
        &secondary_authority.pubkey(),
        withdraw_amount,
        None,
    );

    // Create the sign instruction for withdrawal
    let withdraw_sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        withdraw_ix,
        1, // role_id for the secondary authority
    )?;

    // Create and sign transaction for withdrawal
    let withdraw_transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix.clone(), withdraw_sign_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &secondary_authority],
        context.client.get_latest_blockhash()?,
    );

    // Send and confirm withdrawal transaction with preflight disabled
    println!("Sending withdrawal transaction...");
    let withdraw_signature =
        context.send_and_confirm_with_preflight_disabled(&withdraw_transaction)?;
    println!("Withdrawal transaction confirmed: {}", withdraw_signature);

    // Wait a moment to ensure transaction is fully processed
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Print stake account after withdrawal
    println!("\n=== STAKE ACCOUNT AFTER WITHDRAWAL ===");
    print_stake_account_info(&context.client, &stake_account)?;

    Ok(())
}

#[test]
fn test_stake_with_fixed_limit() -> anyhow::Result<()> {
    let context = setup_test_context()?;

    // Create the swig wallet with authority
    let swig_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let swig = create_swig_ed25519(&context, &swig_authority, id)?;

    // Get the validator's vote account dynamically
    let vote_account = get_validator_vote_account(&context.client)?;

    // Create a secondary authority with StakeLimit permission
    let secondary_authority = Keypair::new();

    // Fund the secondary authority
    request_airdrop(
        &context.client,
        &secondary_authority.pubkey(),
        10_000_000_000,
    )?;

    // Set stake limit to 2 SOL
    let stake_limit = 2_000_000_000;

    // Add secondary authority with StakeLimit permission
    add_authority_with_ed25519_root(
        &context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        vec![ClientAction::StakeLimit(StakeLimit {
            amount: stake_limit,
        })],
    )?;

    // Create a stake account with the swig as the authority
    let stake_account = create_stake_account(
        &context,
        2_000_000_000, // 2 SOL (exactly at the limit)
        &swig,         // Swig is the stake authority
        &swig,         // Swig is the withdraw authority
    )?;

    // Print stake account before delegation
    println!("\n=== STAKE ACCOUNT BEFORE DELEGATION ===");
    print_stake_account_info(&context.client, &stake_account)?;

    // Create a stake delegate instruction
    let delegate_ix = delegate_stake(&stake_account, &swig, &vote_account);

    // Create the sign instruction to have the swig program sign the stake
    // instruction
    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        delegate_ix,
        1, // role_id for the secondary authority
    )?;

    // Set higher compute budget
    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_000_000);

    // Create and sign transaction
    let transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix.clone(), sign_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &secondary_authority],
        context.client.get_latest_blockhash()?,
    );

    // Send and confirm transaction with preflight disabled
    println!("Sending first delegation transaction...");
    let result = context.send_and_confirm_with_preflight_disabled(&transaction);
    println!("First delegation result: {:?}", result);

    if result.is_ok() {
        // Wait a moment to ensure transaction is fully processed
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Print stake account after delegation
        println!("\n=== STAKE ACCOUNT AFTER FIRST DELEGATION ===");
        print_stake_account_info(&context.client, &stake_account)?;
    }

    // Create another stake account that would exceed the limit
    let second_stake_account = create_stake_account(
        &context,
        1_000_000_000, // 1 SOL (would exceed the 2 SOL limit)
        &swig,         // Swig is the stake authority
        &swig,         // Swig is the withdraw authority
    )?;

    // Print second stake account before delegation attempt
    println!("\n=== SECOND STAKE ACCOUNT BEFORE DELEGATION ===");
    print_stake_account_info(&context.client, &second_stake_account)?;

    // Try to delegate the second stake account (should fail due to limit)
    let second_delegate_ix = delegate_stake(&second_stake_account, &swig, &vote_account);

    // Create the sign instruction
    let second_sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        second_delegate_ix,
        1, // role_id for the secondary authority
    )?;

    // Create and sign transaction
    let second_transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix.clone(), second_sign_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &secondary_authority],
        context.client.get_latest_blockhash()?,
    );

    // Send and confirm transaction with preflight disabled
    println!("Sending second delegation transaction (should fail due to limit)...");
    let second_result = context.send_and_confirm_with_preflight_disabled(&second_transaction);
    println!("Second delegation result: {:?}", second_result);

    // Print second stake account after delegation attempt
    println!("\n=== SECOND STAKE ACCOUNT AFTER DELEGATION ATTEMPT ===");
    print_stake_account_info(&context.client, &second_stake_account)?;

    Ok(())
}

#[test]
fn test_stake_with_recurring_limit() -> anyhow::Result<()> {
    let context = setup_test_context()?;

    // Create the swig wallet with authority
    let swig_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let swig = create_swig_ed25519(&context, &swig_authority, id)?;

    // Get the validator's vote account dynamically
    let vote_account = get_validator_vote_account(&context.client)?;

    // Create a secondary authority with StakeRecurringLimit permission
    let secondary_authority = Keypair::new();

    // Fund the secondary authority
    request_airdrop(
        &context.client,
        &secondary_authority.pubkey(),
        10_000_000_000,
    )?;

    // Set recurring stake limit to 3 SOL per 100 slots
    let recurring_amount = 3_000_000_000;
    let window = 100;
    let current_slot = context.client.get_slot()?;

    // Add secondary authority with StakeRecurringLimit permission
    add_authority_with_ed25519_root(
        &context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        vec![ClientAction::StakeRecurringLimit(StakeRecurringLimit {
            recurring_amount,
            window,
            last_reset: current_slot,
            current_amount: recurring_amount,
        })],
    )?;

    // Create a stake account with the swig as the authority
    let stake_account = create_stake_account(
        &context,
        2_000_000_000, // 2 SOL
        &swig,         // Swig is the stake authority
        &swig,         // Swig is the withdraw authority
    )?;

    // Print stake account before delegation
    println!("\n=== FIRST STAKE ACCOUNT BEFORE DELEGATION ===");
    print_stake_account_info(&context.client, &stake_account)?;

    // Create a stake delegate instruction for the first account
    let delegate_ix = delegate_stake(&stake_account, &swig, &vote_account);

    // Create the sign instruction
    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        delegate_ix,
        1, // role_id for the secondary authority
    )?;

    // Set higher compute budget
    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_000_000);

    // Create and sign transaction
    let transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix.clone(), sign_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &secondary_authority],
        context.client.get_latest_blockhash()?,
    );

    // Send and confirm transaction
    println!("Sending first delegation transaction...");
    let result = context.send_and_confirm_with_preflight_disabled(&transaction);
    println!("First delegation result: {:?}", result);

    if result.is_ok() {
        // Wait a moment to ensure transaction is fully processed
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Print stake account after delegation
        println!("\n=== FIRST STAKE ACCOUNT AFTER DELEGATION ===");
        print_stake_account_info(&context.client, &stake_account)?;
    }

    // Create another stake account that would still be within the limit
    let second_stake_account = create_stake_account(
        &context,
        1_000_000_000, // 1 SOL (bringing total to 3 SOL, matching the limit)
        &swig,         // Swig is the stake authority
        &swig,         // Swig is the withdraw authority
    )?;

    // Print second stake account before delegation
    println!("\n=== SECOND STAKE ACCOUNT BEFORE DELEGATION ===");
    print_stake_account_info(&context.client, &second_stake_account)?;

    // Create a stake delegate instruction for the second account
    let second_delegate_ix = delegate_stake(&second_stake_account, &swig, &vote_account);

    // Create the sign instruction
    let second_sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        second_delegate_ix,
        1, // role_id for the secondary authority
    )?;

    // Create and sign transaction
    let second_transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix.clone(), second_sign_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &secondary_authority],
        context.client.get_latest_blockhash()?,
    );

    // Send and confirm transaction
    println!("Sending second delegation transaction...");
    let second_result = context.send_and_confirm_with_preflight_disabled(&second_transaction);
    println!("Second delegation result: {:?}", second_result);

    if second_result.is_ok() {
        // Wait a moment to ensure transaction is fully processed
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Print second stake account after delegation
        println!("\n=== SECOND STAKE ACCOUNT AFTER DELEGATION ===");
        print_stake_account_info(&context.client, &second_stake_account)?;
    }

    // Create a third stake account that would exceed the limit
    let third_stake_account = create_stake_account(
        &context,
        1_000_000_000, // 1 SOL (would exceed the 3 SOL limit)
        &swig,         // Swig is the stake authority
        &swig,         // Swig is the withdraw authority
    )?;

    // Print third stake account before delegation attempt
    println!("\n=== THIRD STAKE ACCOUNT BEFORE DELEGATION ===");
    print_stake_account_info(&context.client, &third_stake_account)?;

    // Try to delegate the third stake account (should fail due to the recurring
    // limit)
    let third_delegate_ix = delegate_stake(&third_stake_account, &swig, &vote_account);

    // Create the sign instruction
    let third_sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        third_delegate_ix,
        1, // role_id for the secondary authority
    )?;

    // Create and sign transaction
    let third_transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix.clone(), third_sign_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &secondary_authority],
        context.client.get_latest_blockhash()?,
    );

    // Send and confirm transaction
    println!("Sending third delegation transaction (should fail due to limit)...");
    let third_result = context.send_and_confirm_with_preflight_disabled(&third_transaction);
    println!("Third delegation result: {:?}", third_result);

    // Print third stake account after delegation attempt
    println!("\n=== THIRD STAKE ACCOUNT AFTER DELEGATION ATTEMPT ===");
    print_stake_account_info(&context.client, &third_stake_account)?;

    Ok(())
}

#[test]
fn test_both_stake_and_unstake_affect_limit() -> anyhow::Result<()> {
    let context = setup_test_context()?;

    // Create the swig wallet with authority
    let swig_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let swig = create_swig_ed25519(&context, &swig_authority, id)?;

    // Get the validator's vote account dynamically
    let vote_account = get_validator_vote_account(&context.client)?;

    // Create a secondary authority with StakeLimit permission
    let secondary_authority = Keypair::new();

    // Fund the secondary authority
    request_airdrop(
        &context.client,
        &secondary_authority.pubkey(),
        10_000_000_000,
    )?;

    // Set stake limit to 3 SOL
    let stake_limit = 3_000_000_000;

    // Add secondary authority with StakeLimit permission
    add_authority_with_ed25519_root(
        &context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        vec![ClientAction::StakeLimit(StakeLimit {
            amount: stake_limit,
        })],
    )?;

    // Create a stake account with the swig as the authority
    let stake_account = create_stake_account(
        &context,
        2_000_000_000, // 2 SOL
        &swig,         // Swig is the stake authority
        &swig,         // Swig is the withdraw authority
    )?;

    // Print stake account before delegation
    println!("\n=== STAKE ACCOUNT BEFORE DELEGATION ===");
    print_stake_account_info(&context.client, &stake_account)?;

    // Create and send a delegate transaction using the swig
    let delegate_ix = delegate_stake(&stake_account, &swig, &vote_account);
    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        delegate_ix,
        1, // role_id for the secondary authority
    )?;

    // Set higher compute budget
    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_000_000);

    // Create and sign transaction
    let transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix.clone(), sign_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &secondary_authority],
        context.client.get_latest_blockhash()?,
    );

    // Send and confirm transaction with preflight disabled
    println!("Sending delegation transaction...");
    let result = context.send_and_confirm_with_preflight_disabled(&transaction);
    println!("Delegation result: {:?}", result);

    if result.is_ok() {
        // Wait a moment to ensure transaction is fully processed
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Print stake account after delegation
        println!("\n=== STAKE ACCOUNT AFTER DELEGATION ===");
        print_stake_account_info(&context.client, &stake_account)?;
    }

    // Now deactivate the stake using the swig
    let deactivate_ix = deactivate_stake(&stake_account, &swig);
    let deactivate_sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        deactivate_ix,
        1, // role_id for the secondary authority
    )?;

    // Create and sign deactivation transaction
    let deactivate_transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix.clone(), deactivate_sign_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &secondary_authority],
        context.client.get_latest_blockhash()?,
    );

    // Send and confirm deactivation transaction with preflight disabled
    println!("Sending deactivation transaction...");
    let deactivate_result =
        context.send_and_confirm_with_preflight_disabled(&deactivate_transaction);
    println!("Deactivation result: {:?}", deactivate_result);

    if deactivate_result.is_ok() {
        // Wait a moment to ensure transaction is fully processed
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Print stake account after deactivation
        println!("\n=== STAKE ACCOUNT AFTER DEACTIVATION ===");
        print_stake_account_info(&context.client, &stake_account)?;
    }

    // Try to withdraw using the swig
    let withdraw_amount = 1_000_000_000; // 1 SOL
    let withdraw_ix = withdraw(
        &stake_account,
        &swig,
        &secondary_authority.pubkey(),
        withdraw_amount,
        None,
    );

    let withdraw_sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        withdraw_ix,
        1, // role_id for the secondary authority
    )?;

    // Create and sign withdrawal transaction
    let withdraw_transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix.clone(), withdraw_sign_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &secondary_authority],
        context.client.get_latest_blockhash()?,
    );

    // Send and confirm withdrawal transaction with preflight disabled
    println!("Sending withdrawal transaction...");
    let withdraw_result = context.send_and_confirm_with_preflight_disabled(&withdraw_transaction);
    println!("Withdrawal result: {:?}", withdraw_result);

    if withdraw_result.is_ok() {
        // Wait a moment to ensure transaction is fully processed
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Print stake account after withdrawal
        println!("\n=== STAKE ACCOUNT AFTER WITHDRAWAL ===");
        print_stake_account_info(&context.client, &stake_account)?;
    }

    Ok(())
}
