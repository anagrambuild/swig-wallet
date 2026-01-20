//! # MultiWalletManager
//!
//! A high-level SDK for managing batch operations across multiple Swig wallets.
//!
//! ## Overview
//!
//! `MultiWalletManager` simplifies the process of performing operations across multiple
//! Swig wallets. It provides three levels of API:
//!
//! 1. **Instruction Creation** - Build signed instructions without sending
//! 2. **Transaction Execution** - Execute batches with automatic batching and retry logic
//! 3. **High-Level Helpers** - One-call methods for common operations (transfer SOL/tokens)
//!
//! ## Quick Start
//!
//! ```no_run
//! use swig_sdk::{MultiWalletManager, BatchConfig, Ed25519ClientRole};
//! use solana_sdk::signature::{Keypair, Signer};
//! use solana_client::rpc_client::RpcClient;
//! use solana_sdk::commitment_config::CommitmentConfig;
//!
//! // Setup
//! let fee_payer = Keypair::new();
//! let authority = Keypair::new();
//! let client_role = Box::new(Ed25519ClientRole::new(authority.pubkey()));
//! let rpc = RpcClient::new_with_commitment(
//!     "https://api.mainnet-beta.solana.com".to_string(),
//!     CommitmentConfig::confirmed(),
//! );
//!
//! let manager = MultiWalletManager::new(client_role, &fee_payer, Some(&authority), rpc);
//!
//! // Transfer SOL from multiple wallets (high-level helper)
//! let wallet_ids: Vec<([u8; 32], u32)> = vec![]; // your wallet IDs
//! let recipient = Keypair::new().pubkey();
//!
//! // Using async execute_batch for full control
//! # async fn example(manager: &mut MultiWalletManager<'_>, wallet_ids: Vec<([u8; 32], u32)>, recipient: solana_sdk::pubkey::Pubkey) -> Result<(), swig_sdk::SwigError> {
//! use solana_program::system_instruction;
//! let result = manager.execute_batch(
//!     wallet_ids,
//!     |_swig_id, _role_id, wallet_addr| {
//!         Ok(system_instruction::transfer(&wallet_addr, &recipient, 1000))
//!     },
//!     BatchConfig::default(),
//! ).await?;
//!
//! println!("Successful: {}, Failed: {}", result.successful_count(), result.failed_count());
//! # Ok(())
//! # }
//! ```

use futures::future::join_all;
#[cfg(all(feature = "rust_sdk_test", test))]
use litesvm::LiteSVM;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    hash::Hash,
    instruction::Instruction,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
    transaction::VersionedTransaction,
};
use spl_associated_token_account::get_associated_token_address;
use spl_token::instruction::transfer;
use spl_token::ID as TOKEN_PROGRAM_ID;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use swig_interface::{program_id, swig};
use swig_state::swig::swig_wallet_address_seeds;
use tokio::sync::Semaphore;
use tokio::time::sleep;

use crate::{client_role::ClientRole, Ed25519ClientRole, SwigError, SwigInstructionBuilder};

// ============================================================================
// Configuration & Types
// ============================================================================

/// Strategy for handling batch execution and failure detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BatchStrategy {
    /// Send batches and return results. Failed batches have all their swig_ids marked as failed.
    #[default]
    Simple,
    /// When a batch fails, recursively split it to find individual failing instructions.
    /// This identifies exactly which swig_id's are failing.
    BinarySearchFailures,
}

/// Configuration for batch execution.
///
/// # Example
///
/// ```
/// use swig_sdk::{BatchConfig, BatchStrategy};
///
/// let config = BatchConfig {
///     strategy: BatchStrategy::BinarySearchFailures,
///     max_accounts_per_tx: 64,
///     max_tx_size_bytes: 1024,
///     max_retries: 3,
///     retry_delay_ms: 500,
///     num_threads: 4, // Enable parallel sending with 4 concurrent threads
/// };
/// ```
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Strategy for handling failures.
    pub strategy: BatchStrategy,
    /// Maximum number of accounts per transaction (Solana limit is 64 for ALT, 128 without).
    pub max_accounts_per_tx: usize,
    /// Maximum transaction size in bytes (conservative default: 1024).
    pub max_tx_size_bytes: usize,
    /// Maximum number of retry attempts for failed transactions.
    pub max_retries: u32,
    /// Delay between retry attempts in milliseconds.
    pub retry_delay_ms: u64,
    /// Number of concurrent threads for sending transactions.
    /// Set to 1 for sequential execution, higher for parallel.
    pub num_threads: usize,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            strategy: BatchStrategy::Simple,
            max_accounts_per_tx: 64,
            max_tx_size_bytes: 1024,
            max_retries: 3,
            retry_delay_ms: 500,
            num_threads: 1, // Sequential by default for safety
        }
    }
}

impl BatchConfig {
    /// Creates a new BatchConfig with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the batch strategy.
    pub fn with_strategy(mut self, strategy: BatchStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Sets the maximum accounts per transaction.
    pub fn with_max_accounts(mut self, max_accounts: usize) -> Self {
        self.max_accounts_per_tx = max_accounts;
        self
    }

    /// Sets the maximum transaction size in bytes.
    pub fn with_max_tx_size(mut self, max_size: usize) -> Self {
        self.max_tx_size_bytes = max_size;
        self
    }

    /// Sets the maximum retry attempts.
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Sets the retry delay in milliseconds.
    pub fn with_retry_delay(mut self, delay_ms: u64) -> Self {
        self.retry_delay_ms = delay_ms;
        self
    }

    /// Sets the number of threads for parallel execution.
    ///
    /// # Arguments
    ///
    /// * `threads` - Number of concurrent threads. Must be >= 1.
    pub fn with_num_threads(mut self, threads: usize) -> Self {
        self.num_threads = threads.max(1);
        self
    }
}

/// Result of a successful batch transaction.
#[derive(Debug, Clone)]
pub struct SuccessfulBatch {
    /// Transaction signature.
    pub signature: Signature,
    /// Swig IDs that were included in this transaction.
    pub swig_ids: Vec<[u8; 32]>,
}

/// Result of a failed instruction/transaction.
#[derive(Debug, Clone)]
pub struct FailedInstruction {
    /// The swig_id that failed.
    pub swig_id: [u8; 32],
    /// The role_id that was used.
    pub role_id: u32,
    /// Error message describing the failure.
    pub error: String,
}

/// Complete result of batch execution.
#[derive(Debug, Clone, Default)]
pub struct BatchExecutionResult {
    /// Successfully executed transactions.
    pub successful: Vec<SuccessfulBatch>,
    /// Failed instructions with their swig_ids.
    pub failed: Vec<FailedInstruction>,
}

impl BatchExecutionResult {
    /// Returns true if all instructions succeeded.
    pub fn is_success(&self) -> bool {
        self.failed.is_empty()
    }

    /// Returns the total number of successful swig operations.
    pub fn successful_count(&self) -> usize {
        self.successful.iter().map(|b| b.swig_ids.len()).sum()
    }

    /// Returns the number of failed swig operations.
    pub fn failed_count(&self) -> usize {
        self.failed.len()
    }

    /// Returns all successful swig IDs.
    pub fn successful_swig_ids(&self) -> Vec<[u8; 32]> {
        self.successful
            .iter()
            .flat_map(|b| b.swig_ids.clone())
            .collect()
    }

    /// Returns all failed swig IDs.
    pub fn failed_swig_ids(&self) -> Vec<[u8; 32]> {
        self.failed.iter().map(|f| f.swig_id).collect()
    }
}

// ============================================================================
// Internal Types
// ============================================================================

/// Internal struct to track batch metadata for execution.
#[derive(Debug, Clone)]
struct BatchWithMetadata {
    instructions: Vec<Instruction>,
    swig_ids: Vec<([u8; 32], u32)>,
}

// ============================================================================
// MultiWalletManager
// ============================================================================

/// Manages batch operations across multiple Swig wallets.
///
/// This struct provides a unified interface for signing and executing instructions
/// across multiple wallets, making it easy to perform batch operations.
///
/// # Architecture
///
/// The API is organized into three levels:
///
/// 1. **Instruction Creation** (`create_*_instructions`)
///    - Build signed instructions without sending
///    - Useful when you need custom transaction assembly
///
/// 2. **Transaction Execution** (`execute_batch`)
///    - Automatic batching respecting Solana limits
///    - Configurable retry and parallelization
///    - Detailed success/failure reporting
///
/// 3. **High-Level Helpers** (`transfer_sol`, `transfer_token`)
///    - One-call methods for common operations
///    - Handle instruction creation and execution
pub struct MultiWalletManager<'c> {
    client_role: Box<dyn ClientRole>,
    fee_payer: &'c Keypair,
    authority_keypair: Option<&'c Keypair>,
    rpc_client: RpcClient,
    #[cfg(all(feature = "rust_sdk_test", test))]
    pub litesvm: &'c mut LiteSVM,
}

impl<'c> MultiWalletManager<'c> {
    // ========================================================================
    // Constructor
    // ========================================================================

    /// Creates a new MultiWalletManager.
    ///
    /// # Arguments
    ///
    /// * `client_role` - The client role for signing (Ed25519, Secp256k1, etc.)
    /// * `fee_payer` - Keypair that pays for transaction fees
    /// * `authority_keypair` - Optional keypair for the authority (needed for Ed25519)
    /// * `rpc_client` - Solana RPC client for sending transactions
    ///
    /// # Example
    ///
    /// ```no_run
    /// use swig_sdk::{MultiWalletManager, Ed25519ClientRole};
    /// use solana_sdk::signature::{Keypair, Signer};
    /// use solana_client::rpc_client::RpcClient;
    /// use solana_sdk::commitment_config::CommitmentConfig;
    ///
    /// let fee_payer = Keypair::new();
    /// let authority = Keypair::new();
    /// let client_role = Box::new(Ed25519ClientRole::new(authority.pubkey()));
    /// let rpc = RpcClient::new_with_commitment(
    ///     "https://api.mainnet-beta.solana.com".to_string(),
    ///     CommitmentConfig::confirmed(),
    /// );
    ///
    /// let manager = MultiWalletManager::new(client_role, &fee_payer, Some(&authority), rpc);
    /// ```
    pub fn new(
        client_role: Box<dyn ClientRole>,
        fee_payer: &'c Keypair,
        authority_keypair: Option<&'c Keypair>,
        rpc_client: RpcClient,
        #[cfg(all(feature = "rust_sdk_test", test))] litesvm: &'c mut LiteSVM,
    ) -> Self {
        Self {
            client_role,
            fee_payer,
            authority_keypair,
            rpc_client,
            #[cfg(all(feature = "rust_sdk_test", test))]
            litesvm,
        }
    }

    // ========================================================================
    // Instruction Creation API
    // ========================================================================

    /// Creates signed instructions for multiple wallets using a custom builder.
    ///
    /// This is the most flexible instruction creation method. The instruction is
    /// constructed dynamically for each wallet using the provided closure.
    ///
    /// # Arguments
    ///
    /// * `swig_ids` - Vector of (swig_id, role_id) tuples for each wallet
    /// * `instruction_builder` - Closure that constructs an instruction for each wallet.
    ///   Receives (swig_id, role_id, swig_wallet_address) and returns an Instruction
    /// * `current_slot` - Current slot number (required for secp256k1/secp256r1 authorities)
    ///
    /// # Returns
    ///
    /// Returns a vector of signed instructions, one per wallet.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use solana_program::system_instruction;
    /// # use swig_sdk::{MultiWalletManager, Ed25519ClientRole};
    /// # use solana_sdk::signature::{Keypair, Signer};
    /// # use solana_client::rpc_client::RpcClient;
    /// # use solana_sdk::commitment_config::CommitmentConfig;
    ///
    /// # let fee_payer = Keypair::new();
    /// # let authority = Keypair::new();
    /// # let client_role = Box::new(Ed25519ClientRole::new(authority.pubkey()));
    /// # let rpc = RpcClient::new_with_commitment("http://localhost:8899".to_string(), CommitmentConfig::confirmed());
    /// # let manager = MultiWalletManager::new(client_role, &fee_payer, Some(&authority), rpc);
    /// let wallet_ids: Vec<([u8; 32], u32)> = vec![];
    /// let recipient = Keypair::new().pubkey();
    ///
    /// let instructions = manager.create_instructions(
    ///     wallet_ids,
    ///     |_swig_id, _role_id, wallet_addr| {
    ///         Ok(system_instruction::transfer(&wallet_addr, &recipient, 1000))
    ///     },
    ///     None,
    /// )?;
    /// # Ok::<(), swig_sdk::SwigError>(())
    /// ```
    pub fn create_instructions<F>(
        &self,
        swig_ids: Vec<([u8; 32], u32)>,
        instruction_builder: F,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError>
    where
        F: Fn([u8; 32], u32, Pubkey) -> Result<Instruction, SwigError>,
    {
        let mut all_signed_instructions = Vec::new();

        for (swig_id, role_id) in swig_ids {
            let swig_account = SwigInstructionBuilder::swig_key(&swig_id);
            let (swig_wallet_address, _) = Pubkey::find_program_address(
                &swig_wallet_address_seeds(swig_account.as_ref()),
                &program_id(),
            );

            let instruction = instruction_builder(swig_id, role_id, swig_wallet_address)?;

            let signed_instructions = self.client_role.sign_v2_instruction(
                swig_account,
                swig_wallet_address,
                role_id,
                vec![instruction],
                current_slot,
                &[self.fee_payer.pubkey()],
            )?;
            all_signed_instructions.extend(signed_instructions);
        }

        Ok(all_signed_instructions)
    }

    /// Creates signed SOL transfer instructions for multiple wallets.
    ///
    /// # Arguments
    ///
    /// * `swig_ids` - Vector of (swig_id, role_id) tuples
    /// * `recipient` - Public key of the recipient
    /// * `amount` - Amount of lamports to transfer from each wallet
    /// * `current_slot` - Current slot number (optional)
    ///
    /// # Returns
    ///
    /// Returns signed transfer instructions, one per wallet.
    pub fn create_sol_transfer_instructions(
        &self,
        swig_ids: Vec<([u8; 32], u32)>,
        recipient: Pubkey,
        amount: u64,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        use solana_program::system_instruction;

        self.create_instructions(
            swig_ids,
            |_swig_id, _role_id, swig_wallet_address| {
                Ok(system_instruction::transfer(
                    &swig_wallet_address,
                    &recipient,
                    amount,
                ))
            },
            current_slot,
        )
    }

    /// Creates signed SPL token transfer instructions for multiple wallets.
    ///
    /// # Arguments
    ///
    /// * `swig_ids` - Vector of (swig_id, role_id) tuples
    /// * `mint` - Public key of the token mint
    /// * `recipient` - Public key of the recipient (will use their ATA)
    /// * `amount` - Amount of tokens to transfer from each wallet
    /// * `current_slot` - Current slot number (optional)
    ///
    /// # Returns
    ///
    /// Returns signed token transfer instructions, one per wallet.
    pub fn create_token_transfer_instructions(
        &self,
        swig_ids: Vec<([u8; 32], u32)>,
        mint: Pubkey,
        recipient: Pubkey,
        amount: u64,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError> {
        let recipient_ata = get_associated_token_address(&recipient, &mint);

        self.create_instructions(
            swig_ids,
            move |_swig_id, _role_id, swig_wallet_address| {
                let swig_ata = get_associated_token_address(&swig_wallet_address, &mint);

                let instruction = transfer(
                    &TOKEN_PROGRAM_ID,
                    &swig_ata,
                    &recipient_ata,
                    &swig_wallet_address,
                    &[],
                    amount,
                )?;

                Ok(instruction)
            },
            current_slot,
        )
    }

    // ========================================================================
    // Transaction Batching
    // ========================================================================

    /// Splits signed instructions into batches respecting Solana's transaction limits.
    ///
    /// This method groups instructions into batches that:
    /// - Respect the account limit per transaction (accounts are deduplicated)
    /// - Respect the transaction size limit
    ///
    /// # Arguments
    ///
    /// * `signed_instructions` - Vector of signed instructions to batch
    /// * `max_accounts_per_tx` - Maximum accounts per transaction
    /// * `max_tx_size_bytes` - Maximum transaction size in bytes
    ///
    /// # Returns
    ///
    /// Returns a vector of batches, where each batch can be sent in a single transaction.
    pub fn split_into_batches(
        signed_instructions: Vec<Instruction>,
        max_accounts_per_tx: usize,
        max_tx_size_bytes: usize,
    ) -> Result<Vec<Vec<Instruction>>, SwigError> {
        if signed_instructions.is_empty() {
            return Ok(vec![]);
        }

        let mut batches = Vec::new();
        let mut current_batch = Vec::new();
        let mut current_accounts = HashSet::new();

        // Based on the assumption that the transaction header and the signature are 64 bytes each.
        const BASE_TX_OVERHEAD: usize = 250;

        for instruction in signed_instructions {
            let instruction_accounts: HashSet<Pubkey> = instruction
                .accounts
                .iter()
                .map(|meta| meta.pubkey)
                .collect();

            let mut test_accounts = current_accounts.clone();
            test_accounts.extend(instruction_accounts.iter());
            let new_accounts_count = test_accounts.len();

            let estimated_total_size =
                Self::estimate_tx_size(&current_batch, &instruction, new_accounts_count);

            if !current_batch.is_empty()
                && (new_accounts_count > max_accounts_per_tx
                    || estimated_total_size > max_tx_size_bytes)
            {
                batches.push(current_batch);
                current_batch = Vec::new();
                current_accounts.clear();
            }

            current_batch.push(instruction);
            current_accounts.extend(instruction_accounts);
        }

        if !current_batch.is_empty() {
            batches.push(current_batch);
        }

        Ok(batches)
    }

    // ========================================================================
    // Transaction Execution API
    // ========================================================================

    /// Executes batch operations across multiple wallets with automatic batching.
    ///
    /// This is the primary method for executing batch operations. It handles:
    /// 1. Signing all instructions using the provided instruction builder
    /// 2. Splitting into batches respecting Solana's transaction limits
    /// 3. Sending transactions with configurable parallelization
    /// 4. Collecting results with detailed success/failure information
    ///
    /// # Arguments
    ///
    /// * `swig_ids` - Vector of (swig_id, role_id) tuples for each wallet
    /// * `instruction_builder` - Closure that constructs an instruction for each wallet
    /// * `config` - Configuration for batch execution (strategy, limits, retries, threads)
    ///
    /// # Returns
    ///
    /// Returns `BatchExecutionResult` with successful transactions and failed instructions.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use solana_program::system_instruction;
    /// use swig_sdk::{MultiWalletManager, BatchConfig, BatchStrategy, Ed25519ClientRole};
    /// # use solana_sdk::signature::{Keypair, Signer};
    /// # use solana_client::rpc_client::RpcClient;
    /// # use solana_sdk::commitment_config::CommitmentConfig;
    ///
    /// # async fn example() -> Result<(), swig_sdk::SwigError> {
    /// # let fee_payer = Keypair::new();
    /// # let authority = Keypair::new();
    /// # let client_role = Box::new(Ed25519ClientRole::new(authority.pubkey()));
    /// # let rpc = RpcClient::new_with_commitment("http://localhost:8899".to_string(), CommitmentConfig::confirmed());
    /// # let mut manager = MultiWalletManager::new(client_role, &fee_payer, Some(&authority), rpc);
    /// let wallet_ids: Vec<([u8; 32], u32)> = vec![];
    /// let recipient = Keypair::new().pubkey();
    ///
    /// let config = BatchConfig::new()
    ///     .with_strategy(BatchStrategy::BinarySearchFailures)
    ///     .with_num_threads(4)  // Send 4 batches in parallel
    ///     .with_max_retries(3);
    ///
    /// let result = manager.execute_batch(
    ///     wallet_ids,
    ///     |_swig_id, _role_id, wallet_addr| {
    ///         Ok(system_instruction::transfer(&wallet_addr, &recipient, 1000))
    ///     },
    ///     config,
    /// ).await?;
    ///
    /// println!("Success: {}, Failed: {}", result.successful_count(), result.failed_count());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn execute_batch<F>(
        &mut self,
        swig_ids: Vec<([u8; 32], u32)>,
        instruction_builder: F,
        config: BatchConfig,
    ) -> Result<BatchExecutionResult, SwigError>
    where
        F: Fn([u8; 32], u32, Pubkey) -> Result<Instruction, SwigError>,
    {
        if swig_ids.is_empty() {
            return Ok(BatchExecutionResult::default());
        }

        // Step 1: Sign all instructions and track metadata
        let signed_with_metadata =
            self.sign_batch_with_metadata(&swig_ids, &instruction_builder, None)?;

        // Step 2: Split into batches with metadata
        let batches = Self::split_into_batches_with_metadata(
            signed_with_metadata,
            config.max_accounts_per_tx,
            config.max_tx_size_bytes,
        )?;

        // Step 3: Execute based on strategy
        let result = match config.strategy {
            BatchStrategy::Simple => self.execute_batches_parallel(batches, &config).await,
            BatchStrategy::BinarySearchFailures => {
                self.execute_binary_search(batches, &config).await
            },
        };

        Ok(result)
    }

    // ========================================================================
    // High-Level Helpers (Convenience Methods)
    // ========================================================================

    /// Transfers SOL from multiple wallets to a recipient.
    ///
    /// This is a high-level convenience method that creates instructions and
    /// executes them in a single call.
    ///
    /// # Arguments
    ///
    /// * `swig_ids` - Vector of (swig_id, role_id) tuples
    /// * `recipient` - Public key of the recipient
    /// * `amount` - Amount of lamports to transfer from each wallet
    /// * `config` - Batch execution configuration
    ///
    /// # Returns
    ///
    /// Returns `BatchExecutionResult` with success/failure information.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use swig_sdk::{MultiWalletManager, BatchConfig, Ed25519ClientRole};
    /// # use solana_sdk::signature::{Keypair, Signer};
    /// # use solana_client::rpc_client::RpcClient;
    /// # use solana_sdk::commitment_config::CommitmentConfig;
    ///
    /// # async fn example() -> Result<(), swig_sdk::SwigError> {
    /// # let fee_payer = Keypair::new();
    /// # let authority = Keypair::new();
    /// # let client_role = Box::new(Ed25519ClientRole::new(authority.pubkey()));
    /// # let rpc = RpcClient::new_with_commitment("http://localhost:8899".to_string(), CommitmentConfig::confirmed());
    /// # let mut manager = MultiWalletManager::new(client_role, &fee_payer, Some(&authority), rpc);
    /// let wallet_ids: Vec<([u8; 32], u32)> = vec![];
    /// let recipient = Keypair::new().pubkey();
    ///
    /// let result = manager.transfer_sol(
    ///     wallet_ids,
    ///     recipient,
    ///     1_000_000, // 0.001 SOL per wallet
    ///     BatchConfig::new().with_num_threads(4),
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn transfer_sol(
        &mut self,
        swig_ids: Vec<([u8; 32], u32)>,
        recipient: Pubkey,
        amount: u64,
        config: BatchConfig,
    ) -> Result<BatchExecutionResult, SwigError> {
        use solana_program::system_instruction;

        self.execute_batch(
            swig_ids,
            |_swig_id, _role_id, swig_wallet_address| {
                Ok(system_instruction::transfer(
                    &swig_wallet_address,
                    &recipient,
                    amount,
                ))
            },
            config,
        )
        .await
    }

    /// Transfers SPL tokens from multiple wallets to a recipient.
    ///
    /// This is a high-level convenience method that creates instructions and
    /// executes them in a single call.
    ///
    /// # Arguments
    ///
    /// * `swig_ids` - Vector of (swig_id, role_id) tuples
    /// * `mint` - Public key of the token mint
    /// * `recipient` - Public key of the recipient (will use their ATA)
    /// * `amount` - Amount of tokens to transfer from each wallet
    /// * `config` - Batch execution configuration
    ///
    /// # Returns
    ///
    /// Returns `BatchExecutionResult` with success/failure information.
    pub async fn transfer_token(
        &mut self,
        swig_ids: Vec<([u8; 32], u32)>,
        mint: Pubkey,
        recipient: Pubkey,
        amount: u64,
        config: BatchConfig,
    ) -> Result<BatchExecutionResult, SwigError> {
        let recipient_ata = get_associated_token_address(&recipient, &mint);

        self.execute_batch(
            swig_ids,
            move |_swig_id, _role_id, swig_wallet_address| {
                let swig_ata = get_associated_token_address(&swig_wallet_address, &mint);

                let instruction = transfer(
                    &TOKEN_PROGRAM_ID,
                    &swig_ata,
                    &recipient_ata,
                    &swig_wallet_address,
                    &[],
                    amount,
                )?;

                Ok(instruction)
            },
            config,
        )
        .await
    }

    // ========================================================================
    // Legacy API (Backwards Compatibility)
    // ========================================================================

    /// Legacy method name for `create_instructions`.
    #[deprecated(since = "2.0.0", note = "Use `create_instructions` instead")]
    pub fn sign_batch_with_instruction_builder<F>(
        &self,
        swig_ids: Vec<([u8; 32], u32)>,
        instruction_builder: F,
        current_slot: Option<u64>,
    ) -> Result<Vec<Instruction>, SwigError>
    where
        F: Fn([u8; 32], u32, Pubkey) -> Result<Instruction, SwigError>,
    {
        self.create_instructions(swig_ids, instruction_builder, current_slot)
    }

    // ========================================================================
    // Private Implementation
    // ========================================================================

    /// Signs instructions and returns them with metadata tracking which swig_id each belongs to.
    fn sign_batch_with_metadata<F>(
        &self,
        swig_ids: &[([u8; 32], u32)],
        instruction_builder: &F,
        current_slot: Option<u64>,
    ) -> Result<Vec<(Instruction, [u8; 32], u32)>, SwigError>
    where
        F: Fn([u8; 32], u32, Pubkey) -> Result<Instruction, SwigError>,
    {
        let mut results = Vec::with_capacity(swig_ids.len());

        for &(swig_id, role_id) in swig_ids {
            let swig_account = SwigInstructionBuilder::swig_key(&swig_id);
            let (swig_wallet_address, _) = Pubkey::find_program_address(
                &swig_wallet_address_seeds(swig_account.as_ref()),
                &program_id(),
            );

            let instruction = instruction_builder(swig_id, role_id, swig_wallet_address)?;

            let signed_instructions = self.client_role.sign_v2_instruction(
                swig_account,
                swig_wallet_address,
                role_id,
                vec![instruction],
                current_slot,
                &[self.fee_payer.pubkey()],
            )?;

            for signed_ix in signed_instructions {
                results.push((signed_ix, swig_id, role_id));
            }
        }

        Ok(results)
    }

    /// Splits signed instructions with metadata into batches.
    fn split_into_batches_with_metadata(
        signed_with_metadata: Vec<(Instruction, [u8; 32], u32)>,
        max_accounts_per_tx: usize,
        max_tx_size_bytes: usize,
    ) -> Result<Vec<BatchWithMetadata>, SwigError> {
        if signed_with_metadata.is_empty() {
            return Ok(vec![]);
        }

        let mut batches = Vec::new();
        let mut current_batch = BatchWithMetadata {
            instructions: Vec::new(),
            swig_ids: Vec::new(),
        };
        let mut current_accounts = HashSet::new();

        for (instruction, swig_id, role_id) in signed_with_metadata {
            let instruction_accounts: HashSet<Pubkey> = instruction
                .accounts
                .iter()
                .map(|meta| meta.pubkey)
                .collect();

            let mut test_accounts = current_accounts.clone();
            test_accounts.extend(instruction_accounts.iter());
            let new_accounts_count = test_accounts.len();

            let estimated_total_size = Self::estimate_tx_size(
                &current_batch.instructions,
                &instruction,
                new_accounts_count,
            );

            if !current_batch.instructions.is_empty()
                && (new_accounts_count > max_accounts_per_tx
                    || estimated_total_size > max_tx_size_bytes)
            {
                batches.push(current_batch);
                current_batch = BatchWithMetadata {
                    instructions: Vec::new(),
                    swig_ids: Vec::new(),
                };
                current_accounts.clear();
            }

            current_batch.instructions.push(instruction);
            current_batch.swig_ids.push((swig_id, role_id));
            current_accounts.extend(instruction_accounts);
        }

        if !current_batch.instructions.is_empty() {
            batches.push(current_batch);
        }

        Ok(batches)
    }

    /// Estimates transaction size for batching decisions.
    fn estimate_tx_size(
        current_batch: &[Instruction],
        new_instruction: &Instruction,
        accounts_count: usize,
    ) -> usize {
        const BASE_TX_OVERHEAD: usize = 250;
        const SIGNATURE_SIZE: usize = 64;
        const NUM_SIGNERS: usize = 2;
        const MESSAGE_HEADER_SIZE: usize = 10;

        let instruction_size =
            |ix: &Instruction| -> usize { 1 + 1 + ix.accounts.len() + 2 + ix.data.len() };

        let estimated_account_keys_size = accounts_count * 32;
        let estimated_instructions_size: usize =
            current_batch.iter().map(instruction_size).sum::<usize>()
                + instruction_size(new_instruction);
        let message_structure_overhead = MESSAGE_HEADER_SIZE + 4 + 4;

        BASE_TX_OVERHEAD
            + SIGNATURE_SIZE * NUM_SIGNERS
            + message_structure_overhead
            + estimated_account_keys_size
            + estimated_instructions_size
    }

    /// Gets the current blockhash for transaction construction.
    #[cfg(all(feature = "rust_sdk_test", test))]
    fn get_blockhash(&self) -> Hash {
        self.litesvm.latest_blockhash()
    }

    #[cfg(not(all(feature = "rust_sdk_test", test)))]
    fn get_blockhash(&self) -> Hash {
        self.rpc_client.get_latest_blockhash().unwrap_or_default()
    }

    /// Sends a transaction and returns the result.
    #[cfg(all(feature = "rust_sdk_test", test))]
    fn send_transaction_sync(&mut self, tx: VersionedTransaction) -> Result<Signature, String> {
        self.litesvm
            .send_transaction(tx)
            .map(|meta| meta.signature)
            .map_err(|e| format!("{:?}", e))
    }

    #[cfg(not(all(feature = "rust_sdk_test", test)))]
    fn send_transaction_sync(&mut self, tx: VersionedTransaction) -> Result<Signature, String> {
        self.rpc_client
            .send_and_confirm_transaction(&tx)
            .map_err(|e| format!("{}", e))
    }

    /// Compiles and creates a transaction from instructions.
    fn create_transaction(
        &self,
        instructions: &[Instruction],
        blockhash: Hash,
    ) -> Result<VersionedTransaction, SwigError> {
        let msg = v0::Message::try_compile(&self.fee_payer.pubkey(), instructions, &[], blockhash)
            .map_err(|e| {
                SwigError::InterfaceError(format!("Failed to compile message: {:?}", e))
            })?;

        let signers: Vec<&Keypair> = if let Some(authority) = self.authority_keypair {
            vec![self.fee_payer, authority]
        } else {
            vec![self.fee_payer]
        };

        VersionedTransaction::try_new(VersionedMessage::V0(msg), &signers).map_err(|e| {
            SwigError::InterfaceError(format!("Failed to create transaction: {:?}", e))
        })
    }

    /// Executes batches with parallel sending support.
    async fn execute_batches_parallel(
        &mut self,
        batches: Vec<BatchWithMetadata>,
        config: &BatchConfig,
    ) -> BatchExecutionResult {
        let mut result = BatchExecutionResult::default();

        if config.num_threads <= 1 {
            // Sequential execution
            for batch in batches {
                let batch_result = self.send_batch_with_retry(&batch, config).await;

                match batch_result {
                    Ok(signature) => {
                        result.successful.push(SuccessfulBatch {
                            signature,
                            swig_ids: batch.swig_ids.iter().map(|(id, _)| *id).collect(),
                        });
                    },
                    Err(error) => {
                        for (swig_id, role_id) in batch.swig_ids {
                            result.failed.push(FailedInstruction {
                                swig_id,
                                role_id,
                                error: error.clone(),
                            });
                        }
                    },
                }
            }
        } else {
            // Parallel execution with semaphore for thread limiting
            // Note: For test mode, we still execute sequentially due to mutable borrow constraints
            #[cfg(all(feature = "rust_sdk_test", test))]
            {
                for batch in batches {
                    let batch_result = self.send_batch_with_retry(&batch, config).await;

                    match batch_result {
                        Ok(signature) => {
                            result.successful.push(SuccessfulBatch {
                                signature,
                                swig_ids: batch.swig_ids.iter().map(|(id, _)| *id).collect(),
                            });
                        },
                        Err(error) => {
                            for (swig_id, role_id) in batch.swig_ids {
                                result.failed.push(FailedInstruction {
                                    swig_id,
                                    role_id,
                                    error: error.clone(),
                                });
                            }
                        },
                    }
                }
            }

            #[cfg(not(all(feature = "rust_sdk_test", test)))]
            {
                let semaphore = Arc::new(Semaphore::new(config.num_threads));
                let rpc_url = self.rpc_client.url();
                let fee_payer_bytes = self.fee_payer.to_bytes();
                let authority_bytes = self.authority_keypair.map(|k| k.to_bytes());
                let max_retries = config.max_retries;
                let retry_delay_ms = config.retry_delay_ms;

                let handles: Vec<_> = batches
                    .into_iter()
                    .map(|batch| {
                        let semaphore = Arc::clone(&semaphore);
                        let rpc_url = rpc_url.clone();
                        let fee_payer_bytes = fee_payer_bytes;
                        let authority_bytes = authority_bytes;

                        tokio::spawn(async move {
                            let _permit = match semaphore.acquire().await {
                                Ok(permit) => permit,
                                Err(e) => {
                                    return (
                                        batch,
                                        Err(format!("Failed to acquire semaphore: {}", e)),
                                    );
                                },
                            };

                            let rpc_client = RpcClient::new_with_commitment(
                                rpc_url,
                                CommitmentConfig::confirmed(),
                            );
                            let fee_payer = match Keypair::from_bytes(&fee_payer_bytes) {
                                Ok(kp) => kp,
                                Err(e) => {
                                    return (
                                        batch,
                                        Err(format!("Failed to create fee payer keypair: {}", e)),
                                    );
                                },
                            };
                            let authority = match authority_bytes {
                                Some(b) => match Keypair::from_bytes(&b) {
                                    Ok(kp) => Some(kp),
                                    Err(e) => {
                                        return (
                                            batch,
                                            Err(format!(
                                                "Failed to create authority keypair: {}",
                                                e
                                            )),
                                        );
                                    },
                                },
                                None => None,
                            };

                            let batch_result = Self::send_batch_static(
                                &rpc_client,
                                &fee_payer,
                                authority.as_ref(),
                                &batch,
                                max_retries,
                                retry_delay_ms,
                            )
                            .await;

                            (batch, batch_result)
                        })
                    })
                    .collect();

                let results = join_all(handles).await;

                for handle_result in results {
                    if let Ok((batch, batch_result)) = handle_result {
                        match batch_result {
                            Ok(signature) => {
                                result.successful.push(SuccessfulBatch {
                                    signature,
                                    swig_ids: batch.swig_ids.iter().map(|(id, _)| *id).collect(),
                                });
                            },
                            Err(error) => {
                                for (swig_id, role_id) in batch.swig_ids {
                                    result.failed.push(FailedInstruction {
                                        swig_id,
                                        role_id,
                                        error: error.clone(),
                                    });
                                }
                            },
                        }
                    }
                }
            }
        }

        result
    }

    /// Static method for sending a batch (used in parallel execution).
    #[cfg(not(all(feature = "rust_sdk_test", test)))]
    async fn send_batch_static(
        rpc_client: &RpcClient,
        fee_payer: &Keypair,
        authority: Option<&Keypair>,
        batch: &BatchWithMetadata,
        max_retries: u32,
        retry_delay_ms: u64,
    ) -> Result<Signature, String> {
        let mut last_error = String::new();

        for attempt in 0..=max_retries {
            if attempt > 0 {
                sleep(Duration::from_millis(retry_delay_ms)).await;
            }

            let blockhash = match rpc_client.get_latest_blockhash() {
                Ok(hash) => hash,
                Err(e) => {
                    last_error = format!("Failed to get latest blockhash: {}", e);
                    continue;
                },
            };

            let msg = match v0::Message::try_compile(
                &fee_payer.pubkey(),
                &batch.instructions,
                &[],
                blockhash,
            ) {
                Ok(msg) => msg,
                Err(e) => {
                    last_error = format!("Failed to compile message: {:?}", e);
                    continue;
                },
            };

            let signers: Vec<&Keypair> = if let Some(auth) = authority {
                vec![fee_payer, auth]
            } else {
                vec![fee_payer]
            };

            let tx = match VersionedTransaction::try_new(VersionedMessage::V0(msg), &signers) {
                Ok(tx) => tx,
                Err(e) => {
                    last_error = format!("Failed to create transaction: {:?}", e);
                    continue;
                },
            };

            match rpc_client.send_and_confirm_transaction(&tx) {
                Ok(signature) => return Ok(signature),
                Err(e) => {
                    last_error = format!("{}", e);
                },
            }
        }

        Err(last_error)
    }

    /// Executes batches using the BinarySearchFailures strategy.
    async fn execute_binary_search(
        &mut self,
        batches: Vec<BatchWithMetadata>,
        config: &BatchConfig,
    ) -> BatchExecutionResult {
        let mut result = BatchExecutionResult::default();

        for batch in batches {
            let batch_result = self.send_batch_with_retry(&batch, config).await;

            match batch_result {
                Ok(signature) => {
                    result.successful.push(SuccessfulBatch {
                        signature,
                        swig_ids: batch.swig_ids.iter().map(|(id, _)| *id).collect(),
                    });
                },
                Err(_) => {
                    let sub_result = self.binary_search_failures(batch, config).await;
                    result.successful.extend(sub_result.successful);
                    result.failed.extend(sub_result.failed);
                },
            }
        }

        result
    }

    /// Recursively splits a failed batch to find individual failing instructions.
    async fn binary_search_failures(
        &mut self,
        batch: BatchWithMetadata,
        config: &BatchConfig,
    ) -> BatchExecutionResult {
        let mut result = BatchExecutionResult::default();

        // Base case: single instruction
        if batch.instructions.len() == 1 {
            let send_result = self.send_batch_with_retry(&batch, config).await;
            match send_result {
                Ok(signature) => {
                    result.successful.push(SuccessfulBatch {
                        signature,
                        swig_ids: batch.swig_ids.iter().map(|(id, _)| *id).collect(),
                    });
                },
                Err(error) => {
                    let (swig_id, role_id) = batch.swig_ids[0];
                    result.failed.push(FailedInstruction {
                        swig_id,
                        role_id,
                        error,
                    });
                },
            }
            return result;
        }

        // Split the batch in half
        let mid = batch.instructions.len() / 2;

        let first_half = BatchWithMetadata {
            instructions: batch.instructions[..mid].to_vec(),
            swig_ids: batch.swig_ids[..mid].to_vec(),
        };

        let second_half = BatchWithMetadata {
            instructions: batch.instructions[mid..].to_vec(),
            swig_ids: batch.swig_ids[mid..].to_vec(),
        };

        // Try first half
        let first_result = self.send_batch_with_retry(&first_half, config).await;
        match first_result {
            Ok(signature) => {
                result.successful.push(SuccessfulBatch {
                    signature,
                    swig_ids: first_half.swig_ids.iter().map(|(id, _)| *id).collect(),
                });
            },
            Err(_) => {
                let sub_result = Box::pin(self.binary_search_failures(first_half, config)).await;
                result.successful.extend(sub_result.successful);
                result.failed.extend(sub_result.failed);
            },
        }

        // Try second half
        let second_result = self.send_batch_with_retry(&second_half, config).await;
        match second_result {
            Ok(signature) => {
                result.successful.push(SuccessfulBatch {
                    signature,
                    swig_ids: second_half.swig_ids.iter().map(|(id, _)| *id).collect(),
                });
            },
            Err(_) => {
                let sub_result = Box::pin(self.binary_search_failures(second_half, config)).await;
                result.successful.extend(sub_result.successful);
                result.failed.extend(sub_result.failed);
            },
        }

        result
    }

    /// Sends a batch with retry logic.
    async fn send_batch_with_retry(
        &mut self,
        batch: &BatchWithMetadata,
        config: &BatchConfig,
    ) -> Result<Signature, String> {
        let mut last_error = String::new();

        for attempt in 0..=config.max_retries {
            if attempt > 0 {
                sleep(Duration::from_millis(config.retry_delay_ms)).await;
            }

            let blockhash = self.get_blockhash();
            let tx = match self.create_transaction(&batch.instructions, blockhash) {
                Ok(tx) => tx,
                Err(e) => {
                    last_error = format!("Transaction creation failed: {:?}", e);
                    continue;
                },
            };

            match self.send_transaction_sync(tx) {
                Ok(signature) => return Ok(signature),
                Err(e) => {
                    last_error = e;
                },
            }
        }

        Err(last_error)
    }
}
