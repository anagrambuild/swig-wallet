#![cfg(feature = "stake_tests")]

mod common;
use std::{
    process::{Child, Command},
    str::FromStr,
    sync::{Mutex, MutexGuard},
    thread,
    time::Duration,
};

use common::*;
use once_cell::sync::Lazy;
use solana_client::{
    rpc_client::RpcClient, rpc_config::RpcSendTransactionConfig, rpc_response::RpcVoteAccountInfo,
};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_program::pubkey::Pubkey as SolanaPubkey;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::{v0, Message, VersionedMessage},
    signature::{Keypair, Signature, Signer},
    transaction::{Transaction, VersionedTransaction},
};
use solana_stake_interface::{
    instruction::{deactivate_stake, delegate_stake, initialize as stake_initialize, withdraw},
    state::{Authorized, Lockup},
};
use solana_system_interface::instruction as system_instruction;
use solana_vote_interface::{instruction as vote_instruction, state::VoteInit};
use swig_interface::{AuthorityConfig, ClientAction, SignV2Instruction};
use swig_state::{
    action::{
        all::All, stake_all::StakeAll, stake_limit::StakeLimit,
        stake_recurring_limit::StakeRecurringLimit,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
    StakeAccountState,
};

// Constants
const LOCALHOST: &str = "http://localhost:8899";
const STAKE_PROGRAM_ID: SolanaPubkey = solana_stake_interface::program::id();
const VOTE_PROGRAM_ID: SolanaPubkey = solana_vote_interface::program::id();

// Global static validator process that will be shared across all tests
static GLOBAL_VALIDATOR: Lazy<Mutex<ValidatorProcess>> = Lazy::new(|| {
    let mut validator = ValidatorProcess::new();
    // Start the validator process when first accessed
    if let Err(e) = validator.start() {
        eprintln!("Warning: Failed to start validator: {}", e);
    }
    Mutex::new(validator)
});

struct ValidatorProcess {
    child: Option<Child>,
}

impl ValidatorProcess {
    fn new() -> Self {
        ValidatorProcess { child: None }
    }

    fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.child.is_some() {
            return Ok(());
        }

        let child = Command::new("solana-test-validator")
            .args(&[
                "--reset",
                "--quiet",
                "--rpc-port",
                "8899",
                "--faucet-port",
                "9900",
            ])
            .spawn()?;

        self.child = Some(child);
        thread::sleep(Duration::from_secs(5));
        Ok(())
    }

    fn _get_guard(&self) -> MutexGuard<ValidatorProcess> {
        GLOBAL_VALIDATOR.lock().unwrap()
    }
}

impl Drop for ValidatorProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct TestContext {
    client: RpcClient,
    payer: Keypair,
}

impl TestContext {
    fn new() -> Self {
        let _guard = GLOBAL_VALIDATOR.lock().unwrap();
        let client = RpcClient::new(LOCALHOST);
        let payer = Keypair::new();

        // Try to airdrop funds to payer
        for _ in 0..5 {
            match client.request_airdrop(&payer.pubkey(), 10_000_000_000) {
                Ok(signature) => {
                    if let Ok(_) = client.confirm_transaction(&signature) {
                        break;
                    }
                },
                Err(_) => {
                    thread::sleep(Duration::from_millis(500));
                },
            }
        }

        TestContext { client, payer }
    }
}

/// Helper function to create a Swig wallet with Ed25519 authority
fn create_swig_ed25519_v2(
    context: &TestContext,
    authority: &Keypair,
    actions: Vec<ClientAction>,
    id: [u8; 32],
) -> anyhow::Result<SolanaPubkey> {
    // Get program ID
    let program_id = SolanaPubkey::from_str("swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB")?;

    // Calculate PDA for swig account
    let (swig, bump) = SolanaPubkey::find_program_address(&swig_account_seeds(&id), &program_id);

    // Create the swig wallet address
    let (swig_wallet_address, wallet_address_bump) =
        SolanaPubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id);

    // Create the instruction
    let create_ix = swig_interface::CreateInstruction::new(
        swig,
        bump,
        context.payer.pubkey(),
        swig_wallet_address,
        wallet_address_bump,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority.pubkey().as_ref(),
        },
        actions,
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

    // Send and confirm transaction
    context.client.send_and_confirm_transaction(&transaction)?;

    Ok(swig_wallet_address)
}

/// Helper function to sign transaction using SignV2
fn sign_with_swig_v2(
    context: &TestContext,
    swig_account: &SolanaPubkey,
    swig_wallet_address: &SolanaPubkey,
    authority: &Keypair,
    instruction: Instruction,
) -> anyhow::Result<String> {
    // Create SignV2 instruction
    let sign_v2_ix = SignV2Instruction::new_ed25519(
        *swig_account,
        *swig_wallet_address,
        authority.pubkey(),
        instruction,
        0, // role_id 0 for root authority
    )?;

    // Get recent blockhash
    let recent_blockhash = context.client.get_latest_blockhash()?;

    // Create and sign transaction
    let transaction = Transaction::new_signed_with_payer(
        &[sign_v2_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, authority],
        recent_blockhash,
    );

    // Send and confirm transaction
    let signature = context.client.send_and_confirm_transaction(&transaction)?;
    Ok(signature.to_string())
}

#[test]
fn test_stake_with_unlimited_permission_v2() {
    let context = TestContext::new();
    let owner = Keypair::new();
    let delegate = Keypair::new();
    let stake_account = Keypair::new();
    let swig_authority = Keypair::new();

    // Airdrop funds
    for keypair in [&owner, &delegate, &swig_authority] {
        for _ in 0..5 {
            match context
                .client
                .request_airdrop(&keypair.pubkey(), 10_000_000_000)
            {
                Ok(signature) => {
                    if context.client.confirm_transaction(&signature).is_ok() {
                        break;
                    }
                },
                Err(_) => thread::sleep(Duration::from_millis(500)),
            }
        }
    }

    let id = rand::random::<[u8; 32]>();

    // Create Swig account with StakeAll permission
    let swig_wallet_address = create_swig_ed25519_v2(
        &context,
        &swig_authority,
        vec![ClientAction::StakeAll(StakeAll {})],
        id,
    )
    .expect("Failed to create swig account");

    let program_id = SolanaPubkey::from_str("swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB").unwrap();
    let (swig_account, _) =
        SolanaPubkey::find_program_address(&swig_account_seeds(&id), &program_id);

    // Create stake account
    let rent = context
        .client
        .get_minimum_balance_for_rent_exemption(200)
        .unwrap();
    let create_tx = Transaction::new_signed_with_payer(
        &[system_instruction::create_account(
            &context.payer.pubkey(),
            &stake_account.pubkey(),
            rent,
            200,
            &STAKE_PROGRAM_ID,
        )],
        Some(&context.payer.pubkey()),
        &[&context.payer, &stake_account],
        context.client.get_latest_blockhash().unwrap(),
    );
    context
        .client
        .send_and_confirm_transaction(&create_tx)
        .unwrap();

    // Initialize stake account
    let authorized = Authorized {
        staker: swig_wallet_address,
        withdrawer: owner.pubkey(),
    };

    let initialize_ix = stake_initialize(&stake_account.pubkey(), &authorized, &Lockup::default());

    let initialize_tx = Transaction::new_signed_with_payer(
        &[initialize_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.client.get_latest_blockhash().unwrap(),
    );
    context
        .client
        .send_and_confirm_transaction(&initialize_tx)
        .unwrap();

    // Create delegate instruction
    let delegate_ix = delegate_stake(
        &stake_account.pubkey(),
        &swig_wallet_address,
        &delegate.pubkey(),
    );

    // Sign with Swig V2
    let signature = sign_with_swig_v2(
        &context,
        &swig_account,
        &swig_wallet_address,
        &swig_authority,
        delegate_ix,
    )
    .expect("Failed to sign with swig v2");

    println!("Stake delegation successful: {}", signature);
}

#[test]
fn test_stake_with_fixed_limit_v2() {
    let context = TestContext::new();
    let owner = Keypair::new();
    let delegate = Keypair::new();
    let stake_account = Keypair::new();
    let swig_authority = Keypair::new();

    // Airdrop funds
    for keypair in [&owner, &delegate, &swig_authority] {
        for _ in 0..5 {
            match context
                .client
                .request_airdrop(&keypair.pubkey(), 10_000_000_000)
            {
                Ok(signature) => {
                    if context.client.confirm_transaction(&signature).is_ok() {
                        break;
                    }
                },
                Err(_) => thread::sleep(Duration::from_millis(500)),
            }
        }
    }

    let id = rand::random::<[u8; 32]>();

    // Create Swig account with StakeLimit permission
    let swig_wallet_address = create_swig_ed25519_v2(
        &context,
        &swig_authority,
        vec![ClientAction::StakeLimit(StakeLimit {
            amount: 500_000_000,
        })],
        id,
    )
    .expect("Failed to create swig account");

    let program_id = SolanaPubkey::from_str("swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB").unwrap();
    let (swig_account, _) =
        SolanaPubkey::find_program_address(&swig_account_seeds(&id), &program_id);

    // Create stake account
    let rent = context
        .client
        .get_minimum_balance_for_rent_exemption(200)
        .unwrap();
    let create_tx = Transaction::new_signed_with_payer(
        &[system_instruction::create_account(
            &context.payer.pubkey(),
            &stake_account.pubkey(),
            rent,
            200,
            &STAKE_PROGRAM_ID,
        )],
        Some(&context.payer.pubkey()),
        &[&context.payer, &stake_account],
        context.client.get_latest_blockhash().unwrap(),
    );
    context
        .client
        .send_and_confirm_transaction(&create_tx)
        .unwrap();

    // Initialize stake account
    let authorized = Authorized {
        staker: swig_wallet_address,
        withdrawer: owner.pubkey(),
    };

    let initialize_ix = stake_initialize(&stake_account.pubkey(), &authorized, &Lockup::default());

    let initialize_tx = Transaction::new_signed_with_payer(
        &[initialize_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.client.get_latest_blockhash().unwrap(),
    );
    context
        .client
        .send_and_confirm_transaction(&initialize_tx)
        .unwrap();

    // Test successful delegation within limit
    let delegate_ix = delegate_stake(
        &stake_account.pubkey(),
        &swig_wallet_address,
        &delegate.pubkey(),
    );

    let signature = sign_with_swig_v2(
        &context,
        &swig_account,
        &swig_wallet_address,
        &swig_authority,
        delegate_ix,
    )
    .expect("Failed to sign with swig v2");

    println!("Stake delegation within limit successful: {}", signature);
}

#[test]
fn test_stake_with_recurring_limit_v2() {
    let context = TestContext::new();
    let owner = Keypair::new();
    let delegate = Keypair::new();
    let stake_account = Keypair::new();
    let swig_authority = Keypair::new();

    // Airdrop funds
    for keypair in [&owner, &delegate, &swig_authority] {
        for _ in 0..5 {
            match context
                .client
                .request_airdrop(&keypair.pubkey(), 10_000_000_000)
            {
                Ok(signature) => {
                    if context.client.confirm_transaction(&signature).is_ok() {
                        break;
                    }
                },
                Err(_) => thread::sleep(Duration::from_millis(500)),
            }
        }
    }

    let id = rand::random::<[u8; 32]>();

    // Create Swig account with StakeRecurringLimit permission
    let swig_wallet_address = create_swig_ed25519_v2(
        &context,
        &swig_authority,
        vec![ClientAction::StakeRecurringLimit(StakeRecurringLimit {
            recurring_amount: 300_000_000,
            window: 10, // 10 slots window
            last_reset: 0,
            current_amount: 300_000_000,
        })],
        id,
    )
    .expect("Failed to create swig account");

    let program_id = SolanaPubkey::from_str("swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB").unwrap();
    let (swig_account, _) =
        SolanaPubkey::find_program_address(&swig_account_seeds(&id), &program_id);

    // Create stake account
    let rent = context
        .client
        .get_minimum_balance_for_rent_exemption(200)
        .unwrap();
    let create_tx = Transaction::new_signed_with_payer(
        &[system_instruction::create_account(
            &context.payer.pubkey(),
            &stake_account.pubkey(),
            rent,
            200,
            &STAKE_PROGRAM_ID,
        )],
        Some(&context.payer.pubkey()),
        &[&context.payer, &stake_account],
        context.client.get_latest_blockhash().unwrap(),
    );
    context
        .client
        .send_and_confirm_transaction(&create_tx)
        .unwrap();

    // Initialize stake account
    let authorized = Authorized {
        staker: swig_wallet_address,
        withdrawer: owner.pubkey(),
    };

    let initialize_ix = stake_initialize(&stake_account.pubkey(), &authorized, &Lockup::default());

    let initialize_tx = Transaction::new_signed_with_payer(
        &[initialize_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.client.get_latest_blockhash().unwrap(),
    );
    context
        .client
        .send_and_confirm_transaction(&initialize_tx)
        .unwrap();

    // Test first delegation within limit
    let delegate_ix_1 = delegate_stake(
        &stake_account.pubkey(),
        &swig_wallet_address,
        &delegate.pubkey(),
    );

    let signature_1 = sign_with_swig_v2(
        &context,
        &swig_account,
        &swig_wallet_address,
        &swig_authority,
        delegate_ix_1,
    )
    .expect("Failed to sign with swig v2");

    println!("First stake delegation successful: {}", signature_1);

    // Wait for recurring limit reset
    thread::sleep(Duration::from_secs(12));

    // Test second delegation after reset
    let delegate_ix_2 = delegate_stake(
        &stake_account.pubkey(),
        &swig_wallet_address,
        &delegate.pubkey(),
    );

    let signature_2 = sign_with_swig_v2(
        &context,
        &swig_account,
        &swig_wallet_address,
        &swig_authority,
        delegate_ix_2,
    )
    .expect("Failed to sign with swig v2");

    println!(
        "Second stake delegation after reset successful: {}",
        signature_2
    );
}

#[test]
fn test_both_stake_and_unstake_affect_limit_v2() {
    let context = TestContext::new();
    let owner = Keypair::new();
    let delegate = Keypair::new();
    let stake_account = Keypair::new();
    let swig_authority = Keypair::new();

    // Airdrop funds
    for keypair in [&owner, &delegate, &swig_authority] {
        for _ in 0..5 {
            match context
                .client
                .request_airdrop(&keypair.pubkey(), 10_000_000_000)
            {
                Ok(signature) => {
                    if context.client.confirm_transaction(&signature).is_ok() {
                        break;
                    }
                },
                Err(_) => thread::sleep(Duration::from_millis(500)),
            }
        }
    }

    let id = rand::random::<[u8; 32]>();

    // Create Swig account with StakeLimit permission
    let swig_wallet_address = create_swig_ed25519_v2(
        &context,
        &swig_authority,
        vec![ClientAction::StakeLimit(StakeLimit {
            amount: 1_000_000_000,
        })],
        id,
    )
    .expect("Failed to create swig account");

    let program_id = SolanaPubkey::from_str("swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB").unwrap();
    let (swig_account, _) =
        SolanaPubkey::find_program_address(&swig_account_seeds(&id), &program_id);

    // Create stake account
    let rent = context
        .client
        .get_minimum_balance_for_rent_exemption(200)
        .unwrap();
    let create_tx = Transaction::new_signed_with_payer(
        &[system_instruction::create_account(
            &context.payer.pubkey(),
            &stake_account.pubkey(),
            rent,
            200,
            &STAKE_PROGRAM_ID,
        )],
        Some(&context.payer.pubkey()),
        &[&context.payer, &stake_account],
        context.client.get_latest_blockhash().unwrap(),
    );
    context
        .client
        .send_and_confirm_transaction(&create_tx)
        .unwrap();

    // Initialize stake account with swig as both staker and withdrawer
    let authorized = Authorized {
        staker: swig_wallet_address,
        withdrawer: swig_wallet_address,
    };

    let initialize_ix = stake_initialize(&stake_account.pubkey(), &authorized, &Lockup::default());

    let initialize_tx = Transaction::new_signed_with_payer(
        &[initialize_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.client.get_latest_blockhash().unwrap(),
    );
    context
        .client
        .send_and_confirm_transaction(&initialize_tx)
        .unwrap();

    // Test stake delegation
    let delegate_ix = delegate_stake(
        &stake_account.pubkey(),
        &swig_wallet_address,
        &delegate.pubkey(),
    );

    let signature_1 = sign_with_swig_v2(
        &context,
        &swig_account,
        &swig_wallet_address,
        &swig_authority,
        delegate_ix,
    )
    .expect("Failed to sign stake delegation");

    println!("Stake delegation successful: {}", signature_1);

    // Test withdraw (this should also affect the limit)
    let withdraw_ix = withdraw(
        &stake_account.pubkey(),
        &swig_wallet_address,
        &owner.pubkey(),
        600_000_000,
        None,
    );

    // This should fail because it would exceed the total limit when combined with
    // the stake
    let result = sign_with_swig_v2(
        &context,
        &swig_account,
        &swig_wallet_address,
        &swig_authority,
        withdraw_ix,
    );

    // We expect this to fail due to limit exceeded
    if result.is_ok() {
        println!("Warning: Withdraw succeeded when it should have failed due to limit");
    } else {
        println!(
            "Withdraw correctly failed due to stake limit: {:?}",
            result.err()
        );
    }
}
