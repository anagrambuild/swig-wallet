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
    instruction::{
        authorize, deactivate_stake, delegate_stake, initialize as stake_initialize, withdraw,
    },
    state::{Authorized, Lockup, StakeAuthorize},
};
use swig_interface::{AuthorityConfig, ClientAction, SignV2Instruction};
use swig_state::{
    action::{
        all::All, program::Program, stake_all::StakeAll, stake_limit::StakeLimit,
        stake_recurring_limit::StakeRecurringLimit,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
    StakeAccountState,
};

// Constants
const LOCALHOST: &str = "http://127.0.0.1:8899";
const STAKE_PROGRAM_ID: SolanaPubkey = solana_stake_interface::program::id();

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
        if RpcClient::new_with_timeout(LOCALHOST, Duration::from_secs(1))
            .get_health()
            .is_ok()
        {
            return Ok(());
        }

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
        'airdrop: for _ in 0..5 {
            match client.request_airdrop(&payer.pubkey(), 10_000_000_000) {
                Ok(signature) => {
                    // confirm_transaction can return Ok(false) immediately without
                    // waiting; poll the same signature until it actually confirms.
                    for _ in 0..30 {
                        match client.confirm_transaction(&signature) {
                            Ok(true) => break 'airdrop,
                            _ => thread::sleep(Duration::from_millis(500)),
                        }
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

/// Helper function to add a second Ed25519 authority to an existing Swig
/// wallet, signed by the current root authority (acting_role_id 0) over RPC.
fn add_swig_ed25519_authority_v2(
    context: &TestContext,
    swig_account: &SolanaPubkey,
    root_authority: &Keypair,
    new_authority: &SolanaPubkey,
    actions: Vec<ClientAction>,
) -> anyhow::Result<()> {
    let add_ix = swig_interface::AddAuthorityInstruction::new_with_ed25519_authority(
        *swig_account,
        context.payer.pubkey(),
        root_authority.pubkey(),
        0, // acting_role_id: root
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.as_ref(),
        },
        actions,
    )?;

    let recent_blockhash = context.client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[add_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, root_authority],
        recent_blockhash,
    );
    context.client.send_and_confirm_transaction(&transaction)?;
    Ok(())
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

/// Helper function to sign transaction using SignV2 with an explicit role_id.
/// Same behavior as `sign_with_swig_v2` but for non-root roles.
fn sign_with_swig_v2_role(
    context: &TestContext,
    swig_account: &SolanaPubkey,
    swig_wallet_address: &SolanaPubkey,
    authority: &Keypair,
    role_id: u32,
    instruction: Instruction,
) -> anyhow::Result<String> {
    let sign_v2_ix = SignV2Instruction::new_ed25519(
        *swig_account,
        *swig_wallet_address,
        authority.pubkey(),
        instruction,
        role_id,
    )?;

    let recent_blockhash = context.client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[sign_v2_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, authority],
        recent_blockhash,
    );

    let signature = context.client.send_and_confirm_transaction(&transaction)?;
    Ok(signature.to_string())
}

/// Returns the local validator's vote account, used by delegation tests.
fn local_vote_account(context: &TestContext) -> anyhow::Result<SolanaPubkey> {
    let accounts = context.client.get_vote_accounts()?;
    let vote: &RpcVoteAccountInfo = accounts
        .current
        .first()
        .or_else(|| accounts.delinquent.first())
        .ok_or_else(|| anyhow::anyhow!("no vote account on local validator"))?;
    Ok(SolanaPubkey::from_str(&vote.vote_pubkey)?)
}

/// Blocks until the validator has advanced at least `slots` slots.
fn wait_for_slots(context: &TestContext, slots: u64) {
    let start = context.client.get_slot().unwrap_or(0);
    for _ in 0..600 {
        thread::sleep(Duration::from_millis(100));
        if let Ok(now) = context.client.get_slot() {
            if now >= start + slots {
                return;
            }
        }
    }
}

/// Swig's `PermissionDeniedInsufficientBalance` (3011), the error a stake limit
/// raises when exceeded.
const SWIG_LIMIT_EXCEEDED_ERROR: &str = "0xbc3";

/// Swig's `AccountDataModifiedUnexpectedly` (43), raised when a CPI changes a
/// protected region of a classified account.
const SWIG_ACCOUNT_DATA_MODIFIED_ERROR: &str = "0x2b";

/// Stake program `EpochRewardsActive` (16). The local validator runs 64-slot
/// epochs, so the rewards window is frequently active and briefly rejects stake
/// operations. Transient — retry rather than fail.
const STAKE_EPOCH_REWARDS_ACTIVE_ERROR: &str = "0x10";

/// Retries a signing operation while it fails with the transient epoch-rewards
/// error.
fn retry_while_epoch_rewards_active<F>(mut attempt: F) -> anyhow::Result<String>
where
    F: FnMut() -> anyhow::Result<String>,
{
    for _ in 0..30 {
        let result = attempt();
        match &result {
            Err(e) if format!("{:?}", e).contains(STAKE_EPOCH_REWARDS_ACTIVE_ERROR) => {
                thread::sleep(Duration::from_millis(500));
            },
            _ => return result,
        }
    }
    attempt()
}

/// Blocks until the validator crosses into a new epoch, which is when a
/// deactivation takes effect.
fn wait_for_epoch_change(context: &TestContext) {
    let start = match context.client.get_epoch_info() {
        Ok(info) => info.epoch,
        Err(_) => return,
    };
    for _ in 0..900 {
        thread::sleep(Duration::from_millis(100));
        if let Ok(info) = context.client.get_epoch_info() {
            if info.epoch > start {
                return;
            }
        }
    }
}

/// Creates a Swig wallet whose root role (role_id 0) holds `All`, plus a
/// bounded second role (role_id 1) holding exactly `bounded_actions`.
///
/// The root role must hold `All` or `ManageAuthority` — the program rejects
/// creation otherwise — so a genuinely capped role has to be a *second*
/// authority. That is also the real threat model: an owner delegating a
/// limited role to someone else.
///
/// Returns `(swig_account, swig_wallet_address)`.
fn setup_bounded_role_wallet(
    context: &TestContext,
    root_authority: &Keypair,
    bounded_authority: &Keypair,
    bounded_actions: Vec<ClientAction>,
    id: [u8; 32],
) -> anyhow::Result<(SolanaPubkey, SolanaPubkey)> {
    let swig_wallet_address =
        create_swig_ed25519_v2(context, root_authority, vec![ClientAction::All(All {})], id)?;

    let program_id = SolanaPubkey::from_str("swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB")?;
    let (swig_account, _) =
        SolanaPubkey::find_program_address(&swig_account_seeds(&id), &program_id);

    add_swig_ed25519_authority_v2(
        context,
        &swig_account,
        root_authority,
        &bounded_authority.pubkey(),
        bounded_actions,
    )?;

    Ok((swig_account, swig_wallet_address))
}

/// Creates and initializes a stake account holding `principal` lamports above
/// rent, with `authority` as BOTH staker and withdrawer.
///
/// Funding real principal matters: a rent-only stake account cannot satisfy any
/// meaningful withdrawal, so the stake program rejects it before Swig's limit
/// logic is ever consulted, and the test proves nothing.
fn create_initialized_stake_account(
    context: &TestContext,
    stake_account: &Keypair,
    authority: &SolanaPubkey,
    principal: u64,
) -> anyhow::Result<()> {
    let rent = context.client.get_minimum_balance_for_rent_exemption(200)?;
    let create_tx = Transaction::new_signed_with_payer(
        &[solana_system_interface::instruction::create_account(
            &context.payer.pubkey(),
            &stake_account.pubkey(),
            rent + principal,
            200,
            &STAKE_PROGRAM_ID,
        )],
        Some(&context.payer.pubkey()),
        &[&context.payer, stake_account],
        context.client.get_latest_blockhash()?,
    );
    context.client.send_and_confirm_transaction(&create_tx)?;

    let authorized = Authorized {
        staker: *authority,
        withdrawer: *authority,
    };
    let initialize_ix = stake_initialize(&stake_account.pubkey(), &authorized, &Lockup::default());
    let initialize_tx = Transaction::new_signed_with_payer(
        &[initialize_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.client.get_latest_blockhash()?,
    );
    context
        .client
        .send_and_confirm_transaction(&initialize_tx)?;
    Ok(())
}

/// Withdraws `amount` from `stake_account` through SignV2 as the bounded role,
/// returning `(result, destination_balance_delta)`.
///
/// Retries while the stake program reports `EpochRewardsActive`, which the
/// local validator's 64-slot epochs trigger often. Only that specific transient
/// error is retried, so genuine rejections still surface immediately.
fn withdraw_through_swig(
    context: &TestContext,
    swig_account: &SolanaPubkey,
    swig_wallet_address: &SolanaPubkey,
    bounded_authority: &Keypair,
    stake_account: &SolanaPubkey,
    destination: &SolanaPubkey,
    amount: u64,
) -> (anyhow::Result<String>, u64) {
    for _ in 0..30 {
        let (result, delta) = withdraw_through_swig_once(
            context,
            swig_account,
            swig_wallet_address,
            bounded_authority,
            stake_account,
            destination,
            amount,
        );
        match &result {
            Err(e) if format!("{:?}", e).contains(STAKE_EPOCH_REWARDS_ACTIVE_ERROR) => {
                thread::sleep(Duration::from_millis(500));
            },
            _ => return (result, delta),
        }
    }
    withdraw_through_swig_once(
        context,
        swig_account,
        swig_wallet_address,
        bounded_authority,
        stake_account,
        destination,
        amount,
    )
}

/// Single withdrawal attempt without retry.
fn withdraw_through_swig_once(
    context: &TestContext,
    swig_account: &SolanaPubkey,
    swig_wallet_address: &SolanaPubkey,
    bounded_authority: &Keypair,
    stake_account: &SolanaPubkey,
    destination: &SolanaPubkey,
    amount: u64,
) -> (anyhow::Result<String>, u64) {
    let withdraw_ix = withdraw(
        stake_account,
        swig_wallet_address,
        destination,
        amount,
        None,
    );

    let before = context.client.get_balance(destination).unwrap_or(0);
    let result = sign_with_swig_v2_role(
        context,
        swig_account,
        swig_wallet_address,
        bounded_authority,
        1,
        withdraw_ix,
    );
    let after = context.client.get_balance(destination).unwrap_or(0);
    (result, after.saturating_sub(before))
}

/// `StakeAll` grants uncapped stake authority, so a large withdrawal succeeds.
#[test]
fn test_stake_with_unlimited_permission_v2() {
    let context = TestContext::new();
    let stake_account = Keypair::new();
    let destination = Keypair::new();
    let root_authority = Keypair::new();
    let bounded_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    let (swig_account, swig_wallet_address) = setup_bounded_role_wallet(
        &context,
        &root_authority,
        &bounded_authority,
        vec![
            ClientAction::Program(Program {
                program_id: STAKE_PROGRAM_ID.to_bytes(),
            }),
            ClientAction::StakeAll(StakeAll {}),
        ],
        id,
    )
    .expect("Failed to set up bounded role wallet");

    create_initialized_stake_account(&context, &stake_account, &swig_wallet_address, 100_000_000)
        .expect("Failed to create stake account");

    let (result, delta) = withdraw_through_swig(
        &context,
        &swig_account,
        &swig_wallet_address,
        &bounded_authority,
        &stake_account.pubkey(),
        &destination.pubkey(),
        60_000_000,
    );

    assert!(
        result.is_ok(),
        "StakeAll should permit an uncapped withdrawal, got: {:?}",
        result.err()
    );
    assert_eq!(
        delta, 60_000_000,
        "destination should receive the full withdrawal"
    );
}

/// `StakeLimit` caps total stake movement: within-limit succeeds, over-limit is
/// rejected and moves no lamports.
#[test]
fn test_stake_with_fixed_limit_v2() {
    let context = TestContext::new();
    let stake_account = Keypair::new();
    let destination = Keypair::new();
    let root_authority = Keypair::new();
    let bounded_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    let (swig_account, swig_wallet_address) = setup_bounded_role_wallet(
        &context,
        &root_authority,
        &bounded_authority,
        vec![
            ClientAction::Program(Program {
                program_id: STAKE_PROGRAM_ID.to_bytes(),
            }),
            ClientAction::StakeLimit(StakeLimit { amount: 50_000_000 }),
        ],
        id,
    )
    .expect("Failed to set up bounded role wallet");

    create_initialized_stake_account(&context, &stake_account, &swig_wallet_address, 200_000_000)
        .expect("Failed to create stake account");

    // Within the 50_000_000 cap.
    let (ok_result, ok_delta) = withdraw_through_swig(
        &context,
        &swig_account,
        &swig_wallet_address,
        &bounded_authority,
        &stake_account.pubkey(),
        &destination.pubkey(),
        10_000_000,
    );
    assert!(
        ok_result.is_ok(),
        "withdrawal within StakeLimit should succeed, got: {:?}",
        ok_result.err()
    );
    assert_eq!(ok_delta, 10_000_000, "within-limit delta mismatch");

    // 60_000_000 exceeds the 40_000_000 remaining.
    let (err_result, err_delta) = withdraw_through_swig(
        &context,
        &swig_account,
        &swig_wallet_address,
        &bounded_authority,
        &stake_account.pubkey(),
        &destination.pubkey(),
        60_000_000,
    );
    assert!(
        err_result.is_err(),
        "withdrawal above StakeLimit must be rejected, but it succeeded"
    );
    assert_eq!(
        err_delta, 0,
        "rejected withdrawal must not move any lamports"
    );
}

/// A withdrawal of exactly the remaining limit is allowed; one lamport more is
/// not. Guards the boundary condition in `StakeLimit::run`.
#[test]
fn test_stake_withdraw_at_exact_limit_boundary_v2() {
    let context = TestContext::new();
    let stake_account = Keypair::new();
    let destination = Keypair::new();
    let root_authority = Keypair::new();
    let bounded_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    let limit: u64 = 25_000_000;
    let (swig_account, swig_wallet_address) = setup_bounded_role_wallet(
        &context,
        &root_authority,
        &bounded_authority,
        vec![
            ClientAction::Program(Program {
                program_id: STAKE_PROGRAM_ID.to_bytes(),
            }),
            ClientAction::StakeLimit(StakeLimit { amount: limit }),
        ],
        id,
    )
    .expect("Failed to set up bounded role wallet");

    create_initialized_stake_account(&context, &stake_account, &swig_wallet_address, 200_000_000)
        .expect("Failed to create stake account");

    // One lamport over the cap must fail.
    let (over_result, over_delta) = withdraw_through_swig(
        &context,
        &swig_account,
        &swig_wallet_address,
        &bounded_authority,
        &stake_account.pubkey(),
        &destination.pubkey(),
        limit + 1,
    );
    assert!(
        over_result.is_err(),
        "limit + 1 must be rejected, but it succeeded"
    );
    assert_eq!(over_delta, 0, "rejected withdrawal must move no lamports");

    // Exactly the cap must succeed.
    let (exact_result, exact_delta) = withdraw_through_swig(
        &context,
        &swig_account,
        &swig_wallet_address,
        &bounded_authority,
        &stake_account.pubkey(),
        &destination.pubkey(),
        limit,
    );
    assert!(
        exact_result.is_ok(),
        "withdrawal of exactly the limit should succeed, got: {:?}",
        exact_result.err()
    );
    assert_eq!(exact_delta, limit, "exact-limit delta mismatch");
}

/// `StakeRecurringLimit` caps spend per window and refills once the window
/// elapses.
#[test]
fn test_stake_with_recurring_limit_v2() {
    let context = TestContext::new();
    let stake_account = Keypair::new();
    let destination = Keypair::new();
    let root_authority = Keypair::new();
    let bounded_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    let window: u64 = 20;
    let recurring: u64 = 50_000_000;
    let (swig_account, swig_wallet_address) = setup_bounded_role_wallet(
        &context,
        &root_authority,
        &bounded_authority,
        vec![
            ClientAction::Program(Program {
                program_id: STAKE_PROGRAM_ID.to_bytes(),
            }),
            ClientAction::StakeRecurringLimit(StakeRecurringLimit {
                recurring_amount: recurring,
                window,
                last_reset: 0,
                current_amount: recurring,
            }),
        ],
        id,
    )
    .expect("Failed to set up bounded role wallet");

    create_initialized_stake_account(&context, &stake_account, &swig_wallet_address, 300_000_000)
        .expect("Failed to create stake account");

    // Above the per-window allowance.
    let (over_result, over_delta) = withdraw_through_swig(
        &context,
        &swig_account,
        &swig_wallet_address,
        &bounded_authority,
        &stake_account.pubkey(),
        &destination.pubkey(),
        recurring + 10_000_000,
    );
    assert!(
        over_result.is_err(),
        "withdrawal above the recurring allowance must be rejected"
    );
    assert_eq!(over_delta, 0, "rejected withdrawal must move no lamports");

    // Consume most of the window's allowance.
    let (first_result, first_delta) = withdraw_through_swig(
        &context,
        &swig_account,
        &swig_wallet_address,
        &bounded_authority,
        &stake_account.pubkey(),
        &destination.pubkey(),
        30_000_000,
    );
    assert!(
        first_result.is_ok(),
        "first within-window withdrawal should succeed, got: {:?}",
        first_result.err()
    );
    assert_eq!(first_delta, 30_000_000, "first withdrawal delta mismatch");

    // Only 20_000_000 remains this window.
    let (second_result, second_delta) = withdraw_through_swig(
        &context,
        &swig_account,
        &swig_wallet_address,
        &bounded_authority,
        &stake_account.pubkey(),
        &destination.pubkey(),
        30_000_000,
    );
    assert!(
        second_result.is_err(),
        "second withdrawal should exhaust the window allowance and be rejected"
    );
    assert_eq!(second_delta, 0, "rejected withdrawal must move no lamports");

    // After the window elapses the allowance refills.
    wait_for_slots(&context, window + 5);
    let (reset_result, reset_delta) = withdraw_through_swig(
        &context,
        &swig_account,
        &swig_wallet_address,
        &bounded_authority,
        &stake_account.pubkey(),
        &destination.pubkey(),
        30_000_000,
    );
    assert!(
        reset_result.is_ok(),
        "withdrawal after the window resets should succeed, got: {:?}",
        reset_result.err()
    );
    assert_eq!(reset_delta, 30_000_000, "post-reset delta mismatch");
}

/// Successive withdrawals accumulate against a single `StakeLimit`.
#[test]
fn test_cumulative_stake_withdrawals_accumulate_against_limit_v2() {
    let context = TestContext::new();
    let stake_account = Keypair::new();
    let destination = Keypair::new();
    let root_authority = Keypair::new();
    let bounded_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    let (swig_account, swig_wallet_address) = setup_bounded_role_wallet(
        &context,
        &root_authority,
        &bounded_authority,
        vec![
            ClientAction::Program(Program {
                program_id: STAKE_PROGRAM_ID.to_bytes(),
            }),
            ClientAction::StakeLimit(StakeLimit { amount: 50_000_000 }),
        ],
        id,
    )
    .expect("Failed to set up bounded role wallet");

    create_initialized_stake_account(&context, &stake_account, &swig_wallet_address, 200_000_000)
        .expect("Failed to create stake account");

    let (first_result, first_delta) = withdraw_through_swig(
        &context,
        &swig_account,
        &swig_wallet_address,
        &bounded_authority,
        &stake_account.pubkey(),
        &destination.pubkey(),
        30_000_000,
    );
    assert!(
        first_result.is_ok(),
        "first withdrawal should succeed, got: {:?}",
        first_result.err()
    );
    assert_eq!(first_delta, 30_000_000, "first withdrawal delta mismatch");

    // 20_000_000 remains, so a second 30_000_000 must be refused.
    let (second_result, second_delta) = withdraw_through_swig(
        &context,
        &swig_account,
        &swig_wallet_address,
        &bounded_authority,
        &stake_account.pubkey(),
        &destination.pubkey(),
        30_000_000,
    );
    assert!(
        second_result.is_err(),
        "cumulative withdrawals must accumulate against StakeLimit"
    );
    assert_eq!(second_delta, 0, "rejected withdrawal must move no lamports");

    // The remainder is still spendable.
    let (third_result, third_delta) = withdraw_through_swig(
        &context,
        &swig_account,
        &swig_wallet_address,
        &bounded_authority,
        &stake_account.pubkey(),
        &destination.pubkey(),
        20_000_000,
    );
    assert!(
        third_result.is_ok(),
        "withdrawal of the exact remainder should succeed, got: {:?}",
        third_result.err()
    );
    assert_eq!(third_delta, 20_000_000, "remainder delta mismatch");
}

/// The limit is enforced for a stake account in the `Stake` (delegated) state
/// and after deactivation, not just for freshly initialized accounts.
///
/// A withdrawal from a delegated account is refused by the stake program while
/// the stake is active, so this delegates, deactivates, waits out the epoch,
/// then withdraws. The principal must exceed the 1 SOL minimum delegation or
/// the stake program rejects `DelegateStake` with error 43.
///
/// A within-limit withdrawal is attempted first as a control: it proves the
/// account is genuinely withdrawable, so the subsequent rejection can only be
/// the StakeLimit and not leftover stake activation.
#[test]
fn test_stake_limit_enforced_for_delegated_and_deactivated_v2() {
    let context = TestContext::new();
    let stake_account = Keypair::new();
    let destination = Keypair::new();
    let root_authority = Keypair::new();
    let bounded_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    let vote_account = match local_vote_account(&context) {
        Ok(v) => v,
        Err(e) => {
            panic!("delegation coverage requires a local vote account: {:?}", e);
        },
    };

    // The limit must cover the delegation itself: delegating N lamports
    // consumes N of the limit, same as unstaking N.
    let (swig_account, swig_wallet_address) = setup_bounded_role_wallet(
        &context,
        &root_authority,
        &bounded_authority,
        vec![
            ClientAction::Program(Program {
                program_id: STAKE_PROGRAM_ID.to_bytes(),
            }),
            ClientAction::StakeLimit(StakeLimit {
                amount: 3_100_000_000,
            }),
        ],
        id,
    )
    .expect("Failed to set up bounded role wallet");

    // Principal must clear the 1 SOL minimum delegation.
    let principal: u64 = 3_000_000_000;
    create_initialized_stake_account(&context, &stake_account, &swig_wallet_address, principal)
        .expect("Failed to create stake account");

    // Delegate: moves the account into the `Stake` state.
    let delegate_ix = delegate_stake(&stake_account.pubkey(), &swig_wallet_address, &vote_account);
    let delegate_result = retry_while_epoch_rewards_active(|| {
        sign_with_swig_v2_role(
            &context,
            &swig_account,
            &swig_wallet_address,
            &bounded_authority,
            1,
            delegate_ix.clone(),
        )
    });
    assert!(
        delegate_result.is_ok(),
        "delegation with Program(Stake) permission should succeed, got: {:?}",
        delegate_result.err()
    );

    // Deactivate so the principal becomes withdrawable.
    let deactivate_ix = deactivate_stake(&stake_account.pubkey(), &swig_wallet_address);
    let deactivate_result = retry_while_epoch_rewards_active(|| {
        sign_with_swig_v2_role(
            &context,
            &swig_account,
            &swig_wallet_address,
            &bounded_authority,
            1,
            deactivate_ix.clone(),
        )
    });
    assert!(
        deactivate_result.is_ok(),
        "deactivation should succeed, got: {:?}",
        deactivate_result.err()
    );

    // Deactivation only takes effect at the next epoch boundary.
    wait_for_epoch_change(&context);

    // Control: a within-limit withdrawal must succeed, proving the account is
    // actually withdrawable. Without this, an over-limit rejection could just
    // mean the stake was still active.
    let (control_result, control_delta) = withdraw_through_swig(
        &context,
        &swig_account,
        &swig_wallet_address,
        &bounded_authority,
        &stake_account.pubkey(),
        &destination.pubkey(),
        5_000_000,
    );
    assert!(
        control_result.is_ok(),
        "within-limit withdrawal from a deactivated stake account should succeed, got: {:?}",
        control_result.err()
    );
    assert_eq!(
        control_delta, 5_000_000,
        "control withdrawal delta mismatch"
    );

    // ~95_000_000 of the limit remains after the delegation and the control
    // withdrawal, so this must be refused.
    let (result, delta) = withdraw_through_swig(
        &context,
        &swig_account,
        &swig_wallet_address,
        &bounded_authority,
        &stake_account.pubkey(),
        &destination.pubkey(),
        200_000_000,
    );
    let err_text = format!("{:?}", result.as_ref().err());
    assert!(
        result.is_err(),
        "over-limit withdrawal from a deactivated stake account must be rejected"
    );
    assert!(
        err_text.contains(SWIG_LIMIT_EXCEEDED_ERROR),
        "rejection must come from the StakeLimit ({}), not an unrelated stake error: {}",
        SWIG_LIMIT_EXCEEDED_ERROR,
        err_text
    );
    assert_eq!(delta, 0, "rejected withdrawal must move no lamports");
}

/// PoC for the reported SignV2 StakeLimit bypass.
///
/// SignV2 CPI-signs as the Swig *wallet* PDA (account index 1), but the stake
/// account classifier keys `SwigStakeAccount` off `authorized_withdrawer` being
/// the Swig *config* PDA (account index 0). A stake account whose withdrawer is
/// the wallet PDA is therefore misclassified as `None`, the post-CPI limit
/// branch never runs, and `StakeLimit::run()` is never reached — while the
/// `Program(Stake)` action still authorizes the CPI.
///
/// This test encodes the SECURE expectation (over-limit withdraw is rejected),
/// so it FAILS while the bug exists and PASSES once fixed.
#[test]
fn test_stake_withdraw_above_limit_via_wallet_pda_is_rejected_v2() {
    let context = TestContext::new();
    let stake_account = Keypair::new();
    let destination = Keypair::new();
    let root_authority = Keypair::new();
    let bounded_authority = Keypair::new();

    let id = rand::random::<[u8; 32]>();

    // Root role (role_id 0) must hold All or ManageAuthority — a root holding
    // only Program(Stake) + StakeLimit is rejected at creation.
    let swig_wallet_address = create_swig_ed25519_v2(
        &context,
        &root_authority,
        vec![ClientAction::All(All {})],
        id,
    )
    .expect("Failed to create swig account");

    let program_id = SolanaPubkey::from_str("swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB").unwrap();
    let (swig_account, _) =
        SolanaPubkey::find_program_address(&swig_account_seeds(&id), &program_id);

    // Bounded second role (role_id 1): stake program access + StakeLimit of
    // 10_000_000 lamports. Deliberately NO `All`, NO `StakeAll`, NO
    // `ManageAuthority` on this role.
    add_swig_ed25519_authority_v2(
        &context,
        &swig_account,
        &root_authority,
        &bounded_authority.pubkey(),
        vec![
            ClientAction::Program(Program {
                program_id: STAKE_PROGRAM_ID.to_bytes(),
            }),
            ClientAction::StakeLimit(StakeLimit { amount: 10_000_000 }),
        ],
    )
    .expect("Failed to add bounded second authority");

    // Sanity check: prove role 1's on-chain action list is exactly
    // Program + StakeLimit (a bypass claim is meaningless otherwise).
    let permission_name = |p: u16| -> String {
        match p {
            0 => "None".to_string(),
            1 => "SolLimit".to_string(),
            3 => "Program".to_string(),
            7 => "All".to_string(),
            8 => "ManageAuthority".to_string(),
            10 => "StakeLimit".to_string(),
            12 => "StakeAll".to_string(),
            other => format!("Other({})", other),
        }
    };
    let swig_data = context
        .client
        .get_account_data(&swig_account)
        .expect("Failed to fetch swig account");
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_data).expect("Failed to parse swig");
    let role_1 = swig_with_roles
        .get_role(1)
        .expect("get_role(1) failed")
        .expect("role 1 missing");
    let mut role_1_permissions = Vec::new();
    let mut cursor = 0usize;
    while cursor < role_1.actions.len() {
        let permission = u16::from_le_bytes(role_1.actions[cursor..cursor + 2].try_into().unwrap());
        let boundary =
            u32::from_le_bytes(role_1.actions[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
        role_1_permissions.push(permission);
        println!("role 1 action: {}", permission_name(permission));
        cursor = boundary;
    }
    println!("role 1 permission tags: {:?}", role_1_permissions);
    assert_eq!(
        role_1_permissions,
        vec![3u16, 10u16],
        "role 1 must hold exactly Program + StakeLimit"
    );

    // Stake account with ~100_000_000 lamports principal (plus rent)
    let rent = context
        .client
        .get_minimum_balance_for_rent_exemption(200)
        .unwrap();
    let principal: u64 = 100_000_000;
    let create_tx = Transaction::new_signed_with_payer(
        &[solana_system_interface::instruction::create_account(
            &context.payer.pubkey(),
            &stake_account.pubkey(),
            rent + principal,
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

    // Authorize the swig WALLET PDA as both staker and withdrawer — the exact
    // arrangement SignV2 signs for.
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

    // Withdraw 60_000_000 lamports = 6x the StakeLimit, leaving the source
    // rent-exempt (rent + 40_000_000 remaining). Signed by the BOUNDED
    // authority with role_id 1.
    let withdraw_amount: u64 = 60_000_000;
    let withdraw_ix = withdraw(
        &stake_account.pubkey(),
        &swig_wallet_address,
        &destination.pubkey(),
        withdraw_amount,
        None,
    );

    let dest_before = context
        .client
        .get_balance(&destination.pubkey())
        .unwrap_or(0);
    let result = sign_with_swig_v2_role(
        &context,
        &swig_account,
        &swig_wallet_address,
        &bounded_authority,
        1, // role_id 1: the bounded second authority
        withdraw_ix,
    );
    let dest_after = context
        .client
        .get_balance(&destination.pubkey())
        .unwrap_or(0);
    let delta = dest_after.saturating_sub(dest_before);

    println!("Over-limit withdraw result: {:?}", result);
    println!(
        "Destination balance before={} after={} delta={} lamports",
        dest_before, dest_after, delta
    );

    // SECURE expectation: rejected by the StakeLimit. Fails today if the bypass
    // is real; passes once the stake classifier recognizes the wallet PDA.
    assert!(
        result.is_err(),
        "STAKELIMIT BYPASS: withdrew {} lamports against StakeLimit {{ amount: 10_000_000 }} \
         (destination delta: {} lamports)",
        withdraw_amount,
        delta
    );
}

/// A delegation larger than the remaining `StakeLimit` is rejected.
///
/// `StakeLimit` is documented to apply to staking and unstaking alike, so a
/// bounded role must not be able to lock up the wallet's SOL by delegating
/// past its cap.
#[test]
fn test_stake_delegation_above_limit_is_rejected_v2() {
    let context = TestContext::new();
    let stake_account = Keypair::new();
    let root_authority = Keypair::new();
    let bounded_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    let vote_account = local_vote_account(&context).expect("local vote account required");

    let (swig_account, swig_wallet_address) = setup_bounded_role_wallet(
        &context,
        &root_authority,
        &bounded_authority,
        vec![
            ClientAction::Program(Program {
                program_id: STAKE_PROGRAM_ID.to_bytes(),
            }),
            ClientAction::StakeLimit(StakeLimit { amount: 10_000_000 }),
        ],
        id,
    )
    .expect("Failed to set up bounded role wallet");

    // 3 SOL clears the minimum delegation and dwarfs the 10_000_000 cap.
    create_initialized_stake_account(
        &context,
        &stake_account,
        &swig_wallet_address,
        3_000_000_000,
    )
    .expect("Failed to create stake account");

    let delegate_ix = delegate_stake(&stake_account.pubkey(), &swig_wallet_address, &vote_account);
    let result = retry_while_epoch_rewards_active(|| {
        sign_with_swig_v2_role(
            &context,
            &swig_account,
            &swig_wallet_address,
            &bounded_authority,
            1,
            delegate_ix.clone(),
        )
    });

    let err_text = format!("{:?}", result.as_ref().err());
    assert!(
        result.is_err(),
        "delegating 3 SOL under a 10_000_000 StakeLimit must be rejected"
    );
    assert!(
        err_text.contains(SWIG_LIMIT_EXCEEDED_ERROR),
        "rejection must come from the StakeLimit ({}), not an unrelated stake error: {}",
        SWIG_LIMIT_EXCEEDED_ERROR,
        err_text
    );
}

/// Staking and unstaking both draw down the same `StakeLimit`.
///
/// Delegating N consumes N of the cap, and a later withdrawal consumes more, so
/// the two together can exhaust a limit that either alone would fit within.
#[test]
fn test_both_stake_and_unstake_affect_limit_v2() {
    let context = TestContext::new();
    let stake_account = Keypair::new();
    let destination = Keypair::new();
    let root_authority = Keypair::new();
    let bounded_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    let vote_account = local_vote_account(&context).expect("local vote account required");

    // Covers the 3 SOL delegation plus 50_000_000 of withdrawals.
    let (swig_account, swig_wallet_address) = setup_bounded_role_wallet(
        &context,
        &root_authority,
        &bounded_authority,
        vec![
            ClientAction::Program(Program {
                program_id: STAKE_PROGRAM_ID.to_bytes(),
            }),
            ClientAction::StakeLimit(StakeLimit {
                amount: 3_050_000_000,
            }),
        ],
        id,
    )
    .expect("Failed to set up bounded role wallet");

    create_initialized_stake_account(
        &context,
        &stake_account,
        &swig_wallet_address,
        3_000_000_000,
    )
    .expect("Failed to create stake account");

    // Staking draws down the limit: 3_000_000_000 consumed, 50_000_000 left.
    let delegate_ix = delegate_stake(&stake_account.pubkey(), &swig_wallet_address, &vote_account);
    let delegate_result = retry_while_epoch_rewards_active(|| {
        sign_with_swig_v2_role(
            &context,
            &swig_account,
            &swig_wallet_address,
            &bounded_authority,
            1,
            delegate_ix.clone(),
        )
    });
    assert!(
        delegate_result.is_ok(),
        "delegation within the limit should succeed, got: {:?}",
        delegate_result.err()
    );

    let deactivate_ix = deactivate_stake(&stake_account.pubkey(), &swig_wallet_address);
    let deactivate_result = retry_while_epoch_rewards_active(|| {
        sign_with_swig_v2_role(
            &context,
            &swig_account,
            &swig_wallet_address,
            &bounded_authority,
            1,
            deactivate_ix.clone(),
        )
    });
    assert!(
        deactivate_result.is_ok(),
        "deactivation should succeed, got: {:?}",
        deactivate_result.err()
    );

    wait_for_epoch_change(&context);

    // Unstaking draws down the same limit: 30_000_000 of the 50_000_000 left.
    let (first_result, first_delta) = withdraw_through_swig(
        &context,
        &swig_account,
        &swig_wallet_address,
        &bounded_authority,
        &stake_account.pubkey(),
        &destination.pubkey(),
        30_000_000,
    );
    assert!(
        first_result.is_ok(),
        "withdrawal within the remaining limit should succeed, got: {:?}",
        first_result.err()
    );
    assert_eq!(first_delta, 30_000_000, "first withdrawal delta mismatch");

    // Only ~20_000_000 remains, so this exceeds the combined budget.
    let (second_result, second_delta) = withdraw_through_swig(
        &context,
        &swig_account,
        &swig_wallet_address,
        &bounded_authority,
        &stake_account.pubkey(),
        &destination.pubkey(),
        30_000_000,
    );
    let err_text = format!("{:?}", second_result.as_ref().err());
    assert!(
        second_result.is_err(),
        "stake and unstake must share one budget; the combination should exceed it"
    );
    assert!(
        err_text.contains(SWIG_LIMIT_EXCEEDED_ERROR),
        "rejection must come from the StakeLimit ({}): {}",
        SWIG_LIMIT_EXCEEDED_ERROR,
        err_text
    );
    assert_eq!(second_delta, 0, "rejected withdrawal must move no lamports");
}

/// Swig's authority metadata (`12..44` staker, `44..76` withdrawer) must remain
/// covered by the post-CPI integrity hash.
///
/// A bounded `Program(Stake)` role can submit a perfectly valid `Authorize`
/// instruction — the Stake Program will happily reassign the staker or
/// withdrawer, because the wallet PDA is the current authority and did sign.
/// Nothing in the stake program stops it. SignV2 is the only thing standing
/// between a delegated role and permanent takeover of the stake account, and it
/// must detect the metadata change and roll the whole transaction back.
///
/// This is the test that pins the exclusion-range decision: the mutable
/// delegation region (`0..4`, `124..200`) is excluded from the hash, but the
/// Meta at `4..124` is not. If someone later widens the exclusion to silence a
/// delegation failure, this test is what catches the regression.
#[test]
fn test_stake_authorize_change_is_rejected_and_rolled_back_v2() {
    let context = TestContext::new();
    let root_authority = Keypair::new();
    let bounded_authority = Keypair::new();

    // Reads the on-chain authorized staker (12..44) and withdrawer (44..76).
    let read_authorities = |stake: &SolanaPubkey| -> (SolanaPubkey, SolanaPubkey) {
        let data = context
            .client
            .get_account_data(stake)
            .expect("failed to fetch stake account");
        let staker = SolanaPubkey::try_from(&data[12..44]).expect("bad staker bytes");
        let withdrawer = SolanaPubkey::try_from(&data[44..76]).expect("bad withdrawer bytes");
        (staker, withdrawer)
    };

    for (label, authorize_kind) in [
        ("staker (12..44)", StakeAuthorize::Staker),
        ("withdrawer (44..76)", StakeAuthorize::Withdrawer),
    ] {
        let stake_account = Keypair::new();
        let attacker = Keypair::new();
        let id = rand::random::<[u8; 32]>();

        let (swig_account, swig_wallet_address) = setup_bounded_role_wallet(
            &context,
            &root_authority,
            &bounded_authority,
            vec![
                ClientAction::Program(Program {
                    program_id: STAKE_PROGRAM_ID.to_bytes(),
                }),
                ClientAction::StakeLimit(StakeLimit { amount: 10_000_000 }),
            ],
            id,
        )
        .expect("Failed to set up bounded role wallet");

        create_initialized_stake_account(
            &context,
            &stake_account,
            &swig_wallet_address,
            100_000_000,
        )
        .expect("Failed to create stake account");

        let (staker_before, withdrawer_before) = read_authorities(&stake_account.pubkey());
        assert_eq!(
            staker_before, swig_wallet_address,
            "precondition: staker should start as the wallet PDA"
        );
        assert_eq!(
            withdrawer_before, swig_wallet_address,
            "precondition: withdrawer should start as the wallet PDA"
        );

        // A valid Authorize the Stake Program itself would accept: the wallet
        // PDA is the current authority and signs via SignV2.
        let authorize_ix = authorize(
            &stake_account.pubkey(),
            &swig_wallet_address,
            &attacker.pubkey(),
            authorize_kind,
            None,
        );
        let result = retry_while_epoch_rewards_active(|| {
            sign_with_swig_v2_role(
                &context,
                &swig_account,
                &swig_wallet_address,
                &bounded_authority,
                1,
                authorize_ix.clone(),
            )
        });

        let err_text = format!("{:?}", result.as_ref().err());
        assert!(
            result.is_err(),
            "reassigning the {} via a bounded Program(Stake) role must be rejected",
            label
        );
        assert!(
            err_text.contains(SWIG_ACCOUNT_DATA_MODIFIED_ERROR),
            "rejection must be AccountDataModifiedUnexpectedly ({}) for {}, got: {}",
            SWIG_ACCOUNT_DATA_MODIFIED_ERROR,
            label,
            err_text
        );

        // The transaction rolled back: authority metadata is untouched and the
        // attacker holds nothing.
        let (staker_after, withdrawer_after) = read_authorities(&stake_account.pubkey());
        assert_eq!(
            staker_after, swig_wallet_address,
            "staker must remain the Swig wallet PDA after the rejected {} change",
            label
        );
        assert_eq!(
            withdrawer_after, swig_wallet_address,
            "withdrawer must remain the Swig wallet PDA after the rejected {} change",
            label
        );
        assert_ne!(
            withdrawer_after,
            attacker.pubkey(),
            "attacker must not hold the withdraw authority"
        );
        assert_ne!(
            staker_after,
            attacker.pubkey(),
            "attacker must not hold the stake authority"
        );
    }
}
