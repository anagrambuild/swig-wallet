#![cfg(not(feature = "program_scope_test"))]
//! End-to-end composition semantics for SignV2 when a role holds a general
//! SOL limit together with several destination limits (one-shot and
//! recurring, across multiple destinations).
//!
//! Every applicable limit must independently allow the debit and charges in
//! the same transaction: the recurring destination allowance is the
//! per-window budget, the destination one-shot is the total budget per
//! destination, and the general SOL limit bounds the aggregate of all
//! spends in a transaction. The effective allowance at every layer is the
//! minimum of the bound layers — never their sum.

mod common;
use common::*;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_sdk::{
    instruction::{Instruction, InstructionError},
    message::{v0, VersionedMessage},
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{AuthorityConfig, ClientAction, SignV2Instruction};
use swig_state::{
    action::{
        program_all::ProgramAll, sol_destination_limit::SolDestinationLimit, sol_limit::SolLimit,
        sol_recurring_destination_limit::SolRecurringDestinationLimit, Actionable,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
    SwigAuthenticateError,
};

const WINDOW: u64 = 100;

const INSUFFICIENT_BALANCE: u32 = SwigAuthenticateError::PermissionDeniedInsufficientBalance as u32;
const DESTINATION_EXCEEDED: u32 =
    SwigAuthenticateError::PermissionDeniedSolDestinationLimitExceeded as u32;
const DESTINATION_RECURRING_EXCEEDED: u32 =
    SwigAuthenticateError::PermissionDeniedSolDestinationRecurringLimitExceeded as u32;
const MISSING_PERMISSION: u32 = SwigAuthenticateError::PermissionDeniedMissingPermission as u32;

fn sign_transfer(
    context: &mut SwigTestContext,
    signer: &Keypair,
    swig: Pubkey,
    wallet: Pubkey,
    role_id: u32,
    inner: Instruction,
) -> Result<(), u32> {
    let sign_ix =
        SignV2Instruction::new_ed25519(swig, wallet, signer.pubkey(), inner, role_id).unwrap();
    context.svm.expire_blockhash();
    let message = v0::Message::try_compile(
        &signer.pubkey(),
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            sign_ix,
        ],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[signer]).unwrap();
    match context.svm.send_transaction(tx) {
        Ok(_) => Ok(()),
        Err(failed) => match failed.err {
            TransactionError::InstructionError(_, InstructionError::Custom(code)) => Err(code),
            other => panic!("unexpected error {other:?}\n{}", failed.meta.pretty_logs()),
        },
    }
}

fn error_code(result: Result<(), u32>) -> u32 {
    result.expect_err("transaction unexpectedly succeeded")
}

/// Signs a transfer whose failure must never leak a partial charge.
macro_rules! expect_reject {
    ($ctx:expr, $signer:expr, $swig:expr, $wallet:expr, $ix:expr, $code:expr) => {
        assert_eq!(
            error_code(sign_transfer($ctx, $signer, $swig, $wallet, 1, $ix)),
            $code
        );
    };
}

fn sol_transfer(wallet: &Pubkey, recipient: &Pubkey, amount: u64) -> Instruction {
    solana_system_interface::instruction::transfer(wallet, recipient, amount)
}

/// A role that mixes a general SOL limit with destination limits on three
/// destinations:
///
/// - destination A: 1 SOL/window recurring + 10 SOL one-shot (a pair)
/// - destination B: 2 SOL/window recurring + 5 SOL one-shot (a pair)
/// - destination C: 200 SOL one-shot (pair half only)
/// - general: 100 SOL lifetime, no recurring half
struct CompositionSetup {
    context: SwigTestContext,
    swig: Pubkey,
    wallet: Pubkey,
    authority: Keypair,
    a: Pubkey,
    b: Pubkey,
    c: Pubkey,
}

fn setup_composition() -> CompositionSetup {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let authority = Keypair::new();
    let a = Keypair::new().pubkey();
    let b = Keypair::new().pubkey();
    let c = Keypair::new().pubkey();
    context
        .svm
        .airdrop(&root.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    context
        .svm
        .airdrop(&authority.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (wallet, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    create_swig_ed25519(&mut context, &root, id).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::SolLimit(SolLimit {
                amount: 100 * LAMPORTS_PER_SOL,
            }),
            ClientAction::SolRecurringDestinationLimit(SolRecurringDestinationLimit {
                destination: a.to_bytes(),
                recurring_amount: LAMPORTS_PER_SOL,
                window: WINDOW,
                last_reset: 0,
                current_amount: LAMPORTS_PER_SOL,
            }),
            ClientAction::SolDestinationLimit(SolDestinationLimit {
                destination: a.to_bytes(),
                amount: 10 * LAMPORTS_PER_SOL,
            }),
            ClientAction::SolRecurringDestinationLimit(SolRecurringDestinationLimit {
                destination: b.to_bytes(),
                recurring_amount: 2 * LAMPORTS_PER_SOL,
                window: WINDOW,
                last_reset: 0,
                current_amount: 2 * LAMPORTS_PER_SOL,
            }),
            ClientAction::SolDestinationLimit(SolDestinationLimit {
                destination: b.to_bytes(),
                amount: 5 * LAMPORTS_PER_SOL,
            }),
            ClientAction::SolDestinationLimit(SolDestinationLimit {
                destination: c.to_bytes(),
                amount: 200 * LAMPORTS_PER_SOL,
            }),
        ],
    )
    .unwrap();

    context
        .svm
        .airdrop(&wallet, 400 * LAMPORTS_PER_SOL)
        .unwrap();
    context.svm.warp_to_slot(WINDOW);
    CompositionSetup {
        context,
        swig,
        wallet,
        authority,
        a,
        b,
        c,
    }
}

fn destination_ledgers(context: &mut SwigTestContext, swig: &Pubkey, dest: &[u8]) -> [u64; 2] {
    let account = context.svm.get_account(swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let role = state.get_role(1).unwrap().unwrap();
    let one_shot = role
        .get_action::<SolDestinationLimit>(dest)
        .unwrap()
        .map(|l| l.amount)
        .unwrap_or(0);
    let recurring = role
        .get_action::<SolRecurringDestinationLimit>(dest)
        .unwrap()
        .map(|l| l.current_amount)
        .unwrap_or(0);
    [one_shot, recurring]
}

fn general_remaining(context: &mut SwigTestContext, swig: &Pubkey) -> u64 {
    let account = context.svm.get_account(swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let role = state.get_role(1).unwrap().unwrap();
    role.get_action::<SolLimit>(&[]).unwrap().unwrap().amount
}

/// The primary narrated flow: a 10 SOL one-shot + 1 SOL/window pair to
/// destination A under a 100 SOL general limit.
///
/// 1. In-window: the 1 SOL recurring window is the binding limit; a second
///    same-window send is rejected and moves nothing.
/// 2. Over 10 windows: each window allows 1 SOL and the 10 SOL one-shot
///    drains with the general ledger tracking every successful send.
/// 3. Once the one-shot reaches 0, a fresh window (recurring has room
///    again) still rejects spends to A — lifetime bound.
#[test_log::test]
fn destination_pair_binds_window_then_lifetime_under_a_general_limit() {
    let CompositionSetup {
        mut context,
        swig,
        wallet,
        authority,
        a,
        ..
    } = setup_composition();

    // Window 1 (slot 100): the window is the binding limit.
    sign_transfer(
        &mut context,
        &authority,
        swig,
        wallet,
        1,
        sol_transfer(&wallet, &a, LAMPORTS_PER_SOL),
    )
    .unwrap();
    let [a_shot, a_recur] = destination_ledgers(&mut context, &swig, &a.to_bytes());
    assert_eq!((a_shot, a_recur), (9 * LAMPORTS_PER_SOL, 0));
    assert_eq!(
        general_remaining(&mut context, &swig),
        99 * LAMPORTS_PER_SOL
    );

    // The window is empty: a second send in the same window fails and
    // charges nothing.
    expect_reject!(
        &mut context,
        &authority,
        swig,
        wallet,
        sol_transfer(&wallet, &a, LAMPORTS_PER_SOL),
        DESTINATION_RECURRING_EXCEEDED
    );
    let [a_shot, a_recur] = destination_ledgers(&mut context, &swig, &a.to_bytes());
    assert_eq!((a_shot, a_recur), (9 * LAMPORTS_PER_SOL, 0));
    assert_eq!(
        general_remaining(&mut context, &swig),
        99 * LAMPORTS_PER_SOL
    );

    // Each following window restores the recurring allowance and drains
    // the 10 SOL lifetime budget, one SOL per window.
    for window in 2..=10 {
        context
            .svm
            .warp_to_slot(WINDOW + 1 + (window - 2) * (WINDOW + 1));
        sign_transfer(
            &mut context,
            &authority,
            swig,
            wallet,
            1,
            sol_transfer(&wallet, &a, LAMPORTS_PER_SOL),
        )
        .unwrap();
        let [a_shot, a_recur] = destination_ledgers(&mut context, &swig, &a.to_bytes());
        assert_eq!(a_recur, 0, "window {window} recurring must be drained");
        assert_eq!(
            a_shot,
            (10 - window) as u64 * LAMPORTS_PER_SOL,
            "window {window} one-shot must have drained"
        );
    }
    assert_eq!(
        general_remaining(&mut context, &swig),
        90 * LAMPORTS_PER_SOL
    );

    // A fresh window has recurring room again, but the lifetime budget is
    // exhausted: still rejected, still nothing recorded. A failed
    // transaction reverts the unused window allowance too.
    context.svm.warp_to_slot(WINDOW * 11 + 1);
    expect_reject!(
        &mut context,
        &authority,
        swig,
        wallet,
        sol_transfer(&wallet, &a, LAMPORTS_PER_SOL),
        DESTINATION_EXCEEDED
    );
    let [a_shot, a_recur] = destination_ledgers(&mut context, &swig, &a.to_bytes());
    assert_eq!((a_shot, a_recur), (0, 0));
    assert_eq!(
        general_remaining(&mut context, &swig),
        90 * LAMPORTS_PER_SOL
    );
}

/// With several destinations, window bounds apply per destination while
/// the general limit charges on every successful send. Destination A
/// allows 1 SOL/window, destination B 2 SOL/window; their one-shot
/// budgets are 10 and 5 SOL. Both pairs drain independently over 5
/// windows and the general ledger ends at exactly 100 − 15 SOL.
#[test_log::test]
fn multiple_destinations_drain_their_pairs_independently_over_one_general_pool() {
    let CompositionSetup {
        mut context,
        swig,
        wallet,
        authority,
        a,
        b,
        ..
    } = setup_composition();

    for window in 0..10u64 {
        if window > 0 {
            context.svm.warp_to_slot(WINDOW + window * (WINDOW + 1));
        }
        // A: 1 SOL this window while its lifetime budget lasts.
        let a_lifetime_left = 10 - window.min(10);
        if a_lifetime_left > 0 {
            sign_transfer(
                &mut context,
                &authority,
                swig,
                wallet,
                1,
                sol_transfer(&wallet, &a, LAMPORTS_PER_SOL),
            )
            .unwrap();
        } else {
            expect_reject!(
                &mut context,
                &authority,
                swig,
                wallet,
                sol_transfer(&wallet, &a, LAMPORTS_PER_SOL),
                DESTINATION_EXCEEDED
            );
        }
        // B: 2 SOL this window, until the 5 SOL lifetime budget stops
        // allowing a full double.
        let b_lifetime_left = 5u64.saturating_sub(2 * window);
        if b_lifetime_left >= 2 {
            sign_transfer(
                &mut context,
                &authority,
                swig,
                wallet,
                1,
                sol_transfer(&wallet, &b, 2 * LAMPORTS_PER_SOL),
            )
            .unwrap();
        } else if b_lifetime_left == 1 {
            // The window allows 2 SOL but the lifetime has 1 left: the
            // one-shot bound rejects and the recurring ledger must stay
            // untouched.
            expect_reject!(
                &mut context,
                &authority,
                swig,
                wallet,
                sol_transfer(&wallet, &b, 2 * LAMPORTS_PER_SOL),
                DESTINATION_EXCEEDED
            );
            sign_transfer(
                &mut context,
                &authority,
                swig,
                wallet,
                1,
                sol_transfer(&wallet, &b, LAMPORTS_PER_SOL),
            )
            .unwrap();
        } else {
            expect_reject!(
                &mut context,
                &authority,
                swig,
                wallet,
                sol_transfer(&wallet, &b, LAMPORTS_PER_SOL),
                DESTINATION_EXCEEDED
            );
        }
    }

    // Lifetime budgets: both pairs fully drained; window allowances were
    // restored every window but never exceeded the one-shot bounds.
    assert_eq!(
        destination_ledgers(&mut context, &swig, &a.to_bytes()),
        [0, 0]
    );
    // B's last window spent only 1 of its 2 SOL allowance: the unused
    // balance stays in the window ledger; failed sends never touch it.
    assert_eq!(
        destination_ledgers(&mut context, &swig, &b.to_bytes()),
        [0, LAMPORTS_PER_SOL]
    );
    // The general pool charged only successful sends: 10 SOL to A + 5 SOL
    // to B.
    assert_eq!(
        general_remaining(&mut context, &swig),
        85 * LAMPORTS_PER_SOL
    );
}

/// The general limit is the final cap over everything. Destination C has a
/// 200 SOL allowance, but the 100 SOL general pool bounds it: a 60 SOL
/// send with 45 SOL left is rejected atomically; the pool drains to 0 and
/// every further send is rejected even though C still has 100 SOL.
#[test_log::test]
fn general_limit_caps_the_aggregate_across_destinations() {
    let CompositionSetup {
        mut context,
        swig,
        wallet,
        authority,
        c,
        ..
    } = setup_composition();

    sign_transfer(
        &mut context,
        &authority,
        swig,
        wallet,
        1,
        sol_transfer(&wallet, &c, 55 * LAMPORTS_PER_SOL),
    )
    .unwrap();
    assert_eq!(
        general_remaining(&mut context, &swig),
        45 * LAMPORTS_PER_SOL
    );
    assert_eq!(
        destination_ledgers(&mut context, &swig, &c.to_bytes())[0],
        145 * LAMPORTS_PER_SOL
    );

    // Fits C (145 left) but not the general pool: rejected, neither ledger
    // moves.
    expect_reject!(
        &mut context,
        &authority,
        swig,
        wallet,
        sol_transfer(&wallet, &c, 60 * LAMPORTS_PER_SOL),
        INSUFFICIENT_BALANCE
    );
    assert_eq!(
        general_remaining(&mut context, &swig),
        45 * LAMPORTS_PER_SOL
    );
    assert_eq!(
        destination_ledgers(&mut context, &swig, &c.to_bytes())[0],
        145 * LAMPORTS_PER_SOL
    );

    sign_transfer(
        &mut context,
        &authority,
        swig,
        wallet,
        1,
        sol_transfer(&wallet, &c, 45 * LAMPORTS_PER_SOL),
    )
    .unwrap();
    assert_eq!(general_remaining(&mut context, &swig), 0);
    assert_eq!(
        destination_ledgers(&mut context, &swig, &c.to_bytes())[0],
        100 * LAMPORTS_PER_SOL
    );

    // General pool exhausted: C still has 100 SOL of allowance but every
    // send is blocked.
    expect_reject!(
        &mut context,
        &authority,
        swig,
        wallet,
        sol_transfer(&wallet, &c, LAMPORTS_PER_SOL),
        INSUFFICIENT_BALANCE
    );
    assert_eq!(
        destination_ledgers(&mut context, &swig, &c.to_bytes())[0],
        100 * LAMPORTS_PER_SOL
    );
}

/// A role that holds destination limits covers every destination it
/// spends to: a transfer to an uncovered destination is rejected with
/// PermissionDeniedMissingPermission and the general pool stays intact.
#[test_log::test]
fn uncovered_destinations_are_rejected_when_destination_limits_exist() {
    let CompositionSetup {
        mut context,
        swig,
        wallet,
        authority,
        ..
    } = setup_composition();
    let d = Keypair::new().pubkey();

    expect_reject!(
        &mut context,
        &authority,
        swig,
        wallet,
        sol_transfer(&wallet, &d, LAMPORTS_PER_SOL),
        MISSING_PERMISSION
    );
    assert_eq!(
        general_remaining(&mut context, &swig),
        100 * LAMPORTS_PER_SOL
    );
}
