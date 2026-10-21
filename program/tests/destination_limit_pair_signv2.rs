#![cfg(not(feature = "program_scope_test"))]
//! End-to-end pair semantics for destination limits under SignV2.
//!
//! When a role holds both a regular (one-shot) and a recurring destination
//! limit for the same destination (SOL) or mint+destination (tokens), each
//! debit must fit within both ledgers and is charged against both: the
//! recurring allowance acts as the per-window budget and the regular amount
//! as the total budget. Authorization-lock reservation capacity honors the
//! same rule by capping a key's window at the smaller of the two twins
//! (covered in `authorization_lock_test.rs`).

mod common;
use common::*;
use litesvm::types::FailedTransactionMetadata;
use litesvm_token::spl_token;
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
        sol_recurring_destination_limit::SolRecurringDestinationLimit,
        sol_recurring_limit::SolRecurringLimit, token_destination_limit::TokenDestinationLimit,
        token_limit::TokenLimit, token_recurring_destination_limit::TokenRecurringDestinationLimit,
        token_recurring_limit::TokenRecurringLimit, Actionable,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
    SwigAuthenticateError,
};

const WINDOW: u64 = 100;

/// Signs and sends one SignV2-delegated transfer, returning the raw
/// transaction failure so tests can assert builtin (non-custom) errors.
fn sign_transfer_raw(
    context: &mut SwigTestContext,
    signer: &Keypair,
    swig: Pubkey,
    wallet: Pubkey,
    role_id: u32,
    inner: Instruction,
) -> FailedTransactionMetadata {
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
    context.svm.send_transaction(tx).unwrap_err()
}

/// Signs and sends one SignV2-delegated transfer; `Ok(())` on success, the
/// inner custom code on failure.
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

struct PairSetup {
    context: SwigTestContext,
    swig: Pubkey,
    wallet: Pubkey,
    authority: Keypair,
    recipient: Pubkey,
}

fn setup_sol_pair() -> PairSetup {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let authority = Keypair::new();
    let recipient = Keypair::new().pubkey();
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
            ClientAction::SolRecurringDestinationLimit(SolRecurringDestinationLimit {
                destination: recipient.to_bytes(),
                recurring_amount: LAMPORTS_PER_SOL,
                window: WINDOW,
                last_reset: 0,
                current_amount: LAMPORTS_PER_SOL,
            }),
            ClientAction::SolDestinationLimit(SolDestinationLimit {
                destination: recipient.to_bytes(),
                amount: 4 * LAMPORTS_PER_SOL,
            }),
        ],
    )
    .unwrap();

    context.svm.airdrop(&wallet, 10 * LAMPORTS_PER_SOL).unwrap();
    context.svm.warp_to_slot(100);
    PairSetup {
        context,
        swig,
        wallet,
        authority,
        recipient,
    }
}

fn sol_transfer(wallet: &Pubkey, recipient: &Pubkey, amount: u64) -> Instruction {
    solana_system_interface::instruction::transfer(wallet, recipient, amount)
}

fn error_code(result: Result<(), u32>) -> u32 {
    result.expect_err("transaction unexpectedly succeeded")
}

#[test_log::test]
fn test_destination_pair_charges_both_regular_and_recurring_v2() {
    let PairSetup {
        mut context,
        swig,
        wallet,
        authority,
        recipient,
    } = setup_sol_pair();

    let transfer_amount = 600_000_000u64;
    sign_transfer(
        &mut context,
        &authority,
        swig,
        wallet,
        1,
        sol_transfer(&wallet, &recipient, transfer_amount),
    )
    .unwrap();

    // Both ledgers charge in the same transaction: the recurring window
    // ledger and the one-shot lifetime ledger.
    let account = context.svm.get_account(&swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let role = state.get_role(1).unwrap().unwrap();
    let dest_key = recipient.to_bytes();
    let recurring = role
        .get_action::<SolRecurringDestinationLimit>(&dest_key)
        .unwrap()
        .unwrap();
    assert_eq!(
        recurring.current_amount,
        LAMPORTS_PER_SOL - transfer_amount,
        "the recurring window ledger must be charged"
    );
    let one_shot = role
        .get_action::<SolDestinationLimit>(&dest_key)
        .unwrap()
        .unwrap();
    assert_eq!(
        one_shot.amount,
        4 * LAMPORTS_PER_SOL - transfer_amount,
        "the one-shot lifetime ledger must be charged in the same transaction"
    );
}

#[test_log::test]
fn test_destination_pair_window_capped_by_recurring_v2() {
    let PairSetup {
        mut context,
        swig,
        wallet,
        authority,
        recipient,
    } = setup_sol_pair();

    // The 4 SOL one-shot has plenty of room, but the debit must also fit the
    // 1 SOL recurring window.
    let result = sign_transfer(
        &mut context,
        &authority,
        swig,
        wallet,
        1,
        sol_transfer(&wallet, &recipient, LAMPORTS_PER_SOL + 1u64),
    );
    assert_eq!(
        error_code(result),
        SwigAuthenticateError::PermissionDeniedSolDestinationRecurringLimitExceeded as u32,
    );

    // Nothing leaked: both ledgers still hold their starting balances.
    let key = recipient.to_bytes();
    let account = context.svm.get_account(&swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let role = state.get_role(1).unwrap().unwrap();
    assert_eq!(
        role.get_action::<SolRecurringDestinationLimit>(&key)
            .unwrap()
            .unwrap()
            .current_amount,
        LAMPORTS_PER_SOL
    );
    assert_eq!(
        role.get_action::<SolDestinationLimit>(&key)
            .unwrap()
            .unwrap()
            .amount,
        4 * LAMPORTS_PER_SOL
    );
    assert_eq!(context.svm.get_balance(&recipient).unwrap_or(0), 0);
}

#[test_log::test]
fn test_destination_pair_lifetime_budget_holds_across_windows_v2() {
    let PairSetup {
        mut context,
        swig,
        wallet,
        authority,
        recipient,
    } = setup_sol_pair();
    let key = recipient.to_bytes();

    // Four fresh windows each spend exactly the per-window (recurring) cap,
    // draining the 4 SOL one-shot total exactly.
    for window in 0..4u64 {
        context.svm.warp_to_slot(100 + window * (WINDOW + 1));
        sign_transfer(
            &mut context,
            &authority,
            swig,
            wallet,
            1,
            sol_transfer(&wallet, &recipient, LAMPORTS_PER_SOL),
        )
        .unwrap();
    }
    assert_eq!(
        context.svm.get_balance(&recipient).unwrap(),
        4 * LAMPORTS_PER_SOL
    );

    // The resulting one-shot ledger state is exhausted.
    let account = context.svm.get_account(&swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let role = state.get_role(1).unwrap().unwrap();
    assert_eq!(
        role.get_action::<SolDestinationLimit>(&key)
            .unwrap()
            .unwrap()
            .amount,
        0u64
    );

    // A fifth window refreshes the recurring allowance, but the lifetime
    // budget is exhausted: any further debit is rejected with the one-shot
    // code even though the recurring ledger has fresh headroom.
    context.svm.warp_to_slot(100 + 5 * (WINDOW + 1));
    let result = sign_transfer(
        &mut context,
        &authority,
        swig,
        wallet,
        1,
        sol_transfer(&wallet, &recipient, LAMPORTS_PER_SOL),
    );
    assert_eq!(
        error_code(result),
        SwigAuthenticateError::PermissionDeniedSolDestinationLimitExceeded as u32,
    );
    assert_eq!(
        context.svm.get_balance(&recipient).unwrap(),
        4 * LAMPORTS_PER_SOL
    );
}

#[test_log::test]
fn test_token_destination_pair_charges_both_limits_v2() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&root.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    context
        .svm
        .airdrop(&authority.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (wallet, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(&mut context.svm, &mint, &wallet, &context.default_payer).unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint,
        &context.default_payer,
        &swig_ata,
        1_000,
    )
    .unwrap();

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
            ClientAction::TokenRecurringDestinationLimit(TokenRecurringDestinationLimit {
                token_mint: mint.to_bytes(),
                destination: recipient_ata.to_bytes(),
                recurring_amount: 200,
                window: WINDOW,
                last_reset: 0,
                current_amount: 200,
            }),
            ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                token_mint: mint.to_bytes(),
                destination: recipient_ata.to_bytes(),
                amount: 1_000,
            }),
        ],
    )
    .unwrap();
    context.svm.warp_to_slot(100);

    let combined_key = [mint.to_bytes(), recipient_ata.to_bytes()].concat();
    sign_transfer(
        &mut context,
        &authority,
        swig,
        wallet,
        1,
        spl_token::instruction::transfer(
            &spl_token::ID,
            &swig_ata,
            &recipient_ata,
            &wallet,
            &[],
            120,
        )
        .unwrap(),
    )
    .unwrap();

    let account = context.svm.get_account(&swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let role = state.get_role(1).unwrap().unwrap();
    assert_eq!(
        role.get_action::<TokenRecurringDestinationLimit>(&combined_key)
            .unwrap()
            .unwrap()
            .current_amount,
        80
    );
    assert_eq!(
        role.get_action::<TokenDestinationLimit>(&combined_key)
            .unwrap()
            .unwrap()
            .amount,
        880
    );

    // A debit that fits the one-shot ledger but not the window is rejected
    // with the token recurring code.
    let result = sign_transfer(
        &mut context,
        &authority,
        swig,
        wallet,
        1,
        spl_token::instruction::transfer(
            &spl_token::ID,
            &swig_ata,
            &recipient_ata,
            &wallet,
            &[],
            81,
        )
        .unwrap(),
    );
    assert_eq!(
        error_code(result),
        SwigAuthenticateError::PermissionDeniedRecurringTokenDestinationLimitExceeded as u32,
    );
}

// ---------------------------------------------------------------------------
// General (non-destination) pairs: TokenLimit + TokenRecurringLimit and the
// SOL equivalents follow the same two-ledger rule for the mint-wide debit.
// ---------------------------------------------------------------------------

fn setup_general_sol_pair() -> PairSetup {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let authority = Keypair::new();
    let recipient = Keypair::new().pubkey();
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
                amount: 4 * LAMPORTS_PER_SOL,
            }),
            ClientAction::SolRecurringLimit(SolRecurringLimit {
                recurring_amount: LAMPORTS_PER_SOL,
                window: WINDOW,
                last_reset: 0,
                current_amount: LAMPORTS_PER_SOL,
            }),
        ],
    )
    .unwrap();

    context.svm.airdrop(&wallet, 10 * LAMPORTS_PER_SOL).unwrap();
    context.svm.warp_to_slot(100);
    PairSetup {
        context,
        swig,
        wallet,
        authority,
        recipient,
    }
}

#[test_log::test]
fn test_general_pair_charges_both_one_shot_and_recurring_v2() {
    let PairSetup {
        mut context,
        swig,
        wallet,
        authority,
        recipient,
    } = setup_general_sol_pair();

    sign_transfer(
        &mut context,
        &authority,
        swig,
        wallet,
        1,
        sol_transfer(&wallet, &recipient, LAMPORTS_PER_SOL),
    )
    .unwrap();

    let account = context.svm.get_account(&swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let role = state.get_role(1).unwrap().unwrap();
    assert_eq!(
        role.get_action::<SolLimit>(&[]).unwrap().unwrap().amount,
        3 * LAMPORTS_PER_SOL,
        "the general one-shot lifetime ledger must be charged"
    );
    assert_eq!(
        role.get_action::<SolRecurringLimit>(&[])
            .unwrap()
            .unwrap()
            .current_amount,
        0u64,
        "the general recurring window ledger must be charged"
    );
}

#[test_log::test]
fn test_general_pair_lifetime_budget_holds_across_windows_v2() {
    let PairSetup {
        mut context,
        swig,
        wallet,
        authority,
        recipient,
    } = setup_general_sol_pair();

    // One fresh-window SOL per window drains the 4 SOL one-shot in four
    // windows; the recurring allowance refills each time.
    for window in 0..4u64 {
        context.svm.warp_to_slot(100 + window * (WINDOW + 1));
        sign_transfer(
            &mut context,
            &authority,
            swig,
            wallet,
            1,
            sol_transfer(&wallet, &recipient, LAMPORTS_PER_SOL),
        )
        .unwrap();
    }
    assert_eq!(
        context.svm.get_balance(&recipient).unwrap(),
        4 * LAMPORTS_PER_SOL
    );

    // The fifth window: the one-shot ledger is exhausted and rejects with
    // PermissionDeniedInsufficientBalance even though the window refilled.
    context.svm.warp_to_slot(100 + 5 * (WINDOW + 1));
    let result = sign_transfer(
        &mut context,
        &authority,
        swig,
        wallet,
        1,
        sol_transfer(&wallet, &recipient, LAMPORTS_PER_SOL),
    );
    assert_eq!(
        error_code(result),
        SwigAuthenticateError::PermissionDeniedInsufficientBalance as u32,
    );
}

fn setup_general_token_pair() -> GenericTokenSetup {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&root.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    context
        .svm
        .airdrop(&authority.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(&mut context.svm, &mint, &wallet, &context.default_payer).unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint,
        &context.default_payer,
        &swig_ata,
        1_000,
    )
    .unwrap();

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
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint.to_bytes(),
                current_amount: 1_000,
            }),
            ClientAction::TokenRecurringLimit(TokenRecurringLimit {
                token_mint: mint.to_bytes(),
                window: WINDOW,
                limit: 200,
                current: 200,
                last_reset: 0,
            }),
        ],
    )
    .unwrap();
    context.svm.warp_to_slot(100);
    GenericTokenSetup {
        context,
        swig,
        wallet,
        authority,
        mint,
        swig_ata,
        recipient_ata,
    }
}

struct GenericTokenSetup {
    context: SwigTestContext,
    swig: Pubkey,
    wallet: Pubkey,
    authority: Keypair,
    mint: Pubkey,
    swig_ata: Pubkey,
    recipient_ata: Pubkey,
}

#[test_log::test]
fn test_token_general_pair_charges_both_limits_v2() {
    let GenericTokenSetup {
        mut context,
        swig,
        wallet,
        authority,
        mint,
        swig_ata,
        recipient_ata,
    } = setup_general_token_pair();

    sign_transfer(
        &mut context,
        &authority,
        swig,
        wallet,
        1,
        spl_token::instruction::transfer(
            &spl_token::ID,
            &swig_ata,
            &recipient_ata,
            &wallet,
            &[],
            120,
        )
        .unwrap(),
    )
    .unwrap();

    let account = context.svm.get_account(&swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let role = state.get_role(1).unwrap().unwrap();
    let mint_key = mint.to_bytes();
    assert_eq!(
        role.get_action::<TokenLimit>(&mint_key)
            .unwrap()
            .unwrap()
            .current_amount,
        880
    );
    assert_eq!(
        role.get_action::<TokenRecurringLimit>(&mint_key)
            .unwrap()
            .unwrap()
            .current,
        80
    );

    // A debit that fits the one-shot ledger but not the window fails and
    // leaves both ledgers untouched. General recurring limits surface the
    // builtin `InsufficientFunds` error rather than a custom code.
    let account_before = context.svm.get_account(&swig).unwrap();
    let failed = sign_transfer_raw(
        &mut context,
        &authority,
        swig,
        wallet,
        1,
        spl_token::instruction::transfer(
            &spl_token::ID,
            &swig_ata,
            &recipient_ata,
            &wallet,
            &[],
            81,
        )
        .unwrap(),
    );
    assert_eq!(
        failed.err,
        TransactionError::InstructionError(1, InstructionError::InsufficientFunds)
    );
    let account_after = context.svm.get_account(&swig).unwrap();
    assert_eq!(account_before.data, account_after.data);
}
