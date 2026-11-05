#![cfg(not(feature = "program_scope_test"))]
//! A role with a global SOL limit and two destinations, each holding a
//! lifetime (one-shot) and a window (recurring) destination limit.
//!
//! Every debit must fit its destination's lifetime and window ledgers and the
//! global ledger, and charges all three. A rejected transaction moves no
//! ledger. The CU test reports SignV2 cost for this matrix against simpler
//! roles.

mod common;
use common::*;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_sdk::{
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{compact_instructions, swig, AuthorityConfig, ClientAction};
use swig_state::{
    action::{
        program::Program, sol_destination_limit::SolDestinationLimit, sol_limit::SolLimit,
        sol_recurring_destination_limit::SolRecurringDestinationLimit,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
    IntoBytes, SwigAuthenticateError,
};

const WINDOW: u64 = 100;
const ROLE: u32 = 1;
const SOL: u64 = LAMPORTS_PER_SOL;

struct Matrix {
    context: SwigTestContext,
    swig: Pubkey,
    wallet: Pubkey,
    authority: Keypair,
    a: Pubkey,
    b: Pubkey,
}

/// Per-destination limits for one destination.
struct Pair {
    lifetime: u64,
    window: u64,
}

fn setup(global: Option<u64>, a: Option<Pair>, b: Option<Pair>) -> Matrix {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let authority = Keypair::new();
    context.svm.airdrop(&root.pubkey(), SOL).unwrap();
    context.svm.airdrop(&authority.pubkey(), SOL).unwrap();
    let dest_a = Keypair::new().pubkey();
    let dest_b = Keypair::new().pubkey();
    // Destinations must already be rent-exempt to receive small transfers.
    context.svm.airdrop(&dest_a, SOL).unwrap();
    context.svm.airdrop(&dest_b, SOL).unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig_key = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id())
            .0;
    create_swig_ed25519(&mut context, &root, id).unwrap();

    let mut actions = vec![ClientAction::Program(Program {
        program_id: solana_system_interface::program::ID.to_bytes(),
    })];
    if let Some(amount) = global {
        actions.push(ClientAction::SolLimit(SolLimit { amount }));
    }
    for (destination, pair) in [(dest_a, a), (dest_b, b)] {
        let Some(pair) = pair else { continue };
        actions.push(ClientAction::SolDestinationLimit(SolDestinationLimit {
            destination: destination.to_bytes(),
            amount: pair.lifetime,
        }));
        actions.push(ClientAction::SolRecurringDestinationLimit(
            SolRecurringDestinationLimit {
                destination: destination.to_bytes(),
                recurring_amount: pair.window,
                window: WINDOW,
                last_reset: 0,
                current_amount: pair.window,
            },
        ));
    }
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority.pubkey().as_ref(),
        },
        actions,
    )
    .unwrap();

    context.svm.airdrop(&wallet, 100 * SOL).unwrap();
    context.svm.warp_to_slot(WINDOW);
    Matrix {
        context,
        swig: swig_key,
        wallet,
        authority,
        a: dest_a,
        b: dest_b,
    }
}

impl Matrix {
    /// One SignV2 that executes every transfer in `transfers` in order.
    fn sign(
        &mut self,
        transfers: &[(Pubkey, u64)],
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        let inner: Vec<Instruction> = transfers
            .iter()
            .map(|(to, amount)| {
                solana_system_interface::instruction::transfer(&self.wallet, to, *amount)
            })
            .collect();
        let accounts = vec![
            AccountMeta::new(self.swig, false),
            AccountMeta::new(self.wallet, false),
            AccountMeta::new_readonly(self.authority.pubkey(), true),
        ];
        let (accounts, compact) = compact_instructions(self.wallet, accounts, inner).unwrap();
        let payload = compact.into_bytes().unwrap();
        let args = swig::actions::sign_v2::SignV2Args::new(ROLE, payload.len() as u16);
        let sign_ix = Instruction {
            program_id: Pubkey::from(swig::ID),
            accounts,
            data: [args.into_bytes().unwrap(), &payload, &[2]].concat(),
        };

        self.context.svm.expire_blockhash();
        let message = v0::Message::try_compile(
            &self.authority.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
                sign_ix,
            ],
            &[],
            self.context.svm.latest_blockhash(),
        )
        .unwrap();
        let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&self.authority])
            .unwrap();
        self.context.svm.send_transaction(tx)
    }

    fn next_window(&mut self) {
        let slot = self
            .context
            .svm
            .get_sysvar::<solana_sdk::clock::Clock>()
            .slot;
        self.context.svm.warp_to_slot(slot + WINDOW + 1);
    }

    /// (global remaining, (A lifetime, A window), (B lifetime, B window))
    fn ledgers(&self) -> (u64, (u64, u64), (u64, u64)) {
        let account = self.context.svm.get_account(&self.swig).unwrap();
        let state = SwigWithRoles::from_bytes(&account.data).unwrap();
        let role = state.get_role(ROLE).unwrap().unwrap();
        let global = role
            .get_action::<SolLimit>(&[])
            .unwrap()
            .map_or(u64::MAX, |l| l.amount);
        let pair = |dest: &Pubkey| {
            let key = dest.to_bytes();
            (
                role.get_action::<SolDestinationLimit>(&key)
                    .unwrap()
                    .map_or(u64::MAX, |l| l.amount),
                role.get_action::<SolRecurringDestinationLimit>(&key)
                    .unwrap()
                    .map_or(u64::MAX, |l| l.current_amount),
            )
        };
        (global, pair(&self.a), pair(&self.b))
    }
}

fn ok(result: Result<TransactionMetadata, FailedTransactionMetadata>) -> TransactionMetadata {
    result.unwrap_or_else(|failed| {
        panic!(
            "transaction failed: {:?}\n{}",
            failed.err,
            failed.meta.pretty_logs()
        )
    })
}

fn rejected(result: Result<TransactionMetadata, FailedTransactionMetadata>) {
    let failed = result.expect_err("transaction unexpectedly succeeded");
    assert!(
        matches!(failed.err, TransactionError::InstructionError(_, _)),
        "unexpected error {:?}",
        failed.err
    );
}

fn custom_code(result: Result<TransactionMetadata, FailedTransactionMetadata>) -> Option<u32> {
    match result.expect_err("transaction unexpectedly succeeded").err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => Some(code),
        _ => None,
    }
}

#[test_log::test]
fn each_destination_keeps_its_own_lifetime_and_window() {
    let mut m = setup(
        Some(10 * SOL),
        Some(Pair {
            lifetime: 2 * SOL,
            window: SOL,
        }),
        Some(Pair {
            lifetime: 3 * SOL,
            window: SOL,
        }),
    );
    let (a, b) = (m.a, m.b);

    // Window 1: both destinations in one SignV2 charge all five ledgers.
    ok(m.sign(&[(a, SOL), (b, SOL)]));
    assert_eq!(m.ledgers(), (8 * SOL, (SOL, 0), (2 * SOL, 0)));

    // Each window ledger is exhausted independently.
    rejected(m.sign(&[(a, 1)]));
    rejected(m.sign(&[(b, 1)]));
    assert_eq!(m.ledgers(), (8 * SOL, (SOL, 0), (2 * SOL, 0)));

    // Window 2: both windows refresh.
    m.next_window();
    ok(m.sign(&[(a, SOL), (b, SOL)]));
    assert_eq!(m.ledgers(), (6 * SOL, (0, 0), (SOL, 0)));

    // Window 3: A's lifetime is spent even though its window refreshed; B
    // still has lifetime left. A rejected transfer to A moves nothing, even
    // when paired with a valid transfer to B.
    m.next_window();
    rejected(m.sign(&[(a, 1)]));
    rejected(m.sign(&[(b, SOL), (a, 1)]));
    assert_eq!(m.ledgers(), (6 * SOL, (0, 0), (SOL, 0)));
    ok(m.sign(&[(b, SOL)]));
    assert_eq!(m.ledgers(), (5 * SOL, (0, 0), (0, 0)));

    // Window 4: both lifetimes are spent.
    m.next_window();
    rejected(m.sign(&[(a, 1)]));
    rejected(m.sign(&[(b, 1)]));
}

#[test_log::test]
fn global_limit_binds_across_destinations() {
    let mut m = setup(
        Some(3 * SOL / 2),
        Some(Pair {
            lifetime: 10 * SOL,
            window: SOL,
        }),
        Some(Pair {
            lifetime: 10 * SOL,
            window: SOL,
        }),
    );
    let (a, b) = (m.a, m.b);

    // Both transfers fit their destinations but not the 1.5 SOL global
    // lifetime: the whole transaction fails and no ledger moves.
    rejected(m.sign(&[(a, SOL), (b, SOL)]));
    assert_eq!(m.ledgers(), (3 * SOL / 2, (10 * SOL, SOL), (10 * SOL, SOL)));

    ok(m.sign(&[(a, SOL), (b, SOL / 2)]));
    assert_eq!(
        m.ledgers(),
        (0, (9 * SOL, 0), (10 * SOL - SOL / 2, SOL / 2))
    );

    // The global limit is spent: B's window and lifetime no longer matter.
    rejected(m.sign(&[(b, 1)]));
    m.next_window();
    rejected(m.sign(&[(a, 1)]));
}

#[test_log::test]
fn transfers_to_the_same_destination_accumulate_in_its_window() {
    let mut m = setup(
        Some(10 * SOL),
        Some(Pair {
            lifetime: 10 * SOL,
            window: SOL,
        }),
        Some(Pair {
            lifetime: 10 * SOL,
            window: SOL,
        }),
    );
    let a = m.a;
    rejected(m.sign(&[(a, SOL / 2), (a, SOL / 2 + 1)]));
    ok(m.sign(&[(a, SOL / 2), (a, SOL / 2)]));
    assert_eq!(m.ledgers().1, (9 * SOL, 0));
}

#[test_log::test]
fn uncovered_destinations_are_rejected() {
    let mut m = setup(
        Some(10 * SOL),
        Some(Pair {
            lifetime: 10 * SOL,
            window: SOL,
        }),
        Some(Pair {
            lifetime: 10 * SOL,
            window: SOL,
        }),
    );
    let (a, stranger) = (m.a, Keypair::new().pubkey());
    m.context.svm.airdrop(&stranger, SOL).unwrap();
    assert_eq!(
        custom_code(m.sign(&[(stranger, 1)])),
        Some(SwigAuthenticateError::PermissionDeniedMissingPermission as u32)
    );
    // Even alongside a covered transfer.
    assert_eq!(
        custom_code(m.sign(&[(a, 1), (stranger, 1)])),
        Some(SwigAuthenticateError::PermissionDeniedMissingPermission as u32)
    );
    assert_eq!(m.ledgers().1, (10 * SOL, SOL));
}

#[test_log::test]
fn sign_v2_compute_for_global_and_two_destination_pairs() {
    let pair = || {
        Some(Pair {
            lifetime: 10 * SOL,
            window: SOL,
        })
    };
    // SignV2's own consumption, from its "consumed X of Y" log line. This
    // excludes the ComputeBudget instruction, like `sign_v2_cu_comparison`,
    // which sends SignV2 alone.
    let cu = |m: &mut Matrix, transfers: &[(Pubkey, u64)]| {
        let meta = ok(m.sign(transfers));
        let prefix = format!("Program {} consumed ", Pubkey::from(swig::ID));
        meta.logs
            .iter()
            .find_map(|log| log.strip_prefix(&prefix))
            .and_then(|rest| rest.split(' ').next())
            .and_then(|units| units.parse::<u64>().ok())
            .expect("SignV2 compute log")
    };
    let amount = SOL / 10;

    let mut global_only = setup(Some(10 * SOL), None, None);
    let to = global_only.a;
    let global_only_cu = cu(&mut global_only, &[(to, amount)]);

    let mut one_pair = setup(None, pair(), None);
    let to = one_pair.a;
    let one_pair_cu = cu(&mut one_pair, &[(to, amount)]);

    let mut matrix = setup(Some(10 * SOL), pair(), pair());
    let (a, b) = (matrix.a, matrix.b);
    let matrix_one_cu = cu(&mut matrix, &[(a, amount)]);
    let matrix_b_cu = cu(&mut matrix, &[(b, amount)]);
    let matrix_two_cu = cu(&mut matrix, &[(a, amount), (b, amount)]);

    println!("MATRIX_CU global_only_1_transfer {global_only_cu}");
    println!("MATRIX_CU one_destination_pair_1_transfer {one_pair_cu}");
    println!("MATRIX_CU global_plus_two_pairs_1_transfer_to_a {matrix_one_cu}");
    println!("MATRIX_CU global_plus_two_pairs_1_transfer_to_b {matrix_b_cu}");
    println!("MATRIX_CU global_plus_two_pairs_2_transfers {matrix_two_cu}");

    // Includes the ComputeBudget instruction. Guards against regressions in
    // limit matching; the matrix stays far below the 200k default budget.
    assert!(
        matrix_two_cu < 15_000,
        "global + two destination pairs used {matrix_two_cu} CU"
    );
}
