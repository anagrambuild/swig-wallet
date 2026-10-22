#![cfg(not(feature = "program_scope_test"))]
//! Differential backward-compatibility test against a previous program build.
//!
//! Each scenario creates wallets and roles with the previous build, then runs
//! the same operations twice with identical keys: once on the previous build
//! throughout, and once after upgrading the program to the current build at a
//! checkpoint. Outcomes (success or exact error) and the final bytes and
//! lamports of every touched account must match, except for operations a
//! scenario lists as intentional changes.
//!
//! Set `SWIG_COMPAT_OLD_SO` to a `swig.so` built from the release to compare
//! against, e.g. `git worktree add /tmp/old origin/main && (cd /tmp/old &&
//! cargo build-sbf --arch v3 --tools-version v1.53)` then
//! `SWIG_COMPAT_OLD_SO=/tmp/old/target/deploy/swig.so`. Without it the tests
//! are skipped.

mod common;
use std::collections::BTreeSet;

use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use common::*;
use litesvm::LiteSVM;
use litesvm_token::spl_token;
use solana_sdk::{
    account::Account,
    clock::Clock,
    instruction::Instruction,
    message::{v0, VersionedMessage},
    native_token::LAMPORTS_PER_SOL,
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    rent::Rent,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{
    AuthorityConfig, ClientAction, CloseSwigV1Instruction, CloseTokenAccountV1Instruction,
    SignV2Instruction, UpdateAuthorityData, UpdateAuthorityInstruction,
};
use swig_state::{
    action::{
        all::All, all_but_manage_authority::AllButManageAuthority, program::Program,
        sol_destination_limit::SolDestinationLimit, sol_limit::SolLimit,
        sol_recurring_destination_limit::SolRecurringDestinationLimit,
        sol_recurring_limit::SolRecurringLimit, sub_account::SubAccount,
        token_destination_limit::TokenDestinationLimit, token_limit::TokenLimit,
        token_recurring_destination_limit::TokenRecurringDestinationLimit,
        token_recurring_limit::TokenRecurringLimit,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds},
};

const NEW_SO: &str = "../target/deploy/swig.so";
const SOL: u64 = LAMPORTS_PER_SOL;
const WINDOW: u64 = 50;

fn key(seed: u8) -> Keypair {
    Keypair::new_from_array([seed; 32])
}

fn addr(seed: u8) -> Pubkey {
    key(seed).pubkey()
}

/// One execution of a scenario.
struct Run {
    ctx: SwigTestContext,
    upgrade: bool,
    upgraded: bool,
    outcomes: Vec<(String, Result<(), String>)>,
}

impl Run {
    fn new(old_so: &str, upgrade: bool) -> Self {
        let mut svm = LiteSVM::new();
        svm.add_program_from_file(program_id(), old_so).unwrap();
        let payer = key(1);
        svm.airdrop(&payer.pubkey(), 1_000 * SOL).unwrap();
        Self {
            ctx: SwigTestContext {
                svm,
                default_payer: payer,
            },
            upgrade,
            upgraded: false,
            outcomes: Vec::new(),
        }
    }

    /// Switches to the current build in the upgrade run. Everything before
    /// this point builds state with the previous build in both runs.
    fn checkpoint(&mut self) {
        if self.upgrade {
            self.ctx
                .svm
                .add_program_from_file(program_id(), NEW_SO)
                .unwrap();
            self.upgraded = true;
        }
    }

    fn send(&mut self, label: &str, ixs: Vec<Instruction>, signers: &[&Keypair]) {
        self.ctx.svm.expire_blockhash();
        let payer = self.ctx.default_payer.insecure_clone();
        let message =
            v0::Message::try_compile(&payer.pubkey(), &ixs, &[], self.ctx.svm.latest_blockhash())
                .unwrap();
        let mut all: Vec<&Keypair> = vec![&payer];
        all.extend(
            signers
                .iter()
                .copied()
                .filter(|s| s.pubkey() != payer.pubkey()),
        );
        let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &all).unwrap();
        let outcome = self
            .ctx
            .svm
            .send_transaction(tx)
            .map(|_| ())
            .map_err(|e| format!("{:?}", e.err));
        self.outcomes.push((label.to_string(), outcome));
    }

    /// Records a helper-driven setup or management call.
    fn record(&mut self, label: &str, result: anyhow::Result<impl Sized>) {
        self.outcomes.push((
            label.to_string(),
            result
                .map(|_| ())
                .map_err(|e| Self::normalize(e.to_string())),
        ));
    }

    /// Keeps only the transaction error, since helper messages also embed
    /// compute usage that legitimately differs between builds.
    fn normalize(message: String) -> String {
        match message.find("err: ") {
            Some(start) => {
                let rest = &message[start + 5..];
                rest[..rest.find(", meta:").unwrap_or(rest.len())].to_string()
            },
            None => message,
        }
    }

    fn warp(&mut self, slots: u64) {
        let slot = self.ctx.svm.get_sysvar::<Clock>().slot;
        self.ctx.svm.warp_to_slot(slot + slots);
    }

    fn snapshot(&self, accounts: &[Pubkey]) -> Vec<(Pubkey, Option<(u64, Vec<u8>, Pubkey)>)> {
        accounts
            .iter()
            .map(|k| {
                (
                    *k,
                    self.ctx
                        .svm
                        .get_account(k)
                        .map(|a| (a.lamports, a.data, a.owner)),
                )
            })
            .collect()
    }
}

struct Wallet {
    swig: Pubkey,
    wallet: Pubkey,
    root: Keypair,
}

fn create_wallet(run: &mut Run, root_seed: u8, id_seed: u8) -> Wallet {
    let root = key(root_seed);
    run.ctx.svm.airdrop(&root.pubkey(), 10 * SOL).unwrap();
    let id = [id_seed; 32];
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;
    let created = create_swig_ed25519(&mut run.ctx, &root, id);
    run.record("create swig", created);
    run.ctx.svm.airdrop(&wallet, 50 * SOL).unwrap();
    Wallet { swig, wallet, root }
}

fn add_role(run: &mut Run, w: &Wallet, label: &str, signer_seed: u8, actions: Vec<ClientAction>) {
    let signer = key(signer_seed);
    run.ctx.svm.airdrop(&signer.pubkey(), 10 * SOL).unwrap();
    let added = add_authority_with_ed25519_root(
        &mut run.ctx,
        &w.swig,
        &w.root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: signer.pubkey().as_ref(),
        },
        actions,
    );
    run.record(label, added);
}

fn sol_send(
    run: &mut Run,
    w: &Wallet,
    label: &str,
    signer_seed: u8,
    role: u32,
    dests: &[(Pubkey, u64)],
) {
    let signer = key(signer_seed);
    let ixs = dests
        .iter()
        .map(|(to, amount)| {
            SignV2Instruction::new_ed25519(
                w.swig,
                w.wallet,
                signer.pubkey(),
                solana_system_interface::instruction::transfer(&w.wallet, to, *amount),
                role,
            )
            .unwrap()
        })
        .collect();
    run.send(label, ixs, &[&signer]);
}

fn system_program() -> ClientAction {
    ClientAction::Program(Program {
        program_id: solana_system_interface::program::ID.to_bytes(),
    })
}

fn token_program() -> ClientAction {
    ClientAction::Program(Program {
        program_id: spl_token::ID.to_bytes(),
    })
}

fn fund_destinations(run: &mut Run, seeds: &[u8]) -> Vec<Pubkey> {
    seeds
        .iter()
        .map(|s| {
            let k = addr(*s);
            run.ctx.svm.airdrop(&k, SOL).unwrap();
            k
        })
        .collect()
}

/// Deterministic SPL mint and token accounts.
fn token_fixture(run: &mut Run, mint: Pubkey, accounts: &[(Pubkey, Pubkey, u64)]) {
    let rent = Rent::default();
    let mut data = vec![0u8; spl_token::state::Mint::LEN];
    spl_token::state::Mint::pack(
        spl_token::state::Mint {
            mint_authority: COption::Some(addr(250)),
            supply: 1_000_000,
            decimals: 0,
            is_initialized: true,
            freeze_authority: COption::None,
        },
        &mut data,
    )
    .unwrap();
    run.ctx
        .svm
        .set_account(
            mint,
            Account {
                lamports: rent.minimum_balance(data.len()),
                data,
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    for (account, owner, amount) in accounts {
        let mut data = vec![0u8; spl_token::state::Account::LEN];
        spl_token::state::Account::pack(
            spl_token::state::Account {
                mint,
                owner: *owner,
                amount: *amount,
                state: spl_token::state::AccountState::Initialized,
                ..Default::default()
            },
            &mut data,
        )
        .unwrap();
        run.ctx
            .svm
            .set_account(
                *account,
                Account {
                    lamports: rent.minimum_balance(data.len()),
                    data,
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
    }
}

fn token_send(
    run: &mut Run,
    w: &Wallet,
    label: &str,
    signer_seed: u8,
    role: u32,
    source: &Pubkey,
    to: &Pubkey,
    amount: u64,
) {
    let signer = key(signer_seed);
    let inner =
        spl_token::instruction::transfer(&spl_token::ID, source, to, &w.wallet, &[], amount)
            .unwrap();
    let ix =
        SignV2Instruction::new_ed25519(w.swig, w.wallet, signer.pubkey(), inner, role).unwrap();
    run.send(label, vec![ix], &[&signer]);
}

fn update_role(run: &mut Run, w: &Wallet, label: &str, role: u32, data: UpdateAuthorityData) {
    let payer = run.ctx.default_payer.pubkey();
    let ix = UpdateAuthorityInstruction::new_with_ed25519_authority(
        w.swig,
        payer,
        w.root.pubkey(),
        0,
        role,
        data,
    )
    .unwrap();
    let root = w.root.insecure_clone();
    run.send(label, vec![ix], &[&root]);
}

type Scenario = fn(&mut Run) -> Vec<Pubkey>;

/// Runs `scenario` on the previous build and on an upgraded program, and
/// asserts identical results except for the labelled intentional changes.
fn assert_compatible(name: &str, scenario: Scenario, intentional: &[&str]) {
    let Ok(old_so) = std::env::var("SWIG_COMPAT_OLD_SO") else {
        println!("COMPAT {name}: skipped (SWIG_COMPAT_OLD_SO not set)");
        return;
    };
    let mut before = Run::new(&old_so, false);
    let watched_before = scenario(&mut before);
    let mut after = Run::new(&old_so, true);
    let watched_after = scenario(&mut after);
    assert!(
        after.upgraded,
        "{name}: scenario never reached its checkpoint"
    );
    assert_eq!(watched_before, watched_after);
    assert_eq!(before.outcomes.len(), after.outcomes.len());

    let intentional: BTreeSet<&str> = intentional.iter().copied().collect();
    let mut changed = BTreeSet::new();
    for ((label, old), (_, new)) in before.outcomes.iter().zip(&after.outcomes) {
        if old != new {
            println!("COMPAT {name}: `{label}` changed: previous={old:?} current={new:?}");
            changed.insert(label.as_str());
        }
    }
    assert_eq!(
        changed, intentional,
        "{name}: operations whose outcome changed differ from the intentional set"
    );
    // Final state may differ only when an outcome intentionally changed.
    if intentional.is_empty() {
        assert_eq!(
            before.snapshot(&watched_before),
            after.snapshot(&watched_after),
            "{name}: account state diverged after upgrade"
        );
    }
    println!(
        "COMPAT {name}: {} operations, {} intentional changes",
        before.outcomes.len(),
        changed.len()
    );
}

// ---------------------------------------------------------------------------
// Scenarios that must behave identically
// ---------------------------------------------------------------------------

fn sol_single_limits(run: &mut Run) -> Vec<Pubkey> {
    let w = create_wallet(run, 10, 10);
    let [a, b, c, d]: [Pubkey; 4] = fund_destinations(run, &[20, 21, 22, 23])
        .try_into()
        .unwrap();
    add_role(
        run,
        &w,
        "add SolLimit role",
        30,
        vec![
            system_program(),
            ClientAction::SolLimit(SolLimit { amount: 3 * SOL }),
        ],
    );
    add_role(
        run,
        &w,
        "add SolRecurringLimit role",
        31,
        vec![
            system_program(),
            ClientAction::SolRecurringLimit(SolRecurringLimit {
                recurring_amount: SOL,
                window: WINDOW,
                last_reset: 0,
                current_amount: SOL,
            }),
        ],
    );
    add_role(
        run,
        &w,
        "add SolDestinationLimit role",
        32,
        vec![
            system_program(),
            ClientAction::SolDestinationLimit(SolDestinationLimit {
                destination: a.to_bytes(),
                amount: 2 * SOL,
            }),
        ],
    );
    add_role(
        run,
        &w,
        "add distinct destination limits role",
        33,
        vec![
            system_program(),
            ClientAction::SolRecurringDestinationLimit(SolRecurringDestinationLimit {
                destination: b.to_bytes(),
                recurring_amount: SOL,
                window: WINDOW,
                last_reset: 0,
                current_amount: SOL,
            }),
            ClientAction::SolDestinationLimit(SolDestinationLimit {
                destination: c.to_bytes(),
                amount: SOL,
            }),
        ],
    );
    add_role(
        run,
        &w,
        "add AllButManageAuthority role",
        34,
        vec![ClientAction::AllButManageAuthority(
            AllButManageAuthority {},
        )],
    );
    add_role(
        run,
        &w,
        "add SolLimit with destination role",
        35,
        vec![
            system_program(),
            ClientAction::SolLimit(SolLimit { amount: 2 * SOL }),
            ClientAction::SolDestinationLimit(SolDestinationLimit {
                destination: d.to_bytes(),
                amount: SOL,
            }),
        ],
    );
    // Spend some allowance with the previous build first.
    sol_send(run, &w, "pre: SolLimit 1", 30, 1, &[(a, SOL)]);
    run.warp(WINDOW + 1);

    run.checkpoint();
    sol_send(run, &w, "SolLimit 1", 30, 1, &[(a, SOL)]);
    sol_send(run, &w, "SolLimit over", 30, 1, &[(a, 2 * SOL)]);
    sol_send(run, &w, "SolLimit rest", 30, 1, &[(a, SOL)]);
    sol_send(run, &w, "SolLimit exhausted", 30, 1, &[(a, 1)]);
    sol_send(run, &w, "recurring 1", 31, 2, &[(b, SOL)]);
    sol_send(run, &w, "recurring empty window", 31, 2, &[(b, 1)]);
    run.warp(WINDOW + 1);
    sol_send(run, &w, "recurring next window", 31, 2, &[(b, SOL)]);
    sol_send(run, &w, "destination A", 32, 3, &[(a, SOL)]);
    sol_send(
        run,
        &w,
        "destination A two in one",
        32,
        3,
        &[(a, SOL / 2), (a, SOL / 2)],
    );
    sol_send(run, &w, "destination A exhausted", 32, 3, &[(a, 1)]);
    sol_send(run, &w, "destination uncovered", 32, 3, &[(b, 1)]);
    sol_send(run, &w, "recurring destination B", 33, 4, &[(b, SOL)]);
    sol_send(run, &w, "recurring destination B empty", 33, 4, &[(b, 1)]);
    sol_send(run, &w, "destination C", 33, 4, &[(c, SOL)]);
    sol_send(run, &w, "destination C exhausted", 33, 4, &[(c, 1)]);
    run.warp(WINDOW + 1);
    sol_send(
        run,
        &w,
        "recurring destination B next window",
        33,
        4,
        &[(b, SOL)],
    );
    sol_send(run, &w, "AllButManageAuthority", 34, 5, &[(a, 5 * SOL)]);
    sol_send(run, &w, "root All", 10, 0, &[(c, 5 * SOL)]);
    sol_send(run, &w, "general + destination", 35, 6, &[(d, SOL)]);
    sol_send(
        run,
        &w,
        "general + destination over destination",
        35,
        6,
        &[(d, 1)],
    );
    vec![w.swig, w.wallet, a, b, c, d]
}

fn token_single_limits(run: &mut Run) -> Vec<Pubkey> {
    let w = create_wallet(run, 11, 11);
    let mint = addr(40);
    let source = addr(41);
    let (da, db, dc) = (addr(42), addr(43), addr(44));
    token_fixture(
        run,
        mint,
        &[
            (source, w.wallet, 10_000),
            (da, addr(45), 0),
            (db, addr(46), 0),
            (dc, addr(47), 0),
        ],
    );
    let m = mint.to_bytes();
    add_role(
        run,
        &w,
        "add TokenLimit role",
        50,
        vec![
            token_program(),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: m,
                current_amount: 1_000,
            }),
        ],
    );
    add_role(
        run,
        &w,
        "add TokenRecurringLimit role",
        51,
        vec![
            token_program(),
            ClientAction::TokenRecurringLimit(TokenRecurringLimit {
                token_mint: m,
                window: WINDOW,
                limit: 500,
                current: 500,
                last_reset: 0,
            }),
        ],
    );
    add_role(
        run,
        &w,
        "add token destination roles",
        52,
        vec![
            token_program(),
            ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                token_mint: m,
                destination: da.to_bytes(),
                amount: 300,
            }),
            ClientAction::TokenRecurringDestinationLimit(TokenRecurringDestinationLimit {
                token_mint: m,
                destination: db.to_bytes(),
                recurring_amount: 200,
                window: WINDOW,
                last_reset: 0,
                current_amount: 200,
            }),
        ],
    );
    run.warp(WINDOW + 1);

    run.checkpoint();
    token_send(run, &w, "TokenLimit 600", 50, 1, &source, &da, 600);
    token_send(run, &w, "TokenLimit over", 50, 1, &source, &da, 401);
    token_send(run, &w, "TokenLimit rest", 50, 1, &source, &da, 400);
    token_send(run, &w, "TokenRecurringLimit 500", 51, 2, &source, &db, 500);
    token_send(run, &w, "TokenRecurringLimit empty", 51, 2, &source, &db, 1);
    run.warp(WINDOW + 1);
    token_send(
        run,
        &w,
        "TokenRecurringLimit next window",
        51,
        2,
        &source,
        &db,
        500,
    );
    token_send(run, &w, "TokenDestination A", 52, 3, &source, &da, 300);
    token_send(
        run,
        &w,
        "TokenDestination A exhausted",
        52,
        3,
        &source,
        &da,
        1,
    );
    token_send(
        run,
        &w,
        "TokenRecurringDestination B",
        52,
        3,
        &source,
        &db,
        200,
    );
    token_send(
        run,
        &w,
        "TokenRecurringDestination B empty",
        52,
        3,
        &source,
        &db,
        1,
    );
    token_send(
        run,
        &w,
        "token uncovered destination",
        52,
        3,
        &source,
        &dc,
        1,
    );
    token_send(run, &w, "root token transfer", 11, 0, &source, &dc, 1_000);
    vec![w.swig, w.wallet, source, da, db, dc]
}

fn tails_and_management(run: &mut Run) -> Vec<Pubkey> {
    let w = create_wallet(run, 12, 12);
    let claimer = addr(60);
    run.ctx.svm.airdrop(&claimer, SOL).unwrap();
    let set = set_rent_claimer_with_ed25519(&mut run.ctx, &w.swig, &w.root, 0, claimer);
    run.record("set rent claimer", set);
    add_role(
        run,
        &w,
        "add sub-account role",
        61,
        vec![ClientAction::SubAccount(SubAccount::new_for_creation())],
    );
    let subber = key(61);
    let sub = create_sub_account(&mut run.ctx, &w.swig, &subber, 1, [12; 32]);
    run.record("create v1 sub-account", sub);
    add_role(
        run,
        &w,
        "add limited role",
        62,
        vec![
            system_program(),
            ClientAction::SolLimit(SolLimit { amount: SOL }),
        ],
    );
    let empty_token = addr(63);
    let mint = addr(64);
    token_fixture(run, mint, &[(empty_token, w.wallet, 0)]);

    run.checkpoint();
    add_role(
        run,
        &w,
        "add role after upgrade",
        65,
        vec![
            system_program(),
            ClientAction::SolLimit(SolLimit { amount: 2 * SOL }),
        ],
    );
    update_role(
        run,
        &w,
        "update: add actions",
        3,
        UpdateAuthorityData::AddActions(vec![ClientAction::SolDestinationLimit(
            SolDestinationLimit {
                destination: claimer.to_bytes(),
                amount: SOL,
            },
        )]),
    );
    update_role(
        run,
        &w,
        "update: replace all",
        3,
        UpdateAuthorityData::ReplaceAll(vec![
            system_program(),
            ClientAction::SolLimit(SolLimit { amount: 5 * SOL }),
        ]),
    );
    // Roles: 0 root, 1 sub-account, 2 limited, 3 added after the upgrade.
    sol_send(run, &w, "limited role spends", 62, 2, &[(claimer, SOL)]);
    update_role(
        run,
        &w,
        "update: remove by type",
        2,
        UpdateAuthorityData::RemoveActionsByType(vec![
            swig_state::action::Permission::SolLimit as u8,
        ]),
    );
    sol_send(
        run,
        &w,
        "limited role without limit",
        62,
        2,
        &[(claimer, 1)],
    );
    let removed = remove_authority_with_ed25519_root(&mut run.ctx, &w.swig, &w.root, 3);
    run.record("remove role", removed);
    sol_send(run, &w, "root spends", 12, 0, &[(claimer, SOL)]);
    let root = w.root.insecure_clone();
    let close_token = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        w.swig,
        w.wallet,
        root.pubkey(),
        claimer,
        spl_token::ID,
        vec![empty_token],
        0,
    )
    .unwrap();
    run.send("close empty token account", vec![close_token], &[&root]);
    // Fails on both builds while the v1 sub-account is live.
    let close = CloseSwigV1Instruction::new_with_ed25519_authority(
        w.swig,
        w.wallet,
        root.pubkey(),
        claimer,
        0,
    )
    .unwrap();
    run.send("close swig with live sub-account", vec![close], &[&root]);
    vec![w.swig, w.wallet, claimer, empty_token]
}

fn secp256k1_role(run: &mut Run) -> Vec<Pubkey> {
    let signer = PrivateKeySigner::from_bytes(&B256::from([7u8; 32])).unwrap();
    let id = [13u8; 32];
    let created = create_swig_secp256k1(&mut run.ctx, &signer, id);
    let swig = created.as_ref().map(|(s, _)| *s).unwrap();
    run.record("create secp256k1 swig", created);
    let wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;
    run.ctx.svm.airdrop(&wallet, 10 * SOL).unwrap();
    let dest = fund_destinations(run, &[70])[0];
    let sign = |payload: &[u8]| -> [u8; 65] {
        signer
            .sign_hash_sync(&B256::from_slice(&payload[..32]))
            .unwrap()
            .as_bytes()
    };
    let slot = run.ctx.svm.get_sysvar::<Clock>().slot;
    let pre = SignV2Instruction::new_secp256k1(
        swig,
        wallet,
        sign,
        slot,
        1,
        solana_system_interface::instruction::transfer(&wallet, &dest, SOL),
        0,
    )
    .unwrap();
    run.send("pre: secp sign", vec![pre], &[]);

    run.checkpoint();
    let slot = run.ctx.svm.get_sysvar::<Clock>().slot;
    for (counter, label) in [
        (2, "secp sign"),
        (2, "secp replayed counter"),
        (3, "secp next counter"),
    ] {
        let ix = SignV2Instruction::new_secp256k1(
            swig,
            wallet,
            sign,
            slot,
            counter,
            solana_system_interface::instruction::transfer(&wallet, &dest, SOL / 10),
            0,
        )
        .unwrap();
        run.send(label, vec![ix], &[]);
    }
    vec![swig, wallet, dest]
}

#[test]
fn compat_sol_single_limits() {
    assert_compatible("sol_single_limits", sol_single_limits, &[]);
}

#[test]
fn compat_token_single_limits() {
    assert_compatible("token_single_limits", token_single_limits, &[]);
}

#[test]
fn compat_tails_and_management() {
    assert_compatible("tails_and_management", tails_and_management, &[]);
}

#[test]
fn compat_secp256k1_role() {
    assert_compatible("secp256k1_role", secp256k1_role, &[]);
}

// ---------------------------------------------------------------------------
// Scenarios with intentional changes
// ---------------------------------------------------------------------------

fn paired_limits(run: &mut Run) -> Vec<Pubkey> {
    let w = create_wallet(run, 14, 14);
    let a = fund_destinations(run, &[80])[0];
    add_role(
        run,
        &w,
        "add general pair role",
        81,
        vec![
            system_program(),
            ClientAction::SolLimit(SolLimit { amount: 3 * SOL }),
            ClientAction::SolRecurringLimit(SolRecurringLimit {
                recurring_amount: SOL,
                window: WINDOW,
                last_reset: 0,
                current_amount: SOL,
            }),
        ],
    );
    add_role(
        run,
        &w,
        "add destination pair role",
        82,
        vec![
            system_program(),
            ClientAction::SolDestinationLimit(SolDestinationLimit {
                destination: a.to_bytes(),
                amount: 2 * SOL,
            }),
            ClientAction::SolRecurringDestinationLimit(SolRecurringDestinationLimit {
                destination: a.to_bytes(),
                recurring_amount: SOL,
                window: WINDOW,
                last_reset: 0,
                current_amount: SOL,
            }),
        ],
    );
    run.warp(WINDOW + 1);

    run.checkpoint();
    sol_send(
        run,
        &w,
        "general pair: above window",
        81,
        1,
        &[(a, 2 * SOL)],
    );
    sol_send(
        run,
        &w,
        "general pair: within window",
        81,
        1,
        &[(a, SOL / 2)],
    );
    for window in 1..=3 {
        sol_send(
            run,
            &w,
            &format!("destination pair: window {window}"),
            82,
            2,
            &[(a, SOL)],
        );
        run.warp(WINDOW + 1);
    }
    vec![w.swig, w.wallet, a]
}

#[test]
fn compat_paired_limits_charge_both() {
    // Previously a general one-shot limit ignored its recurring twin, and a
    // destination's recurring limit ignored its one-shot twin. Both are now
    // charged, so the window caps the general pair and the 2 SOL lifetime
    // caps the destination pair.
    assert_compatible(
        "paired_limits",
        paired_limits,
        &["general pair: above window", "destination pair: window 3"],
    );
}

fn duplicate_limits(run: &mut Run) -> Vec<Pubkey> {
    let w = create_wallet(run, 15, 15);
    let a = fund_destinations(run, &[90])[0];
    let dup_destination = || {
        vec![
            system_program(),
            ClientAction::SolDestinationLimit(SolDestinationLimit {
                destination: a.to_bytes(),
                amount: SOL,
            }),
            ClientAction::SolDestinationLimit(SolDestinationLimit {
                destination: a.to_bytes(),
                amount: 5 * SOL,
            }),
        ]
    };
    let mint = addr(91).to_bytes();
    let dup_token = || {
        vec![
            token_program(),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint,
                current_amount: 10,
            }),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint,
                current_amount: 20,
            }),
        ]
    };
    add_role(
        run,
        &w,
        "pre: add duplicate destination role",
        92,
        dup_destination(),
    );
    add_role(run, &w, "pre: add duplicate token role", 93, dup_token());

    run.checkpoint();
    // Existing roles with duplicates keep signing as before (first match).
    sol_send(run, &w, "existing duplicate role signs", 92, 1, &[(a, SOL)]);
    sol_send(
        run,
        &w,
        "existing duplicate role first match exhausted",
        92,
        1,
        &[(a, 1)],
    );
    // New duplicates are rejected.
    add_role(
        run,
        &w,
        "add duplicate destination role",
        94,
        dup_destination(),
    );
    add_role(run, &w, "add duplicate token role", 95, dup_token());
    update_role(
        run,
        &w,
        "update: append unrelated action to existing duplicate role",
        1,
        UpdateAuthorityData::AddActions(vec![ClientAction::SolLimit(SolLimit { amount: SOL })]),
    );
    update_role(
        run,
        &w,
        "update: remove action from existing duplicate role",
        2,
        UpdateAuthorityData::RemoveActionsByType(vec![
            swig_state::action::Permission::Program as u8,
        ]),
    );
    sol_send(
        run,
        &w,
        "existing duplicate role after unrelated update",
        92,
        1,
        &[(a, 1)],
    );
    update_role(
        run,
        &w,
        "update: append duplicate",
        1,
        UpdateAuthorityData::AddActions(vec![ClientAction::SolDestinationLimit(
            SolDestinationLimit {
                destination: a.to_bytes(),
                amount: SOL,
            },
        )]),
    );
    vec![w.swig, w.wallet, a]
}

#[test]
fn compat_duplicate_limits_rejected_for_new_actions_only() {
    assert_compatible(
        "duplicate_limits",
        duplicate_limits,
        &[
            "add duplicate destination role",
            "add duplicate token role",
            "update: append duplicate",
        ],
    );
}
