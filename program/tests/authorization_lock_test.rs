#![cfg(not(feature = "program_scope_test"))]
//! Authorization lock lifecycle and enforcement.

mod common;

use common::*;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use litesvm_token::spl_token;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_sdk::{
    instruction::{Instruction, InstructionError},
    message::{v0, VersionedMessage},
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    rent::Rent,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use solana_system_interface::instruction as system_instruction;
use swig_interface::{
    swig::error::SwigError, AddAuthorizationLockV1Instruction, AuthorityConfig, ClientAction,
    CloseSwigV1Instruction, CloseTokenAccountV1Instruction, CreateSessionInstruction,
    RemoveAuthorizationLockV1Instruction, ReplaceAuthorityInstruction, SignV2Instruction,
};
use swig_state::{
    action::{
        all::All, manage_authorization_locks::ManageAuthorizationLocks, program::Program,
        sol_destination_limit::SolDestinationLimit, sol_limit::SolLimit,
        sol_recurring_destination_limit::SolRecurringDestinationLimit,
        sol_recurring_limit::SolRecurringLimit, token_destination_limit::TokenDestinationLimit,
        token_limit::TokenLimit, token_recurring_destination_limit::TokenRecurringDestinationLimit,
        token_recurring_limit::TokenRecurringLimit,
    },
    authority::{
        programexec::{session::CreateProgramExecSessionAuthority, ProgramExecAuthority},
        AuthorityType,
    },
    swig::{swig_account_seeds, swig_wallet_address_seeds, Swig},
    tail::{
        authorization_locks::{self, AuthorizationLock, LOCK_LEN, MAX_AUTHORIZATION_LOCKS},
        rent_claimer,
    },
    IntoBytes, SwigAuthenticateError, SwigStateError,
};

const ROOT_ROLE: u32 = 0;
const CARD_ROLE: u32 = 1;
const NATIVE: [u8; 32] = authorization_locks::NATIVE_SOL_MINT;
const MAX_DURATION: u64 = 1_000;
const ROOT_MAX_DURATION: u64 = 1_000_000;

struct Wallet {
    context: SwigTestContext,
    swig: Pubkey,
    wallet: Pubkey,
    root: Keypair,
    card: Keypair,
}

impl Wallet {
    /// Root role 0 holds `All` and may lock for up to `ROOT_MAX_DURATION`.
    /// Role 1 is a card issuer that may lock SOL and spend up to
    /// `card_sol_limit`.
    fn new(card_sol_limit: u64) -> Self {
        Self::with_card_actions(vec![
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
            ClientAction::SolLimit(SolLimit {
                amount: card_sol_limit,
            }),
            ClientAction::Program(Program {
                program_id: solana_system_interface::program::ID.to_bytes(),
            }),
        ])
    }

    fn with_card_actions(card_actions: Vec<ClientAction>) -> Self {
        let mut context = setup_test_context().unwrap();
        let root = Keypair::new();
        let card = Keypair::new();
        context
            .svm
            .airdrop(&root.pubkey(), LAMPORTS_PER_SOL)
            .unwrap();
        context
            .svm
            .airdrop(&card.pubkey(), LAMPORTS_PER_SOL)
            .unwrap();
        let id = rand::random::<[u8; 32]>();
        let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
        let wallet =
            Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id())
                .0;
        create_swig_ed25519(&mut context, &root, id).unwrap();
        // The root may grant itself a lock bound; no other role can manage it.
        update_authority_replace_with_ed25519_root(
            &mut context,
            &swig,
            &root,
            ROOT_ROLE,
            vec![
                ClientAction::All(All {}),
                ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(
                    ROOT_MAX_DURATION,
                )),
            ],
        )
        .unwrap();
        add_authority_with_ed25519_root(
            &mut context,
            &swig,
            &root,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: card.pubkey().as_ref(),
            },
            card_actions,
        )
        .unwrap();
        context.svm.airdrop(&wallet, 10 * LAMPORTS_PER_SOL).unwrap();
        context.svm.warp_to_slot(100);
        Self {
            context,
            swig,
            wallet,
            root,
            card,
        }
    }

    fn slot(&self) -> u64 {
        self.context
            .svm
            .get_sysvar::<solana_sdk::clock::Clock>()
            .slot
    }

    fn warp(&mut self, slot: u64) {
        self.context.svm.warp_to_slot(slot);
        self.context.svm.expire_blockhash();
    }

    fn send(
        &mut self,
        instructions: &[Instruction],
        signers: &[&Keypair],
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        self.context.svm.expire_blockhash();
        let mut ixs = vec![ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)];
        ixs.extend_from_slice(instructions);
        let message = v0::Message::try_compile(
            &self.context.default_payer.pubkey(),
            &ixs,
            &[],
            self.context.svm.latest_blockhash(),
        )
        .unwrap();
        let mut all_signers = vec![&self.context.default_payer];
        all_signers.extend_from_slice(signers);
        let tx =
            VersionedTransaction::try_new(VersionedMessage::V0(message), &all_signers).unwrap();
        self.context.svm.send_transaction(tx)
    }

    fn add_lock_ix(
        &self,
        signer: &Keypair,
        role_id: u32,
        asset: Pubkey,
        mint: [u8; 32],
        amount: u64,
        expiry_slot: u64,
    ) -> Instruction {
        AddAuthorizationLockV1Instruction::new_with_ed25519_authority(
            self.swig,
            self.context.default_payer.pubkey(),
            signer.pubkey(),
            self.wallet,
            asset,
            role_id,
            mint,
            amount,
            expiry_slot,
        )
        .unwrap()
    }

    fn add_lock(
        &mut self,
        signer: &Keypair,
        role_id: u32,
        asset: Pubkey,
        mint: [u8; 32],
        amount: u64,
        expiry_slot: u64,
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        let ix = self.add_lock_ix(signer, role_id, asset, mint, amount, expiry_slot);
        self.send(&[ix], &[signer])
    }

    fn add_sol_lock(
        &mut self,
        signer: &Keypair,
        role_id: u32,
        amount: u64,
        expiry_slot: u64,
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        let wallet = self.wallet;
        self.add_lock(signer, role_id, wallet, NATIVE, amount, expiry_slot)
    }

    fn remove_lock_ix(&self, signer: &Keypair, role_id: u32, lock_id: u32) -> Instruction {
        RemoveAuthorizationLockV1Instruction::new_with_ed25519_authority(
            self.swig,
            self.context.default_payer.pubkey(),
            signer.pubkey(),
            self.wallet,
            role_id,
            lock_id,
            self.rent_claimer(),
        )
        .unwrap()
    }

    fn remove_lock(
        &mut self,
        signer: &Keypair,
        role_id: u32,
        lock_id: u32,
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        let ix = self.remove_lock_ix(signer, role_id, lock_id);
        self.send(&[ix], &[signer])
    }

    fn sign_ix(&self, signer: &Keypair, role_id: u32, inner: Instruction) -> Instruction {
        SignV2Instruction::new_ed25519(self.swig, self.wallet, signer.pubkey(), inner, role_id)
            .unwrap()
    }

    fn sol_transfer_ix(&self, signer: &Keypair, role_id: u32, lamports: u64) -> Instruction {
        let inner = system_instruction::transfer(&self.wallet, &Keypair::new().pubkey(), lamports);
        self.sign_ix(signer, role_id, inner)
    }

    fn spend_sol(
        &mut self,
        signer: &Keypair,
        role_id: u32,
        lamports: u64,
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        let ix = self.sol_transfer_ix(signer, role_id, lamports);
        self.send(&[ix], &[signer])
    }

    fn lockable_sol(&self) -> u64 {
        self.context.svm.get_balance(&self.wallet).unwrap() - Rent::default().minimum_balance(0)
    }

    fn data(&self) -> Vec<u8> {
        self.context.svm.get_account(&self.swig).unwrap().data
    }

    fn locks(&self) -> (u32, Vec<AuthorizationLock>) {
        let data = self.data();
        let parts = Swig::split_parts(&data).unwrap();
        match authorization_locks::read_strict(parts.tail).unwrap() {
            Some(entry) => (entry.next_lock_id(), entry.iter().collect()),
            None => (0, Vec::new()),
        }
    }

    fn rent_claimer(&self) -> Option<Pubkey> {
        let data = self.data();
        let parts = Swig::split_parts(&data).unwrap();
        rent_claimer::read_strict(parts.tail)
            .unwrap()
            .map(|key| Pubkey::new_from_array(*key))
    }

    fn token_setup(&mut self, amount: u64) -> (Pubkey, Pubkey) {
        let payer = self.context.default_payer.insecure_clone();
        let mint = setup_mint(&mut self.context.svm, &payer).unwrap();
        let ata = setup_ata(&mut self.context.svm, &mint, &self.wallet, &payer).unwrap();
        mint_to(&mut self.context.svm, &mint, &payer, &ata, amount).unwrap();
        (mint, ata)
    }

    fn token_transfer_ix(
        &mut self,
        signer: &Keypair,
        role_id: u32,
        mint: &Pubkey,
        source: &Pubkey,
        amount: u64,
    ) -> Instruction {
        let payer = self.context.default_payer.insecure_clone();
        let owner = Keypair::new().pubkey();
        let destination = setup_ata(&mut self.context.svm, mint, &owner, &payer).unwrap();
        let inner = spl_token::instruction::transfer(
            &spl_token::ID,
            source,
            &destination,
            &self.wallet,
            &[],
            amount,
        )
        .unwrap();
        self.sign_ix(signer, role_id, inner)
    }

    fn token_balance(&self, account: &Pubkey) -> u64 {
        let data = self.context.svm.get_account(account).unwrap().data;
        u64::from_le_bytes(data[64..72].try_into().unwrap())
    }

    /// Adds an Ed25519 role with `actions` and returns its key and role id.
    fn add_role(&mut self, actions: Vec<ClientAction>) -> (Keypair, u32) {
        let signer = Keypair::new();
        self.context
            .svm
            .airdrop(&signer.pubkey(), LAMPORTS_PER_SOL)
            .unwrap();
        let root = self.root.insecure_clone();
        add_authority_with_ed25519_root(
            &mut self.context,
            &self.swig,
            &root,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: signer.pubkey().as_ref(),
            },
            actions,
        )
        .unwrap();
        let data = self.data();
        let role_id = swig_state::swig::SwigWithRoles::from_bytes(&data)
            .unwrap()
            .lookup_role_id(signer.pubkey().as_ref())
            .unwrap()
            .unwrap();
        (signer, role_id)
    }

    /// Adds a second unrestricted role that may lock, so tests can separate
    /// the lock holder from the spender.
    fn add_issuer(&mut self) -> (Keypair, u32) {
        self.add_role(vec![
            ClientAction::All(All {}),
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(
                ROOT_MAX_DURATION,
            )),
        ])
    }

    /// A limited role that may lock and spend up to `limit` of `mint`.
    fn add_token_card(&mut self, mint: &Pubkey, limit: u64) -> (Keypair, u32) {
        self.add_role(vec![
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint.to_bytes(),
                current_amount: limit,
            }),
            ClientAction::Program(Program {
                program_id: spl_token::ID.to_bytes(),
            }),
        ])
    }

    fn lock(&self, lock_id: u32) -> AuthorizationLock {
        self.locks()
            .1
            .into_iter()
            .find(|lock| lock.lock_id == lock_id)
            .unwrap()
    }
}

fn custom_error(result: Result<TransactionMetadata, FailedTransactionMetadata>) -> u32 {
    match result {
        Ok(_) => panic!("transaction unexpectedly succeeded"),
        Err(failed) => match failed.err {
            TransactionError::InstructionError(_, InstructionError::Custom(code)) => code,
            other => panic!("unexpected error {other:?}\n{}", failed.meta.pretty_logs()),
        },
    }
}

fn assert_swig_error(
    result: Result<TransactionMetadata, FailedTransactionMetadata>,
    expected: SwigError,
) {
    assert_eq!(custom_error(result), expected as u32);
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

// ---------------------------------------------------------------------------
// SignV2 enforcement
// ---------------------------------------------------------------------------

#[test]
fn sol_lock_binds_all_role_to_the_reserved_floor() {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 500;
    ok(w.add_sol_lock(&card, CARD_ROLE, 3 * LAMPORTS_PER_SOL, expiry));

    let spendable = w.lockable_sol() - 3 * LAMPORTS_PER_SOL;
    assert_swig_error(
        w.spend_sol(&root, ROOT_ROLE, spendable + 1),
        SwigError::AuthorizationLockViolated,
    );
    ok(w.spend_sol(&root, ROOT_ROLE, spendable));
    assert_eq!(w.lockable_sol(), 3 * LAMPORTS_PER_SOL);
    assert_swig_error(
        w.spend_sol(&root, ROOT_ROLE, 1),
        SwigError::AuthorizationLockViolated,
    );
}

#[test]
fn holder_spends_within_its_lock_and_the_lock_is_captured() {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 500;
    ok(w.add_sol_lock(&card, CARD_ROLE, 3 * LAMPORTS_PER_SOL, expiry));
    // The owner drains everything else.
    let spendable = w.lockable_sol() - 3 * LAMPORTS_PER_SOL;
    ok(w.spend_sol(&root, ROOT_ROLE, spendable));

    // No release needed: the holder spends its reserved funds directly.
    ok(w.spend_sol(&card, CARD_ROLE, LAMPORTS_PER_SOL));
    assert_eq!(w.lockable_sol(), 2 * LAMPORTS_PER_SOL);
    assert_eq!(w.lock(0).amount, 2 * LAMPORTS_PER_SOL);
    // What is still reserved stays out of other roles' reach.
    assert_swig_error(
        w.spend_sol(&root, ROOT_ROLE, 1),
        SwigError::AuthorizationLockViolated,
    );

    // Capturing the rest leaves a zero-amount lock that no longer binds and
    // that an admin role may prune.
    ok(w.spend_sol(&card, CARD_ROLE, 2 * LAMPORTS_PER_SOL));
    let lock = w.lock(0);
    assert_eq!(lock.amount, 0);
    assert!(!lock.is_active(w.slot()));
    let deposit = system_instruction::transfer(
        &w.context.default_payer.pubkey(),
        &w.wallet,
        LAMPORTS_PER_SOL,
    );
    ok(w.send(&[deposit], &[]));
    ok(w.spend_sol(&root, ROOT_ROLE, LAMPORTS_PER_SOL));
    ok(w.remove_lock(&root, ROOT_ROLE, 0));
    assert!(w.locks().1.is_empty());
}

#[test]
fn holder_may_spend_beyond_its_lock_from_free_balance() {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 500;
    ok(w.add_sol_lock(&card, CARD_ROLE, 2 * LAMPORTS_PER_SOL, expiry));
    let before = w.lockable_sol();
    ok(w.spend_sol(&card, CARD_ROLE, 3 * LAMPORTS_PER_SOL));
    assert_eq!(w.lockable_sol(), before - 3 * LAMPORTS_PER_SOL);
    assert_eq!(w.lock(0).amount, 0);
    // 5 SOL limit, 3 SOL spent: the limit, not the lock, bounds what is left.
    assert!(w
        .spend_sol(&card, CARD_ROLE, 2 * LAMPORTS_PER_SOL + 1)
        .is_err());
    ok(w.spend_sol(&card, CARD_ROLE, 2 * LAMPORTS_PER_SOL));
}

#[test]
fn capture_releases_and_spends_atomically() {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 500;
    ok(w.add_sol_lock(&card, CARD_ROLE, 2 * LAMPORTS_PER_SOL, expiry));
    // The owner drains everything else.
    let spendable = w.lockable_sol() - 2 * LAMPORTS_PER_SOL;
    ok(w.spend_sol(&root, ROOT_ROLE, spendable));

    // Capture: release and spend the reserved funds in one transaction.
    let release = w.remove_lock_ix(&card, CARD_ROLE, 0);
    let spend = w.sol_transfer_ix(&card, CARD_ROLE, 2 * LAMPORTS_PER_SOL);
    ok(w.send(&[release, spend], &[&card]));
    assert_eq!(w.lockable_sol(), 0);
    assert!(w.locks().1.is_empty());
}

#[test]
fn capture_consumes_the_holders_oldest_lock_first() {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 500;
    ok(w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, expiry));
    ok(w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, expiry));
    ok(w.spend_sol(&card, CARD_ROLE, 3 * LAMPORTS_PER_SOL / 2));
    assert_eq!(w.lock(0).amount, 0);
    assert_eq!(w.lock(1).amount, LAMPORTS_PER_SOL / 2);
    // Releasing the remainder voids the rest of the hold.
    ok(w.remove_lock(&card, CARD_ROLE, 1));
    assert_eq!(w.locks().1.len(), 1);
}

#[test]
fn locks_from_several_roles_are_summed_for_everyone_else() {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let (issuer, issuer_role) = w.add_issuer();
    let expiry = w.slot() + 500;
    ok(w.add_sol_lock(&card, CARD_ROLE, 2 * LAMPORTS_PER_SOL, expiry));
    ok(w.add_sol_lock(&issuer, issuer_role, 3 * LAMPORTS_PER_SOL, expiry));
    let spendable = w.lockable_sol() - 5 * LAMPORTS_PER_SOL;
    assert_swig_error(
        w.spend_sol(&root, ROOT_ROLE, spendable + 1),
        SwigError::AuthorizationLockViolated,
    );
    ok(w.spend_sol(&root, ROOT_ROLE, spendable));
    // Neither lock was captured by a role that does not hold it.
    assert_eq!(w.lock(0).amount, 2 * LAMPORTS_PER_SOL);
    assert_eq!(w.lock(1).amount, 3 * LAMPORTS_PER_SOL);
}

#[test]
fn expired_locks_stop_binding_at_the_expiry_slot() {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 50;
    let lockable = w.lockable_sol();
    ok(w.add_lock(
        &card,
        CARD_ROLE,
        w.wallet,
        NATIVE,
        4 * LAMPORTS_PER_SOL,
        expiry,
    ));
    let rest = lockable - 4 * LAMPORTS_PER_SOL;
    ok(w.spend_sol(&root, ROOT_ROLE, rest));

    w.warp(expiry - 1);
    assert_swig_error(
        w.spend_sol(&root, ROOT_ROLE, 1),
        SwigError::AuthorizationLockViolated,
    );
    w.warp(expiry);
    ok(w.spend_sol(&root, ROOT_ROLE, 4 * LAMPORTS_PER_SOL));
    // Expired locks remain stored until pruned.
    assert_eq!(w.locks().1.len(), 1);
}

#[test]
fn deposits_are_never_blocked_by_locks() {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let (issuer, issuer_role) = w.add_issuer();
    let expiry = w.slot() + 500;
    let lockable = w.lockable_sol();
    ok(w.add_sol_lock(&issuer, issuer_role, lockable, expiry));

    // New deposits are unreserved and can be spent in the same transaction.
    let payer = w.context.default_payer.pubkey();
    let deposit = system_instruction::transfer(&payer, &w.wallet, LAMPORTS_PER_SOL);
    let spend = w.sol_transfer_ix(&root, ROOT_ROLE, LAMPORTS_PER_SOL);
    ok(w.send(&[deposit, spend], &[&root]));
    assert_eq!(w.lockable_sol(), lockable);
    assert_swig_error(
        w.spend_sol(&root, ROOT_ROLE, 1),
        SwigError::AuthorizationLockViolated,
    );

    // A holder's SignV2 with a net inflow to a locked account neither
    // captures nor raises its lock.
    let (mint, ata) = w.token_setup(1_000);
    let payer_kp = w.context.default_payer.insecure_clone();
    let wallet = w.wallet;
    let second = litesvm_token::CreateAccount::new(&mut w.context.svm, &payer_kp, &mint)
        .owner(&wallet)
        .account_kp(Keypair::new())
        .send()
        .unwrap();
    mint_to(&mut w.context.svm, &mint, &payer_kp, &second, 500).unwrap();
    ok(w.add_lock(&issuer, issuer_role, ata, mint.to_bytes(), 400, expiry));
    let inflow =
        spl_token::instruction::transfer(&spl_token::ID, &second, &ata, &w.wallet, &[], 500)
            .unwrap();
    let ix = w.sign_ix(&issuer, issuer_role, inflow);
    ok(w.send(&[ix], &[&issuer]));
    assert_eq!(w.token_balance(&ata), 1_500);
    assert_eq!(w.lock(1).amount, 400);
    // Each SignV2 is measured on its own: a deposit in an earlier instruction
    // is free balance, and the holder's later spend is a net outflow.
    let deposit = system_instruction::transfer(&payer, &w.wallet, LAMPORTS_PER_SOL);
    let spend = w.sol_transfer_ix(&issuer, issuer_role, LAMPORTS_PER_SOL / 2);
    ok(w.send(&[deposit, spend], &[&issuer]));
    assert_eq!(w.lock(0).amount, lockable - LAMPORTS_PER_SOL / 2);
}

#[test]
fn underfunded_locked_account_may_not_shrink_further() {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let (issuer, issuer_role) = w.add_issuer();
    let (mint, ata) = w.token_setup(1_000);
    let expiry = w.slot() + 500;
    ok(w.add_lock(&issuer, issuer_role, ata, mint.to_bytes(), 800, expiry));

    // Simulate an external debit (e.g. a permanent delegate) below the lock.
    let mut account = w.context.svm.get_account(&ata).unwrap();
    account.data[64..72].copy_from_slice(&500u64.to_le_bytes());
    w.context.svm.set_account(ata, account).unwrap();

    let ix = w.token_transfer_ix(&root, ROOT_ROLE, &mint, &ata, 1);
    assert_swig_error(
        w.send(&[ix], &[&root]),
        SwigError::AuthorizationLockViolated,
    );
}

#[test]
fn token_lock_binds_all_role_and_only_the_locked_account() {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let (issuer, issuer_role) = w.add_issuer();
    let (mint, ata) = w.token_setup(1_000);
    let payer = w.context.default_payer.insecure_clone();
    let other = Keypair::new();
    let wallet = w.wallet;
    let second = litesvm_token::CreateAccount::new(&mut w.context.svm, &payer, &mint)
        .owner(&wallet)
        .account_kp(other)
        .send()
        .unwrap();
    mint_to(&mut w.context.svm, &mint, &payer, &second, 1_000).unwrap();

    let expiry = w.slot() + 500;
    ok(w.add_lock(&issuer, issuer_role, ata, mint.to_bytes(), 600, expiry));

    let ix = w.token_transfer_ix(&root, ROOT_ROLE, &mint, &ata, 401);
    assert_swig_error(
        w.send(&[ix], &[&root]),
        SwigError::AuthorizationLockViolated,
    );
    let ix = w.token_transfer_ix(&root, ROOT_ROLE, &mint, &ata, 400);
    ok(w.send(&[ix], &[&root]));
    assert_eq!(w.token_balance(&ata), 600);

    // A second account of the same mint is unaffected.
    let ix = w.token_transfer_ix(&root, ROOT_ROLE, &mint, &second, 1_000);
    ok(w.send(&[ix], &[&root]));

    // The unrestricted holder spends its own hold and captures it.
    let ix = w.token_transfer_ix(&issuer, issuer_role, &mint, &ata, 250);
    ok(w.send(&[ix], &[&issuer]));
    assert_eq!(w.lock(0).amount, 350);
}

#[test]
fn locked_token_account_cannot_change_authority_delegate_or_close_authority() {
    // Identity checks bind the lock holder too.
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let (mint, ata) = w.token_setup(1_000);
    let expiry = w.slot() + 500;
    ok(w.add_lock(&root, ROOT_ROLE, ata, mint.to_bytes(), 100, expiry));
    let attacker = Keypair::new().pubkey();

    let set_owner = spl_token::instruction::set_authority(
        &spl_token::ID,
        &ata,
        Some(&attacker),
        spl_token::instruction::AuthorityType::AccountOwner,
        &w.wallet,
        &[],
    )
    .unwrap();
    let approve =
        spl_token::instruction::approve(&spl_token::ID, &ata, &attacker, &w.wallet, &[], 100)
            .unwrap();
    let set_close = spl_token::instruction::set_authority(
        &spl_token::ID,
        &ata,
        Some(&attacker),
        spl_token::instruction::AuthorityType::CloseAccount,
        &w.wallet,
        &[],
    )
    .unwrap();
    for inner in [set_owner, approve, set_close] {
        let ix = w.sign_ix(&root, ROOT_ROLE, inner);
        assert_swig_error(
            w.send(&[ix], &[&root]),
            SwigError::AuthorizationLockViolated,
        );
    }
}

#[test]
fn read_only_locked_accounts_are_not_checked() {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let (mint, ata) = w.token_setup(1_000);
    let expiry = w.slot() + 500;
    ok(w.add_lock(&root, ROOT_ROLE, ata, mint.to_bytes(), 1_000, expiry));
    // SOL movements are independent of the token reservation.
    ok(w.spend_sol(&root, ROOT_ROLE, LAMPORTS_PER_SOL));
}

#[test]
fn limited_role_cannot_spend_locked_tokens() {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let (mint, ata) = w.token_setup(1_000);
    let (spender, spender_role) = w.add_role(vec![
        ClientAction::TokenLimit(TokenLimit {
            token_mint: mint.to_bytes(),
            current_amount: 1_000,
        }),
        ClientAction::Program(Program {
            program_id: spl_token::ID.to_bytes(),
        }),
    ]);
    let expiry = w.slot() + 500;
    ok(w.add_lock(&root, ROOT_ROLE, ata, mint.to_bytes(), 900, expiry));
    let ix = w.token_transfer_ix(&spender, spender_role, &mint, &ata, 101);
    assert_swig_error(
        w.send(&[ix], &[&spender]),
        SwigError::AuthorizationLockViolated,
    );
    let ix = w.token_transfer_ix(&spender, spender_role, &mint, &ata, 100);
    ok(w.send(&[ix], &[&spender]));
    assert_eq!(w.lock(0).amount, 900);
}

#[test]
fn holder_cannot_dig_into_another_holders_lock() {
    // Bob holds 50 and Carol 30 of a 100-token account. Bob may end at >= 30,
    // Carol at >= 50, and everyone else at >= 80.
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let (mint, ata) = w.token_setup(100);
    let (bob, bob_role) = w.add_token_card(&mint, 1_000);
    let (carol, carol_role) = w.add_token_card(&mint, 1_000);
    let expiry = w.slot() + 500;
    ok(w.add_lock(&bob, bob_role, ata, mint.to_bytes(), 50, expiry));
    ok(w.add_lock(&carol, carol_role, ata, mint.to_bytes(), 30, expiry));

    let ix = w.token_transfer_ix(&bob, bob_role, &mint, &ata, 71);
    assert_swig_error(w.send(&[ix], &[&bob]), SwigError::AuthorizationLockViolated);
    let ix = w.token_transfer_ix(&carol, carol_role, &mint, &ata, 51);
    assert_swig_error(
        w.send(&[ix], &[&carol]),
        SwigError::AuthorizationLockViolated,
    );
    let ix = w.token_transfer_ix(&root, ROOT_ROLE, &mint, &ata, 21);
    assert_swig_error(
        w.send(&[ix], &[&root]),
        SwigError::AuthorizationLockViolated,
    );

    let ix = w.token_transfer_ix(&root, ROOT_ROLE, &mint, &ata, 20);
    ok(w.send(&[ix], &[&root]));
    assert_eq!((w.lock(0).amount, w.lock(1).amount), (50, 30));

    // Bob spends his whole hold; Carol's is untouched.
    let ix = w.token_transfer_ix(&bob, bob_role, &mint, &ata, 51);
    assert_swig_error(w.send(&[ix], &[&bob]), SwigError::AuthorizationLockViolated);
    let ix = w.token_transfer_ix(&bob, bob_role, &mint, &ata, 50);
    ok(w.send(&[ix], &[&bob]));
    assert_eq!((w.lock(0).amount, w.lock(1).amount), (0, 30));
    assert_eq!(w.token_balance(&ata), 30);

    // Only Carol may now spend the remaining 30.
    let ix = w.token_transfer_ix(&root, ROOT_ROLE, &mint, &ata, 1);
    assert_swig_error(
        w.send(&[ix], &[&root]),
        SwigError::AuthorizationLockViolated,
    );
    let ix = w.token_transfer_ix(&bob, bob_role, &mint, &ata, 1);
    assert_swig_error(w.send(&[ix], &[&bob]), SwigError::AuthorizationLockViolated);
    let ix = w.token_transfer_ix(&carol, carol_role, &mint, &ata, 30);
    ok(w.send(&[ix], &[&carol]));
    assert_eq!((w.lock(0).amount, w.lock(1).amount), (0, 0));
}

// ---------------------------------------------------------------------------
// Creation: permissions, bounds, and asset validation
// ---------------------------------------------------------------------------

#[test]
fn role_without_lock_permission_cannot_create_locks() {
    let mut w = Wallet::with_card_actions(vec![ClientAction::SolLimit(SolLimit {
        amount: LAMPORTS_PER_SOL,
    })]);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 10;
    assert_eq!(
        custom_error(w.add_sol_lock(&card, CARD_ROLE, 1, expiry)),
        SwigAuthenticateError::PermissionDeniedMissingPermission as u32
    );
}

#[test]
fn wrong_signer_cannot_create_locks_for_a_role() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let impostor = Keypair::new();
    let expiry = w.slot() + 10;
    assert!(w.add_sol_lock(&impostor, CARD_ROLE, 1, expiry).is_err());
    assert!(w.locks().1.is_empty());
}

#[test]
fn delegated_lock_duration_is_bounded() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let now = w.slot();
    assert_swig_error(
        w.add_sol_lock(&card, CARD_ROLE, 1, now + MAX_DURATION + 1),
        SwigError::InvalidAuthorizationLockExpiry,
    );
    ok(w.add_sol_lock(&card, CARD_ROLE, 1, now + MAX_DURATION));
    // Unrestricted roles are bounded by their own duration too.
    let root = w.root.insecure_clone();
    assert_swig_error(
        w.add_sol_lock(&root, ROOT_ROLE, 1, u64::MAX),
        SwigError::InvalidAuthorizationLockExpiry,
    );
    assert_swig_error(
        w.add_sol_lock(&root, ROOT_ROLE, 1, now + ROOT_MAX_DURATION + 1),
        SwigError::InvalidAuthorizationLockExpiry,
    );
    ok(w.add_sol_lock(&root, ROOT_ROLE, 1, now + ROOT_MAX_DURATION));
}

#[test]
fn all_without_lock_permission_cannot_lock() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let swig = w.swig;
    update_authority_replace_with_ed25519_root(
        &mut w.context,
        &swig,
        &root,
        ROOT_ROLE,
        vec![ClientAction::All(All {})],
    )
    .unwrap();
    let expiry = w.slot() + 10;
    assert_eq!(
        custom_error(w.add_sol_lock(&root, ROOT_ROLE, 1, expiry)),
        SwigAuthenticateError::PermissionDeniedMissingPermission as u32
    );
}

#[test]
fn expiry_must_be_in_the_future_and_amount_nonzero() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let now = w.slot();
    assert_swig_error(
        w.add_sol_lock(&root, ROOT_ROLE, 1, now),
        SwigError::InvalidAuthorizationLockExpiry,
    );
    assert_swig_error(
        w.add_sol_lock(&root, ROOT_ROLE, 1, now - 1),
        SwigError::InvalidAuthorizationLockExpiry,
    );
    assert_swig_error(
        w.add_sol_lock(&root, ROOT_ROLE, 0, now + 1),
        SwigError::InvalidAuthorizationLockAmount,
    );
}

#[test]
fn delegated_locks_are_bounded_by_the_role_spend_limit() {
    let mut w = Wallet::new(2 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 100;
    assert_swig_error(
        w.add_sol_lock(&card, CARD_ROLE, 2 * LAMPORTS_PER_SOL + 1, expiry),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );
    ok(w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, expiry));
    // The role's other active locks count against the same limit.
    assert_swig_error(
        w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL + 1, expiry),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );
    ok(w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, expiry));
    // Expired locks free capacity.
    w.warp(expiry);
    ok(w.add_sol_lock(&card, CARD_ROLE, 2 * LAMPORTS_PER_SOL, expiry + 100));
}

#[test]
fn delegated_locks_need_a_spend_limit_for_that_asset() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let (mint, ata) = w.token_setup(1_000);
    let expiry = w.slot() + 100;
    // SolLimit grants no token capacity.
    assert_swig_error(
        w.add_lock(&card, CARD_ROLE, ata, mint.to_bytes(), 1, expiry),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );

    let mut w = Wallet::with_card_actions(vec![ClientAction::ManageAuthorizationLocks(
        ManageAuthorizationLocks::new(MAX_DURATION),
    )]);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 100;
    assert_swig_error(
        w.add_sol_lock(&card, CARD_ROLE, 1, expiry),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );
}

#[test]
fn spend_capacity_honors_recurring_and_destination_limits() {
    let mut w = Wallet::with_card_actions(vec![
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
        ClientAction::SolRecurringLimit(SolRecurringLimit {
            recurring_amount: 3 * LAMPORTS_PER_SOL,
            window: 100,
            last_reset: 0,
            current_amount: 3 * LAMPORTS_PER_SOL,
        }),
    ]);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 100;
    assert_swig_error(
        w.add_sol_lock(&card, CARD_ROLE, 3 * LAMPORTS_PER_SOL + 1, expiry),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );
    ok(w.add_sol_lock(&card, CARD_ROLE, 3 * LAMPORTS_PER_SOL, expiry));

    let merchant = Keypair::new().pubkey();
    let mut w = Wallet::with_card_actions(vec![
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
        ClientAction::SolDestinationLimit(SolDestinationLimit {
            destination: merchant.to_bytes(),
            amount: LAMPORTS_PER_SOL,
        }),
    ]);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 100;
    assert_swig_error(
        w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL + 1, expiry),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );
    ok(w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, expiry));
}

#[test]
fn spend_capacity_honors_pair_limits_as_the_smaller_twin() {
    // A regular (one-shot) 15 SOL limit and a 1 SOL per-window recurring
    // limit for the same destination: SignV2 charges both, so the window a
    // lock can reserve against is min(15, 1) = 1 SOL — not the 16 SOL the
    // pre-pair-capacity formula would have summed.
    let merchant = Keypair::new().pubkey();
    let mut w = Wallet::with_card_actions(vec![
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
        ClientAction::SolRecurringDestinationLimit(SolRecurringDestinationLimit {
            destination: merchant.to_bytes(),
            recurring_amount: LAMPORTS_PER_SOL,
            window: 100,
            last_reset: 0,
            current_amount: LAMPORTS_PER_SOL,
        }),
        ClientAction::SolDestinationLimit(SolDestinationLimit {
            destination: merchant.to_bytes(),
            amount: 15 * LAMPORTS_PER_SOL,
        }),
    ]);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 100;
    ok(w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, expiry));
    // Reserving the one-shot's full amount on top of the recurring cap
    // exceeds the pair minimum.
    assert_swig_error(
        w.add_sol_lock(&card, CARD_ROLE, 15 * LAMPORTS_PER_SOL, expiry),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );
    assert_swig_error(
        w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, expiry),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );

    // Distinct destinations keep their own pair capacities.
    let other = Keypair::new().pubkey();
    let mut w = Wallet::with_card_actions(vec![
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
        ClientAction::SolDestinationLimit(SolDestinationLimit {
            destination: merchant.to_bytes(),
            amount: LAMPORTS_PER_SOL,
        }),
        ClientAction::SolDestinationLimit(SolDestinationLimit {
            destination: other.to_bytes(),
            amount: 2 * LAMPORTS_PER_SOL,
        }),
    ]);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 100;
    ok(w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, expiry));
    ok(w.add_sol_lock(&card, CARD_ROLE, 2 * LAMPORTS_PER_SOL, expiry));
    assert_swig_error(
        w.add_sol_lock(&card, CARD_ROLE, 1, expiry),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );

    // The same holds for token destination pairs.
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let token_card = Keypair::new();
    let (mint, ata) = w.token_setup(500);
    add_authority_with_ed25519_root(
        &mut w.context,
        &w.swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: token_card.pubkey().as_ref(),
        },
        vec![
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
            ClientAction::TokenRecurringDestinationLimit(TokenRecurringDestinationLimit {
                token_mint: mint.to_bytes(),
                destination: ata.to_bytes(),
                recurring_amount: 100,
                window: 100,
                last_reset: 0,
                current_amount: 100,
            }),
            ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                token_mint: mint.to_bytes(),
                destination: ata.to_bytes(),
                amount: 10_000,
            }),
        ],
    )
    .unwrap();
    let expiry = w.slot() + 100;
    ok(w.add_lock(&token_card, 2, ata, mint.to_bytes(), 100, expiry));
    assert_swig_error(
        w.add_lock(&token_card, 2, ata, mint.to_bytes(), 10_000, expiry),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );
}

#[test]
fn spend_capacity_honors_general_pairs_as_the_smaller_twin() {
    // General (non-destination) pairs behave like destination pairs: a
    // one-shot limit and a windowed recurring limit for the same asset cap
    // a lock at min(one-shot, recurring), not at their sum. SOL first.
    let mut w = Wallet::with_card_actions(vec![
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
        ClientAction::SolLimit(SolLimit {
            amount: 15 * LAMPORTS_PER_SOL,
        }),
        ClientAction::SolRecurringLimit(SolRecurringLimit {
            recurring_amount: LAMPORTS_PER_SOL,
            window: 100,
            last_reset: 0,
            current_amount: LAMPORTS_PER_SOL,
        }),
    ]);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 100;
    ok(w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, expiry));
    assert_swig_error(
        w.add_sol_lock(&card, CARD_ROLE, 15 * LAMPORTS_PER_SOL, expiry),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );
    assert_swig_error(
        w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL + 1, expiry),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );

    // Same rule for general token pairs (per mint).
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let token_card = Keypair::new();
    let (mint, ata) = w.token_setup(500);
    add_authority_with_ed25519_root(
        &mut w.context,
        &w.swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: token_card.pubkey().as_ref(),
        },
        vec![
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint.to_bytes(),
                current_amount: 10_000,
            }),
            ClientAction::TokenRecurringLimit(TokenRecurringLimit {
                token_mint: mint.to_bytes(),
                window: 100,
                limit: 100,
                current: 100,
                last_reset: 0,
            }),
        ],
    )
    .unwrap();
    let expiry = w.slot() + 100;
    ok(w.add_lock(&token_card, 2, ata, mint.to_bytes(), 100, expiry));
    assert_swig_error(
        w.add_lock(&token_card, 2, ata, mint.to_bytes(), 10_000, expiry),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );
    assert_swig_error(
        w.add_lock(&token_card, 2, ata, mint.to_bytes(), 101, expiry),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );
}

#[test]
fn locks_cannot_exceed_the_lockable_balance() {
    let mut w = Wallet::new(100 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 100;
    let lockable = w.lockable_sol();
    // The rent-exempt reserve is never lockable.
    assert_swig_error(
        w.add_sol_lock(&card, CARD_ROLE, lockable + 1, expiry),
        SwigError::AuthorizationLockExceedsBalance,
    );
    ok(w.add_sol_lock(&card, CARD_ROLE, lockable - 10, expiry));
    // Every role's active locks on the account count.
    assert_swig_error(
        w.add_sol_lock(&root, ROOT_ROLE, 11, expiry),
        SwigError::AuthorizationLockExceedsBalance,
    );
    ok(w.add_sol_lock(&root, ROOT_ROLE, 10, expiry));

    let (mint, ata) = w.token_setup(500);
    assert_swig_error(
        w.add_lock(&root, ROOT_ROLE, ata, mint.to_bytes(), 501, expiry),
        SwigError::AuthorizationLockExceedsBalance,
    );
}

#[test]
fn sol_locks_must_target_the_wallet_address() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let rich = Keypair::new().pubkey();
    w.context
        .svm
        .airdrop(&rich, 100 * LAMPORTS_PER_SOL)
        .unwrap();
    let expiry = w.slot() + 100;
    assert_swig_error(
        w.add_lock(&root, ROOT_ROLE, rich, NATIVE, 1, expiry),
        SwigError::InvalidAuthorizationLockAsset,
    );
}

#[test]
fn wallet_address_account_must_be_the_real_pda() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let fake = Keypair::new().pubkey();
    w.context
        .svm
        .airdrop(&fake, 100 * LAMPORTS_PER_SOL)
        .unwrap();
    let expiry = w.slot() + 100;
    let ix = AddAuthorizationLockV1Instruction::new_with_ed25519_authority(
        w.swig,
        w.context.default_payer.pubkey(),
        root.pubkey(),
        fake,
        fake,
        ROOT_ROLE,
        NATIVE,
        1,
        expiry,
    )
    .unwrap();
    assert_swig_error(w.send(&[ix], &[&root]), SwigError::InvalidSeedSwigAccount);
}

#[test]
fn asset_account_must_match_the_signed_arguments() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let (mint, ata) = w.token_setup(1_000);
    let expiry = w.slot() + 100;
    let mut ix = w.add_lock_ix(&root, ROOT_ROLE, ata, mint.to_bytes(), 1, expiry);
    // Swap the asset account meta for another token account.
    let (_, other) = w.token_setup(1_000);
    ix.accounts[4].pubkey = other;
    assert_swig_error(
        w.send(&[ix], &[&root]),
        SwigError::InvalidAuthorizationLockAsset,
    );
}

#[test]
fn token_lock_asset_must_be_a_clean_wallet_token_account() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let payer = w.context.default_payer.insecure_clone();
    let (mint, ata) = w.token_setup(1_000);
    let expiry = w.slot() + 100;

    // Mint mismatch.
    let other_mint = setup_mint(&mut w.context.svm, &payer).unwrap();
    assert_swig_error(
        w.add_lock(&root, ROOT_ROLE, ata, other_mint.to_bytes(), 1, expiry),
        SwigError::InvalidAuthorizationLockAsset,
    );

    // Token account owned by someone else.
    let stranger = Keypair::new().pubkey();
    let foreign = setup_ata(&mut w.context.svm, &mint, &stranger, &payer).unwrap();
    mint_to(&mut w.context.svm, &mint, &payer, &foreign, 1_000).unwrap();
    assert_swig_error(
        w.add_lock(&root, ROOT_ROLE, foreign, mint.to_bytes(), 1, expiry),
        SwigError::InvalidAuthorizationLockAsset,
    );

    // Native mint with a token account.
    assert_swig_error(
        w.add_lock(&root, ROOT_ROLE, ata, NATIVE, 1, expiry),
        SwigError::InvalidAuthorizationLockAsset,
    );

    // A delegate could drain the account outside Swig.
    let mut account = w.context.svm.get_account(&ata).unwrap();
    account.data[72..76].copy_from_slice(&[1, 0, 0, 0]);
    account.data[76..108].copy_from_slice(stranger.as_ref());
    w.context.svm.set_account(ata, account.clone()).unwrap();
    assert_swig_error(
        w.add_lock(&root, ROOT_ROLE, ata, mint.to_bytes(), 1, expiry),
        SwigError::InvalidAuthorizationLockAsset,
    );

    // A foreign close authority.
    account.data[72..108].fill(0);
    account.data[129..133].copy_from_slice(&[1, 0, 0, 0]);
    account.data[133..165].copy_from_slice(stranger.as_ref());
    w.context.svm.set_account(ata, account.clone()).unwrap();
    assert_swig_error(
        w.add_lock(&root, ROOT_ROLE, ata, mint.to_bytes(), 1, expiry),
        SwigError::InvalidAuthorizationLockAsset,
    );

    // Frozen.
    account.data[129..165].fill(0);
    account.data[108] = 2;
    w.context.svm.set_account(ata, account.clone()).unwrap();
    assert_swig_error(
        w.add_lock(&root, ROOT_ROLE, ata, mint.to_bytes(), 1, expiry),
        SwigError::InvalidAuthorizationLockAsset,
    );

    // A wallet-controlled close authority is fine.
    account.data[108] = 1;
    account.data[129..133].copy_from_slice(&[1, 0, 0, 0]);
    account.data[133..165].copy_from_slice(w.wallet.as_ref());
    w.context.svm.set_account(ata, account).unwrap();
    ok(w.add_lock(&root, ROOT_ROLE, ata, mint.to_bytes(), 1, expiry));
}

#[test]
fn lock_count_is_capped_and_ids_are_never_reused() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 100;
    for _ in 0..MAX_AUTHORIZATION_LOCKS {
        ok(w.add_sol_lock(&root, ROOT_ROLE, 1, expiry));
    }
    assert_eq!(
        custom_error(w.add_sol_lock(&root, ROOT_ROLE, 1, expiry)),
        SwigStateError::AuthorizationLockLimitReached as u32
    );
    ok(w.remove_lock(&root, ROOT_ROLE, 5));
    ok(w.add_sol_lock(&root, ROOT_ROLE, 1, expiry));
    let (next, locks) = w.locks();
    assert_eq!(next, MAX_AUTHORIZATION_LOCKS as u32 + 1);
    assert_eq!(locks.len(), MAX_AUTHORIZATION_LOCKS);
    assert!(locks.iter().all(|lock| lock.lock_id != 5));
    assert_eq!(
        locks.last().unwrap().lock_id,
        MAX_AUTHORIZATION_LOCKS as u32
    );
}

#[test]
fn lock_records_creator_and_terms() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 77;
    ok(w.add_sol_lock(&card, CARD_ROLE, 12_345, expiry));
    let (next, locks) = w.locks();
    assert_eq!(next, 1);
    assert_eq!(
        locks,
        vec![AuthorizationLock {
            asset_account: w.wallet.to_bytes(),
            mint: NATIVE,
            amount: 12_345,
            expiry_slot: expiry,
            role_id: CARD_ROLE,
            lock_id: 0,
        }]
    );
}

#[test]
fn payer_funds_lock_rent_and_removal_refunds_it() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 100;
    let len_before = w.data().len();
    let swig_lamports_before = w.context.svm.get_balance(&w.swig).unwrap();
    ok(w.add_sol_lock(&card, CARD_ROLE, 1, expiry));
    let first_len = w.data().len();
    // The first lock materializes the entry header.
    assert_eq!(first_len, len_before + 8 + LOCK_LEN);
    ok(w.add_sol_lock(&card, CARD_ROLE, 1, expiry));
    assert_eq!(w.data().len(), first_len + LOCK_LEN);
    let rent = Rent::default();
    assert_eq!(
        w.context.svm.get_balance(&w.swig).unwrap(),
        swig_lamports_before + rent.minimum_balance(first_len + LOCK_LEN)
            - rent.minimum_balance(len_before)
    );

    let payer_before = w
        .context
        .svm
        .get_balance(&w.context.default_payer.pubkey())
        .unwrap();
    let meta = ok(w.remove_lock(&card, CARD_ROLE, 1));
    assert_eq!(w.data().len(), first_len);
    let fee = meta.fee;
    assert_eq!(
        w.context
            .svm
            .get_balance(&w.context.default_payer.pubkey())
            .unwrap(),
        payer_before - fee + rent.minimum_balance(first_len + LOCK_LEN)
            - rent.minimum_balance(first_len)
    );
}

#[test]
fn secp256k1_role_can_create_and_release_locks() {
    use alloy_signer_local::{LocalSigner, PrivateKeySigner};
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let wallet_key: PrivateKeySigner = LocalSigner::random();
    let eth_pubkey = wallet_key
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();
    add_authority_with_ed25519_root(
        &mut w.context,
        &w.swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256k1,
            authority: &eth_pubkey[1..],
        },
        vec![
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
            ClientAction::SolLimit(SolLimit {
                amount: LAMPORTS_PER_SOL,
            }),
        ],
    )
    .unwrap();
    let role_id = 2;
    let make_sign = || {
        let signer = wallet_key.clone();
        move |payload: &[u8]| -> [u8; 65] {
            use alloy_signer::SignerSync;
            let hash = alloy_primitives::B256::from_slice(&payload[..32]);
            signer.sign_hash_sync(&hash).unwrap().as_bytes()
        }
    };

    let slot = w.slot();
    let add = AddAuthorizationLockV1Instruction::new_with_secp256k1_authority(
        w.swig,
        w.context.default_payer.pubkey(),
        make_sign(),
        slot,
        1,
        w.wallet,
        w.wallet,
        role_id,
        NATIVE,
        1_000,
        slot + 100,
    )
    .unwrap();
    ok(w.send(&[add.clone()], &[]));
    assert_eq!(w.locks().1.len(), 1);
    // Replaying the same signed payload fails on the counter.
    assert!(w.send(&[add], &[]).is_err());
    assert_eq!(w.locks().1.len(), 1);

    let remove = RemoveAuthorizationLockV1Instruction::new_with_secp256k1_authority(
        w.swig,
        w.context.default_payer.pubkey(),
        make_sign(),
        slot,
        2,
        w.wallet,
        role_id,
        0,
        None,
    )
    .unwrap();
    ok(w.send(&[remove], &[]));
    assert!(w.locks().1.is_empty());
}

// ---------------------------------------------------------------------------
// Release and pruning
// ---------------------------------------------------------------------------

#[test]
fn only_the_creator_can_release_an_active_lock() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 100;
    ok(w.add_sol_lock(&card, CARD_ROLE, 1, expiry));
    assert_swig_error(
        w.remove_lock(&root, ROOT_ROLE, 0),
        SwigError::AuthorizationLockNotOwner,
    );
    // Claiming the creator's role id requires the creator's signature.
    assert!(w.remove_lock(&root, CARD_ROLE, 0).is_err());
    ok(w.remove_lock(&card, CARD_ROLE, 0));
}

#[test]
fn expired_locks_can_be_pruned_by_admin_roles_only() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let bystander = Keypair::new();
    add_authority_with_ed25519_root(
        &mut w.context,
        &w.swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: bystander.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
    )
    .unwrap();
    let expiry = w.slot() + 10;
    ok(w.add_sol_lock(&card, CARD_ROLE, 1, expiry));
    w.warp(expiry);
    assert_eq!(
        custom_error(w.remove_lock(&bystander, 2, 0)),
        SwigAuthenticateError::PermissionDeniedMissingPermission as u32
    );
    ok(w.remove_lock(&root, ROOT_ROLE, 0));
    assert!(w.locks().1.is_empty());
}

#[test]
fn removing_an_unknown_lock_fails() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    assert_swig_error(
        w.remove_lock(&root, ROOT_ROLE, 0),
        SwigError::AuthorizationLockNotFound,
    );
    let expiry = w.slot() + 10;
    ok(w.add_sol_lock(&root, ROOT_ROLE, 1, expiry));
    ok(w.remove_lock(&root, ROOT_ROLE, 0));
    assert_swig_error(
        w.remove_lock(&root, ROOT_ROLE, 0),
        SwigError::AuthorizationLockNotFound,
    );
}

#[test]
fn removal_refunds_the_configured_rent_claimer() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 10;
    ok(w.add_sol_lock(&root, ROOT_ROLE, 1, expiry));
    let claimer = Keypair::new().pubkey();
    w.context.svm.airdrop(&claimer, LAMPORTS_PER_SOL).unwrap();
    set_rent_claimer_with_ed25519(&mut w.context, &w.swig, &root, ROOT_ROLE, claimer).unwrap();
    assert_eq!(w.rent_claimer(), Some(claimer));

    // Without the claimer account the refund destination is missing.
    let mut ix = w.remove_lock_ix(&root, ROOT_ROLE, 0);
    ix.accounts.remove(4);
    ix.data.pop();
    ix.data.push(4);
    assert_swig_error(
        w.send(&[ix], &[&root]),
        SwigError::InvalidRentClaimerDestination,
    );

    let before = w.context.svm.get_balance(&claimer).unwrap();
    ok(w.remove_lock(&root, ROOT_ROLE, 0));
    assert!(w.context.svm.get_balance(&claimer).unwrap() > before);
    assert_eq!(w.rent_claimer(), Some(claimer));
}

// ---------------------------------------------------------------------------
// Protecting the creating role and the reserved funds
// ---------------------------------------------------------------------------

#[test]
fn creator_role_cannot_be_removed_while_locks_are_active() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 10;
    ok(w.add_sol_lock(&card, CARD_ROLE, 1, expiry));
    let err = remove_authority_with_ed25519_root(&mut w.context, &w.swig, &root, CARD_ROLE)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(&format!(
            "Custom({})",
            SwigError::AuthorizationLockActive as u32
        )),
        "{err}"
    );
    w.warp(expiry);
    remove_authority_with_ed25519_root(&mut w.context, &w.swig, &root, CARD_ROLE).unwrap();
}

#[test]
fn creator_role_cannot_be_rewritten_while_locks_are_active() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 10;
    ok(w.add_sol_lock(&card, CARD_ROLE, 1, expiry));
    let err = update_authority_replace_with_ed25519_root(
        &mut w.context,
        &w.swig,
        &root,
        CARD_ROLE,
        vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains(&format!(
            "Custom({})",
            SwigError::AuthorizationLockActive as u32
        )),
        "{err}"
    );
    w.warp(expiry);
    update_authority_replace_with_ed25519_root(
        &mut w.context,
        &w.swig,
        &root,
        CARD_ROLE,
        vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
    )
    .unwrap();
}

#[test]
fn creator_signer_cannot_be_replaced_by_another_role_while_locks_are_active() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 10;
    ok(w.add_sol_lock(&card, CARD_ROLE, 1, expiry));
    let takeover = Keypair::new();
    let ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        w.swig,
        root.pubkey(),
        ROOT_ROLE,
        CARD_ROLE,
        takeover.pubkey().as_ref(),
    )
    .unwrap();
    assert_swig_error(
        w.send(&[ix.clone()], &[&root]),
        SwigError::AuthorizationLockActive,
    );
    w.warp(expiry);
    ok(w.send(&[ix], &[&root]));
}

#[test]
fn swig_cannot_close_while_locks_are_active() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 10;
    ok(w.add_sol_lock(&root, ROOT_ROLE, 1, expiry));
    let destination = Keypair::new().pubkey();
    let close = CloseSwigV1Instruction::new_with_ed25519_authority(
        w.swig,
        w.wallet,
        root.pubkey(),
        destination,
        ROOT_ROLE,
    )
    .unwrap();
    assert_swig_error(
        w.send(&[close], &[&root]),
        SwigError::AuthorizationLockActive,
    );
}

#[test]
fn locked_token_account_cannot_be_closed() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let (mint, ata) = w.token_setup(1_000);
    let expiry = w.slot() + 10;
    ok(w.add_lock(&root, ROOT_ROLE, ata, mint.to_bytes(), 1, expiry));
    let destination = Keypair::new().pubkey();
    let close = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        w.swig,
        w.wallet,
        root.pubkey(),
        destination,
        spl_token::ID,
        vec![ata],
        ROOT_ROLE,
    )
    .unwrap();
    assert_swig_error(
        w.send(&[close], &[&root]),
        SwigError::AuthorizationLockActive,
    );
}

// ---------------------------------------------------------------------------
// Coexistence with other tail entries and role changes
// ---------------------------------------------------------------------------

#[test]
fn locks_survive_role_and_tail_changes() {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 500;
    ok(w.add_sol_lock(&card, CARD_ROLE, 2 * LAMPORTS_PER_SOL, expiry));
    ok(w.add_sol_lock(&root, ROOT_ROLE, LAMPORTS_PER_SOL, expiry));
    let before = w.locks();

    // Grow and shrink the roles region around the tail.
    let extra = Keypair::new();
    add_authority_with_ed25519_root(
        &mut w.context,
        &w.swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: extra.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
    )
    .unwrap();
    assert_eq!(w.locks(), before);
    let claimer = Keypair::new().pubkey();
    w.context.svm.airdrop(&claimer, LAMPORTS_PER_SOL).unwrap();
    set_rent_claimer_with_ed25519(&mut w.context, &w.swig, &root, ROOT_ROLE, claimer).unwrap();
    assert_eq!(w.locks(), before);
    update_authority_replace_with_ed25519_root(
        &mut w.context,
        &w.swig,
        &root,
        2,
        vec![ClientAction::SolLimit(SolLimit { amount: 2 })],
    )
    .unwrap();
    assert_eq!(w.locks(), before);
    remove_authority_with_ed25519_root(&mut w.context, &w.swig, &root, 2).unwrap();
    assert_eq!(w.locks(), before);
    assert_eq!(w.rent_claimer(), Some(claimer));

    // Enforcement, capture, and release still work afterwards. The root's
    // own lock does not restrict it; the card's does.
    let spendable = w.lockable_sol() - 2 * LAMPORTS_PER_SOL;
    assert_swig_error(
        w.spend_sol(&root, ROOT_ROLE, spendable + 1),
        SwigError::AuthorizationLockViolated,
    );
    ok(w.spend_sol(&root, ROOT_ROLE, spendable));
    assert_eq!(w.lock(1).amount, 0);
    ok(w.remove_lock(&card, CARD_ROLE, 0));
    ok(w.spend_sol(&root, ROOT_ROLE, 2 * LAMPORTS_PER_SOL));
    assert_eq!(w.rent_claimer(), Some(claimer));
}

// ---------------------------------------------------------------------------
// Bypass regressions
// ---------------------------------------------------------------------------

#[test]
fn blocked_wallet_funded_create_account_cannot_spend_locked_sol() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let (issuer, issuer_role) = w.add_issuer();
    let expiry = w.slot() + 100;
    let lockable = w.lockable_sol();
    ok(w.add_sol_lock(&issuer, issuer_role, lockable, expiry));
    let new_account = Keypair::new();
    let inner = system_instruction::create_account(
        &w.wallet,
        &new_account.pubkey(),
        LAMPORTS_PER_SOL,
        0,
        &solana_system_interface::program::ID,
    );
    let ix = SignV2Instruction::new_ed25519_with_signers(
        w.swig,
        w.wallet,
        root.pubkey(),
        inner,
        ROOT_ROLE,
        &[new_account.pubkey()],
    )
    .unwrap();
    assert_swig_error(
        w.send(&[ix], &[&root, &new_account]),
        SwigError::AuthorizationLockViolated,
    );
}

#[test]
fn blocked_burning_locked_tokens() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let (issuer, issuer_role) = w.add_issuer();
    let (mint, ata) = w.token_setup(1_000);
    let expiry = w.slot() + 100;
    ok(w.add_lock(&issuer, issuer_role, ata, mint.to_bytes(), 1_000, expiry));
    let inner =
        spl_token::instruction::burn(&spl_token::ID, &ata, &mint, &w.wallet, &[], 1).unwrap();
    let ix = w.sign_ix(&root, ROOT_ROLE, inner.clone());
    assert_swig_error(
        w.send(&[ix], &[&root]),
        SwigError::AuthorizationLockViolated,
    );
    assert_eq!(w.token_balance(&ata), 1_000);
    // A burn by the holder is an outflow it may make, and it captures.
    let ix = w.sign_ix(&issuer, issuer_role, inner);
    ok(w.send(&[ix], &[&issuer]));
    assert_eq!(w.lock(0).amount, 999);
}

#[test]
fn blocked_closing_a_locked_wsol_account_through_sign_v2() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let payer = w.context.default_payer.insecure_clone();
    let wsol = spl_token::native_mint::ID;
    let wallet = w.wallet;
    use solana_sdk::{account::Account, program_option::COption, program_pack::Pack};
    let _ = &payer;
    let reserve = Rent::default().minimum_balance(spl_token::state::Account::LEN);
    let ata = Pubkey::new_unique();
    let token = spl_token::state::Account {
        mint: wsol,
        owner: wallet,
        amount: LAMPORTS_PER_SOL,
        state: spl_token::state::AccountState::Initialized,
        is_native: COption::Some(reserve),
        ..Default::default()
    };
    let mut data = vec![0; spl_token::state::Account::LEN];
    spl_token::state::Account::pack(token, &mut data).unwrap();
    w.context
        .svm
        .set_account(
            ata,
            Account {
                lamports: LAMPORTS_PER_SOL + reserve,
                data,
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    let expiry = w.slot() + 100;
    ok(w.add_lock(
        &root,
        ROOT_ROLE,
        ata,
        wsol.to_bytes(),
        LAMPORTS_PER_SOL,
        expiry,
    ));

    // Even the holder cannot close the locked account through SignV2.
    let inner =
        spl_token::instruction::close_account(&spl_token::ID, &ata, &w.wallet, &w.wallet, &[])
            .unwrap();
    let ix = w.sign_ix(&root, ROOT_ROLE, inner);
    assert_swig_error(
        w.send(&[ix], &[&root]),
        SwigError::AuthorizationLockViolated,
    );
    assert_eq!(w.token_balance(&ata), LAMPORTS_PER_SOL);
}

#[test]
fn externally_frozen_locked_account_does_not_brick_sign_v2() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let (mint, ata) = w.token_setup(1_000);
    let expiry = w.slot() + 100;
    ok(w.add_lock(&root, ROOT_ROLE, ata, mint.to_bytes(), 500, expiry));
    let mut account = w.context.svm.get_account(&ata).unwrap();
    account.data[108] = 2;
    w.context.svm.set_account(ata, account).unwrap();

    // An unrelated SOL transfer that happens to carry the frozen account as
    // a writable meta still succeeds.
    let mut inner =
        system_instruction::transfer(&w.wallet, &Keypair::new().pubkey(), LAMPORTS_PER_SOL);
    inner
        .accounts
        .push(solana_sdk::instruction::AccountMeta::new(ata, false));
    let ix = w.sign_ix(&root, ROOT_ROLE, inner);
    ok(w.send(&[ix], &[&root]));
}

#[test]
fn blocked_thaw_and_drain_of_a_frozen_locked_account() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let (issuer, issuer_role) = w.add_issuer();
    let payer = w.context.default_payer.insecure_clone();
    let freezer = Keypair::new();
    w.context
        .svm
        .airdrop(&freezer.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    let freezer_key = freezer.pubkey();
    let mint = litesvm_token::CreateMint::new(&mut w.context.svm, &payer)
        .freeze_authority(&freezer_key)
        .send()
        .unwrap();
    let wallet = w.wallet;
    let ata = setup_ata(&mut w.context.svm, &mint, &wallet, &payer).unwrap();
    mint_to(&mut w.context.svm, &mint, &payer, &ata, 1_000).unwrap();
    let expiry = w.slot() + 100;
    ok(w.add_lock(&issuer, issuer_role, ata, mint.to_bytes(), 1_000, expiry));

    let freeze =
        spl_token::instruction::freeze_account(&spl_token::ID, &ata, &mint, &freezer_key, &[])
            .unwrap();
    ok(w.send(&[freeze], &[&freezer]));

    // The wallet owner colludes with the freeze authority: thaw inside SignV2
    // and drain in the same CPI batch.
    let thaw = spl_token::instruction::thaw_account(&spl_token::ID, &ata, &mint, &freezer_key, &[])
        .unwrap();
    let thaw_ix = SignV2Instruction::new_ed25519_with_signers(
        w.swig,
        w.wallet,
        root.pubkey(),
        thaw,
        ROOT_ROLE,
        &[freezer_key],
    )
    .unwrap();
    let drain = w.token_transfer_ix(&root, ROOT_ROLE, &mint, &ata, 1_000);
    assert_swig_error(
        w.send(&[thaw_ix, drain], &[&root, &freezer]),
        SwigError::AuthorizationLockViolated,
    );
    assert_eq!(w.token_balance(&ata), 1_000);
}

#[test]
fn renewing_delegate_can_be_stripped_of_lock_permission() {
    use swig_interface::{UpdateAuthorityData, UpdateAuthorityInstruction};
    use swig_state::action::Permission;
    let mut w = Wallet::new(2 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let expiry = w.slot() + MAX_DURATION;
    ok(w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, expiry));

    let update = |w: &Wallet, data: UpdateAuthorityData| {
        UpdateAuthorityInstruction::new_with_ed25519_authority(
            w.swig,
            w.context.default_payer.pubkey(),
            root.pubkey(),
            ROOT_ROLE,
            CARD_ROLE,
            data,
        )
        .unwrap()
    };
    // Any other change to the locked role stays blocked.
    let tighten = update(
        &w,
        UpdateAuthorityData::RemoveActionsByType(vec![Permission::SolLimit as u8]),
    );
    assert_swig_error(
        w.send(&[tighten], &[&root]),
        SwigError::AuthorizationLockActive,
    );
    let both = update(
        &w,
        UpdateAuthorityData::RemoveActionsByType(vec![
            Permission::ManageAuthorizationLocks as u8,
            Permission::SolLimit as u8,
        ]),
    );
    assert_swig_error(
        w.send(&[both], &[&root]),
        SwigError::AuthorizationLockActive,
    );

    // Revoking only the lock permission is allowed.
    let revoke = update(
        &w,
        UpdateAuthorityData::RemoveActionsByType(vec![Permission::ManageAuthorizationLocks as u8]),
    );
    ok(w.send(&[revoke], &[&root]));

    // The delegate can no longer renew, but its existing lock still binds the
    // owner and it can still capture it.
    let renew_expiry = w.slot() + 10;
    assert_eq!(
        custom_error(w.add_sol_lock(&card, CARD_ROLE, 1, renew_expiry)),
        SwigAuthenticateError::PermissionDeniedMissingPermission as u32
    );
    let spendable = w.lockable_sol() - LAMPORTS_PER_SOL;
    assert_swig_error(
        w.spend_sol(&root, ROOT_ROLE, spendable + 1),
        SwigError::AuthorizationLockViolated,
    );
    ok(w.spend_sol(&card, CARD_ROLE, LAMPORTS_PER_SOL));
    assert_eq!(w.lock(0).amount, 0);
    // With no active locks left, root can remove the role.
    remove_authority_with_ed25519_root(&mut w.context, &w.swig, &root, CARD_ROLE).unwrap();
}

fn token_2022_fixture(w: &mut Wallet, permanent_delegate: bool) -> (Pubkey, Pubkey) {
    use solana_sdk::{account::Account, program_option::COption, program_pack::Pack};
    let token_2022 = spl_token_2022_interface::ID;
    let mint = Pubkey::new_unique();
    let mut mint_data = vec![0u8; spl_token::state::Mint::LEN];
    spl_token::state::Mint::pack(
        spl_token::state::Mint {
            mint_authority: COption::Some(Pubkey::new_unique()),
            supply: 1_000,
            decimals: 0,
            is_initialized: true,
            freeze_authority: COption::None,
        },
        &mut mint_data,
    )
    .unwrap();
    if permanent_delegate {
        mint_data.resize(165, 0);
        mint_data.push(1); // AccountType::Mint
        mint_data.extend_from_slice(&12u16.to_le_bytes());
        mint_data.extend_from_slice(&32u16.to_le_bytes());
        mint_data.extend_from_slice(Pubkey::new_unique().as_ref());
    }
    let account = Pubkey::new_unique();
    let mut account_data = vec![0u8; spl_token::state::Account::LEN];
    spl_token::state::Account::pack(
        spl_token::state::Account {
            mint,
            owner: w.wallet,
            amount: 1_000,
            state: spl_token::state::AccountState::Initialized,
            ..Default::default()
        },
        &mut account_data,
    )
    .unwrap();
    let rent = Rent::default();
    for (key, data) in [(mint, mint_data), (account, account_data)] {
        w.context
            .svm
            .set_account(
                key,
                Account {
                    lamports: rent.minimum_balance(data.len()),
                    data,
                    owner: token_2022,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
    }
    (mint, account)
}

#[test]
fn token_2022_locks_reject_permanent_delegate_mints() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 100;

    let (mint, account) = token_2022_fixture(&mut w, false);
    // The mint account is required for Token-2022 assets.
    let mut ix = w.add_lock_ix(&root, ROOT_ROLE, account, mint.to_bytes(), 10, expiry);
    let authority_meta = ix.accounts.pop().unwrap();
    ix.accounts.pop();
    ix.accounts.push(authority_meta);
    let authority_index = ix.data.len() - 1;
    ix.data[authority_index] = 5;
    assert_swig_error(
        w.send(&[ix], &[&root]),
        SwigError::InvalidAuthorizationLockAsset,
    );
    ok(w.add_lock(&root, ROOT_ROLE, account, mint.to_bytes(), 10, expiry));

    let (mint, account) = token_2022_fixture(&mut w, true);
    assert_swig_error(
        w.add_lock(&root, ROOT_ROLE, account, mint.to_bytes(), 10, expiry),
        SwigError::InvalidAuthorizationLockAsset,
    );
}

#[test]
fn creator_may_rotate_its_own_signer_while_locked() {
    let mut w = Wallet::with_card_actions(vec![
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
        ClientAction::SolLimit(SolLimit {
            amount: LAMPORTS_PER_SOL,
        }),
        ClientAction::ReplaceAuthority(
            swig_state::action::replace_authority::ReplaceAuthority::new(CARD_ROLE),
        ),
    ]);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 100;
    ok(w.add_sol_lock(&card, CARD_ROLE, 1, expiry));
    let rotated = Keypair::new();
    let ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        w.swig,
        card.pubkey(),
        CARD_ROLE,
        CARD_ROLE,
        rotated.pubkey().as_ref(),
    )
    .unwrap();
    ok(w.send(&[ix], &[&card]));
    w.context
        .svm
        .airdrop(&rotated.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    ok(w.remove_lock(&rotated, CARD_ROLE, 0));
}

#[test]
fn all_but_manage_authority_role_locks_whole_balance_within_its_duration() {
    let abma = || {
        ClientAction::AllButManageAuthority(
            swig_state::action::all_but_manage_authority::AllButManageAuthority {},
        )
    };
    // Without the lock permission it cannot lock at all.
    let mut w = Wallet::with_card_actions(vec![abma()]);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 10;
    assert_eq!(
        custom_error(w.add_sol_lock(&card, CARD_ROLE, 1, expiry)),
        SwigAuthenticateError::PermissionDeniedMissingPermission as u32
    );

    // With it, it may lock the whole balance without spend limits, but only
    // for its granted duration.
    let mut w = Wallet::with_card_actions(vec![
        abma(),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
    ]);
    let card = w.card.insecure_clone();
    let lockable = w.lockable_sol();
    let now = w.slot();
    assert_swig_error(
        w.add_sol_lock(&card, CARD_ROLE, lockable, u64::MAX),
        SwigError::InvalidAuthorizationLockExpiry,
    );
    ok(w.add_sol_lock(&card, CARD_ROLE, lockable, now + MAX_DURATION));
}

#[test]
fn role_cannot_change_its_own_lock_duration() {
    use swig_interface::{UpdateAuthorityData, UpdateAuthorityInstruction};
    use swig_state::action::{manage_authority::ManageAuthority, Permission};
    let card_actions = |duration: u64| {
        vec![
            ClientAction::ManageAuthority(ManageAuthority {}),
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(duration)),
            ClientAction::SolLimit(SolLimit {
                amount: LAMPORTS_PER_SOL,
            }),
        ]
    };
    let mut w = Wallet::with_card_actions(card_actions(MAX_DURATION));
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let update = |w: &Wallet, signer: &Keypair, acting: u32, data: UpdateAuthorityData| {
        UpdateAuthorityInstruction::new_with_ed25519_authority(
            w.swig,
            w.context.default_payer.pubkey(),
            signer.pubkey(),
            acting,
            CARD_ROLE,
            data,
        )
        .unwrap()
    };

    // Raising its own bound, by either update form, is rejected.
    let raise = update(
        &w,
        &card,
        CARD_ROLE,
        UpdateAuthorityData::ReplaceAll(card_actions(MAX_DURATION * 10)),
    );
    assert_swig_error(
        w.send(&[raise], &[&card]),
        SwigError::AuthorizationLockDurationSelfUpdate,
    );
    // Rewriting its actions with the same bound is allowed.
    let same = update(
        &w,
        &card,
        CARD_ROLE,
        UpdateAuthorityData::ReplaceAll(card_actions(MAX_DURATION)),
    );
    ok(w.send(&[same], &[&card]));
    // Dropping its own lock permission is allowed...
    let drop = update(
        &w,
        &card,
        CARD_ROLE,
        UpdateAuthorityData::RemoveActionsByType(vec![Permission::ManageAuthorizationLocks as u8]),
    );
    ok(w.send(&[drop], &[&card]));
    // ...but granting it back to itself is not.
    let regrant = update(
        &w,
        &card,
        CARD_ROLE,
        UpdateAuthorityData::AddActions(vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks::new(MAX_DURATION),
        )]),
    );
    assert_swig_error(
        w.send(&[regrant], &[&card]),
        SwigError::AuthorizationLockDurationSelfUpdate,
    );

    // Another manager may grant or change the bound.
    let grant = update(
        &w,
        &root,
        ROOT_ROLE,
        UpdateAuthorityData::ReplaceAll(card_actions(MAX_DURATION * 10)),
    );
    ok(w.send(&[grant], &[&root]));
    let now = w.slot();
    ok(w.add_sol_lock(&card, CARD_ROLE, 1, now + MAX_DURATION * 10));
}

#[test]
fn manage_authority_role_can_prune_expired_locks() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let admin = Keypair::new();
    add_authority_with_ed25519_root(
        &mut w.context,
        &w.swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: admin.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(
            swig_state::action::manage_authority::ManageAuthority {},
        )],
    )
    .unwrap();
    let expiry = w.slot() + 10;
    ok(w.add_sol_lock(&root, ROOT_ROLE, 1, expiry));
    assert_swig_error(
        w.remove_lock(&admin, 2, 0),
        SwigError::AuthorizationLockNotOwner,
    );
    w.warp(expiry);
    ok(w.remove_lock(&admin, 2, 0));
}

#[test]
fn locks_require_a_migrated_swig() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let swig = w.swig;
    convert_swig_to_v1(&mut w.context, &swig);
    let expiry = w.slot() + 10;
    assert!(w.add_sol_lock(&root, ROOT_ROLE, 1, expiry).is_err());
    assert!(w.locks().1.is_empty());
}

#[test]
fn add_then_remove_is_rent_neutral_for_an_overfunded_config_account() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    // Configuration SOL above the rent reserve must not leak to the payer.
    let swig = w.swig;
    w.context.svm.airdrop(&swig, 5 * LAMPORTS_PER_SOL).unwrap();
    let expiry = w.slot() + 100;
    ok(w.add_sol_lock(&card, CARD_ROLE, 1, expiry));
    let swig_before = w.context.svm.get_balance(&swig).unwrap();
    let payer = w.context.default_payer.pubkey();
    for _ in 0..3 {
        let payer_before = w.context.svm.get_balance(&payer).unwrap();
        let add = ok(w.add_sol_lock(&card, CARD_ROLE, 1, expiry));
        let (_, locks) = w.locks();
        let id = locks.last().unwrap().lock_id;
        let remove = ok(w.remove_lock(&card, CARD_ROLE, id));
        assert_eq!(w.context.svm.get_balance(&swig).unwrap(), swig_before);
        assert_eq!(
            w.context.svm.get_balance(&payer).unwrap(),
            payer_before - add.fee - remove.fee
        );
    }
}

#[test]
fn sign_v2_cost_with_maximum_locks_is_bounded() {
    // Another role's locks: the guard only.
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let (issuer, issuer_role) = w.add_issuer();
    let expiry = w.slot() + 100;
    let baseline = ok(w.spend_sol(&root, ROOT_ROLE, LAMPORTS_PER_SOL)).compute_units_consumed;
    for _ in 0..MAX_AUTHORIZATION_LOCKS {
        ok(w.add_sol_lock(&issuer, issuer_role, 1, expiry));
    }
    let guarded = ok(w.spend_sol(&root, ROOT_ROLE, LAMPORTS_PER_SOL)).compute_units_consumed;
    // The holder's own locks: every one of them is captured and written back.
    let captured = ok(w.spend_sol(&issuer, issuer_role, LAMPORTS_PER_SOL)).compute_units_consumed;
    assert!(w.locks().1.iter().all(|lock| lock.amount == 0));
    println!("AUTH_LOCK_CU baseline {baseline} guarded {guarded} captured {captured}");
    // Covers the ComputeBudget instruction plus SignV2.
    assert!(
        guarded - baseline < 5_500,
        "32 locks added {} CU",
        guarded - baseline
    );
    assert!(
        captured - baseline < 6_000,
        "capturing 32 locks added {} CU",
        captured - baseline
    );

    // A limited holder also re-checks its remaining locks against its limits.
    let mut w = Wallet::new(10 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 100;
    let step = LAMPORTS_PER_SOL / 10;
    let baseline = ok(w.spend_sol(&card, CARD_ROLE, step)).compute_units_consumed;
    for _ in 0..MAX_AUTHORIZATION_LOCKS {
        ok(w.add_sol_lock(&card, CARD_ROLE, 1_000, expiry));
    }
    let captured = ok(w.spend_sol(&card, CARD_ROLE, step)).compute_units_consumed;
    assert_eq!(w.lock(0).amount, 0);
    println!("AUTH_LOCK_CU limited baseline {baseline} captured {captured}");
    assert!(
        // Includes hashing the 2.8 KB larger config account twice, which
        // the limited path does for every role.
        captured - baseline < 10_000,
        "capturing with 32 limited locks added {} CU",
        captured - baseline
    );
}

// ---------------------------------------------------------------------------
// The creator's limits back its reservations
// ---------------------------------------------------------------------------

#[test]
fn limits_are_charged_on_spend_and_locks_captured_before_the_capacity_check() {
    // Bob with a 2 SOL limit and a 2 SOL lock spends 2 SOL: the limit falls
    // to 0, the lock is captured to 0, and the capacity check passes.
    let mut w = Wallet::new(2 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 500;
    ok(w.add_sol_lock(&card, CARD_ROLE, 2 * LAMPORTS_PER_SOL, expiry));
    ok(w.spend_sol(&card, CARD_ROLE, LAMPORTS_PER_SOL));
    assert_eq!(w.lock(0).amount, LAMPORTS_PER_SOL);
    ok(w.spend_sol(&card, CARD_ROLE, LAMPORTS_PER_SOL));
    assert_eq!(w.lock(0).amount, 0);
    // The limit, charged on spend, is now exhausted.
    assert!(w.spend_sol(&card, CARD_ROLE, 1).is_err());
}

#[test]
fn holder_cannot_keep_locks_beyond_its_remaining_capacity() {
    // A 600 hold on one account and a 1000 token limit: spending elsewhere
    // may not leave the hold larger than the limit that remains.
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let (mint, ata) = w.token_setup(1_000);
    let payer = w.context.default_payer.insecure_clone();
    let wallet = w.wallet;
    let second = litesvm_token::CreateAccount::new(&mut w.context.svm, &payer, &mint)
        .owner(&wallet)
        .account_kp(Keypair::new())
        .send()
        .unwrap();
    mint_to(&mut w.context.svm, &mint, &payer, &second, 1_000).unwrap();
    let (card, role) = w.add_token_card(&mint, 1_000);
    let expiry = w.slot() + 500;
    ok(w.add_lock(&card, role, ata, mint.to_bytes(), 600, expiry));

    let ix = w.token_transfer_ix(&card, role, &mint, &second, 401);
    assert_swig_error(
        w.send(&[ix], &[&card]),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );
    let ix = w.token_transfer_ix(&card, role, &mint, &second, 400);
    ok(w.send(&[ix], &[&card]));
    assert_eq!(w.lock(0).amount, 600);
    // Spending from the locked account captures as it charges, so the hold
    // and the limit fall together.
    let ix = w.token_transfer_ix(&card, role, &mint, &ata, 600);
    ok(w.send(&[ix], &[&card]));
    assert_eq!(w.lock(0).amount, 0);
}

#[test]
fn locks_count_against_the_remaining_recurring_window() {
    let window = 100;
    let mut w = Wallet::with_card_actions(vec![
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
        ClientAction::SolRecurringLimit(SolRecurringLimit {
            recurring_amount: 3 * LAMPORTS_PER_SOL,
            window,
            last_reset: 0,
            current_amount: 3 * LAMPORTS_PER_SOL,
        }),
        ClientAction::Program(Program {
            program_id: solana_system_interface::program::ID.to_bytes(),
        }),
    ]);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 500;
    ok(w.spend_sol(&card, CARD_ROLE, 2 * LAMPORTS_PER_SOL));

    // Only 1 SOL is left in this window, so the role cannot hold more.
    assert_swig_error(
        w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL + 1, expiry),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );
    ok(w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, expiry));
    // Spending the hold uses the window's last 1 SOL and captures it.
    assert!(w.spend_sol(&card, CARD_ROLE, LAMPORTS_PER_SOL + 1).is_err());
    ok(w.spend_sol(&card, CARD_ROLE, LAMPORTS_PER_SOL));
    assert_eq!(w.lock(0).amount, 0);

    // A fresh window restores the full allowance.
    let next_window = w.slot() + window + 1;
    w.warp(next_window);
    ok(w.add_sol_lock(&card, CARD_ROLE, 2 * LAMPORTS_PER_SOL, expiry));
    ok(w.spend_sol(&card, CARD_ROLE, 3 * LAMPORTS_PER_SOL));
    assert_eq!(w.lock(1).amount, 0);
}

#[test]
fn destination_limits_back_locks_too() {
    let merchant = Keypair::new().pubkey();
    let mut w = Wallet::with_card_actions(vec![
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
        ClientAction::SolDestinationLimit(SolDestinationLimit {
            destination: merchant.to_bytes(),
            amount: LAMPORTS_PER_SOL,
        }),
        ClientAction::Program(Program {
            program_id: solana_system_interface::program::ID.to_bytes(),
        }),
    ]);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 500;
    ok(w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, expiry));

    let pay = |w: &Wallet, to: &Pubkey, lamports| {
        w.sign_ix(
            &card,
            CARD_ROLE,
            system_instruction::transfer(&w.wallet, to, lamports),
        )
    };
    // Only the merchant can be paid.
    let elsewhere = pay(&w, &Keypair::new().pubkey(), LAMPORTS_PER_SOL / 2);
    assert!(w.send(&[elsewhere], &[&card]).is_err());
    let first = pay(&w, &merchant, LAMPORTS_PER_SOL / 2);
    ok(w.send(&[first], &[&card]));
    assert_eq!(w.lock(0).amount, LAMPORTS_PER_SOL / 2);
    let rest = pay(&w, &merchant, LAMPORTS_PER_SOL / 2);
    ok(w.send(&[rest], &[&card]));
    assert_eq!(w.lock(0).amount, 0);
}

#[test]
fn token_limits_back_token_locks() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let (mint, ata) = w.token_setup(10_000);
    let (card, role) = w.add_token_card(&mint, 1_000);
    let expiry = w.slot() + 500;
    ok(w.add_lock(&card, role, ata, mint.to_bytes(), 600, expiry));

    // Spending within the hold captures it and is charged to the limit.
    let ix = w.token_transfer_ix(&card, role, &mint, &ata, 401);
    ok(w.send(&[ix], &[&card]));
    assert_eq!(w.lock(0).amount, 199);
    // Spending past the hold comes from free balance, within the limit.
    let ix = w.token_transfer_ix(&card, role, &mint, &ata, 500);
    ok(w.send(&[ix], &[&card]));
    assert_eq!(w.lock(0).amount, 0);
    // 901 of the 1000 limit is spent.
    let ix = w.token_transfer_ix(&card, role, &mint, &ata, 100);
    assert!(w.send(&[ix], &[&card]).is_err());
    let ix = w.token_transfer_ix(&card, role, &mint, &ata, 99);
    ok(w.send(&[ix], &[&card]));
}

#[test]
fn other_roles_limits_are_independent_of_a_creators_locks() {
    let mut w = Wallet::new(2 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let spender = Keypair::new();
    add_authority_with_ed25519_root(
        &mut w.context,
        &w.swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: spender.pubkey().as_ref(),
        },
        vec![
            ClientAction::SolLimit(SolLimit {
                amount: LAMPORTS_PER_SOL,
            }),
            ClientAction::Program(Program {
                program_id: solana_system_interface::program::ID.to_bytes(),
            }),
        ],
    )
    .unwrap();
    let expiry = w.slot() + 500;
    ok(w.add_sol_lock(&card, CARD_ROLE, 2 * LAMPORTS_PER_SOL, expiry));
    // Another limited role spends its full allowance; only the balance floor
    // applies to it.
    ok(w.spend_sol(&spender, 2, LAMPORTS_PER_SOL));
}

#[test]
fn spend_capacity_composes_general_and_destination_pairs() {
    // A general 100 SOL limit together with a destination pair (10 SOL
    // one-shot + 1 SOL/window recurring to A) and a 5 SOL one-shot to B:
    // the reservation can never exceed what a transaction can spend, so
    // total capacity is min(100, min(10, 1) + 5) = 6 SOL.
    let a = Keypair::new().pubkey();
    let b = Keypair::new().pubkey();
    let mut w = Wallet::with_card_actions(vec![
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
        ClientAction::SolLimit(SolLimit {
            amount: 100 * LAMPORTS_PER_SOL,
        }),
        ClientAction::SolRecurringDestinationLimit(SolRecurringDestinationLimit {
            destination: a.to_bytes(),
            recurring_amount: LAMPORTS_PER_SOL,
            window: 100,
            last_reset: 0,
            current_amount: LAMPORTS_PER_SOL,
        }),
        ClientAction::SolDestinationLimit(SolDestinationLimit {
            destination: a.to_bytes(),
            amount: 10 * LAMPORTS_PER_SOL,
        }),
        ClientAction::SolDestinationLimit(SolDestinationLimit {
            destination: b.to_bytes(),
            amount: 5 * LAMPORTS_PER_SOL,
        }),
    ]);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 100;
    ok(w.add_sol_lock(&card, CARD_ROLE, 6 * LAMPORTS_PER_SOL, expiry));
    assert_swig_error(
        w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, expiry),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );

    // A general recurring half tightens it further: min(100, 3 SOL window)
    // general capacity with a 1/window pair to A gives min(3, 1) = 1 SOL.
    let mut w = Wallet::with_card_actions(vec![
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
        ClientAction::SolLimit(SolLimit {
            amount: 100 * LAMPORTS_PER_SOL,
        }),
        ClientAction::SolRecurringLimit(SolRecurringLimit {
            recurring_amount: 3 * LAMPORTS_PER_SOL,
            window: 100,
            last_reset: 0,
            current_amount: 3 * LAMPORTS_PER_SOL,
        }),
        ClientAction::SolRecurringDestinationLimit(SolRecurringDestinationLimit {
            destination: a.to_bytes(),
            recurring_amount: LAMPORTS_PER_SOL,
            window: 100,
            last_reset: 0,
            current_amount: LAMPORTS_PER_SOL,
        }),
        ClientAction::SolDestinationLimit(SolDestinationLimit {
            destination: a.to_bytes(),
            amount: 10 * LAMPORTS_PER_SOL,
        }),
    ]);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 100;
    ok(w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, expiry));
    assert_swig_error(
        w.add_sol_lock(&card, CARD_ROLE, 2 * LAMPORTS_PER_SOL, expiry),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );
}

// ---------------------------------------------------------------------------
// ProgramExec authorities
// ---------------------------------------------------------------------------

const TEST_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("BXAu5ZWHnGun2XZjUZ9nqwiZ5dNVmofPGYdMC4rx4qLV");
const TEST_PROGRAM_PATH: &str = "../target/deploy/test_program_authority.so";
const TEST_PROGRAM_DISCRIMINATOR: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const PROGRAM_EXEC_ROLE: u32 = 2;

fn program_exec_lock_actions() -> Vec<ClientAction> {
    vec![
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
        ClientAction::SolLimit(SolLimit {
            amount: LAMPORTS_PER_SOL,
        }),
    ]
}

impl Wallet {
    /// Deploys the test program, creates its (succeeding) state account and
    /// returns it.
    fn deploy_test_program(&mut self) -> Pubkey {
        let program = std::fs::read(TEST_PROGRAM_PATH)
            .expect("test program missing; run `cargo build-sbf` first");
        self.context.svm.add_program(TEST_PROGRAM_ID, &program);
        let state = Keypair::new().pubkey();
        self.context
            .svm
            .set_account(
                state,
                solana_sdk::account::Account {
                    lamports: 1_000_000,
                    data: vec![0],
                    owner: TEST_PROGRAM_ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        state
    }

    /// Adds a ProgramExec role bound to the test program as role 2.
    fn add_program_exec_role(&mut self, actions: Vec<ClientAction>) -> Pubkey {
        let state = self.deploy_test_program();
        let authority = ProgramExecAuthority::create_authority_data(
            &TEST_PROGRAM_ID.to_bytes(),
            &TEST_PROGRAM_DISCRIMINATOR,
        );
        let root = self.root.insecure_clone();
        add_authority_with_ed25519_root(
            &mut self.context,
            &self.swig,
            &root,
            AuthorityConfig {
                authority_type: AuthorityType::ProgramExec,
                authority: &authority,
            },
            actions,
        )
        .unwrap();
        state
    }

    /// The test program instruction a ProgramExec role authenticates against.
    /// Its first two accounts are what the authority binds to.
    fn program_exec_proof(&self, first: Pubkey, second: Pubkey, state: Pubkey) -> Instruction {
        Instruction {
            program_id: TEST_PROGRAM_ID,
            accounts: vec![
                solana_sdk::instruction::AccountMeta::new_readonly(first, false),
                solana_sdk::instruction::AccountMeta::new_readonly(second, false),
                solana_sdk::instruction::AccountMeta::new_readonly(state, false),
                solana_sdk::instruction::AccountMeta::new_readonly(program_id(), false),
            ],
            data: TEST_PROGRAM_DISCRIMINATOR.to_vec(),
        }
    }

    fn program_exec_add_lock_ixs(
        &self,
        proof: Instruction,
        asset: Pubkey,
        mint: [u8; 32],
        amount: u64,
        expiry_slot: u64,
    ) -> Vec<Instruction> {
        AddAuthorizationLockV1Instruction::new_with_program_exec(
            self.swig,
            self.context.default_payer.pubkey(),
            proof,
            self.wallet,
            asset,
            PROGRAM_EXEC_ROLE,
            mint,
            amount,
            expiry_slot,
        )
        .unwrap()
    }

    fn program_exec_remove_lock_ixs(&self, proof: Instruction, lock_id: u32) -> Vec<Instruction> {
        RemoveAuthorizationLockV1Instruction::new_with_program_exec(
            self.swig,
            self.context.default_payer.pubkey(),
            proof,
            self.wallet,
            PROGRAM_EXEC_ROLE,
            lock_id,
            self.rent_claimer(),
        )
        .unwrap()
    }
}

#[test]
fn program_exec_role_can_add_and_remove_locks() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let mut actions = program_exec_lock_actions();
    let (mint, ata) = w.token_setup(1_000);
    actions.push(ClientAction::TokenLimit(TokenLimit {
        token_mint: mint.to_bytes(),
        current_amount: 1_000,
    }));
    let state = w.add_program_exec_role(actions);
    let expiry = w.slot() + 100;
    let proof = w.program_exec_proof(w.swig, w.wallet, state);

    // SOL lock: the instructions sysvar follows the asset account.
    let wallet = w.wallet;
    let ixs = w.program_exec_add_lock_ixs(proof.clone(), wallet, NATIVE, 1_000, expiry);
    ok(w.send(&ixs, &[]));
    // Token lock: the instructions sysvar follows the trailing mint.
    let ixs = w.program_exec_add_lock_ixs(proof.clone(), ata, mint.to_bytes(), 600, expiry);
    ok(w.send(&ixs, &[]));

    let (_, locks) = w.locks();
    assert_eq!(locks.len(), 2);
    assert!(locks.iter().all(|lock| lock.role_id == PROGRAM_EXEC_ROLE));
    assert_eq!(locks[0].asset_account, w.wallet.to_bytes());
    assert_eq!(locks[1].asset_account, ata.to_bytes());

    // The lock binds every role, root included.
    let root = w.root.insecure_clone();
    let spendable = w.lockable_sol() - 1_000;
    assert_swig_error(
        w.spend_sol(&root, ROOT_ROLE, spendable + 1),
        SwigError::AuthorizationLockViolated,
    );

    let ixs = w.program_exec_remove_lock_ixs(proof.clone(), 0);
    ok(w.send(&ixs, &[]));
    // Explicit target index: compute budget (0), proof (1), remove (2).
    let ixs = RemoveAuthorizationLockV1Instruction::new_with_program_exec_ix_index(
        w.swig,
        w.context.default_payer.pubkey(),
        proof,
        w.wallet,
        PROGRAM_EXEC_ROLE,
        1,
        None,
        1,
    )
    .unwrap();
    ok(w.send(&ixs, &[]));
    assert!(w.locks().1.is_empty());
}

#[test]
fn program_exec_session_role_can_add_and_remove_locks() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let state = w.deploy_test_program();
    let mut prefix = [0u8; 40];
    prefix[..8].copy_from_slice(&TEST_PROGRAM_DISCRIMINATOR);
    let session_authority = CreateProgramExecSessionAuthority::new(
        TEST_PROGRAM_ID.to_bytes(),
        8,
        prefix,
        [0; 32],
        1_000,
    );
    let root = w.root.insecure_clone();
    add_authority_with_ed25519_root(
        &mut w.context,
        &w.swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::ProgramExecSession,
            authority: session_authority.into_bytes().unwrap(),
        },
        program_exec_lock_actions(),
    )
    .unwrap();

    // The program proves itself once to open a session; CreateSessionV1's
    // second account is the payer.
    let session = Keypair::new();
    let payer = w.context.default_payer.pubkey();
    let create_session = CreateSessionInstruction::new_with_program_exec(
        w.swig,
        payer,
        w.program_exec_proof(w.swig, payer, state),
        PROGRAM_EXEC_ROLE,
        500,
        session.pubkey(),
    )
    .unwrap();
    ok(w.send(&create_session, &[]));

    // Session-based roles authorize locks with the session key.
    let expiry = w.slot() + 100;
    ok(w.add_sol_lock(&session, PROGRAM_EXEC_ROLE, 1_000, expiry));
    let (_, locks) = w.locks();
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0].role_id, PROGRAM_EXEC_ROLE);

    // A stranger cannot use the role.
    assert!(w
        .remove_lock(&Keypair::new(), PROGRAM_EXEC_ROLE, 0)
        .is_err());
    ok(w.remove_lock(&session, PROGRAM_EXEC_ROLE, 0));
    assert!(w.locks().1.is_empty());

    // Once the session expires the key no longer works.
    let expiry = w.slot() + 1_000;
    ok(w.add_sol_lock(&session, PROGRAM_EXEC_ROLE, 1_000, expiry));
    let slot = w.slot();
    w.warp(slot + 501);
    assert_eq!(
        custom_error(w.remove_lock(&session, PROGRAM_EXEC_ROLE, 1)),
        SwigAuthenticateError::PermissionDeniedSessionExpired as u32
    );
}

#[test]
fn remove_requires_the_canonical_wallet_address() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 100;
    ok(w.add_sol_lock(&root, ROOT_ROLE, 1, expiry));

    let mut ix = w.remove_lock_ix(&root, ROOT_ROLE, 0);
    ix.accounts[1].pubkey = Keypair::new().pubkey();
    assert_swig_error(w.send(&[ix], &[&root]), SwigError::InvalidSeedSwigAccount);

    // Another swig's wallet address is rejected too.
    let other_swig = Keypair::new().pubkey();
    let other_wallet = Pubkey::find_program_address(
        &swig_wallet_address_seeds(other_swig.as_ref()),
        &program_id(),
    )
    .0;
    let mut ix = w.remove_lock_ix(&root, ROOT_ROLE, 0);
    ix.accounts[1].pubkey = other_wallet;
    assert_swig_error(w.send(&[ix], &[&root]), SwigError::InvalidSeedSwigAccount);
    assert_eq!(w.locks().1.len(), 1);

    // A ProgramExec proof bound to a fake wallet address cannot pass either.
    let state = w.add_program_exec_role(program_exec_lock_actions());
    let expiry = w.slot() + 100;
    let wallet = w.wallet;
    let proof = w.program_exec_proof(w.swig, wallet, state);
    let ixs = w.program_exec_add_lock_ixs(proof, wallet, NATIVE, 1, expiry);
    ok(w.send(&ixs, &[]));
    let fake = Keypair::new().pubkey();
    let mut ixs = w.program_exec_remove_lock_ixs(w.program_exec_proof(w.swig, fake, state), 1);
    ixs[1].accounts[1].pubkey = fake;
    assert_swig_error(w.send(&ixs, &[]), SwigError::InvalidSeedSwigAccount);

    ok(w.remove_lock(&root, ROOT_ROLE, 0));
    let ixs = w.program_exec_remove_lock_ixs(w.program_exec_proof(w.swig, wallet, state), 1);
    ok(w.send(&ixs, &[]));
    assert!(w.locks().1.is_empty());
}

#[test]
fn program_exec_lock_rejects_mismatched_proof_accounts() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let state = w.add_program_exec_role(program_exec_lock_actions());
    let expiry = w.slot() + 100;
    let (swig, wallet) = (w.swig, w.wallet);
    let payer = w.context.default_payer.pubkey();
    let invalid_wallet =
        SwigAuthenticateError::PermissionDeniedProgramExecInvalidWalletAccount as u32;
    let invalid_config =
        SwigAuthenticateError::PermissionDeniedProgramExecInvalidConfigAccount as u32;

    // The pre-reorder binding (config, payer) no longer matches.
    let ixs = w.program_exec_add_lock_ixs(
        w.program_exec_proof(swig, payer, state),
        wallet,
        NATIVE,
        1,
        expiry,
    );
    assert_eq!(custom_error(w.send(&ixs, &[])), invalid_wallet);
    let ixs = w.program_exec_add_lock_ixs(
        w.program_exec_proof(Keypair::new().pubkey(), wallet, state),
        wallet,
        NATIVE,
        1,
        expiry,
    );
    assert_eq!(custom_error(w.send(&ixs, &[])), invalid_config);
    let ixs = w.program_exec_add_lock_ixs(
        w.program_exec_proof(wallet, swig, state),
        wallet,
        NATIVE,
        1,
        expiry,
    );
    assert_eq!(custom_error(w.send(&ixs, &[])), invalid_config);
    assert!(w.locks().1.is_empty());

    let ixs = w.program_exec_add_lock_ixs(
        w.program_exec_proof(swig, wallet, state),
        wallet,
        NATIVE,
        1,
        expiry,
    );
    ok(w.send(&ixs, &[]));

    let ixs = w.program_exec_remove_lock_ixs(w.program_exec_proof(swig, payer, state), 0);
    assert_eq!(custom_error(w.send(&ixs, &[])), invalid_wallet);
    let ixs = w.program_exec_remove_lock_ixs(
        w.program_exec_proof(Keypair::new().pubkey(), wallet, state),
        0,
    );
    assert_eq!(custom_error(w.send(&ixs, &[])), invalid_config);
    assert_eq!(w.locks().1.len(), 1);

    let ixs = w.program_exec_remove_lock_ixs(w.program_exec_proof(swig, wallet, state), 0);
    ok(w.send(&ixs, &[]));
    assert!(w.locks().1.is_empty());
}

// ---------------------------------------------------------------------------
// Holder exemption across asset programs and authority kinds
// ---------------------------------------------------------------------------

/// A Token-2022 account of `mint` owned by `owner`, holding `amount`.
fn token_2022_account(w: &mut Wallet, mint: &Pubkey, owner: &Pubkey, amount: u64) -> Pubkey {
    use solana_sdk::{account::Account, program_pack::Pack};
    let account = Pubkey::new_unique();
    let mut data = vec![0u8; spl_token::state::Account::LEN];
    spl_token::state::Account::pack(
        spl_token::state::Account {
            mint: *mint,
            owner: *owner,
            amount,
            state: spl_token::state::AccountState::Initialized,
            ..Default::default()
        },
        &mut data,
    )
    .unwrap();
    w.context
        .svm
        .set_account(
            account,
            Account {
                lamports: Rent::default().minimum_balance(data.len()),
                data,
                owner: spl_token_2022_interface::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    account
}

#[test]
fn token_2022_holder_spends_and_captures_while_others_are_held_off() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let (issuer, issuer_role) = w.add_issuer();
    let (mint, account) = token_2022_fixture(&mut w, false);
    let destination = token_2022_account(&mut w, &mint, &Keypair::new().pubkey(), 0);
    let expiry = w.slot() + 100;
    ok(w.add_lock(&issuer, issuer_role, account, mint.to_bytes(), 600, expiry));

    let transfer = |w: &Wallet, signer: &Keypair, role: u32, amount: u64| {
        #[allow(deprecated)]
        let inner = spl_token_2022_interface::instruction::transfer(
            &spl_token_2022_interface::ID,
            &account,
            &destination,
            &w.wallet,
            &[],
            amount,
        )
        .unwrap();
        w.sign_ix(signer, role, inner)
    };
    let ix = transfer(&w, &root, ROOT_ROLE, 401);
    assert_swig_error(
        w.send(&[ix], &[&root]),
        SwigError::AuthorizationLockViolated,
    );
    let ix = transfer(&w, &root, ROOT_ROLE, 400);
    ok(w.send(&[ix], &[&root]));
    assert_eq!(w.lock(0).amount, 600);

    let ix = transfer(&w, &issuer, issuer_role, 450);
    ok(w.send(&[ix], &[&issuer]));
    assert_eq!(w.token_balance(&account), 150);
    assert_eq!(w.lock(0).amount, 150);
}

#[test]
fn session_holder_spends_and_captures_its_lock() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let state = w.deploy_test_program();
    let mut prefix = [0u8; 40];
    prefix[..8].copy_from_slice(&TEST_PROGRAM_DISCRIMINATOR);
    let session_authority = CreateProgramExecSessionAuthority::new(
        TEST_PROGRAM_ID.to_bytes(),
        8,
        prefix,
        [0; 32],
        1_000,
    );
    let root = w.root.insecure_clone();
    add_authority_with_ed25519_root(
        &mut w.context,
        &w.swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::ProgramExecSession,
            authority: session_authority.into_bytes().unwrap(),
        },
        program_exec_spend_actions(),
    )
    .unwrap();
    let session = Keypair::new();
    let payer = w.context.default_payer.pubkey();
    let create_session = CreateSessionInstruction::new_with_program_exec(
        w.swig,
        payer,
        w.program_exec_proof(w.swig, payer, state),
        PROGRAM_EXEC_ROLE,
        500,
        session.pubkey(),
    )
    .unwrap();
    ok(w.send(&create_session, &[]));

    let expiry = w.slot() + 100;
    ok(w.add_sol_lock(&session, PROGRAM_EXEC_ROLE, LAMPORTS_PER_SOL, expiry));
    let spendable = w.lockable_sol() - LAMPORTS_PER_SOL;
    ok(w.spend_sol(&root, ROOT_ROLE, spendable));

    // The session key signs as the role that holds the lock.
    ok(w.spend_sol(&session, PROGRAM_EXEC_ROLE, 3 * LAMPORTS_PER_SOL / 5));
    assert_eq!(w.lock(0).amount, 2 * LAMPORTS_PER_SOL / 5);
    assert_swig_error(
        w.spend_sol(&root, ROOT_ROLE, 1),
        SwigError::AuthorizationLockViolated,
    );
}

#[test]
fn program_exec_holder_spends_and_captures_its_lock() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let state = w.add_program_exec_role(program_exec_spend_actions());
    let expiry = w.slot() + 100;
    let wallet = w.wallet;
    let proof = w.program_exec_proof(w.swig, wallet, state);
    let ixs = w.program_exec_add_lock_ixs(proof.clone(), wallet, NATIVE, LAMPORTS_PER_SOL, expiry);
    ok(w.send(&ixs, &[]));
    let spendable = w.lockable_sol() - LAMPORTS_PER_SOL;
    ok(w.spend_sol(&root, ROOT_ROLE, spendable));

    let spend = |w: &Wallet, lamports| {
        SignV2Instruction::new_program_exec(
            w.swig,
            w.wallet,
            w.context.default_payer.pubkey(),
            proof.clone(),
            system_instruction::transfer(&w.wallet, &Keypair::new().pubkey(), lamports),
            PROGRAM_EXEC_ROLE,
        )
        .unwrap()
    };
    let ixs = spend(&w, LAMPORTS_PER_SOL + 1);
    assert!(w.send(&ixs, &[]).is_err());
    let ixs = spend(&w, LAMPORTS_PER_SOL);
    ok(w.send(&ixs, &[]));
    assert_eq!(w.lock(0).amount, 0);
    assert_eq!(w.lockable_sol(), 0);
}

fn program_exec_spend_actions() -> Vec<ClientAction> {
    let mut actions = program_exec_lock_actions();
    actions.push(ClientAction::Program(Program {
        program_id: solana_system_interface::program::ID.to_bytes(),
    }));
    actions
}

// ---------------------------------------------------------------------------
// SignV2 compute cost by lock scenario
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum CuScenario {
    /// No tail at all.
    NoTail,
    /// A tail (rent claimer) without a lock entry.
    TailWithoutLocks,
    /// One active lock on a token account that is not in the transaction.
    OneLockNotTouched,
    /// One other role's active lock on the wallet's SOL: floor check only.
    OneOtherRolesLockGuarded,
    /// One of the signer's own SOL locks, captured in full.
    OneLockCaptured,
    /// 32 other-role SOL locks: floor check only.
    MaxOtherRolesLocksGuarded,
    /// 32 of the signer's own SOL locks, all captured.
    MaxLocksAllCaptured,
}

/// Returns the compute units of one 0.1 SOL SignV2 transfer (plus the
/// compute-budget instruction) by an `All` signer or a limited signer.
fn lock_scenario_cu(limited: bool, scenario: CuScenario) -> u64 {
    let step = LAMPORTS_PER_SOL / 10;
    let mut w = Wallet::new(10 * LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let (signer, role) = if limited {
        (w.card.insecure_clone(), CARD_ROLE)
    } else {
        w.add_issuer()
    };
    let (other, other_role) = w.add_issuer();
    let expiry = w.slot() + 500;
    match scenario {
        CuScenario::NoTail => {},
        CuScenario::TailWithoutLocks => {
            let claimer = Keypair::new().pubkey();
            w.context.svm.airdrop(&claimer, LAMPORTS_PER_SOL).unwrap();
            set_rent_claimer_with_ed25519(&mut w.context, &w.swig, &root, ROOT_ROLE, claimer)
                .unwrap();
        },
        CuScenario::OneLockNotTouched => {
            let (mint, ata) = w.token_setup(1_000);
            ok(w.add_lock(&other, other_role, ata, mint.to_bytes(), 500, expiry));
        },
        CuScenario::OneOtherRolesLockGuarded => {
            ok(w.add_sol_lock(&other, other_role, LAMPORTS_PER_SOL, expiry));
        },
        CuScenario::OneLockCaptured => {
            ok(w.add_sol_lock(&signer, role, step, expiry));
        },
        CuScenario::MaxOtherRolesLocksGuarded => {
            for _ in 0..MAX_AUTHORIZATION_LOCKS {
                ok(w.add_sol_lock(&other, other_role, 1_000, expiry));
            }
        },
        CuScenario::MaxLocksAllCaptured => {
            for _ in 0..MAX_AUTHORIZATION_LOCKS {
                ok(w.add_sol_lock(&signer, role, 1_000, expiry));
            }
        },
    }
    let cu = ok(w.spend_sol(&signer, role, step)).compute_units_consumed;
    if matches!(
        scenario,
        CuScenario::OneLockCaptured | CuScenario::MaxLocksAllCaptured
    ) {
        assert!(w.locks().1.iter().all(|lock| lock.amount == 0));
    }
    cu
}

#[test]
fn sign_v2_lock_cu_table() {
    use CuScenario::*;
    let scenarios = [
        NoTail,
        TailWithoutLocks,
        OneLockNotTouched,
        OneOtherRolesLockGuarded,
        OneLockCaptured,
        MaxOtherRolesLocksGuarded,
        MaxLocksAllCaptured,
    ];
    for limited in [false, true] {
        let signer = if limited { "limited" } else { "All" };
        let cu: Vec<u64> = scenarios
            .iter()
            .map(|&scenario| lock_scenario_cu(limited, scenario))
            .collect();
        for (scenario, cu) in scenarios.iter().zip(&cu) {
            println!("LOCK_CU {signer} {scenario:?} {cu}");
        }
        // Wallets without a lock entry pay only for finding none.
        assert!(
            cu[1] - cu[0] < 150,
            "{signer}: lock-free tail costs {}",
            cu[1] - cu[0]
        );
        // A lock on an account the transaction does not touch costs one
        // pass over the records and no allocation.
        assert!(
            cu[2] - cu[1] < 400,
            "{signer}: untouched lock costs {}",
            cu[2] - cu[1]
        );
        // Guarding or capturing one lock stays around a rent-sysvar read.
        assert!(
            cu[3] - cu[1] < 1_200,
            "{signer}: guarded lock costs {}",
            cu[3] - cu[1]
        );
        assert!(
            cu[4] - cu[1] < 1_000,
            "{signer}: captured lock costs {}",
            cu[4] - cu[1]
        );
    }
}

// ---------------------------------------------------------------------------
// Non-holders may spend exactly up to the available amount
// ---------------------------------------------------------------------------

/// Asserts the transaction failed, and not because of a lock.
fn assert_fails_without_lock_violation(
    result: Result<TransactionMetadata, FailedTransactionMetadata>,
) {
    match result {
        Ok(_) => panic!("transaction unexpectedly succeeded"),
        Err(failed) => {
            if let TransactionError::InstructionError(_, InstructionError::Custom(code)) =
                failed.err
            {
                assert_ne!(
                    code,
                    SwigError::AuthorizationLockViolated as u32,
                    "{}",
                    failed.meta.pretty_logs()
                );
            }
        },
    }
}

/// Spends `available + 1` (rejected by the lock), then exactly `available`,
/// then 1 more (rejected again).
fn assert_exact_boundary(
    w: &mut Wallet,
    signer: &Keypair,
    spend: &dyn Fn(&mut Wallet, &Keypair, u64) -> Instruction,
    available: u64,
) {
    let over = spend(w, signer, available + 1);
    assert_swig_error(
        w.send(&[over], &[signer]),
        SwigError::AuthorizationLockViolated,
    );
    let exact = spend(w, signer, available);
    ok(w.send(&[exact], &[signer]));
    let one = spend(w, signer, 1);
    assert_swig_error(
        w.send(&[one], &[signer]),
        SwigError::AuthorizationLockViolated,
    );
}

fn sol_spender(limit: u64) -> Vec<ClientAction> {
    vec![
        ClientAction::SolLimit(SolLimit { amount: limit }),
        ClientAction::Program(Program {
            program_id: solana_system_interface::program::ID.to_bytes(),
        }),
    ]
}

fn token_spender(mint: &Pubkey, program: &Pubkey, limit: u64) -> Vec<ClientAction> {
    vec![
        ClientAction::TokenLimit(TokenLimit {
            token_mint: mint.to_bytes(),
            current_amount: limit,
        }),
        ClientAction::Program(Program {
            program_id: program.to_bytes(),
        }),
    ]
}

/// A wallet whose card role holds a 3 SOL lock, with the SOL others may spend.
fn sol_locked_wallet() -> (Wallet, u64) {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 500;
    ok(w.add_sol_lock(&card, CARD_ROLE, 3 * LAMPORTS_PER_SOL, expiry));
    let available = w.lockable_sol() - 3 * LAMPORTS_PER_SOL;
    (w, available)
}

fn sol_spend(role: u32) -> impl Fn(&mut Wallet, &Keypair, u64) -> Instruction {
    move |w: &mut Wallet, signer: &Keypair, lamports: u64| w.sol_transfer_ix(signer, role, lamports)
}

#[test]
fn others_spend_exactly_the_available_sol() {
    // The owner (`All`).
    let (mut w, available) = sol_locked_wallet();
    let root = w.root.insecure_clone();
    assert_exact_boundary(&mut w, &root, &sol_spend(ROOT_ROLE), available);
    assert_eq!(w.lockable_sol(), 3 * LAMPORTS_PER_SOL);

    // A limited role with no lock permissions and a limit above what is
    // available: the lock, not the limit, is the boundary.
    let (mut w, available) = sol_locked_wallet();
    let (spender, role) = w.add_role(sol_spender(100 * LAMPORTS_PER_SOL));
    assert_exact_boundary(&mut w, &spender, &sol_spend(role), available);
    assert_eq!(w.lockable_sol(), 3 * LAMPORTS_PER_SOL);

    // A limited role whose limit binds first fails on its limit, not the lock.
    let (mut w, available) = sol_locked_wallet();
    let limit = available / 2;
    let (spender, role) = w.add_role(sol_spender(limit));
    assert_fails_without_lock_violation(w.spend_sol(&spender, role, limit + 1));
    ok(w.spend_sol(&spender, role, limit));
    assert_fails_without_lock_violation(w.spend_sol(&spender, role, 1));
    // The rest stays spendable by others, exactly to the boundary.
    let root = w.root.insecure_clone();
    assert_exact_boundary(&mut w, &root, &sol_spend(ROOT_ROLE), available - limit);
}

#[test]
fn several_non_holder_spends_together_reach_the_boundary() {
    // Two SignV2 instructions in one transaction.
    let (mut w, available) = sol_locked_wallet();
    let root = w.root.insecure_clone();
    let first = w.sol_transfer_ix(&root, ROOT_ROLE, available / 3);
    let over = w.sol_transfer_ix(&root, ROOT_ROLE, available - available / 3 + 1);
    assert_swig_error(
        w.send(&[first.clone(), over], &[&root]),
        SwigError::AuthorizationLockViolated,
    );
    let rest = w.sol_transfer_ix(&root, ROOT_ROLE, available - available / 3);
    ok(w.send(&[first, rest], &[&root]));
    assert_eq!(w.lockable_sol(), 3 * LAMPORTS_PER_SOL);

    // Sequential transactions by two different non-holders.
    let (mut w, available) = sol_locked_wallet();
    let root = w.root.insecure_clone();
    let (spender, role) = w.add_role(sol_spender(100 * LAMPORTS_PER_SOL));
    ok(w.spend_sol(&spender, role, available / 4));
    ok(w.spend_sol(&root, ROOT_ROLE, available / 4));
    let left = available - 2 * (available / 4);
    assert_exact_boundary(&mut w, &spender, &sol_spend(role), left);
}

/// SPL Token or Token-2022 fixture: a 1_000-token account held 600 by a
/// limited card, plus a destination account.
struct TokenFixture {
    w: Wallet,
    program: Pubkey,
    mint: Pubkey,
    source: Pubkey,
    destination: Pubkey,
    card: Keypair,
    card_role: u32,
}

impl TokenFixture {
    fn new(token_2022: bool) -> Self {
        let mut w = Wallet::new(LAMPORTS_PER_SOL);
        let (program, mint, source, destination) = if token_2022 {
            let (mint, source) = token_2022_fixture(&mut w, false);
            let destination = token_2022_account(&mut w, &mint, &Keypair::new().pubkey(), 0);
            (spl_token_2022_interface::ID, mint, source, destination)
        } else {
            let (mint, source) = w.token_setup(1_000);
            let payer = w.context.default_payer.insecure_clone();
            let owner = Keypair::new().pubkey();
            let destination = setup_ata(&mut w.context.svm, &mint, &owner, &payer).unwrap();
            (spl_token::ID, mint, source, destination)
        };
        let (card, card_role) = w.add_role(vec![
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint.to_bytes(),
                current_amount: 1_000,
            }),
            ClientAction::Program(Program {
                program_id: program.to_bytes(),
            }),
        ]);
        let expiry = w.slot() + 500;
        ok(w.add_lock(&card, card_role, source, mint.to_bytes(), 600, expiry));
        Self {
            w,
            program,
            mint,
            source,
            destination,
            card,
            card_role,
        }
    }

    fn spend(&self, role: u32) -> impl Fn(&mut Wallet, &Keypair, u64) -> Instruction {
        let (program, source, destination) = (self.program, self.source, self.destination);
        move |w: &mut Wallet, signer: &Keypair, amount: u64| {
            #[allow(deprecated)]
            let inner = if program == spl_token::ID {
                spl_token::instruction::transfer(
                    &program,
                    &source,
                    &destination,
                    &w.wallet,
                    &[],
                    amount,
                )
                .unwrap()
            } else {
                spl_token_2022_interface::instruction::transfer(
                    &program,
                    &source,
                    &destination,
                    &w.wallet,
                    &[],
                    amount,
                )
                .unwrap()
            };
            w.sign_ix(signer, role, inner)
        }
    }

    fn send_spend(
        &mut self,
        signer: &Keypair,
        role: u32,
        amount: u64,
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        let ix = self.spend(role)(&mut self.w, signer, amount);
        self.w.send(&[ix], &[signer])
    }
}

#[test]
fn others_spend_exactly_the_available_tokens() {
    for token_2022 in [false, true] {
        // The owner (`All`).
        let mut f = TokenFixture::new(token_2022);
        let root = f.w.root.insecure_clone();
        let spend = f.spend(ROOT_ROLE);
        assert_exact_boundary(&mut f.w, &root, &spend, 400);
        assert_eq!(f.w.token_balance(&f.source), 600);

        // A limited role with no lock permissions and a larger limit.
        let mut f = TokenFixture::new(token_2022);
        let (spender, role) = f.w.add_role(token_spender(&f.mint, &f.program, 10_000));
        let spend = f.spend(role);
        assert_exact_boundary(&mut f.w, &spender, &spend, 400);

        // A limited role whose limit binds first.
        let mut f = TokenFixture::new(token_2022);
        let (spender, role) = f.w.add_role(token_spender(&f.mint, &f.program, 250));
        assert_fails_without_lock_violation(f.send_spend(&spender, role, 251));
        ok(f.send_spend(&spender, role, 250));
        assert_fails_without_lock_violation(f.send_spend(&spender, role, 1));
        let root = f.w.root.insecure_clone();
        let spend = f.spend(ROOT_ROLE);
        assert_exact_boundary(&mut f.w, &root, &spend, 150);
    }
}

#[test]
fn a_partial_capture_lowers_the_floor_for_others_by_exactly_that_amount() {
    for token_2022 in [false, true] {
        let mut f = TokenFixture::new(token_2022);
        let root = f.w.root.insecure_clone();
        // Others are held to 400 of 1_000 before the capture.
        assert_swig_error(
            f.send_spend(&root, ROOT_ROLE, 401),
            SwigError::AuthorizationLockViolated,
        );
        let card = f.card.insecure_clone();
        ok(f.send_spend(&card, f.card_role, 250));
        assert_eq!(f.w.lock(0).amount, 350);
        // The floor fell from 600 to 350: others may spend the 750 left down
        // to 350, i.e. 400 + the 250 captured - the 250 the holder spent.
        let spend = f.spend(ROOT_ROLE);
        assert_exact_boundary(&mut f.w, &root, &spend, 400);
        assert_eq!(f.w.token_balance(&f.source), 350);
    }

    // SOL: a 3 SOL hold, 1 SOL captured, others' floor is now 2 SOL.
    let (mut w, available) = sol_locked_wallet();
    let card = w.card.insecure_clone();
    ok(w.spend_sol(&card, CARD_ROLE, LAMPORTS_PER_SOL));
    assert_eq!(w.lock(0).amount, 2 * LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    assert_exact_boundary(&mut w, &root, &sol_spend(ROOT_ROLE), available);
    assert_eq!(w.lockable_sol(), 2 * LAMPORTS_PER_SOL);
}

#[test]
fn inactive_locks_leave_the_full_balance_to_others() {
    for token_2022 in [false, true] {
        // Captured to zero but still stored.
        let mut f = TokenFixture::new(token_2022);
        let card = f.card.insecure_clone();
        ok(f.send_spend(&card, f.card_role, 600));
        assert_eq!(f.w.lock(0).amount, 0);
        let root = f.w.root.insecure_clone();
        assert_fails_without_lock_violation(f.send_spend(&root, ROOT_ROLE, 401));
        ok(f.send_spend(&root, ROOT_ROLE, 400));
        assert_eq!(f.w.token_balance(&f.source), 0);

        // Expired.
        let mut f = TokenFixture::new(token_2022);
        let expiry = f.w.lock(0).expiry_slot;
        f.w.warp(expiry);
        let root = f.w.root.insecure_clone();
        assert_fails_without_lock_violation(f.send_spend(&root, ROOT_ROLE, 1_001));
        ok(f.send_spend(&root, ROOT_ROLE, 1_000));
        assert_eq!(f.w.token_balance(&f.source), 0);
    }

    // SOL: an expired hold, then a hold captured to zero.
    let (mut w, _) = sol_locked_wallet();
    let expiry = w.lock(0).expiry_slot;
    w.warp(expiry);
    let root = w.root.insecure_clone();
    let lockable = w.lockable_sol();
    assert_fails_without_lock_violation(w.spend_sol(&root, ROOT_ROLE, lockable + 1));
    ok(w.spend_sol(&root, ROOT_ROLE, lockable));
    assert_eq!(w.lockable_sol(), 0);

    let (mut w, _) = sol_locked_wallet();
    let card = w.card.insecure_clone();
    ok(w.spend_sol(&card, CARD_ROLE, 3 * LAMPORTS_PER_SOL));
    assert_eq!(w.lock(0).amount, 0);
    let (spender, role) = w.add_role(sol_spender(100 * LAMPORTS_PER_SOL));
    let lockable = w.lockable_sol();
    assert_fails_without_lock_violation(w.spend_sol(&spender, role, lockable + 1));
    ok(w.spend_sol(&spender, role, lockable));
    assert_eq!(w.lockable_sol(), 0);
}

#[test]
fn mixed_holders_each_spend_exactly_to_their_own_boundary() {
    // Balance 100, Bob holds 50 and Carol 30: others may spend exactly 20,
    // Bob 70, Carol 50.
    fn fixture() -> (Wallet, Pubkey, Pubkey, (Keypair, u32), (Keypair, u32)) {
        let mut w = Wallet::new(LAMPORTS_PER_SOL);
        let (mint, ata) = w.token_setup(100);
        let bob = w.add_token_card(&mint, 1_000);
        let carol = w.add_token_card(&mint, 1_000);
        let expiry = w.slot() + 500;
        ok(w.add_lock(&bob.0, bob.1, ata, mint.to_bytes(), 50, expiry));
        ok(w.add_lock(&carol.0, carol.1, ata, mint.to_bytes(), 30, expiry));
        (w, mint, ata, bob, carol)
    }
    let spend = |role: u32, mint: Pubkey, ata: Pubkey| {
        move |w: &mut Wallet, signer: &Keypair, amount: u64| {
            w.token_transfer_ix(signer, role, &mint, &ata, amount)
        }
    };

    let (mut w, mint, ata, _, _) = fixture();
    let root = w.root.insecure_clone();
    assert_exact_boundary(&mut w, &root, &spend(ROOT_ROLE, mint, ata), 20);
    assert_eq!(w.token_balance(&ata), 80);

    let (mut w, mint, ata, _, _) = fixture();
    let (spender, role) = w.add_role(token_spender(&mint, &spl_token::ID, 1_000));
    assert_exact_boundary(&mut w, &spender, &spend(role, mint, ata), 20);

    let (mut w, mint, ata, (bob, bob_role), _) = fixture();
    assert_exact_boundary(&mut w, &bob, &spend(bob_role, mint, ata), 70);
    assert_eq!(w.token_balance(&ata), 30);
    assert_eq!((w.lock(0).amount, w.lock(1).amount), (0, 30));

    let (mut w, mint, ata, _, (carol, carol_role)) = fixture();
    assert_exact_boundary(&mut w, &carol, &spend(carol_role, mint, ata), 50);
    assert_eq!(w.token_balance(&ata), 50);
    assert_eq!((w.lock(0).amount, w.lock(1).amount), (50, 0));
}

// ---------------------------------------------------------------------------
// SignV2 stays lean: no extra accounts, no resizing
// ---------------------------------------------------------------------------

#[test]
fn capture_to_zero_neither_resizes_nor_refunds_the_config() {
    // An unrestricted holder, so SignV2 charges no limit in the config either.
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let (holder, role) = w.add_issuer();
    let expiry = w.slot() + 500;
    ok(w.add_sol_lock(&holder, role, LAMPORTS_PER_SOL, expiry));
    let config = w.context.svm.get_account(&w.swig).unwrap();
    ok(w.spend_sol(&holder, role, LAMPORTS_PER_SOL));
    let after = w.context.svm.get_account(&w.swig).unwrap();
    assert_eq!(after.data.len(), config.data.len());
    assert_eq!(after.lamports, config.lamports);
    let (_, locks) = w.locks();
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0].amount, 0);
    assert_eq!(
        AuthorizationLock {
            amount: LAMPORTS_PER_SOL,
            ..locks[0]
        },
        AuthorizationLock {
            asset_account: w.wallet.to_bytes(),
            mint: NATIVE,
            amount: LAMPORTS_PER_SOL,
            expiry_slot: expiry,
            role_id: role,
            lock_id: 0,
        }
    );
    // Only the amount bytes changed.
    let mut expected = config.data.clone();
    let offset = expected.len() - LOCK_LEN + 64;
    expected[offset..offset + 8].copy_from_slice(&0u64.to_le_bytes());
    assert_eq!(after.data, expected);
}

#[test]
fn sign_v2_needs_no_extra_accounts_for_locks() {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let recipient = Keypair::new().pubkey();
    w.context.svm.airdrop(&recipient, LAMPORTS_PER_SOL).unwrap();
    let transfer = |w: &Wallet| system_instruction::transfer(&w.wallet, &recipient, 1_000_000);
    let card_ix = w.sign_ix(&card, CARD_ROLE, transfer(&w));
    let root_ix = w.sign_ix(&root, ROOT_ROLE, transfer(&w));
    let metas = |ix: &Instruction| {
        ix.accounts
            .iter()
            .map(|meta| (meta.pubkey, meta.is_signer, meta.is_writable))
            .collect::<Vec<_>>()
    };
    let no_lock_metas = (metas(&card_ix), metas(&root_ix));
    // Exactly config, wallet address, authority, then the inner
    // instruction's accounts: no payer, rent claimer, sysvar or mint.
    assert_eq!(
        no_lock_metas.0,
        vec![
            (w.swig, false, true),
            (w.wallet, false, true),
            (card.pubkey(), true, false),
            (solana_system_interface::program::ID, false, false),
            (recipient, false, true),
        ]
    );
    ok(w.send(&[card_ix.clone()], &[&card]));
    ok(w.send(&[root_ix.clone()], &[&root]));

    // With locks held by both the signer and another role, and a rent
    // claimer configured, the same instructions are built and succeed,
    // including capturing the signer's lock.
    let claimer = Keypair::new().pubkey();
    w.context.svm.airdrop(&claimer, LAMPORTS_PER_SOL).unwrap();
    set_rent_claimer_with_ed25519(&mut w.context, &w.swig, &root, ROOT_ROLE, claimer).unwrap();
    let expiry = w.slot() + 500;
    ok(w.add_sol_lock(&card, CARD_ROLE, 2_000_000, expiry));
    ok(w.add_sol_lock(&root, ROOT_ROLE, LAMPORTS_PER_SOL, expiry));
    let card_ix = w.sign_ix(&card, CARD_ROLE, transfer(&w));
    let root_ix = w.sign_ix(&root, ROOT_ROLE, transfer(&w));
    assert_eq!((metas(&card_ix), metas(&root_ix)), no_lock_metas);
    ok(w.send(&[card_ix], &[&card]));
    ok(w.send(&[root_ix], &[&root]));
    assert_eq!(w.lock(0).amount, 1_000_000);
    assert_eq!(w.lock(1).amount, LAMPORTS_PER_SOL - 1_000_000);
}

// ---------------------------------------------------------------------------
// Removing and changing a holder once its locks are inactive
// ---------------------------------------------------------------------------

const EXPIRES_SOON: u64 = 10;

impl Wallet {
    fn rent_accounts(&self) -> swig_interface::AuthorityRentAccounts {
        swig_interface::AuthorityRentAccounts {
            payer: self.context.default_payer.pubkey(),
            rent_claimer: self.rent_claimer(),
        }
    }

    fn remove_role(
        &mut self,
        signer: &Keypair,
        acting_role: u32,
        target: u32,
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        let ix = swig_interface::RemoveAuthorityInstruction::new_with_ed25519_authority(
            self.swig,
            self.rent_accounts(),
            signer.pubkey(),
            acting_role,
            target,
        )
        .unwrap();
        self.send(&[ix], &[signer])
    }

    fn update_role(
        &mut self,
        signer: &Keypair,
        acting_role: u32,
        target: u32,
        data: swig_interface::UpdateAuthorityData,
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        let ix = swig_interface::UpdateAuthorityInstruction::new_with_ed25519_authority(
            self.swig,
            self.rent_accounts(),
            signer.pubkey(),
            acting_role,
            target,
            data,
        )
        .unwrap();
        self.send(&[ix], &[signer])
    }

    fn replace_signer(
        &mut self,
        signer: &Keypair,
        acting_role: u32,
        target: u32,
        new_signer: &Pubkey,
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        let ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
            self.swig,
            signer.pubkey(),
            acting_role,
            target,
            new_signer.as_ref(),
        )
        .unwrap();
        self.send(&[ix], &[signer])
    }

    fn role_exists(&self, role_id: u32) -> bool {
        let data = self.data();
        swig_state::swig::SwigWithRoles::from_bytes(&data)
            .unwrap()
            .get_role(role_id)
            .unwrap()
            .is_some()
    }

    fn roles_end(&self) -> usize {
        Swig::roles_end_offset(&self.data()).unwrap()
    }

    fn add_manage_authority_admin(&mut self) -> (Keypair, u32) {
        self.add_role(vec![ClientAction::ManageAuthority(
            swig_state::action::manage_authority::ManageAuthority {},
        )])
    }
}

/// The card holds a short SOL lock (id 0); the root holds a long one (id 1).
fn wallet_with_expiring_card_lock() -> (Wallet, u64) {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let expiry = w.slot() + EXPIRES_SOON;
    ok(w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, expiry));
    let root_expiry = w.slot() + 500;
    ok(w.add_sol_lock(&root, ROOT_ROLE, LAMPORTS_PER_SOL, root_expiry));
    (w, expiry)
}

/// Removes the card with `actor` and checks that its inactive lock went with
/// it: the tail shrank by one record, rent went to the payer, and the root's
/// lock and the lock-id counter are untouched.
fn remove_card_and_check_pruning(w: &mut Wallet, actor: &Keypair, actor_role: u32) {
    let (next_before, locks_before) = w.locks();
    let root_lock = *locks_before
        .iter()
        .find(|lock| lock.role_id == ROOT_ROLE)
        .unwrap();
    let len_before = w.data().len();
    let roles_end_before = w.roles_end();
    let swig_before = w.context.svm.get_balance(&w.swig).unwrap();
    let payer = w.context.default_payer.pubkey();
    let payer_before = w.context.svm.get_balance(&payer).unwrap();

    let meta = ok(w.remove_role(actor, actor_role, CARD_ROLE));

    assert!(!w.role_exists(CARD_ROLE));
    let (next_after, locks_after) = w.locks();
    assert_eq!(next_after, next_before);
    assert_eq!(locks_after, vec![root_lock]);
    let role_bytes = roles_end_before - w.roles_end();
    let len_after = w.data().len();
    assert_eq!(len_after, len_before - role_bytes - LOCK_LEN);
    let rent = Rent::default();
    let refund = (rent.minimum_balance(len_before) - rent.minimum_balance(len_after))
        .min(swig_before - rent.minimum_balance(len_after));
    let swig_after = w.context.svm.get_balance(&w.swig).unwrap();
    assert_eq!(swig_after, swig_before - refund);
    assert!(swig_after >= rent.minimum_balance(len_after));
    assert_eq!(
        w.context.svm.get_balance(&payer).unwrap(),
        payer_before - meta.fee + refund
    );
}

#[test]
fn manage_authority_removes_a_holder_once_its_lock_expires() {
    let (mut w, expiry) = wallet_with_expiring_card_lock();
    let (admin, admin_role) = w.add_manage_authority_admin();
    assert_swig_error(
        w.remove_role(&admin, admin_role, CARD_ROLE),
        SwigError::AuthorizationLockActive,
    );
    w.warp(expiry - 1);
    assert_swig_error(
        w.remove_role(&admin, admin_role, CARD_ROLE),
        SwigError::AuthorizationLockActive,
    );
    w.warp(expiry);
    remove_card_and_check_pruning(&mut w, &admin, admin_role);
}

#[test]
fn manage_authority_removes_a_holder_whose_lock_was_captured_to_zero() {
    let (mut w, expiry) = wallet_with_expiring_card_lock();
    let (admin, admin_role) = w.add_manage_authority_admin();
    let card = w.card.insecure_clone();
    ok(w.spend_sol(&card, CARD_ROLE, LAMPORTS_PER_SOL));
    let card_lock = w.lock(0);
    assert_eq!(card_lock.amount, 0);
    assert!(w.slot() < expiry);
    remove_card_and_check_pruning(&mut w, &admin, admin_role);
}

#[test]
fn all_removes_a_holder_once_its_lock_expires() {
    let (mut w, expiry) = wallet_with_expiring_card_lock();
    let root = w.root.insecure_clone();
    assert_swig_error(
        w.remove_role(&root, ROOT_ROLE, CARD_ROLE),
        SwigError::AuthorizationLockActive,
    );
    w.warp(expiry);
    remove_card_and_check_pruning(&mut w, &root, ROOT_ROLE);
}

#[test]
fn a_holder_may_remove_itself_once_its_lock_expires() {
    let (mut w, expiry) = wallet_with_expiring_card_lock();
    let card = w.card.insecure_clone();
    assert_swig_error(
        w.remove_role(&card, CARD_ROLE, CARD_ROLE),
        SwigError::AuthorizationLockActive,
    );
    w.warp(expiry);
    remove_card_and_check_pruning(&mut w, &card, CARD_ROLE);
}

#[test]
fn all_but_manage_authority_cannot_remove_roles_locked_or_not() {
    let (mut w, expiry) = wallet_with_expiring_card_lock();
    let (actor, actor_role) = w.add_role(vec![ClientAction::AllButManageAuthority(
        swig_state::action::all_but_manage_authority::AllButManageAuthority {},
    )]);
    let denied = SwigAuthenticateError::PermissionDeniedToManageAuthority as u32;
    assert_eq!(
        custom_error(w.remove_role(&actor, actor_role, CARD_ROLE)),
        denied
    );
    w.warp(expiry);
    assert_eq!(
        custom_error(w.remove_role(&actor, actor_role, CARD_ROLE)),
        denied
    );
    assert!(w.role_exists(CARD_ROLE));
    assert_eq!(w.locks().1.len(), 2);
}

#[test]
fn removal_refunds_pruned_lock_rent_to_the_rent_claimer() {
    let (mut w, expiry) = wallet_with_expiring_card_lock();
    let root = w.root.insecure_clone();
    let claimer = Keypair::new().pubkey();
    w.context.svm.airdrop(&claimer, LAMPORTS_PER_SOL).unwrap();
    set_rent_claimer_with_ed25519(&mut w.context, &w.swig, &root, ROOT_ROLE, claimer).unwrap();
    let (admin, admin_role) = w.add_manage_authority_admin();
    w.warp(expiry);
    let len_before = w.data().len();
    let roles_end_before = w.roles_end();
    let swig_before = w.context.svm.get_balance(&w.swig).unwrap();
    let claimer_before = w.context.svm.get_balance(&claimer).unwrap();
    let payer = w.context.default_payer.pubkey();
    let payer_before = w.context.svm.get_balance(&payer).unwrap();
    let meta = ok(w.remove_role(&admin, admin_role, CARD_ROLE));
    let len_after = w.data().len();
    assert_eq!(
        len_after,
        len_before - (roles_end_before - w.roles_end()) - LOCK_LEN
    );
    let refund = swig_before - w.context.svm.get_balance(&w.swig).unwrap();
    let rent = Rent::default();
    assert_eq!(
        refund,
        rent.minimum_balance(len_before) - rent.minimum_balance(len_after)
    );
    assert_eq!(
        w.context.svm.get_balance(&claimer).unwrap(),
        claimer_before + refund
    );
    assert_eq!(
        w.context.svm.get_balance(&payer).unwrap(),
        payer_before - meta.fee
    );
    assert_eq!(w.rent_claimer(), Some(claimer));
    assert_eq!(w.locks().1.len(), 1);
}

#[test]
fn a_new_role_inherits_nothing_from_a_removed_holder() {
    let (mut w, expiry) = wallet_with_expiring_card_lock();
    let (admin, admin_role) = w.add_manage_authority_admin();
    w.warp(expiry);
    ok(w.remove_role(&admin, admin_role, CARD_ROLE));

    // Role ids come from a monotonic counter, so the card's id is never
    // reused, and its records are gone anyway.
    let (newcomer, new_role) = w.add_role(vec![
        ClientAction::All(All {}),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
    ]);
    assert!(new_role > admin_role);
    assert!(w.locks().1.iter().all(|lock| lock.role_id == ROOT_ROLE));
    // It cannot release the remaining lock, the card's old lock id is gone,
    // and the root's lock still binds it.
    assert_swig_error(
        w.remove_lock(&newcomer, new_role, 1),
        SwigError::AuthorizationLockNotOwner,
    );
    assert_swig_error(
        w.remove_lock(&newcomer, new_role, 0),
        SwigError::AuthorizationLockNotFound,
    );
    let available = w.lockable_sol() - LAMPORTS_PER_SOL;
    assert_swig_error(
        w.spend_sol(&newcomer, new_role, available + 1),
        SwigError::AuthorizationLockViolated,
    );
    ok(w.spend_sol(&newcomer, new_role, available));
    assert_eq!(w.lock(1).amount, LAMPORTS_PER_SOL);
    // New locks continue the counter.
    let wallet = w.wallet;
    w.context.svm.airdrop(&wallet, LAMPORTS_PER_SOL).unwrap();
    let expiry = w.slot() + 10;
    ok(w.add_sol_lock(&newcomer, new_role, 1, expiry));
    assert_eq!(w.locks().0, 3);
}

#[test]
fn manage_authority_updates_or_replaces_a_holder_once_its_locks_are_inactive() {
    use swig_interface::UpdateAuthorityData;
    use swig_state::action::Permission;
    let rewrite = || {
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::SolLimit(SolLimit {
            amount: LAMPORTS_PER_SOL,
        })])
    };

    // Expired.
    let (mut w, expiry) = wallet_with_expiring_card_lock();
    let (admin, admin_role) = w.add_manage_authority_admin();
    assert_swig_error(
        w.update_role(&admin, admin_role, CARD_ROLE, rewrite()),
        SwigError::AuthorizationLockActive,
    );
    let takeover = Keypair::new().pubkey();
    assert_swig_error(
        w.replace_signer(&admin, admin_role, CARD_ROLE, &takeover),
        SwigError::AuthorizationLockActive,
    );
    // Stripping only the lock permission was already allowed while active.
    ok(w.update_role(
        &admin,
        admin_role,
        CARD_ROLE,
        UpdateAuthorityData::RemoveActionsByType(vec![Permission::ManageAuthorizationLocks as u8]),
    ));
    w.warp(expiry);
    ok(w.update_role(&admin, admin_role, CARD_ROLE, rewrite()));
    ok(w.replace_signer(&admin, admin_role, CARD_ROLE, &takeover));
    // The records stay with the (still existing) role until pruned or the
    // role is removed.
    assert_eq!(w.locks().1.len(), 2);

    // Captured to zero.
    let (mut w, _) = wallet_with_expiring_card_lock();
    let (admin, admin_role) = w.add_manage_authority_admin();
    let card = w.card.insecure_clone();
    ok(w.spend_sol(&card, CARD_ROLE, LAMPORTS_PER_SOL));
    ok(w.update_role(&admin, admin_role, CARD_ROLE, rewrite()));
    let takeover = Keypair::new().pubkey();
    ok(w.replace_signer(&admin, admin_role, CARD_ROLE, &takeover));
}

#[test]
fn one_active_lock_still_blocks_removal_and_changes() {
    let (mut w, expiry) = wallet_with_expiring_card_lock();
    let card = w.card.insecure_clone();
    let long_expiry = w.slot() + 500;
    ok(w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, long_expiry));
    let (admin, admin_role) = w.add_manage_authority_admin();
    w.warp(expiry);
    assert!(!w.lock(0).is_active(w.slot()));
    assert!(w.lock(2).is_active(w.slot()));
    assert_swig_error(
        w.remove_role(&admin, admin_role, CARD_ROLE),
        SwigError::AuthorizationLockActive,
    );
    assert_swig_error(
        w.update_role(
            &admin,
            admin_role,
            CARD_ROLE,
            swig_interface::UpdateAuthorityData::ReplaceAll(vec![ClientAction::SolLimit(
                SolLimit { amount: 1 },
            )]),
        ),
        SwigError::AuthorizationLockActive,
    );
    let takeover = Keypair::new().pubkey();
    assert_swig_error(
        w.replace_signer(&admin, admin_role, CARD_ROLE, &takeover),
        SwigError::AuthorizationLockActive,
    );
    assert!(w.role_exists(CARD_ROLE));
    assert_eq!(w.locks().1.len(), 3);

    // Once that one is captured to zero, removal prunes both.
    ok(w.spend_sol(&card, CARD_ROLE, LAMPORTS_PER_SOL));
    let root_lock = w.lock(1);
    ok(w.remove_role(&admin, admin_role, CARD_ROLE));
    assert_eq!(w.locks(), (3, vec![root_lock]));
}
