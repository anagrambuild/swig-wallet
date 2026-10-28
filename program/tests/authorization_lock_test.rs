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
    CloseSwigV1Instruction, CloseTokenAccountV1Instruction, RemoveAuthorizationLockV1Instruction,
    ReplaceAuthorityInstruction, SignV2Instruction,
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
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds, Swig},
    tail::{
        authorization_locks::{self, AuthorizationLock, LOCK_LEN, MAX_AUTHORIZATION_LOCKS},
        rent_claimer,
    },
    SwigAuthenticateError, SwigStateError,
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
fn sol_lock_binds_the_creating_role_until_released() {
    let mut w = Wallet::new(20 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 500;
    let lockable = w.lockable_sol();
    ok(w.add_sol_lock(&card, CARD_ROLE, lockable, expiry));
    assert_swig_error(
        w.spend_sol(&card, CARD_ROLE, LAMPORTS_PER_SOL),
        SwigError::AuthorizationLockViolated,
    );
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
fn partial_capture_cannot_dip_into_a_second_lock() {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 500;
    ok(w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, expiry));
    ok(w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, expiry));
    let spendable = w.lockable_sol() - 2 * LAMPORTS_PER_SOL;
    ok(w.spend_sol(&root, ROOT_ROLE, spendable));

    let release = w.remove_lock_ix(&card, CARD_ROLE, 0);
    let overspend = w.sol_transfer_ix(&card, CARD_ROLE, LAMPORTS_PER_SOL + 1);
    assert_swig_error(
        w.send(&[release.clone(), overspend], &[&card]),
        SwigError::AuthorizationLockViolated,
    );
    let spend = w.sol_transfer_ix(&card, CARD_ROLE, LAMPORTS_PER_SOL);
    ok(w.send(&[release, spend], &[&card]));
    assert_eq!(w.locks().1.len(), 1);
}

#[test]
fn locks_from_several_roles_are_summed() {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 500;
    ok(w.add_sol_lock(&card, CARD_ROLE, 2 * LAMPORTS_PER_SOL, expiry));
    ok(w.add_sol_lock(&root, ROOT_ROLE, 3 * LAMPORTS_PER_SOL, expiry));
    let spendable = w.lockable_sol() - 5 * LAMPORTS_PER_SOL;
    assert_swig_error(
        w.spend_sol(&root, ROOT_ROLE, spendable + 1),
        SwigError::AuthorizationLockViolated,
    );
    ok(w.spend_sol(&root, ROOT_ROLE, spendable));
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
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 500;
    let lockable = w.lockable_sol();
    ok(w.add_sol_lock(&root, ROOT_ROLE, lockable, expiry));

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
}

#[test]
fn underfunded_locked_account_may_not_shrink_further() {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let root = w.root.insecure_clone();
    let (mint, ata) = w.token_setup(1_000);
    let expiry = w.slot() + 500;
    let wallet = w.wallet;
    let _ = wallet;
    ok(w.add_lock(&root, ROOT_ROLE, ata, mint.to_bytes(), 800, expiry));

    // Simulate an external debit (e.g. a permanent delegate) below the lock.
    let mut account = w.context.svm.get_account(&ata).unwrap();
    account.data[64..72].copy_from_slice(&500u64.to_le_bytes());
    w.context.svm.set_account(ata, account).unwrap();

    let ix = w.token_transfer_ix(&root, ROOT_ROLE, &mint, &ata, 1);
    assert_swig_error(
        w.send(&[ix], &[&root]),
        SwigError::AuthorizationLockViolated,
    );
    let _ = card;
}

#[test]
fn token_lock_binds_all_role_and_only_the_locked_account() {
    let mut w = Wallet::new(5 * LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
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
    ok(w.add_lock(&root, ROOT_ROLE, ata, mint.to_bytes(), 600, expiry));

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
}

#[test]
fn locked_token_account_cannot_change_authority_delegate_or_close_authority() {
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
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint.to_bytes(),
                current_amount: 1_000,
            }),
            ClientAction::Program(Program {
                program_id: spl_token::ID.to_bytes(),
            }),
        ],
    )
    .unwrap();
    let expiry = w.slot() + 500;
    ok(w.add_lock(&root, ROOT_ROLE, ata, mint.to_bytes(), 900, expiry));
    let ix = w.token_transfer_ix(&spender, 2, &mint, &ata, 101);
    assert_swig_error(
        w.send(&[ix], &[&spender]),
        SwigError::AuthorizationLockViolated,
    );
    let ix = w.token_transfer_ix(&spender, 2, &mint, &ata, 100);
    ok(w.send(&[ix], &[&spender]));
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
    ix.accounts.remove(3);
    ix.data.pop();
    ix.data.push(3);
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

    // Enforcement and release still work afterwards.
    let spendable = w.lockable_sol() - 3 * LAMPORTS_PER_SOL;
    assert_swig_error(
        w.spend_sol(&root, ROOT_ROLE, spendable + 1),
        SwigError::AuthorizationLockViolated,
    );
    ok(w.remove_lock(&card, CARD_ROLE, 0));
    ok(w.spend_sol(&root, ROOT_ROLE, spendable + 2 * LAMPORTS_PER_SOL));
    assert_eq!(w.rent_claimer(), Some(claimer));
}

// ---------------------------------------------------------------------------
// Bypass regressions
// ---------------------------------------------------------------------------

#[test]
fn blocked_wallet_funded_create_account_cannot_spend_locked_sol() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 100;
    let lockable = w.lockable_sol();
    ok(w.add_sol_lock(&root, ROOT_ROLE, lockable, expiry));
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
    let (mint, ata) = w.token_setup(1_000);
    let expiry = w.slot() + 100;
    ok(w.add_lock(&root, ROOT_ROLE, ata, mint.to_bytes(), 1_000, expiry));
    let inner =
        spl_token::instruction::burn(&spl_token::ID, &ata, &mint, &w.wallet, &[], 1).unwrap();
    let ix = w.sign_ix(&root, ROOT_ROLE, inner);
    assert_swig_error(
        w.send(&[ix], &[&root]),
        SwigError::AuthorizationLockViolated,
    );
    assert_eq!(w.token_balance(&ata), 1_000);
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
    ok(w.add_lock(&root, ROOT_ROLE, ata, mint.to_bytes(), 1_000, expiry));

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
    let release = w.remove_lock_ix(&card, CARD_ROLE, 0);
    let capture = w.sol_transfer_ix(&card, CARD_ROLE, LAMPORTS_PER_SOL);
    ok(w.send(&[release, capture], &[&card]));
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
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let expiry = w.slot() + 100;
    let baseline = ok(w.spend_sol(&root, ROOT_ROLE, LAMPORTS_PER_SOL)).compute_units_consumed;
    for _ in 0..MAX_AUTHORIZATION_LOCKS {
        ok(w.add_sol_lock(&root, ROOT_ROLE, 1, expiry));
    }
    let locked = ok(w.spend_sol(&root, ROOT_ROLE, LAMPORTS_PER_SOL)).compute_units_consumed;
    println!("AUTH_LOCK_CU baseline {baseline} with_max_locks {locked}");
    // Covers the ComputeBudget instruction plus SignV2.
    assert!(
        locked - baseline < 10_000,
        "32 locks added {} CU",
        locked - baseline
    );
}

// ---------------------------------------------------------------------------
// The creator's limits back its reservations
// ---------------------------------------------------------------------------

#[test]
fn creator_cannot_spend_the_limit_backing_its_locks() {
    let mut w = Wallet::new(2 * LAMPORTS_PER_SOL);
    let card = w.card.insecure_clone();
    let expiry = w.slot() + 500;
    ok(w.add_sol_lock(&card, CARD_ROLE, 3 * LAMPORTS_PER_SOL / 2, expiry));

    // 2 SOL limit, 1.5 SOL held: only 0.5 SOL is free to spend elsewhere,
    // even though the wallet balance is far above the lock floor.
    assert_swig_error(
        w.spend_sol(&card, CARD_ROLE, LAMPORTS_PER_SOL),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );
    ok(w.spend_sol(&card, CARD_ROLE, LAMPORTS_PER_SOL / 2));
    assert_swig_error(
        w.spend_sol(&card, CARD_ROLE, 1),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );

    // Capturing the hold uses exactly the reserved allowance.
    let release = w.remove_lock_ix(&card, CARD_ROLE, 0);
    let capture = w.sol_transfer_ix(&card, CARD_ROLE, 3 * LAMPORTS_PER_SOL / 2);
    ok(w.send(&[release, capture], &[&card]));
    // The limit is now exhausted.
    assert!(w.spend_sol(&card, CARD_ROLE, 1).is_err());
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
    assert_swig_error(
        w.spend_sol(&card, CARD_ROLE, 1),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );

    // A fresh window restores the full allowance; the hold still reserves 1.
    let next_window = w.slot() + window + 1;
    w.warp(next_window);
    ok(w.add_sol_lock(&card, CARD_ROLE, LAMPORTS_PER_SOL, expiry));
    assert_swig_error(
        w.spend_sol(&card, CARD_ROLE, LAMPORTS_PER_SOL + 1),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );
    ok(w.spend_sol(&card, CARD_ROLE, LAMPORTS_PER_SOL));
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

    let pay = |w: &Wallet, lamports| {
        w.sign_ix(
            &card,
            CARD_ROLE,
            system_instruction::transfer(&w.wallet, &merchant, lamports),
        )
    };
    let early = pay(&w, LAMPORTS_PER_SOL / 2);
    assert_swig_error(
        w.send(&[early], &[&card]),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );
    let release = w.remove_lock_ix(&card, CARD_ROLE, 0);
    let capture = pay(&w, LAMPORTS_PER_SOL);
    ok(w.send(&[release, capture], &[&card]));
}

#[test]
fn token_limits_back_token_locks() {
    let mut w = Wallet::new(LAMPORTS_PER_SOL);
    let root = w.root.insecure_clone();
    let (mint, ata) = w.token_setup(10_000);
    let card = Keypair::new();
    add_authority_with_ed25519_root(
        &mut w.context,
        &w.swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: card.pubkey().as_ref(),
        },
        vec![
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks::new(MAX_DURATION)),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint.to_bytes(),
                current_amount: 1_000,
            }),
            ClientAction::Program(Program {
                program_id: spl_token::ID.to_bytes(),
            }),
        ],
    )
    .unwrap();
    let role = 2;
    let expiry = w.slot() + 500;
    ok(w.add_lock(&card, role, ata, mint.to_bytes(), 600, expiry));

    let ix = w.token_transfer_ix(&card, role, &mint, &ata, 401);
    assert_swig_error(
        w.send(&[ix], &[&card]),
        SwigError::AuthorizationLockExceedsSpendLimit,
    );
    let ix = w.token_transfer_ix(&card, role, &mint, &ata, 400);
    ok(w.send(&[ix], &[&card]));
    let release = w.remove_lock_ix(&card, role, 0);
    let capture = w.token_transfer_ix(&card, role, &mint, &ata, 600);
    ok(w.send(&[release, capture], &[&card]));
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
