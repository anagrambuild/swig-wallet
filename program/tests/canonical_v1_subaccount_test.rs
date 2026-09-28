#![cfg(not(feature = "program_scope_test"))]
//! Pre-upgrade alternate configs must not control another wallet's V1 subaccounts.
mod common;
#[path = "../src/error.rs"]
mod swig_error;

use common::*;
use litesvm_token::spl_token;
use solana_sdk::{
    instruction::{Instruction, InstructionError},
    message::{v0, VersionedMessage},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_error::SwigError;
use swig_interface::{
    AuthorityConfig, ClientAction, CreateInstruction, CreateSubAccountInstruction,
    SignV2Instruction, SubAccountSignInstruction, ToggleSubAccountInstruction,
    WithdrawFromSubAccountInstruction,
};
use swig_state::{
    action::{all::All, sub_account::SubAccount},
    authority::AuthorityType,
    role::Position,
    swig::{
        sub_account_seeds, swig_account_seeds, swig_account_seeds_with_bump,
        swig_wallet_address_seeds, Swig, SwigWithRoles,
    },
    Transmutable,
};

fn send(
    context: &mut SwigTestContext,
    authority: &Keypair,
    ix: Instruction,
) -> Result<(), TransactionError> {
    context.svm.expire_blockhash();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, authority],
    )
    .unwrap();
    context.svm.send_transaction(tx).map(|_| ()).map_err(|e| {
        eprintln!("{}", e.meta.pretty_logs());
        e.err
    })
}

fn alternate_config(id: &[u8; 32]) -> (Pubkey, u8) {
    let (_, canonical_bump) = Pubkey::find_program_address(&swig_account_seeds(id), &program_id());
    (0..canonical_bump)
        .rev()
        .find_map(|bump| {
            Pubkey::create_program_address(
                &swig_account_seeds_with_bump(id, &[bump]),
                &program_id(),
            )
            .ok()
            .map(|key| (key, bump))
        })
        .expect("fixture must have another valid config bump")
}

fn create_instruction(config: Pubkey, bump: u8, root: &Keypair, id: [u8; 32]) -> Instruction {
    let (wallet, wallet_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(config.as_ref()), &program_id());
    CreateInstruction::new(
        config,
        bump,
        root.pubkey(),
        wallet,
        wallet_bump,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: root.pubkey().as_ref(),
        },
        vec![
            ClientAction::All(All {}),
            ClientAction::SubAccount(SubAccount::new_for_creation()),
        ],
        id,
    )
    .unwrap()
}

/// Assert the exact preflight error and rollback of every supplied account except
/// the transaction fee payer. This includes token data, authority state and SOL.
fn assert_rejected_unchanged(
    context: &mut SwigTestContext,
    authority: &Keypair,
    ix: Instruction,
    error: SwigError,
    victim: Pubkey,
) {
    let before: Vec<_> = ix
        .accounts
        .iter()
        .map(|meta| meta.pubkey)
        .chain([victim])
        .filter(|key| *key != context.default_payer.pubkey())
        .map(|key| (key, context.svm.get_account(&key)))
        .collect();
    assert_eq!(
        send(context, authority, ix),
        Err(TransactionError::InstructionError(
            0,
            InstructionError::Custom(error as u32)
        ))
    );
    for (key, account) in before {
        assert_eq!(
            context.svm.get_account(&key),
            account,
            "account {key} changed"
        );
    }
}

struct Fixture {
    context: SwigTestContext,
    root: Keypair,
    attacker: Keypair,
    canonical: Pubkey,
    canonical_wallet: Pubkey,
    alternate: Pubkey,
    alternate_bump: u8,
    alternate_wallet: Pubkey,
    alternate_wallet_bump: u8,
    child: Pubkey,
    child_bump: u8,
}

impl Fixture {
    fn new(create_child: bool) -> Self {
        let mut context = setup_test_context().unwrap();
        let root = Keypair::new();
        let attacker = Keypair::new();
        context.svm.airdrop(&root.pubkey(), 10_000_000_000).unwrap();
        context
            .svm
            .airdrop(&attacker.pubkey(), 10_000_000_000)
            .unwrap();
        let id = [42; 32];
        let (canonical, bump) =
            Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
        let (canonical_wallet, _) = Pubkey::find_program_address(
            &swig_wallet_address_seeds(canonical.as_ref()),
            &program_id(),
        );
        send(
            &mut context,
            &root,
            create_instruction(canonical, bump, &root, id),
        )
        .unwrap();
        let (child, child_bump) = Pubkey::find_program_address(
            &sub_account_seeds(&id, &0u32.to_le_bytes()),
            &program_id(),
        );
        if create_child {
            assert_eq!(
                create_sub_account(&mut context, &canonical, &root, 0, id).unwrap(),
                child
            );
            context.svm.airdrop(&child, 1_000_000_000).unwrap();
        }
        let (alternate, alternate_bump) = alternate_config(&id);
        let (alternate_wallet, alternate_wallet_bump) = Pubkey::find_program_address(
            &swig_wallet_address_seeds(alternate.as_ref()),
            &program_id(),
        );
        context.svm.airdrop(&alternate_wallet, 1_000_000).unwrap();
        let mut fixture = Self {
            context,
            root,
            attacker,
            canonical,
            canonical_wallet,
            alternate,
            alternate_bump,
            alternate_wallet,
            alternate_wallet_bump,
            child,
            child_bump,
        };
        fixture.seed_preupgrade_alternate();
        fixture
    }

    fn seed_preupgrade_alternate(&mut self) {
        // Reconstruct state allowed before the upgrade: same ID/permissions/child,
        // a valid alternate config bump, and a different root authority. Production
        // creation now rejects this, so inject the existing account through LiteSVM.
        let mut account = self.context.svm.get_account(&self.canonical).unwrap();
        account.data[std::mem::offset_of!(Swig, bump)] = self.alternate_bump;
        account.data[std::mem::offset_of!(Swig, wallet_bump)] = self.alternate_wallet_bump;
        let auth_start = Swig::LEN + Position::LEN;
        assert_eq!(
            &account.data[auth_start..auth_start + 32],
            self.root.pubkey().as_ref()
        );
        account.data[auth_start..auth_start + 32].copy_from_slice(self.attacker.pubkey().as_ref());
        self.context
            .svm
            .set_account(self.alternate, account)
            .unwrap();
    }
}

#[test]
fn alternate_cannot_create_v1_subaccount() {
    let mut f = Fixture::new(false);
    let attack = CreateSubAccountInstruction::new_with_ed25519_authority(
        f.alternate,
        f.attacker.pubkey(),
        f.attacker.pubkey(),
        f.child,
        0,
        f.child_bump,
    )
    .unwrap();
    assert_rejected_unchanged(
        &mut f.context,
        &f.attacker,
        attack,
        SwigError::InvalidSeedSwigAccount,
        f.canonical,
    );
    let valid = CreateSubAccountInstruction::new_with_ed25519_authority(
        f.canonical,
        f.root.pubkey(),
        f.root.pubkey(),
        f.child,
        0,
        f.child_bump,
    )
    .unwrap();
    send(&mut f.context, &f.root, valid).unwrap();
    let child = f.context.svm.get_account(&f.child).unwrap();
    assert_eq!(child.owner, solana_system_interface::program::ID);
    assert!(child.lamports > 0);
}

#[test]
fn alternate_cannot_sign_with_v1_subaccount() {
    let mut f = Fixture::new(true);
    let transfer =
        solana_system_interface::instruction::transfer(&f.child, &f.attacker.pubkey(), 100_000);
    let attack = SubAccountSignInstruction::new_with_ed25519_authority(
        f.alternate,
        f.child,
        f.attacker.pubkey(),
        0,
        vec![transfer.clone()],
    )
    .unwrap();
    assert_rejected_unchanged(
        &mut f.context,
        &f.attacker,
        attack,
        SwigError::InvalidSeedSwigAccount,
        f.canonical,
    );
    let before = f.context.svm.get_balance(&f.child).unwrap();
    let valid = SubAccountSignInstruction::new_with_ed25519_authority(
        f.canonical,
        f.child,
        f.root.pubkey(),
        0,
        vec![transfer],
    )
    .unwrap();
    send(&mut f.context, &f.root, valid).unwrap();
    assert_eq!(
        f.context.svm.get_balance(&f.child).unwrap(),
        before - 100_000
    );
}

#[test]
fn alternate_cannot_withdraw_v1_sol() {
    let mut f = Fixture::new(true);
    let attack = WithdrawFromSubAccountInstruction::new_with_ed25519_authority(
        f.alternate,
        f.attacker.pubkey(),
        f.attacker.pubkey(),
        f.child,
        f.alternate_wallet,
        0,
        100_000,
    )
    .unwrap();
    assert_rejected_unchanged(
        &mut f.context,
        &f.attacker,
        attack,
        SwigError::InvalidSeedSwigAccount,
        f.canonical,
    );
    let before = f.context.svm.get_balance(&f.canonical_wallet).unwrap();
    let valid = WithdrawFromSubAccountInstruction::new_with_ed25519_authority(
        f.canonical,
        f.root.pubkey(),
        f.root.pubkey(),
        f.child,
        f.canonical_wallet,
        0,
        100_000,
    )
    .unwrap();
    send(&mut f.context, &f.root, valid).unwrap();
    assert_eq!(
        f.context.svm.get_balance(&f.canonical_wallet).unwrap(),
        before + 100_000
    );
}

#[test]
fn alternate_cannot_withdraw_v1_tokens() {
    let mut f = Fixture::new(true);
    let mint = setup_mint(&mut f.context.svm, &f.context.default_payer).unwrap();
    let source = setup_ata(
        &mut f.context.svm,
        &mint,
        &f.child,
        &f.context.default_payer,
    )
    .unwrap();
    let attacker_destination = setup_ata(
        &mut f.context.svm,
        &mint,
        &f.alternate_wallet,
        &f.context.default_payer,
    )
    .unwrap();
    let owner_destination = setup_ata(
        &mut f.context.svm,
        &mint,
        &f.canonical_wallet,
        &f.context.default_payer,
    )
    .unwrap();
    mint_to(
        &mut f.context.svm,
        &mint,
        &f.context.default_payer,
        &source,
        1000,
    )
    .unwrap();
    let attack = WithdrawFromSubAccountInstruction::new_token_with_ed25519_authority(
        f.alternate,
        f.attacker.pubkey(),
        f.attacker.pubkey(),
        f.child,
        f.alternate_wallet,
        source,
        attacker_destination,
        spl_token::id(),
        0,
        10,
    )
    .unwrap();
    assert_rejected_unchanged(
        &mut f.context,
        &f.attacker,
        attack,
        SwigError::InvalidSeedSwigAccount,
        f.canonical,
    );
    let valid = WithdrawFromSubAccountInstruction::new_token_with_ed25519_authority(
        f.canonical,
        f.root.pubkey(),
        f.root.pubkey(),
        f.child,
        f.canonical_wallet,
        source,
        owner_destination,
        spl_token::id(),
        0,
        10,
    )
    .unwrap();
    send(&mut f.context, &f.root, valid).unwrap();
    let destination = f.context.svm.get_account(&owner_destination).unwrap();
    assert_eq!(
        spl_token::state::Account::unpack(&destination.data)
            .unwrap()
            .amount,
        10
    );
    let source = f.context.svm.get_account(&source).unwrap();
    assert_eq!(
        spl_token::state::Account::unpack(&source.data)
            .unwrap()
            .amount,
        990
    );
}

#[test]
fn alternate_cannot_toggle_v1_subaccount() {
    let mut f = Fixture::new(true);
    let attack = ToggleSubAccountInstruction::new_with_ed25519_authority(
        f.alternate,
        f.attacker.pubkey(),
        f.attacker.pubkey(),
        f.child,
        0,
        0,
        false,
    )
    .unwrap();
    assert_rejected_unchanged(
        &mut f.context,
        &f.attacker,
        attack,
        SwigError::InvalidSeedSwigAccount,
        f.canonical,
    );
    let valid = ToggleSubAccountInstruction::new_with_ed25519_authority(
        f.canonical,
        f.root.pubkey(),
        f.root.pubkey(),
        f.child,
        0,
        0,
        false,
    )
    .unwrap();
    send(&mut f.context, &f.root, valid).unwrap();
    let account = f.context.svm.get_account(&f.canonical).unwrap();
    let swig = SwigWithRoles::from_bytes(&account.data).unwrap();
    let role = swig.get_role(0).unwrap().unwrap();
    assert!(
        !role
            .get_action::<SubAccount>(f.child.as_ref())
            .unwrap()
            .unwrap()
            .enabled
    );
}

#[test]
fn v1_guard_rejects_invalid_config_headers_without_mutation() {
    let mut f = Fixture::new(true);
    let ix = ToggleSubAccountInstruction::new_with_ed25519_authority(
        f.canonical,
        f.root.pubkey(),
        f.root.pubkey(),
        f.child,
        0,
        0,
        false,
    )
    .unwrap();
    let original = f.context.svm.get_account(&f.canonical).unwrap();
    for case in 0..6 {
        let mut account = original.clone();
        let expected = match case {
            0 => {
                account.data[std::mem::offset_of!(Swig, bump)] ^= 1;
                SwigError::InvalidSeedSwigAccount
            },
            1 => {
                account.data[std::mem::offset_of!(Swig, id)] ^= 1;
                SwigError::InvalidSeedSwigAccount
            },
            2 => {
                account.data.truncate(Swig::LEN - 1);
                SwigError::InvalidSwigAccountDiscriminator
            },
            3 => {
                account.data.clear();
                SwigError::InvalidSwigAccountDiscriminator
            },
            4 => {
                account.data[0] = 255;
                SwigError::InvalidSwigAccountDiscriminator
            },
            _ => {
                account.owner = solana_system_interface::program::ID;
                SwigError::OwnerMismatchSwigAccount
            },
        };
        f.context.svm.set_account(f.canonical, account).unwrap();
        assert_rejected_unchanged(&mut f.context, &f.root, ix.clone(), expected, f.canonical);
    }
}

#[test]
fn ordinary_sign_v2_still_accepts_preexisting_alternate_config() {
    let mut f = Fixture::new(false);
    let before = f.context.svm.get_balance(&f.alternate_wallet).unwrap();
    let ix = SignV2Instruction::new_ed25519(
        f.alternate,
        f.alternate_wallet,
        f.attacker.pubkey(),
        solana_system_interface::instruction::transfer(&f.alternate_wallet, &f.root.pubkey(), 1),
        0,
    )
    .unwrap();
    send(&mut f.context, &f.attacker, ix).unwrap();
    assert_eq!(
        f.context.svm.get_balance(&f.alternate_wallet).unwrap(),
        before - 1
    );
}
