#![cfg(not(feature = "program_scope_test"))]
//! Roles ⟂ tail invariance.
//!
//! These tests assert that the presence or absence of the rent-claimer tail does
//! NOT affect the roles in any way, and that the roles keep working across every
//! mutation while the rent claimer (when set) is preserved byte-for-byte.
//!
//! Two complementary angles:
//!   * **Differential** — run the *same* role operations on two wallets that share
//!     identical authorities; one carries a tail, one does not. The roles region
//!     must come out byte-for-byte identical.
//!   * **Functional** — after mutating roles on a tailed wallet, the roles still
//!     authenticate and authorize real work (adding authorities, and a SignV2
//!     SOL spend), and the claimer value never changes.

mod common;

use common::*;
use solana_sdk::{
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ClientAction, SignV2Instruction};
use swig_state::{
    action::{all::All, manage_authority::ManageAuthority, sol_limit::SolLimit},
    authority::AuthorityType,
    swig::{swig_wallet_address_seeds, Swig, SwigWithRoles},
    tail::rent_claimer,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn account_data(context: &SwigTestContext, swig: &Pubkey) -> Vec<u8> {
    context.svm.get_account(swig).unwrap().data
}

/// The roles region only (header + tail excluded). This is what must be
/// invariant to the tail.
fn roles_bytes(context: &SwigTestContext, swig: &Pubkey) -> Vec<u8> {
    let data = account_data(context, swig);
    Swig::split_parts(&data).unwrap().roles.to_vec()
}

fn configured_claimer(context: &SwigTestContext, swig: &Pubkey) -> Option<[u8; 32]> {
    let data = account_data(context, swig);
    rent_claimer::read_strict(Swig::split_parts(&data).unwrap().tail)
        .unwrap()
        .copied()
}

fn role_count(context: &SwigTestContext, swig: &Pubkey) -> u16 {
    let data = account_data(context, swig);
    SwigWithRoles::from_bytes(&data).unwrap().state.roles
}

fn has_role_for(context: &SwigTestContext, swig: &Pubkey, authority: &Pubkey) -> bool {
    let data = account_data(context, swig);
    SwigWithRoles::from_bytes(&data)
        .unwrap()
        .lookup_role_id(authority.as_ref())
        .unwrap()
        .is_some()
}

fn ed_config(authority: &Pubkey) -> AuthorityConfig<'_> {
    AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: authority.as_ref(),
    }
}

/// Creates a pair of swigs sharing the same root keypair — one plain, one with a
/// rent-claimer tail set. Returns `(plain, tailed)`.
fn create_pair(
    context: &mut SwigTestContext,
    root: &Keypair,
    claimer: &Pubkey,
) -> (Pubkey, Pubkey) {
    let (plain, _) = create_swig_ed25519(context, root, rand::random::<[u8; 32]>()).unwrap();
    let (tailed, _) = create_swig_ed25519(context, root, rand::random::<[u8; 32]>()).unwrap();
    set_rent_claimer_with_ed25519(context, &tailed, root, 0, *claimer).unwrap();
    (plain, tailed)
}

// ===========================================================================
// Differential — roles region must be byte-identical with vs without a tail
// ===========================================================================

/// Adding the same authorities to a plain wallet and to a tailed wallet yields an
/// identical roles region. The tail neither shifts nor perturbs role bytes.
#[test_log::test]
fn roles_identical_after_add_regardless_of_tail() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let claimer = Keypair::new().pubkey();
    let (plain, tailed) = create_pair(&mut context, &root, &claimer);

    // Baseline: role 0 only — already identical.
    assert_eq!(roles_bytes(&context, &plain), roles_bytes(&context, &tailed));

    // Same authority keypairs + same actions applied to BOTH wallets.
    // (`ClientAction` isn't `Clone`, so build a fresh vec per call.)
    let extra = [Keypair::new(), Keypair::new(), Keypair::new()];
    for (i, kp) in extra.iter().enumerate() {
        let amount = (i as u64) + 1;
        let mk = || vec![ClientAction::SolLimit(SolLimit { amount })];
        add_authority_with_ed25519_root(&mut context, &plain, &root, ed_config(&kp.pubkey()), mk())
            .unwrap();
        add_authority_with_ed25519_root(&mut context, &tailed, &root, ed_config(&kp.pubkey()), mk())
            .unwrap();

        assert_eq!(
            roles_bytes(&context, &plain),
            roles_bytes(&context, &tailed),
            "roles diverged after add #{i}"
        );
    }

    // The tail is unaffected the whole time; the plain wallet never grew one.
    assert_eq!(configured_claimer(&context, &tailed), Some(claimer.to_bytes()));
    assert_eq!(configured_claimer(&context, &plain), None);
}

/// Removing a middle role shifts everything after it. The resulting roles region
/// is identical whether or not a tail sits past the roles.
#[test_log::test]
fn roles_identical_after_remove_middle_regardless_of_tail() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let claimer = Keypair::new().pubkey();
    let (plain, tailed) = create_pair(&mut context, &root, &claimer);

    let a = Keypair::new();
    let b = Keypair::new();
    let c = Keypair::new();
    for kp in [&a, &b, &c] {
        let mk = || vec![ClientAction::SolLimit(SolLimit { amount: 7 })];
        add_authority_with_ed25519_root(&mut context, &plain, &root, ed_config(&kp.pubkey()), mk())
            .unwrap();
        add_authority_with_ed25519_root(&mut context, &tailed, &root, ed_config(&kp.pubkey()), mk())
            .unwrap();
    }
    assert_eq!(roles_bytes(&context, &plain), roles_bytes(&context, &tailed));

    // Remove the middle role (id 2 = `b`) on both.
    remove_authority_with_ed25519_root(&mut context, &plain, &root, 2).unwrap();
    remove_authority_with_ed25519_root(&mut context, &tailed, &root, 2).unwrap();

    assert_eq!(
        roles_bytes(&context, &plain),
        roles_bytes(&context, &tailed),
        "roles diverged after middle-role removal"
    );
    assert_eq!(configured_claimer(&context, &tailed), Some(claimer.to_bytes()));
    // `b` is gone, `a` and `c` remain — on both wallets identically.
    assert!(!has_role_for(&context, &tailed, &b.pubkey()));
    assert!(has_role_for(&context, &tailed, &a.pubkey()));
    assert!(has_role_for(&context, &tailed, &c.pubkey()));
}

/// Updating a role's actions (grow then shrink) produces an identical roles
/// region with or without a tail.
#[test_log::test]
fn roles_identical_after_update_regardless_of_tail() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let claimer = Keypair::new().pubkey();
    let (plain, tailed) = create_pair(&mut context, &root, &claimer);

    let target = Keypair::new();
    let mk_init = || vec![ClientAction::ManageAuthority(ManageAuthority {})];
    add_authority_with_ed25519_root(&mut context, &plain, &root, ed_config(&target.pubkey()), mk_init())
        .unwrap();
    add_authority_with_ed25519_root(&mut context, &tailed, &root, ed_config(&target.pubkey()), mk_init())
        .unwrap();

    // Grow.
    let mk_grown = || {
        vec![
            ClientAction::ManageAuthority(ManageAuthority {}),
            ClientAction::SolLimit(SolLimit { amount: 42 }),
        ]
    };
    update_authority_replace_with_ed25519_root(&mut context, &plain, &root, 1, mk_grown()).unwrap();
    update_authority_replace_with_ed25519_root(&mut context, &tailed, &root, 1, mk_grown()).unwrap();
    assert_eq!(
        roles_bytes(&context, &plain),
        roles_bytes(&context, &tailed),
        "roles diverged after update-grow"
    );

    // Shrink.
    let mk_shrunk = || vec![ClientAction::SolLimit(SolLimit { amount: 42 })];
    update_authority_replace_with_ed25519_root(&mut context, &plain, &root, 1, mk_shrunk()).unwrap();
    update_authority_replace_with_ed25519_root(&mut context, &tailed, &root, 1, mk_shrunk()).unwrap();
    assert_eq!(
        roles_bytes(&context, &plain),
        roles_bytes(&context, &tailed),
        "roles diverged after update-shrink"
    );
    assert_eq!(configured_claimer(&context, &tailed), Some(claimer.to_bytes()));
}

// ===========================================================================
// Functional — roles keep working with a tail present; claimer stays put
// ===========================================================================

/// An authority added alongside a tail is fully functional: it can itself manage
/// authorities. The claimer is untouched by that nested mutation.
#[test_log::test]
fn added_role_is_functional_with_tail_present() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let manager = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    let claimer = Keypair::new().pubkey();
    set_rent_claimer_with_ed25519(&mut context, &swig, &root, 0, claimer).unwrap();

    // Add an All authority (role 1) while the tail exists.
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        ed_config(&manager.pubkey()),
        vec![ClientAction::All(All {})],
    )
    .unwrap();

    // The newly added role exercises its own authority: it adds role 2.
    let downstream = Keypair::new();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &manager,
        ed_config(&downstream.pubkey()),
        vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
    )
    .unwrap();

    assert_eq!(role_count(&context, &swig), 3);
    assert!(has_role_for(&context, &swig, &downstream.pubkey()));
    assert_eq!(configured_claimer(&context, &swig), Some(claimer.to_bytes()));
}

/// After removing a middle role on a tailed wallet, the surviving roles keep
/// their authority/permissions and still work.
#[test_log::test]
fn surviving_roles_functional_after_remove_with_tail() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let mid = Keypair::new();
    let survivor = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    let claimer = Keypair::new().pubkey();
    set_rent_claimer_with_ed25519(&mut context, &swig, &root, 0, claimer).unwrap();

    // role 1 = mid (All), role 2 = survivor (All)
    add_authority_with_ed25519_root(&mut context, &swig, &root, ed_config(&mid.pubkey()), vec![ClientAction::All(All {})]).unwrap();
    add_authority_with_ed25519_root(&mut context, &swig, &root, ed_config(&survivor.pubkey()), vec![ClientAction::All(All {})]).unwrap();

    // Remove the middle role.
    remove_authority_with_ed25519_root(&mut context, &swig, &root, 1).unwrap();
    assert!(!has_role_for(&context, &swig, &mid.pubkey()));

    // `survivor` still authenticates + authorizes: it adds a new authority.
    let downstream = Keypair::new();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &survivor,
        ed_config(&downstream.pubkey()),
        vec![ClientAction::SolLimit(SolLimit { amount: 3 })],
    )
    .unwrap();

    assert!(has_role_for(&context, &swig, &downstream.pubkey()));
    assert_eq!(configured_claimer(&context, &swig), Some(claimer.to_bytes()));
}

/// An `update` to a role's permissions takes real effect even with a tail set:
/// a SolLimit-only role cannot manage authorities until updated to gain
/// ManageAuthority — and the claimer is preserved throughout.
#[test_log::test]
fn update_changes_effective_permissions_with_tail() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let worker = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    let claimer = Keypair::new().pubkey();
    set_rent_claimer_with_ed25519(&mut context, &swig, &root, 0, claimer).unwrap();

    // role 1 = worker with only SolLimit — cannot manage authorities.
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        ed_config(&worker.pubkey()),
        vec![ClientAction::SolLimit(SolLimit { amount: 5 })],
    )
    .unwrap();

    let before = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &worker,
        ed_config(&Keypair::new().pubkey()),
        vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
    );
    assert!(before.is_err(), "SolLimit-only role must not manage authorities");

    // Grant ManageAuthority via update (root acting).
    update_authority_replace_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        1,
        vec![
            ClientAction::SolLimit(SolLimit { amount: 5 }),
            ClientAction::ManageAuthority(ManageAuthority {}),
        ],
    )
    .unwrap();

    // Now the same operation succeeds.
    let added = Keypair::new();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &worker,
        ed_config(&added.pubkey()),
        vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
    )
    .unwrap();
    assert!(has_role_for(&context, &swig, &added.pubkey()));
    assert_eq!(configured_claimer(&context, &swig), Some(claimer.to_bytes()));
}

/// A role can actually SPEND from the wallet (SignV2 SOL transfer) with the tail
/// present — both the root role and a later-added role.
#[test_log::test]
fn roles_can_sign_v2_spend_with_tail_present() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    context.svm.airdrop(&root.pubkey(), 20_000_000_000).unwrap();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let claimer = Keypair::new().pubkey();
    set_rent_claimer_with_ed25519(&mut context, &swig, &root, 0, claimer).unwrap();

    // Add an All authority that we'll also spend with.
    let spender = Keypair::new();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        ed_config(&spender.pubkey()),
        vec![ClientAction::All(All {})],
    )
    .unwrap();

    // Fund the wallet PDA.
    let fund_ix = solana_system_interface::instruction::transfer(
        &root.pubkey(),
        &swig_wallet_address,
        2_000_000_000,
    );
    let fund_msg = v0::Message::try_compile(&root.pubkey(), &[fund_ix], &[], context.svm.latest_blockhash()).unwrap();
    context
        .svm
        .send_transaction(VersionedTransaction::try_new(VersionedMessage::V0(fund_msg), &[&root]).unwrap())
        .unwrap();

    // Helper closure: spend `amount` via SignV2 using `(authority, role_id)`.
    let mut spend = |context: &mut SwigTestContext, authority: &Keypair, role_id: u32, amount: u64| {
        let recipient = Keypair::new().pubkey();
        let transfer_ix =
            solana_system_interface::instruction::transfer(&swig_wallet_address, &recipient, amount);
        let sign_ix =
            SignV2Instruction::new_ed25519(swig, swig_wallet_address, authority.pubkey(), transfer_ix, role_id)
                .unwrap();
        let msg = v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[sign_ix],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap();
        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(msg),
            &[&context.default_payer, authority],
        )
        .unwrap();
        let result = context.svm.send_transaction(tx);
        assert!(result.is_ok(), "SignV2 spend failed: {:?}", result.err());
        (recipient, amount)
    };

    // Root (role 0) spends.
    let (r1, a1) = spend(&mut context, &root, 0, 100_000_000);
    assert_eq!(context.svm.get_account(&r1).map(|a| a.lamports).unwrap_or(0), a1);

    // Added authority (role 1) spends.
    let (r2, a2) = spend(&mut context, &spender, 1, 150_000_000);
    assert_eq!(context.svm.get_account(&r2).map(|a| a.lamports).unwrap_or(0), a2);

    // The tail survived all of the signing activity.
    assert_eq!(configured_claimer(&context, &swig), Some(claimer.to_bytes()));
}

// ===========================================================================
// Claimer byte-identity through heavy churn
// ===========================================================================

/// Through a long sequence of add/update/remove operations, the claimer value is
/// preserved byte-for-byte (not merely "present").
#[test_log::test]
fn claimer_is_byte_identical_through_heavy_churn() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    let claimer = Keypair::new().pubkey();
    let expected = Some(claimer.to_bytes());
    set_rent_claimer_with_ed25519(&mut context, &swig, &root, 0, claimer).unwrap();
    assert_eq!(configured_claimer(&context, &swig), expected);

    // Add four authorities (roles 1..=4).
    let kps: Vec<Keypair> = (0..4).map(|_| Keypair::new()).collect();
    for kp in &kps {
        add_authority_with_ed25519_root(
            &mut context,
            &swig,
            &root,
            ed_config(&kp.pubkey()),
            vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
        )
        .unwrap();
        assert_eq!(configured_claimer(&context, &swig), expected);
    }

    // Update one (grow), update it back (shrink).
    update_authority_replace_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        2,
        vec![
            ClientAction::SolLimit(SolLimit { amount: 1 }),
            ClientAction::ManageAuthority(ManageAuthority {}),
        ],
    )
    .unwrap();
    assert_eq!(configured_claimer(&context, &swig), expected);
    update_authority_replace_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        2,
        vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
    )
    .unwrap();
    assert_eq!(configured_claimer(&context, &swig), expected);

    // Remove roles from the middle outward.
    for remove_id in [2u32, 4, 1, 3] {
        remove_authority_with_ed25519_root(&mut context, &swig, &root, remove_id).unwrap();
        assert_eq!(
            configured_claimer(&context, &swig),
            expected,
            "claimer changed after removing role {remove_id}"
        );
    }

    // Back to just the root role, claimer still intact.
    assert_eq!(role_count(&context, &swig), 1);
    assert_eq!(configured_claimer(&context, &swig), expected);
}
