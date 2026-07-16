#![cfg(not(feature = "program_scope_test"))]
//! Edge-case matrix for the immutable rent-claimer tail feature.
//!
//! Focus areas (per the design doc):
//!   * Changing swig sizes — `add` / `remove` / `update` authority must preserve
//!     the 40-byte tail across every realloc (grow + shrink).
//!   * Rent-claimer combinations — set semantics, the permission gate, the
//!     close-path destination pin, rent accounting, and backward compatibility.
//!
//! Each section is labelled with its matrix id (A/B/C/D/F/G/H/I/K).

mod common;

use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use common::*;
use litesvm_token::spl_token;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_sdk::{
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{
    AuthorityConfig, ClientAction, CloseSwigV1Instruction, CloseTokenAccountV1Instruction,
    CreateInstruction, SetRentClaimerV1Instruction,
};
use swig_state::{
    action::{
        all::All, all_but_manage_authority::AllButManageAuthority,
        close_swig_authority::CloseSwigAuthority, manage_authority::ManageAuthority,
        sol_limit::SolLimit,
    },
    authority::{secp256k1::Secp256k1Authority, AuthorityType},
    swig::{swig_account_seeds, swig_wallet_address_seeds, Swig, SwigWithRoles},
    tail::rent_claimer,
};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

/// Reads the configured rent claimer straight from the on-chain account, going
/// through the same strict tail parser the program uses.
fn configured_claimer(context: &SwigTestContext, swig_pubkey: &Pubkey) -> Option<[u8; 32]> {
    let account = context.svm.get_account(swig_pubkey).unwrap();
    let parts = Swig::split_parts(&account.data).unwrap();
    rent_claimer::read_strict(parts.tail).unwrap().copied()
}

/// Number of roles currently stored on the swig.
fn role_count(context: &SwigTestContext, swig_pubkey: &Pubkey) -> u16 {
    let account = context.svm.get_account(swig_pubkey).unwrap();
    SwigWithRoles::from_bytes(&account.data)
        .unwrap()
        .state
        .roles
}

fn account_len(context: &SwigTestContext, swig_pubkey: &Pubkey) -> usize {
    context.svm.get_account(swig_pubkey).unwrap().data.len()
}

fn lamports_of(context: &SwigTestContext, key: &Pubkey) -> u64 {
    context
        .svm
        .get_account(key)
        .map(|a| a.lamports)
        .unwrap_or(0)
}

fn wallet_address(swig_pubkey: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    )
    .0
}

/// Closes a swig with an Ed25519 authority and returns the transaction result.
fn close_swig_ed25519(
    context: &mut SwigTestContext,
    swig_pubkey: &Pubkey,
    authority: &Keypair,
    role_id: u32,
    destination: &Pubkey,
) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata> {
    let close_ix = CloseSwigV1Instruction::new_with_ed25519_authority(
        *swig_pubkey,
        wallet_address(swig_pubkey),
        authority.pubkey(),
        *destination,
        role_id,
    )
    .unwrap();
    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, authority]).unwrap();
    context.svm.send_transaction(tx)
}

fn secp256k1_counter(
    context: &SwigTestContext,
    swig_pubkey: &Pubkey,
    wallet: &PrivateKeySigner,
) -> u32 {
    let account = context.svm.get_account(swig_pubkey).unwrap();
    let swig = SwigWithRoles::from_bytes(&account.data).unwrap();
    let eth_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();
    let role_id = swig.lookup_role_id(&eth_pubkey[1..]).unwrap().unwrap();
    let role = swig.get_role(role_id).unwrap().unwrap();
    role.authority
        .as_any()
        .downcast_ref::<Secp256k1Authority>()
        .unwrap()
        .signature_odometer
}

fn create_test_secp256r1_keypair() -> (openssl::ec::EcKey<openssl::pkey::Private>, [u8; 33]) {
    use openssl::{
        bn::BigNumContext,
        ec::{EcGroup, EcKey, PointConversionForm},
        nid::Nid,
    };
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let signing_key = EcKey::generate(&group).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let pubkey_bytes = signing_key
        .public_key()
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();
    (signing_key, pubkey_bytes.try_into().unwrap())
}

// ===========================================================================
// A. SetRentClaimerV1 — core set semantics
// ===========================================================================

/// A5: setting the claimer to the swig account's own pubkey is rejected —
/// the swig cannot be its own rent claimer.
#[test_log::test]
fn a5_set_claimer_to_swig_itself_fails() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let result =
        set_rent_claimer_with_ed25519(&mut context, &swig_pubkey, &authority, 0, swig_pubkey);
    assert!(result.is_err(), "swig as its own rent claimer must fail");
    assert_eq!(configured_claimer(&context, &swig_pubkey), None);
}

/// A5b: setting the claimer to the swig wallet address PDA is rejected —
/// close proceeds must not be routed back into the wallet's own accounts.
#[test_log::test]
fn a5b_set_claimer_to_wallet_address_fails() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let result = set_rent_claimer_with_ed25519(
        &mut context,
        &swig_pubkey,
        &authority,
        0,
        wallet_address(&swig_pubkey),
    );
    assert!(
        result.is_err(),
        "swig wallet address as rent claimer must fail"
    );
    assert_eq!(configured_claimer(&context, &swig_pubkey), None);
}

/// A6: setting the claimer to the acting authority's own pubkey is allowed.
/// (The §3 attack is only relevant to *mutation*, which v1 forbids.)
#[test_log::test]
fn a6_set_claimer_to_acting_authority_succeeds() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    set_rent_claimer_with_ed25519(
        &mut context,
        &swig_pubkey,
        &authority,
        0,
        authority.pubkey(),
    )
    .unwrap();
    assert_eq!(
        configured_claimer(&context, &swig_pubkey),
        Some(authority.pubkey().to_bytes())
    );
}

/// A8: an unknown `role_id` must fail and must not write a tail.
#[test_log::test]
fn a8_set_with_unknown_role_id_fails() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    // Role 7 does not exist; signing key is the real root.
    let result = set_rent_claimer_with_ed25519(
        &mut context,
        &swig_pubkey,
        &authority,
        7,
        Keypair::new().pubkey(),
    );
    assert!(result.is_err(), "unknown role_id must fail");
    assert_eq!(configured_claimer(&context, &swig_pubkey), None);
}

// ===========================================================================
// B. Permission gate
// ===========================================================================

/// B2: a role holding only `CloseSwigAuthority` may perform the one-time set.
#[test_log::test]
fn b2_close_swig_authority_can_set() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let closer = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: closer.pubkey().as_ref(),
        },
        vec![ClientAction::CloseSwigAuthority(CloseSwigAuthority {})],
    )
    .unwrap();

    let claimer = Keypair::new().pubkey();
    set_rent_claimer_with_ed25519(&mut context, &swig_pubkey, &closer, 1, claimer).unwrap();
    assert_eq!(
        configured_claimer(&context, &swig_pubkey),
        Some(claimer.to_bytes())
    );
}

/// B3: `ManageAuthority` alone is explicitly insufficient to set.
#[test_log::test]
fn b3_manage_authority_cannot_set() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let manager = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: manager.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    let result = set_rent_claimer_with_ed25519(
        &mut context,
        &swig_pubkey,
        &manager,
        1,
        Keypair::new().pubkey(),
    );
    assert!(
        result.is_err(),
        "ManageAuthority must not be able to set the rent claimer"
    );
    assert_eq!(configured_claimer(&context, &swig_pubkey), None);
}

/// B4: pin the behavior of `AllButManageAuthority`. The doc only authorizes
/// `All` and `CloseSwigAuthority`, and the handler checks exactly those two, so
/// `AllButManageAuthority` must be rejected.
#[test_log::test]
fn b4_all_but_manage_authority_cannot_set() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let broad = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: broad.pubkey().as_ref(),
        },
        vec![ClientAction::AllButManageAuthority(
            AllButManageAuthority {},
        )],
    )
    .unwrap();

    let result = set_rent_claimer_with_ed25519(
        &mut context,
        &swig_pubkey,
        &broad,
        1,
        Keypair::new().pubkey(),
    );
    assert!(
        result.is_err(),
        "AllButManageAuthority is not one of the two authorized set permissions"
    );
    assert_eq!(configured_claimer(&context, &swig_pubkey), None);
}

// ===========================================================================
// C. Authority-type coverage for set
// ===========================================================================

/// C3: a Secp256k1 root authority can set the rent claimer.
#[test_log::test]
fn c3_secp256k1_authority_can_set() {
    let mut context = setup_test_context().unwrap();
    let wallet = LocalSigner::random();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_secp256k1(&mut context, &wallet, id).unwrap();

    let claimer = Keypair::new().pubkey();
    let next_counter = secp256k1_counter(&context, &swig_pubkey, &wallet) + 1;
    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        wallet.sign_hash_sync(&B256::from(hash)).unwrap().as_bytes()
    };

    let set_ix = SetRentClaimerV1Instruction::new_with_secp256k1_authority(
        swig_pubkey,
        context.default_payer.pubkey(),
        signing_fn,
        0, // current_slot
        next_counter,
        0, // role_id
        claimer.to_bytes(),
    )
    .unwrap();
    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                set_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer]).unwrap();
    let result = context.svm.send_transaction(tx);
    assert!(result.is_ok(), "secp256k1 set failed: {:?}", result.err());
    assert_eq!(
        configured_claimer(&context, &swig_pubkey),
        Some(claimer.to_bytes())
    );
}

/// C6: a Secp256r1 root authority can set the rent claimer.
#[test_log::test]
fn c6_secp256r1_authority_can_set() {
    let mut context = setup_test_context().unwrap();
    let (signing_key, public_key) = create_test_secp256r1_keypair();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_secp256r1(&mut context, &public_key, id).unwrap();

    let claimer = Keypair::new().pubkey();
    let authority_fn = |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap()
    };

    let set_ixs = SetRentClaimerV1Instruction::new_with_secp256r1_authority(
        swig_pubkey,
        context.default_payer.pubkey(),
        authority_fn,
        0, // current_slot
        1, // counter
        0, // role_id
        claimer.to_bytes(),
        &public_key,
    )
    .unwrap();
    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                set_ixs[0].clone(),
                set_ixs[1].clone(),
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer]).unwrap();
    let result = context.svm.send_transaction(tx);
    assert!(result.is_ok(), "secp256r1 set failed: {:?}", result.err());
    assert_eq!(
        configured_claimer(&context, &swig_pubkey),
        Some(claimer.to_bytes())
    );
}

// ===========================================================================
// D. Changing swig sizes — tail preservation across realloc
// ===========================================================================

/// D1: adding an authority (grow) preserves a previously-set tail.
#[test_log::test]
fn d1_add_authority_preserves_tail() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    let claimer = Keypair::new().pubkey();
    set_rent_claimer_with_ed25519(&mut context, &swig_pubkey, &root, 0, claimer).unwrap();
    let len_before = account_len(&context, &swig_pubkey);

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: Keypair::new().pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
    )
    .unwrap();

    assert_eq!(
        configured_claimer(&context, &swig_pubkey),
        Some(claimer.to_bytes())
    );
    assert_eq!(role_count(&context, &swig_pubkey), 2);
    assert!(
        account_len(&context, &swig_pubkey) > len_before,
        "account should have grown"
    );
    // Tail must remain a clean single entry — read_strict would error otherwise.
}

/// D2: adding an authority when there is NO tail must not synthesize one.
#[test_log::test]
fn d2_add_authority_without_tail_creates_no_tail() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: Keypair::new().pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
    )
    .unwrap();

    assert_eq!(configured_claimer(&context, &swig_pubkey), None);
}

/// D3: adding authorities of different types (different role sizes) preserves
/// the tail.
#[test_log::test]
fn d3_add_mixed_authority_types_preserves_tail() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    let claimer = Keypair::new().pubkey();
    set_rent_claimer_with_ed25519(&mut context, &swig_pubkey, &root, 0, claimer).unwrap();

    // Ed25519 authority (32-byte authority).
    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: Keypair::new().pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();
    assert_eq!(
        configured_claimer(&context, &swig_pubkey),
        Some(claimer.to_bytes())
    );

    // Secp256k1 authority (64-byte authority) — a different role size.
    let secp = LocalSigner::random();
    let eth_pubkey = secp
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();
    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256k1,
            authority: &eth_pubkey[1..],
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 5 })],
    )
    .unwrap();

    assert_eq!(
        configured_claimer(&context, &swig_pubkey),
        Some(claimer.to_bytes())
    );
    assert_eq!(role_count(&context, &swig_pubkey), 3);
}

/// D5: multiple sequential grows keep the tail intact after every realloc.
#[test_log::test]
fn d5_multiple_adds_preserve_tail() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    let claimer = Keypair::new().pubkey();
    set_rent_claimer_with_ed25519(&mut context, &swig_pubkey, &root, 0, claimer).unwrap();

    for i in 0..4u64 {
        add_authority_with_ed25519_root(
            &mut context,
            &swig_pubkey,
            &root,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: Keypair::new().pubkey().as_ref(),
            },
            vec![ClientAction::SolLimit(SolLimit { amount: i + 1 })],
        )
        .unwrap();
        assert_eq!(
            configured_claimer(&context, &swig_pubkey),
            Some(claimer.to_bytes()),
            "tail corrupted after add #{i}"
        );
    }
    assert_eq!(role_count(&context, &swig_pubkey), 5);
}

/// D6: after growing the roles, the close path still enforces the pinned tail.
#[test_log::test]
fn d6_close_enforced_after_grow() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    let claimer = Keypair::new();
    set_rent_claimer_with_ed25519(&mut context, &swig_pubkey, &root, 0, claimer.pubkey()).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: Keypair::new().pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
    )
    .unwrap();

    // Wrong destination still rejected.
    let wrong = Keypair::new().pubkey();
    assert!(
        close_swig_ed25519(&mut context, &swig_pubkey, &root, 0, &wrong).is_err(),
        "close to wrong destination must fail even after a grow"
    );
    // Correct destination succeeds.
    assert!(
        close_swig_ed25519(&mut context, &swig_pubkey, &root, 0, &claimer.pubkey()).is_ok(),
        "close to pinned claimer must succeed after a grow"
    );
}

/// D7: removing a middle role (forces a shift of everything after it) must not
/// corrupt the tail.
#[test_log::test]
fn d7_remove_middle_role_preserves_tail() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let middle = Keypair::new();
    let last = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: middle.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
    )
    .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: last.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 2 })],
    )
    .unwrap();

    let claimer = Keypair::new().pubkey();
    set_rent_claimer_with_ed25519(&mut context, &swig_pubkey, &root, 0, claimer).unwrap();
    let len_before = account_len(&context, &swig_pubkey);

    // Remove the middle role (id 1).
    remove_authority_with_ed25519_root(&mut context, &swig_pubkey, &root, 1).unwrap();

    assert_eq!(
        configured_claimer(&context, &swig_pubkey),
        Some(claimer.to_bytes()),
        "tail corrupted by middle-role removal"
    );
    assert_eq!(role_count(&context, &swig_pubkey), 2);
    assert!(
        account_len(&context, &swig_pubkey) < len_before,
        "account should have shrunk"
    );
}

/// D8: removing the last role preserves the tail.
#[test_log::test]
fn d8_remove_last_role_preserves_tail() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: Keypair::new().pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
    )
    .unwrap();

    let claimer = Keypair::new().pubkey();
    set_rent_claimer_with_ed25519(&mut context, &swig_pubkey, &root, 0, claimer).unwrap();
    remove_authority_with_ed25519_root(&mut context, &swig_pubkey, &root, 1).unwrap();

    assert_eq!(
        configured_claimer(&context, &swig_pubkey),
        Some(claimer.to_bytes())
    );
    assert_eq!(role_count(&context, &swig_pubkey), 1);
}

/// D10: removing an authority when there is no tail creates none.
#[test_log::test]
fn d10_remove_authority_without_tail_creates_no_tail() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: Keypair::new().pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
    )
    .unwrap();
    remove_authority_with_ed25519_root(&mut context, &swig_pubkey, &root, 1).unwrap();

    assert_eq!(configured_claimer(&context, &swig_pubkey), None);
    assert_eq!(role_count(&context, &swig_pubkey), 1);
}

/// D12 + D13: updating a role's actions to grow then shrink preserves the tail
/// across the two-phase realloc in both directions.
#[test_log::test]
fn d12_update_authority_grow_then_shrink_preserves_tail() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let target = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: target.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    let claimer = Keypair::new().pubkey();
    set_rent_claimer_with_ed25519(&mut context, &swig_pubkey, &root, 0, claimer).unwrap();
    let len_one_action = account_len(&context, &swig_pubkey);

    // Grow: add a second action to role 1.
    update_authority_replace_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        1,
        vec![
            ClientAction::ManageAuthority(ManageAuthority {}),
            ClientAction::SolLimit(SolLimit { amount: 9 }),
        ],
    )
    .unwrap();
    assert_eq!(
        configured_claimer(&context, &swig_pubkey),
        Some(claimer.to_bytes()),
        "tail corrupted by update-grow"
    );
    assert!(
        account_len(&context, &swig_pubkey) > len_one_action,
        "update should have grown"
    );

    // Shrink: drop back to a single action.
    update_authority_replace_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        1,
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();
    assert_eq!(
        configured_claimer(&context, &swig_pubkey),
        Some(claimer.to_bytes()),
        "tail corrupted by update-shrink"
    );
    assert_eq!(account_len(&context, &swig_pubkey), len_one_action);
}

/// D18: a previously-set claimer survives a full churn of grow → remove → update
/// and remains immutable (a second set still fails).
#[test_log::test]
fn d18_claimer_survives_full_role_churn() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let a = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    let claimer = Keypair::new().pubkey();
    set_rent_claimer_with_ed25519(&mut context, &swig_pubkey, &root, 0, claimer).unwrap();

    // grow
    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: a.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();
    // update (grow)
    update_authority_replace_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        1,
        vec![
            ClientAction::ManageAuthority(ManageAuthority {}),
            ClientAction::SolLimit(SolLimit { amount: 3 }),
        ],
    )
    .unwrap();
    // shrink (remove)
    remove_authority_with_ed25519_root(&mut context, &swig_pubkey, &root, 1).unwrap();

    assert_eq!(
        configured_claimer(&context, &swig_pubkey),
        Some(claimer.to_bytes())
    );

    // D19: still immutable after all the reallocs.
    let second = set_rent_claimer_with_ed25519(
        &mut context,
        &swig_pubkey,
        &root,
        0,
        Keypair::new().pubkey(),
    );
    assert!(
        second.is_err(),
        "claimer must stay immutable through role churn"
    );
}

/// D17: setting the claimer AFTER growing the roles writes the tail at the
/// correct (post-grow) end of the account.
#[test_log::test]
fn d17_add_then_set_writes_tail_at_correct_offset() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: Keypair::new().pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
    )
    .unwrap();

    let claimer = Keypair::new().pubkey();
    set_rent_claimer_with_ed25519(&mut context, &swig_pubkey, &root, 0, claimer).unwrap();
    assert_eq!(
        configured_claimer(&context, &swig_pubkey),
        Some(claimer.to_bytes())
    );
    assert_eq!(role_count(&context, &swig_pubkey), 2);
}

// ===========================================================================
// F. Close enforcement — CloseSwigV1
// ===========================================================================

/// F1: an unset wallet closes to any destination (today's behavior).
#[test_log::test]
fn f1_unset_close_allows_any_destination() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    let destination = Keypair::new().pubkey();
    let result = close_swig_ed25519(&mut context, &swig_pubkey, &root, 0, &destination);
    assert!(
        result.is_ok(),
        "unset wallet should close to any destination: {:?}",
        result.err()
    );
}

/// F4: a delegated `CloseSwigAuthority` role can wind the wallet down, but only
/// to the pinned claimer (the core §9.3 security property).
#[test_log::test]
fn f4_delegated_close_authority_must_use_pinned_destination() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let closer = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    let claimer = Keypair::new();
    set_rent_claimer_with_ed25519(&mut context, &swig_pubkey, &root, 0, claimer.pubkey()).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: closer.pubkey().as_ref(),
        },
        vec![ClientAction::CloseSwigAuthority(CloseSwigAuthority {})],
    )
    .unwrap();

    // F5-style: delegated authority cannot redirect rent to itself.
    assert!(
        close_swig_ed25519(&mut context, &swig_pubkey, &closer, 1, &closer.pubkey()).is_err(),
        "delegated close authority must not redirect rent"
    );
    // But it can still execute the close to the pinned claimer.
    let claimer_before = lamports_of(&context, &claimer.pubkey());
    assert!(
        close_swig_ed25519(&mut context, &swig_pubkey, &closer, 1, &claimer.pubkey()).is_ok(),
        "delegated close authority should close to the pinned claimer"
    );
    assert!(lamports_of(&context, &claimer.pubkey()) > claimer_before);
}

// ===========================================================================
// G. Close enforcement — CloseTokenAccountV1
// ===========================================================================

/// G3: an unset wallet closes token accounts to any destination.
#[test_log::test]
fn g3_unset_token_close_allows_any_destination() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();
    let swig_wallet_address = wallet_address(&swig_pubkey);

    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let ata = setup_ata(
        &mut context.svm,
        &mint,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    let destination = Keypair::new().pubkey();
    let close_ix = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        root.pubkey(),
        destination,
        spl_token::ID,
        vec![ata],
        0,
    )
    .unwrap();
    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &root]).unwrap();
    assert!(
        context.svm.send_transaction(tx).is_ok(),
        "unset token close to any dest should succeed"
    );
}

/// G4 + G5: closing multiple token accounts in one ix routes to the pinned
/// claimer (G4), and a wrong destination rejects them all (G5).
#[test_log::test]
fn g4_g5_multiple_token_accounts_respect_pin() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();
    let swig_wallet_address = wallet_address(&swig_pubkey);

    let claimer = Keypair::new();
    set_rent_claimer_with_ed25519(&mut context, &swig_pubkey, &root, 0, claimer.pubkey()).unwrap();

    let mint1 = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let mint2 = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let ata1 = setup_ata(
        &mut context.svm,
        &mint1,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let ata2 = setup_ata(
        &mut context.svm,
        &mint2,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let total_rent = lamports_of(&context, &ata1) + lamports_of(&context, &ata2);

    // G5: wrong destination rejects all.
    let wrong = Keypair::new().pubkey();
    let close_wrong = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        root.pubkey(),
        wrong,
        spl_token::ID,
        vec![ata1, ata2],
        0,
    )
    .unwrap();
    let msg = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_wrong,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(msg, &[&context.default_payer, &root]).unwrap();
    assert!(
        context.svm.send_transaction(tx).is_err(),
        "wrong dest must reject all token closes"
    );
    // Nothing should have moved.
    assert!(
        context
            .svm
            .get_account(&ata1)
            .map(|a| a.lamports)
            .unwrap_or(0)
            > 0
    );

    // G4: correct destination routes all rent to the claimer.
    let claimer_before = lamports_of(&context, &claimer.pubkey());
    let close_ok = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        root.pubkey(),
        claimer.pubkey(),
        spl_token::ID,
        vec![ata1, ata2],
        0,
    )
    .unwrap();
    let msg = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ok,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(msg, &[&context.default_payer, &root]).unwrap();
    assert!(
        context.svm.send_transaction(tx).is_ok(),
        "pinned dest should close all token accounts"
    );
    assert_eq!(
        lamports_of(&context, &claimer.pubkey()).saturating_sub(claimer_before),
        total_rent,
        "claimer should receive rent from both token accounts"
    );
}

// ===========================================================================
// H. Rent / lamport accounting
// ===========================================================================

/// H1: setting the claimer grows the account by exactly the tail entry and
/// leaves it rent-exempt at the new size.
#[test_log::test]
fn h1_set_grows_by_entry_len_and_stays_rent_exempt() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();
    let len_before = account_len(&context, &swig_pubkey);

    set_rent_claimer_with_ed25519(
        &mut context,
        &swig_pubkey,
        &root,
        0,
        Keypair::new().pubkey(),
    )
    .unwrap();

    let len_after = account_len(&context, &swig_pubkey);
    assert_eq!(
        len_after - len_before,
        rent_claimer::ENTRY_LEN,
        "should grow by exactly 40 bytes"
    );
    assert_eq!(
        lamports_of(&context, &swig_pubkey),
        context.svm.minimum_balance_for_rent_exemption(len_after),
        "swig must be rent-exempt at the new size"
    );
}

/// H2: if the payer cannot fund the +40 bytes of rent exemption, the set fails
/// and no tail is written.
#[test_log::test]
fn h2_insufficient_payer_fails_cleanly() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    // A payer with enough for the tx fee but not the rent-exemption delta.
    let poor_payer = Keypair::new();
    context.svm.airdrop(&poor_payer.pubkey(), 100_000).unwrap();

    let set_ix = SetRentClaimerV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        poor_payer.pubkey(),
        root.pubkey(),
        0,
        Keypair::new().pubkey().to_bytes(),
    )
    .unwrap();
    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &poor_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                set_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&poor_payer, &root]).unwrap();
    assert!(
        context.svm.send_transaction(tx).is_err(),
        "underfunded payer must fail the set"
    );
    assert_eq!(configured_claimer(&context, &swig_pubkey), None);
}

/// H4: the +40 bytes of rent is reclaimed by the pinned claimer on close.
#[test_log::test]
fn h4_tail_rent_reclaimed_by_claimer_on_close() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();
    let swig_wallet_address = wallet_address(&swig_pubkey);

    let claimer = Keypair::new();
    set_rent_claimer_with_ed25519(&mut context, &swig_pubkey, &root, 0, claimer.pubkey()).unwrap();

    let swig_lamports_before = lamports_of(&context, &swig_pubkey);
    let wallet_lamports_before = lamports_of(&context, &swig_wallet_address);
    let claimer_before = lamports_of(&context, &claimer.pubkey());

    assert!(close_swig_ed25519(&mut context, &swig_pubkey, &root, 0, &claimer.pubkey()).is_ok());

    let closed_rent = context.svm.minimum_balance_for_rent_exemption(1);
    let expected = wallet_lamports_before + swig_lamports_before.saturating_sub(closed_rent);
    assert_eq!(
        lamports_of(&context, &claimer.pubkey()).saturating_sub(claimer_before),
        expected,
        "claimer should reclaim the swig rent including the +40 byte tail"
    );
}

// ===========================================================================
// I. Backward compatibility
// ===========================================================================

/// I1: a wallet that never opts in behaves identically across its whole
/// lifecycle and never grows a tail.
#[test_log::test]
fn i1_never_opt_in_lifecycle_has_no_tail() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let extra = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();
    assert_eq!(configured_claimer(&context, &swig_pubkey), None);

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: extra.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
    )
    .unwrap();
    assert_eq!(configured_claimer(&context, &swig_pubkey), None);

    remove_authority_with_ed25519_root(&mut context, &swig_pubkey, &root, 1).unwrap();
    assert_eq!(configured_claimer(&context, &swig_pubkey), None);

    let destination = Keypair::new().pubkey();
    assert!(
        close_swig_ed25519(&mut context, &swig_pubkey, &root, 0, &destination).is_ok(),
        "never-opted-in wallet should close to any destination"
    );
}

// ===========================================================================
// K. Lifecycle / first-write race
// ===========================================================================

/// K1: bundling `CreateV1 + SetRentClaimerV1` in one transaction sets the
/// claimer atomically — the wallet is never observable in an unset state.
#[test_log::test]
fn k1_bundled_create_and_set_is_atomic() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let payer = context.default_payer.pubkey();

    let (swig_pubkey, swig_bump) =
        Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let (swig_wallet_address, wallet_bump) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(swig_pubkey.as_ref()),
        &program_id(),
    );

    let create_ix = CreateInstruction::new(
        swig_pubkey,
        swig_bump,
        payer,
        swig_wallet_address,
        wallet_bump,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {})],
        id,
    )
    .unwrap();

    let claimer = Keypair::new().pubkey();
    let set_ix = SetRentClaimerV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        payer,
        authority.pubkey(),
        0,
        claimer.to_bytes(),
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &payer,
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                create_ix,
                set_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &authority]).unwrap();
    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "bundled create+set failed: {:?}",
        result.err()
    );
    assert_eq!(
        configured_claimer(&context, &swig_pubkey),
        Some(claimer.to_bytes())
    );
}

/// K2: with `CreateV1` alone, a different authority can win the first-write
/// race; the original authority's later set then fails (immutable).
#[test_log::test]
fn k2_first_write_wins() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let other = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    // A second All authority is added.
    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: other.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {})],
    )
    .unwrap();

    // `other` wins the race.
    let other_claimer = Keypair::new().pubkey();
    set_rent_claimer_with_ed25519(&mut context, &swig_pubkey, &other, 1, other_claimer).unwrap();
    assert_eq!(
        configured_claimer(&context, &swig_pubkey),
        Some(other_claimer.to_bytes())
    );

    // root loses — the value is immutable.
    let root_attempt = set_rent_claimer_with_ed25519(
        &mut context,
        &swig_pubkey,
        &root,
        0,
        Keypair::new().pubkey(),
    );
    assert!(
        root_attempt.is_err(),
        "first write wins; later set must fail"
    );
    assert_eq!(
        configured_claimer(&context, &swig_pubkey),
        Some(other_claimer.to_bytes())
    );
}

/// K3: two `SetRentClaimerV1` in a single transaction — the second fails, so the
/// whole transaction is rejected and no tail is written.
#[test_log::test]
fn k3_two_sets_in_one_tx_fails() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root, id).unwrap();
    let payer = context.default_payer.pubkey();

    let set_ix_1 = SetRentClaimerV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        payer,
        root.pubkey(),
        0,
        Keypair::new().pubkey().to_bytes(),
    )
    .unwrap();
    let set_ix_2 = SetRentClaimerV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        payer,
        root.pubkey(),
        0,
        Keypair::new().pubkey().to_bytes(),
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &payer,
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                set_ix_1,
                set_ix_2,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &root]).unwrap();
    assert!(
        context.svm.send_transaction(tx).is_err(),
        "two sets in one tx must fail"
    );
    assert_eq!(configured_claimer(&context, &swig_pubkey), None);
}
