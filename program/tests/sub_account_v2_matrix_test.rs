#![cfg(not(feature = "program_scope_test"))]
//! Normative authorization-matrix coverage for V2 sub-accounts.
//!
//! Each test maps to a row of the V2 auth table: default-deny for wallet-level
//! overrides (All / ManageAuthority / AllButManageAuthority), scope-limited
//! grants, id-scoping of the `All` umbrella, cross-role sharing, self-grant
//! recovery, atomic role-deletion, V1/V2 seed non-collision, and duplicate
//! rejection.
mod common;

use common::*;
use solana_sdk::{
    instruction::Instruction,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{
    AuthorityConfig, ClientAction, CreateSubAccountV2Instruction, SubAccountSignV2Instruction,
    ToggleSubAccountV2Instruction, WithdrawFromSubAccountV2Instruction,
};
use swig_state::{
    action::{
        all::All,
        all_but_manage_authority::AllButManageAuthority,
        manage_authority::ManageAuthority,
        sub_account_v2::{
            SubAccountV2All, SubAccountV2Create, SubAccountV2Sign, SubAccountV2Toggle,
            SubAccountV2Withdraw,
        },
    },
    authority::AuthorityType,
    swig::{
        sub_account_seeds, sub_account_v2_asset_seeds, sub_account_v2_state_seeds,
        swig_wallet_address_seeds, SwigWithRoles,
    },
};

// ---- helpers ----------------------------------------------------------------

fn v2_state_pda(id: &[u8; 32], subacc_id: u32) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &sub_account_v2_state_seeds(id, &subacc_id.to_le_bytes()),
        &program_id(),
    )
}

fn v2_asset_pda(id: &[u8; 32], subacc_id: u32) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &sub_account_v2_asset_seeds(id, &subacc_id.to_le_bytes()),
        &program_id(),
    )
}

fn role_id_of(context: &SwigTestContext, swig: &Pubkey, authority: &Pubkey) -> u32 {
    let data = context.svm.get_account(swig).unwrap().data;
    SwigWithRoles::from_bytes(&data)
        .unwrap()
        .lookup_role_id(authority.as_ref())
        .unwrap()
        .unwrap()
}

fn send(context: &mut SwigTestContext, payer: &Keypair, ix: Instruction) -> anyhow::Result<()> {
    let message =
        v0::Message::try_compile(&payer.pubkey(), &[ix], &[], context.svm.latest_blockhash())
            .unwrap();
    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[payer.insecure_clone()])
            .unwrap();
    context
        .svm
        .send_transaction(tx)
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("tx failed: {:?}", e))
}

/// Root wallet + a creator role (SubAccountV2Create) that creates sub-account 0.
/// Returns (swig_key, root, id, creator, state_pda, asset_pda).
fn setup(context: &mut SwigTestContext) -> (Pubkey, Keypair, [u8; 32], Keypair, Pubkey, Pubkey) {
    let root = Keypair::new();
    let creator = Keypair::new();
    context.svm.airdrop(&root.pubkey(), 10_000_000_000).unwrap();
    context
        .svm
        .airdrop(&creator.pubkey(), 10_000_000_000)
        .unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(context, &root, id).unwrap();

    add_authority_with_ed25519_root(
        context,
        &swig_key,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: creator.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccountV2Create(SubAccountV2Create)],
    )
    .unwrap();

    let creator_role = role_id_of(context, &swig_key, &creator.pubkey());
    let (state_pda, state_bump) = v2_state_pda(&id, 0);
    let (asset_pda, asset_bump) = v2_asset_pda(&id, 0);
    let ix = CreateSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        asset_pda,
        creator_role,
        state_bump,
        asset_bump,
    )
    .unwrap();
    send(context, &creator, ix).unwrap();
    context.svm.airdrop(&asset_pda, 1_000_000_000).unwrap();
    (swig_key, root, id, creator, state_pda, asset_pda)
}

/// Adds a role holding `actions` and returns (keypair, role_id).
fn add_role(
    context: &mut SwigTestContext,
    swig: &Pubkey,
    root: &Keypair,
    actions: Vec<ClientAction>,
) -> (Keypair, u32) {
    let kp = Keypair::new();
    context.svm.airdrop(&kp.pubkey(), 10_000_000_000).unwrap();
    add_authority_with_ed25519_root(
        context,
        swig,
        root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: kp.pubkey().as_ref(),
        },
        actions,
    )
    .unwrap();
    let role = role_id_of(context, swig, &kp.pubkey());
    (kp, role)
}

fn sign_ix(
    swig: Pubkey,
    state: Pubkey,
    asset: Pubkey,
    authority: &Keypair,
    role_id: u32,
    subacc_id: u32,
    recipient: &Pubkey,
    amount: u64,
) -> Instruction {
    let inner = solana_system_interface::instruction::transfer(&asset, recipient, amount);
    SubAccountSignV2Instruction::new_with_ed25519_authority(
        swig,
        state,
        asset,
        authority.pubkey(),
        role_id,
        subacc_id,
        vec![inner],
    )
    .unwrap()
}

fn withdraw_ix(
    swig: Pubkey,
    state: Pubkey,
    asset: Pubkey,
    authority: &Keypair,
    role_id: u32,
    subacc_id: u32,
    amount: u64,
) -> Instruction {
    let (wallet, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    WithdrawFromSubAccountV2Instruction::new_with_ed25519_authority(
        swig,
        authority.pubkey(),
        authority.pubkey(),
        state,
        asset,
        wallet,
        role_id,
        subacc_id,
        amount,
    )
    .unwrap()
}

fn toggle_ix(
    swig: Pubkey,
    state: Pubkey,
    authority: &Keypair,
    role_id: u32,
    subacc_id: u32,
    enabled: bool,
) -> Instruction {
    ToggleSubAccountV2Instruction::new_with_ed25519_authority(
        swig,
        authority.pubkey(),
        authority.pubkey(),
        state,
        role_id,
        subacc_id,
        enabled,
    )
    .unwrap()
}

// ---- wallet-level overrides are denied --------------------------------------

fn assert_override_denied_all_runtime(actions: Vec<ClientAction>) {
    let mut context = setup_test_context().unwrap();
    let (swig, root, id, _creator, state, asset) = setup(&mut context);
    let recipient = Keypair::new();
    let (role_kp, role) = add_role(&mut context, &swig, &root, actions);

    // sign / withdraw / toggle all denied for sub-account 0.
    let s = sign_ix(
        swig,
        state,
        asset,
        &role_kp,
        role,
        0,
        &recipient.pubkey(),
        1_000,
    );
    assert!(
        send(&mut context, &role_kp, s).is_err(),
        "sign must be denied"
    );
    let w = withdraw_ix(swig, state, asset, &role_kp, role, 0, 1_000);
    assert!(
        send(&mut context, &role_kp, w).is_err(),
        "withdraw must be denied"
    );
    let t = toggle_ix(swig, state, &role_kp, role, 0, false);
    assert!(
        send(&mut context, &role_kp, t).is_err(),
        "toggle must be denied"
    );
}

#[test]
fn test_all_override_denied_v2_runtime() {
    assert_override_denied_all_runtime(vec![ClientAction::All(All {})]);
}

#[test]
fn test_manage_authority_override_denied_v2_runtime() {
    assert_override_denied_all_runtime(vec![ClientAction::ManageAuthority(ManageAuthority {})]);
}

#[test]
fn test_all_but_manage_authority_override_denied_v2_runtime() {
    assert_override_denied_all_runtime(vec![ClientAction::AllButManageAuthority(
        AllButManageAuthority {},
    )]);
}

// ---- scoped permissions authorize exactly their op --------------------------

#[test]
fn test_scoped_sign_only() {
    let mut context = setup_test_context().unwrap();
    let (swig, root, _id, _creator, state, asset) = setup(&mut context);
    let recipient = Keypair::new();
    let (kp, role) = add_role(
        &mut context,
        &swig,
        &root,
        vec![ClientAction::SubAccountV2Sign(SubAccountV2Sign::new(0))],
    );

    // sign OK
    let s = sign_ix(swig, state, asset, &kp, role, 0, &recipient.pubkey(), 5_000);
    assert!(send(&mut context, &kp, s).is_ok());
    assert_eq!(
        context
            .svm
            .get_account(&recipient.pubkey())
            .unwrap()
            .lamports,
        5_000
    );
    // withdraw + toggle denied
    let w = withdraw_ix(swig, state, asset, &kp, role, 0, 1_000);
    assert!(send(&mut context, &kp, w).is_err());
    let t = toggle_ix(swig, state, &kp, role, 0, false);
    assert!(send(&mut context, &kp, t).is_err());
}

#[test]
fn test_scoped_withdraw_only() {
    let mut context = setup_test_context().unwrap();
    let (swig, root, id, _creator, state, asset) = setup(&mut context);
    let recipient = Keypair::new();
    let (kp, role) = add_role(
        &mut context,
        &swig,
        &root,
        vec![ClientAction::SubAccountV2Withdraw(
            SubAccountV2Withdraw::new(0),
        )],
    );

    let (wallet, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let before = context.svm.get_account(&wallet).unwrap().lamports;
    let w = withdraw_ix(swig, state, asset, &kp, role, 0, 7_000);
    assert!(send(&mut context, &kp, w).is_ok());
    assert_eq!(
        context.svm.get_account(&wallet).unwrap().lamports - before,
        7_000
    );
    // sign + toggle denied
    let s = sign_ix(swig, state, asset, &kp, role, 0, &recipient.pubkey(), 1_000);
    assert!(send(&mut context, &kp, s).is_err());
    let t = toggle_ix(swig, state, &kp, role, 0, false);
    assert!(send(&mut context, &kp, t).is_err());
}

#[test]
fn test_scoped_toggle_only() {
    let mut context = setup_test_context().unwrap();
    let (swig, root, _id, _creator, state, asset) = setup(&mut context);
    let recipient = Keypair::new();
    let (kp, role) = add_role(
        &mut context,
        &swig,
        &root,
        vec![ClientAction::SubAccountV2Toggle(SubAccountV2Toggle::new(0))],
    );

    let t = toggle_ix(swig, state, &kp, role, 0, false);
    assert!(send(&mut context, &kp, t).is_ok());
    // sign + withdraw denied
    let s = sign_ix(swig, state, asset, &kp, role, 0, &recipient.pubkey(), 1_000);
    assert!(send(&mut context, &kp, s).is_err());
    let w = withdraw_ix(swig, state, asset, &kp, role, 0, 1_000);
    assert!(send(&mut context, &kp, w).is_err());
}

#[test]
fn test_all_scope_is_id_scoped() {
    let mut context = setup_test_context().unwrap();
    let (swig, root, id, creator, state0, asset0) = setup(&mut context);
    let recipient = Keypair::new();

    // Create a second sub-account (id 1) with the creator role.
    let creator_role = role_id_of(&context, &swig, &creator.pubkey());
    let (state1, sb1) = v2_state_pda(&id, 1);
    let (asset1, ab1) = v2_asset_pda(&id, 1);
    let create1 = CreateSubAccountV2Instruction::new_with_ed25519_authority(
        swig,
        creator.pubkey(),
        creator.pubkey(),
        state1,
        asset1,
        creator_role,
        sb1,
        ab1,
    )
    .unwrap();
    send(&mut context, &creator, create1).unwrap();
    context.svm.airdrop(&asset1, 1_000_000_000).unwrap();

    // Role scoped to id 0 only.
    let (kp, role) = add_role(
        &mut context,
        &swig,
        &root,
        vec![ClientAction::SubAccountV2All(SubAccountV2All::new(0))],
    );

    // Works on id 0.
    let s0 = sign_ix(
        swig,
        state0,
        asset0,
        &kp,
        role,
        0,
        &recipient.pubkey(),
        3_000,
    );
    assert!(send(&mut context, &kp, s0).is_ok());
    // Denied on id 1.
    let s1 = sign_ix(
        swig,
        state1,
        asset1,
        &kp,
        role,
        1,
        &recipient.pubkey(),
        3_000,
    );
    assert!(
        send(&mut context, &kp, s1).is_err(),
        "All{{0}} must not reach id 1"
    );
}

// ---- sharing one sub-account across roles -----------------------------------

#[test]
fn test_share_one_subaccount_across_roles() {
    let mut context = setup_test_context().unwrap();
    let (swig, root, _id, _creator, state, asset) = setup(&mut context);
    let recipient = Keypair::new();

    // Two independent roles both granted Sign{0} for the same sub-account.
    let (a, ra) = add_role(
        &mut context,
        &swig,
        &root,
        vec![ClientAction::SubAccountV2Sign(SubAccountV2Sign::new(0))],
    );
    let (b, rb) = add_role(
        &mut context,
        &swig,
        &root,
        vec![ClientAction::SubAccountV2Sign(SubAccountV2Sign::new(0))],
    );

    let sa = sign_ix(swig, state, asset, &a, ra, 0, &recipient.pubkey(), 1_000);
    assert!(send(&mut context, &a, sa).is_ok());
    let sb = sign_ix(swig, state, asset, &b, rb, 0, &recipient.pubkey(), 2_000);
    assert!(send(&mut context, &b, sb).is_ok());
    assert_eq!(
        context
            .svm
            .get_account(&recipient.pubkey())
            .unwrap()
            .lamports,
        3_000
    );
}

// ---- self-grant recovery ----------------------------------------------------

#[test]
fn test_self_grant_recovery() {
    let mut context = setup_test_context().unwrap();
    let (swig, root, id, _creator, state, asset) = setup(&mut context);

    // Root holds All (role 0) but cannot withdraw a V2 sub-account by default.
    let root_role = role_id_of(&context, &swig, &root.pubkey());
    let w = withdraw_ix(swig, state, asset, &root, root_role, 0, 1_000);
    assert!(
        send(&mut context, &root, w).is_err(),
        "All must not withdraw by default"
    );

    // Root grants itself a scoped Withdraw and then succeeds.
    update_authority_replace_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        root_role,
        vec![
            ClientAction::All(All {}),
            ClientAction::SubAccountV2Withdraw(SubAccountV2Withdraw::new(0)),
        ],
    )
    .unwrap();
    let w2 = withdraw_ix(swig, state, asset, &root, root_role, 0, 1_000);
    assert!(
        send(&mut context, &root, w2).is_ok(),
        "self-granted withdraw should succeed"
    );
}

// ---- role deletion removes scoped grants atomically -------------------------

#[test]
fn test_role_deletion_removes_scoped_grant() {
    let mut context = setup_test_context().unwrap();
    let (swig, root, _id, _creator, state, asset) = setup(&mut context);
    let recipient = Keypair::new();
    let (kp, role) = add_role(
        &mut context,
        &swig,
        &root,
        vec![ClientAction::SubAccountV2Sign(SubAccountV2Sign::new(0))],
    );

    // Works before deletion.
    let s = sign_ix(swig, state, asset, &kp, role, 0, &recipient.pubkey(), 1_000);
    assert!(send(&mut context, &kp, s).is_ok());

    // Remove the role; its scoped grant is gone with it.
    remove_authority_with_ed25519_root(&mut context, &swig, &root, role).unwrap();
    let s2 = sign_ix(swig, state, asset, &kp, role, 0, &recipient.pubkey(), 1_000);
    assert!(
        send(&mut context, &kp, s2).is_err(),
        "removed role cannot sign"
    );
}

// ---- V1 / V2 seed non-collision ---------------------------------------------

#[test]
fn test_v1_v2_seed_non_collision() {
    let id = rand::random::<[u8; 32]>();
    for n in 0u32..4 {
        let n_le = n.to_le_bytes();
        let (v1, _) = Pubkey::find_program_address(&sub_account_seeds(&id, &n_le), &program_id());
        let (v2_asset, _) = v2_asset_pda(&id, n);
        let (v2_state, _) = v2_state_pda(&id, n);
        assert_ne!(
            v1, v2_asset,
            "V1 sub-account collides with V2 asset for id {}",
            n
        );
        assert_ne!(
            v1, v2_state,
            "V1 sub-account collides with V2 state for id {}",
            n
        );
        assert_ne!(v2_asset, v2_state);
    }
}

// ---- duplicate scoped action rejected ---------------------------------------

#[test]
fn test_duplicate_scoped_action_rejected() {
    let mut context = setup_test_context().unwrap();
    let (swig, root, _id, _creator, _state, _asset) = setup(&mut context);

    // Two Sign{0} actions on one role must be rejected at add time.
    let kp = Keypair::new();
    context.svm.airdrop(&kp.pubkey(), 10_000_000_000).unwrap();
    let res = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: kp.pubkey().as_ref(),
        },
        vec![
            ClientAction::SubAccountV2Sign(SubAccountV2Sign::new(0)),
            ClientAction::SubAccountV2Sign(SubAccountV2Sign::new(0)),
        ],
    );
    assert!(res.is_err(), "duplicate (Sign, id=0) must be rejected");
}
