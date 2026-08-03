#![cfg(not(feature = "program_scope_test"))]
//! Combination realloc-stability test.
//!
//! A wallet with multiple roles and a rent claimer, driven through every swig
//! account **size-modifying** instruction — add authority, update authority
//! (grow and shrink), create V2 sub-account, remove authority. After each op the
//! *unrelated* roles and the rent-claimer tail must survive byte-for-byte, and
//! the rent claimer must never change. Built on the reusable `common::stability`
//! harness so this kind of test needs no bespoke decode/compare boilerplate.

mod common;

use common::{
    stability::{scoped_v2_body, SwigSnapshot},
    *,
};
use solana_sdk::{
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ClientAction, CreateSubAccountV2Instruction};
use swig_state::{
    action::{
        manage_authority::ManageAuthority,
        sol_limit::SolLimit,
        sub_account_v2::{
            SubAccountV2All, SubAccountV2Create, SubAccountV2Sign, SubAccountV2Toggle,
            SubAccountV2Withdraw,
        },
        Permission,
    },
    authority::AuthorityType,
    swig::{sub_account_v2_asset_seeds, sub_account_v2_state_seeds, SwigWithRoles},
};

fn ed(authority: &Pubkey) -> AuthorityConfig<'_> {
    AuthorityConfig {
        authority_type: AuthorityType::Ed25519,
        authority: authority.as_ref(),
    }
}

fn fund(context: &mut SwigTestContext, kp: &Keypair) {
    context.svm.airdrop(&kp.pubkey(), 100_000_000_000).unwrap();
}

fn role_id(context: &SwigTestContext, swig: &Pubkey, authority: &Pubkey) -> u32 {
    let data = context.svm.get_account(swig).unwrap().data;
    SwigWithRoles::from_bytes(&data)
        .unwrap()
        .lookup_role_id(authority.as_ref())
        .unwrap()
        .unwrap()
}

/// Sends a `CreateSubAccountV2` signed by `signer`, which must hold
/// `SubAccountV2Create` on `role`.
fn create_v2(
    context: &mut SwigTestContext,
    swig: &Pubkey,
    signer: &Keypair,
    role: u32,
    id: &[u8; 32],
    subacc_id: u32,
) {
    let id_le = subacc_id.to_le_bytes();
    let (state_pda, state_bump) =
        Pubkey::find_program_address(&sub_account_v2_state_seeds(id, &id_le), &program_id());
    let (asset_pda, asset_bump) =
        Pubkey::find_program_address(&sub_account_v2_asset_seeds(id, &id_le), &program_id());
    let ix = CreateSubAccountV2Instruction::new_with_ed25519_authority(
        *swig,
        signer.pubkey(),
        signer.pubkey(),
        state_pda,
        asset_pda,
        role,
        state_bump,
        asset_bump,
    )
    .unwrap();
    let msg =
        v0::Message::try_compile(&signer.pubkey(), &[ix], &[], context.svm.latest_blockhash())
            .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[signer.insecure_clone()])
        .unwrap();
    context
        .svm
        .send_transaction(tx)
        .expect("create_sub_account_v2 failed");
}

#[test]
fn test_realloc_stability_with_rent_claimer_and_multiple_roles() {
    let mut context = setup_test_context().unwrap();

    // Role 0: root (All).
    let root = Keypair::new();
    fund(&mut context, &root);
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    // Role 1: the creator (SubAccountV2Create) — a middle role once 2 & 3 exist.
    let creator = Keypair::new();
    fund(&mut context, &creator);
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        ed(&creator.pubkey()),
        vec![ClientAction::SubAccountV2Create(SubAccountV2Create)],
    )
    .unwrap();

    // Role 2: two permissions — the untouched witness throughout the whole run.
    let role2 = Keypair::new();
    fund(&mut context, &role2);
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        ed(&role2.pubkey()),
        vec![
            ClientAction::ManageAuthority(ManageAuthority {}),
            ClientAction::SolLimit(SolLimit { amount: 111 }),
        ],
    )
    .unwrap();

    // Role 3: four permissions (varied scoped V2 types, distinct ids).
    let role3 = Keypair::new();
    fund(&mut context, &role3);
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        ed(&role3.pubkey()),
        vec![
            ClientAction::SubAccountV2Create(SubAccountV2Create),
            ClientAction::SubAccountV2All(SubAccountV2All::new(201)),
            ClientAction::SubAccountV2Withdraw(SubAccountV2Withdraw::new(202)),
            ClientAction::SubAccountV2Toggle(SubAccountV2Toggle::new(203)),
        ],
    )
    .unwrap();

    // Set the rent claimer (grows the tail), signed by root.
    let claimer = Keypair::new().pubkey();
    set_rent_claimer_with_ed25519(&mut context, &swig, &root, 0, claimer).unwrap();

    let id_creator = creator.pubkey().to_bytes();
    let id_r3 = role3.pubkey().to_bytes();

    let s = SwigSnapshot::capture(&context, &swig);
    assert_eq!(s.roles.len(), 4, "root + 3 roles");
    assert_eq!(
        s.rent_claimer,
        Some(claimer.to_bytes()),
        "rent claimer must be set"
    );

    // === 1) ADD AUTHORITY (grow): add role 4; no existing role changes. ===
    let role4 = Keypair::new();
    fund(&mut context, &role4);
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        ed(&role4.pubkey()),
        vec![ClientAction::SolLimit(SolLimit { amount: 5 })],
    )
    .unwrap();
    let id_r4 = role4.pubkey().to_bytes();
    let after = SwigSnapshot::capture(&context, &swig);
    s.assert_others_stable(&after, &[]);
    assert!(
        after.role_by_identity(&id_r4).is_some(),
        "role 4 should exist"
    );
    assert!(
        after.account_len > s.account_len,
        "add authority should grow the account"
    );
    let s = after;

    // === 2) UPDATE AUTHORITY (grow role 4): replace 1 action with 3. ===
    let r4_id = role_id(&context, &swig, &role4.pubkey());
    update_authority_replace_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        r4_id,
        vec![
            ClientAction::SolLimit(SolLimit { amount: 5 }),
            ClientAction::SubAccountV2Sign(SubAccountV2Sign::new(300)),
            ClientAction::SubAccountV2Toggle(SubAccountV2Toggle::new(301)),
        ],
    )
    .unwrap();
    let after = SwigSnapshot::capture(&context, &swig);
    s.assert_others_stable(&after, &[id_r4]);
    assert_eq!(
        after.actions_of(&id_r4).len(),
        3,
        "role 4 should hold 3 actions"
    );
    let s = after;

    // === 3) CREATE SUB-ACCOUNT V2 by the creator (MIDDLE role): appends
    //         SubAccountV2All{0} and reallocs, shifting roles 2, 3, 4. ===
    let creator_role = role_id(&context, &swig, &creator.pubkey());
    create_v2(&mut context, &swig, &creator, creator_role, &id, 0);
    let after = SwigSnapshot::capture(&context, &swig);
    s.assert_others_stable(&after, &[id_creator]);
    assert_eq!(after.counter, s.counter + 1, "counter must advance");
    let mut expected_creator = s.actions_of(&id_creator).clone();
    expected_creator.push((Permission::SubAccountV2All, scoped_v2_body(0)));
    assert_eq!(
        after.actions_of(&id_creator),
        &expected_creator,
        "creator must gain exactly SubAccountV2All{{0}}"
    );
    let s = after;

    // === 4) UPDATE AUTHORITY (shrink role 3): 4 actions -> 1. ===
    let r3_id = role_id(&context, &swig, &role3.pubkey());
    update_authority_replace_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        r3_id,
        vec![ClientAction::SubAccountV2Create(SubAccountV2Create)],
    )
    .unwrap();
    let after = SwigSnapshot::capture(&context, &swig);
    s.assert_others_stable(&after, &[id_r3]);
    assert_eq!(
        after.actions_of(&id_r3).len(),
        1,
        "role 3 should shrink to 1 action"
    );
    assert!(
        after.account_len < s.account_len,
        "shrinking a role should shrink the account"
    );
    let s = after;

    // === 5) REMOVE AUTHORITY (shrink): remove role 4 entirely. ===
    let r4_id = role_id(&context, &swig, &role4.pubkey());
    remove_authority_with_ed25519_root(&mut context, &swig, &root, r4_id).unwrap();
    let after = SwigSnapshot::capture(&context, &swig);
    s.assert_others_stable(&after, &[id_r4]);
    assert!(
        after.role_by_identity(&id_r4).is_none(),
        "role 4 should be gone"
    );
    let s = after;

    // === 6) CREATE another sub-account — the creator still works after all the
    //         grows, shrinks, and the removal that shuffled the buffer. ===
    let creator_role = role_id(&context, &swig, &creator.pubkey());
    create_v2(&mut context, &swig, &creator, creator_role, &id, 1);
    let after = SwigSnapshot::capture(&context, &swig);
    s.assert_others_stable(&after, &[id_creator]);
    assert_eq!(after.counter, 2, "second create advances the counter");

    // The rent claimer survived every realloc, byte-for-byte.
    assert_eq!(after.rent_claimer, Some(claimer.to_bytes()));
}
