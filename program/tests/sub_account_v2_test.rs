#![cfg(not(feature = "program_scope_test"))]
//! End-to-end tests for V2 sub-accounts: creation (with auto-granted scoped
//! access), SOL withdrawal, the enabled kill-switch, and the default-deny rule
//! that `All` alone cannot create.
mod common;

use common::*;
use solana_sdk::{
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
        sub_account_v2::{SubAccountV2All, SubAccountV2Create},
        Action, Permission,
    },
    authority::AuthorityType,
    sub_account_v2::SubAccountV2,
    swig::{sub_account_v2_asset_seeds, sub_account_v2_state_seeds, Swig, SwigWithRoles},
    Transmutable,
};

const CREATOR_ROLE_ID: u32 = 1;

/// Creates a swig with a root authority plus a role (id 1) holding a
/// `SubAccountV2Create` permission. Returns (swig_key, creator_keypair, id).
fn setup_v2(context: &mut SwigTestContext) -> anyhow::Result<(Pubkey, Keypair, [u8; 32])> {
    let root = Keypair::new();
    let creator = Keypair::new();
    context.svm.airdrop(&root.pubkey(), 10_000_000_000).unwrap();
    context
        .svm
        .airdrop(&creator.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(context, &root, id)?;

    add_authority_with_ed25519_root(
        context,
        &swig_key,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: creator.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccountV2Create(SubAccountV2Create)],
    )?;
    Ok((swig_key, creator, id))
}

fn v2_state_pda(id: &[u8; 32], subacc_id: u32) -> (Pubkey, u8) {
    let id_le = subacc_id.to_le_bytes();
    Pubkey::find_program_address(&sub_account_v2_state_seeds(id, &id_le), &program_id())
}

fn v2_asset_pda(id: &[u8; 32], subacc_id: u32) -> (Pubkey, u8) {
    let id_le = subacc_id.to_le_bytes();
    Pubkey::find_program_address(&sub_account_v2_asset_seeds(id, &id_le), &program_id())
}

fn create_v2(
    context: &mut SwigTestContext,
    swig_key: &Pubkey,
    creator: &Keypair,
    id: &[u8; 32],
    subacc_id: u32,
) -> anyhow::Result<(Pubkey, Pubkey)> {
    let (state_pda, state_bump) = v2_state_pda(id, subacc_id);
    let (asset_pda, asset_bump) = v2_asset_pda(id, subacc_id);
    let ix = CreateSubAccountV2Instruction::new_with_ed25519_authority(
        *swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        asset_pda,
        CREATOR_ROLE_ID,
        state_bump,
        asset_bump,
    )
    .map_err(|e| anyhow::anyhow!("build create v2: {:?}", e))?;
    send(context, creator, ix)?;
    Ok((state_pda, asset_pda))
}

fn send(
    context: &mut SwigTestContext,
    payer: &Keypair,
    ix: solana_sdk::instruction::Instruction,
) -> anyhow::Result<()> {
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

fn decode_counter(context: &SwigTestContext, swig_key: &Pubkey) -> u32 {
    let data = context.svm.get_account(swig_key).unwrap().data;
    let swig = unsafe { Swig::load_unchecked(&data[..Swig::LEN]).unwrap() };
    swig.sub_account_counter
}

/// Returns true if the given role holds a `SubAccountV2All` action for
/// `subacc_id`.
fn role_has_all_scope(
    context: &SwigTestContext,
    swig_key: &Pubkey,
    role_id: u32,
    subacc_id: u32,
) -> bool {
    let data = context.svm.get_account(swig_key).unwrap().data;
    let swig = SwigWithRoles::from_bytes(&data).unwrap();
    let role = swig.get_role(role_id).unwrap().unwrap();
    let mut cursor = 0;
    for _ in 0..role.position.num_actions() {
        let header =
            unsafe { Action::load_unchecked(&role.actions[cursor..cursor + Action::LEN]).unwrap() };
        cursor += Action::LEN;
        let len = header.length() as usize;
        if header.permission().unwrap() == Permission::SubAccountV2All {
            let body = &role.actions[cursor..cursor + len];
            let read_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
            if read_id == subacc_id {
                return true;
            }
        }
        cursor += len;
    }
    false
}

#[test]
fn test_create_sub_account_v2_initializes_state_and_grants_creator() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, creator, id) = setup_v2(&mut context).unwrap();

    assert_eq!(decode_counter(&context, &swig_key), 0);

    let (state_pda, asset_pda) = create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();

    // Counter advanced.
    assert_eq!(decode_counter(&context, &swig_key), 1);

    // State account is program-owned and correctly populated.
    let state_acc = context.svm.get_account(&state_pda).unwrap();
    assert_eq!(state_acc.owner, program_id());
    assert_eq!(state_acc.data.len(), SubAccountV2::LEN);
    let state = unsafe { SubAccountV2::load_unchecked(&state_acc.data).unwrap() };
    assert!(state.enabled);
    assert_eq!(state.subacc_id, 0);
    assert_eq!(state.swig_id, id);
    assert_eq!(state.sub_account, asset_pda.to_bytes());

    // Asset account is system-owned and rent-exempt.
    let asset_acc = context.svm.get_account(&asset_pda).unwrap();
    assert_eq!(asset_acc.owner, solana_system_interface::program::id());
    assert!(asset_acc.lamports > 0);

    // Creator role auto-granted SubAccountV2All { 0 }.
    assert!(role_has_all_scope(&context, &swig_key, CREATOR_ROLE_ID, 0));
}

#[test]
fn test_create_multiple_sub_accounts_from_one_role() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, creator, id) = setup_v2(&mut context).unwrap();

    create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();
    create_v2(&mut context, &swig_key, &creator, &id, 1).unwrap();

    assert_eq!(decode_counter(&context, &swig_key), 2);
    assert!(role_has_all_scope(&context, &swig_key, CREATOR_ROLE_ID, 0));
    assert!(role_has_all_scope(&context, &swig_key, CREATOR_ROLE_ID, 1));
}

#[test]
fn test_withdraw_sol_from_sub_account_v2() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, creator, id) = setup_v2(&mut context).unwrap();
    let (_state_pda, asset_pda) = create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_state::swig::swig_wallet_address_seeds(swig_key.as_ref()),
        &program_id(),
    );

    context.svm.airdrop(&asset_pda, 1_000_000_000).unwrap();
    let asset_before = context.svm.get_account(&asset_pda).unwrap().lamports;
    let dest_before = context
        .svm
        .get_account(&swig_wallet_address)
        .unwrap()
        .lamports;

    let amount = 100_000_000u64;
    let ix = WithdrawFromSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        _state_pda,
        asset_pda,
        swig_wallet_address,
        CREATOR_ROLE_ID,
        0,
        amount,
    )
    .unwrap();
    send(&mut context, &creator, ix).unwrap();

    let asset_after = context.svm.get_account(&asset_pda).unwrap().lamports;
    let dest_after = context
        .svm
        .get_account(&swig_wallet_address)
        .unwrap()
        .lamports;
    assert_eq!(asset_before - asset_after, amount);
    assert_eq!(dest_after - dest_before, amount);
}

#[test]
fn test_toggle_disables_withdraw() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, creator, id) = setup_v2(&mut context).unwrap();
    let (state_pda, asset_pda) = create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();
    context.svm.airdrop(&asset_pda, 1_000_000_000).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_state::swig::swig_wallet_address_seeds(swig_key.as_ref()),
        &program_id(),
    );

    // Disable the sub-account.
    let toggle = ToggleSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        CREATOR_ROLE_ID,
        0,
        false,
    )
    .unwrap();
    send(&mut context, &creator, toggle).unwrap();

    let state = context.svm.get_account(&state_pda).unwrap();
    let decoded = unsafe { SubAccountV2::load_unchecked(&state.data).unwrap() };
    assert!(!decoded.enabled);

    // Withdrawing from a disabled sub-account must fail.
    let ix = WithdrawFromSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        asset_pda,
        swig_wallet_address,
        CREATOR_ROLE_ID,
        0,
        10_000_000,
    )
    .unwrap();
    assert!(
        send(&mut context, &creator, ix).is_err(),
        "withdraw should fail while sub-account is disabled"
    );
}

#[test]
fn test_all_permission_cannot_create_sub_account_v2() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let all_authority = Keypair::new();
    context.svm.airdrop(&root.pubkey(), 10_000_000_000).unwrap();
    context
        .svm
        .airdrop(&all_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    // Role 1 holds only `All` — no SubAccountV2Create.
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: all_authority.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {})],
    )
    .unwrap();

    let (state_pda, state_bump) = v2_state_pda(&id, 0);
    let (asset_pda, asset_bump) = v2_asset_pda(&id, 0);
    let ix = CreateSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        all_authority.pubkey(),
        all_authority.pubkey(),
        state_pda,
        asset_pda,
        1,
        state_bump,
        asset_bump,
    )
    .unwrap();
    assert!(
        send(&mut context, &all_authority, ix).is_err(),
        "All alone must not be able to create a V2 sub-account"
    );
    // Counter must not have advanced.
    assert_eq!(decode_counter(&context, &swig_key), 0);
}

#[test]
fn test_sign_transfers_from_asset_pda() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, creator, id) = setup_v2(&mut context).unwrap();
    let (state_pda, asset_pda) = create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();
    context.svm.airdrop(&asset_pda, 1_000_000_000).unwrap();

    let recipient = Keypair::new();
    let amount = 50_000_000u64;
    let inner =
        solana_system_interface::instruction::transfer(&asset_pda, &recipient.pubkey(), amount);

    let ix = SubAccountSignV2Instruction::new_with_ed25519_authority(
        swig_key,
        state_pda,
        asset_pda,
        creator.pubkey(),
        CREATOR_ROLE_ID,
        0,
        vec![inner],
    )
    .unwrap();
    send(&mut context, &creator, ix).unwrap();

    let recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    assert_eq!(recipient_balance, amount);
}
