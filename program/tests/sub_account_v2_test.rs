#![cfg(not(feature = "program_scope_test"))]
//! End-to-end tests for V2 sub-accounts: creation (with auto-granted scoped
//! access), SOL withdrawal, the enabled kill-switch, and the default-deny rule
//! that `All` alone cannot create.
mod common;

use common::stability::{scoped_v2_body, SwigSnapshot};
use common::*;
use litesvm_token::spl_token;
use solana_sdk::{
    message::{v0, VersionedMessage},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{
    AuthorityConfig, ClientAction, CloseSwigV1Instruction, CreateSubAccountV2Instruction,
    SubAccountSignV2Instruction, ToggleSubAccountV2Instruction,
    WithdrawFromSubAccountV2Instruction,
};
use swig_state::{
    action::{
        all::All,
        manage_authority::ManageAuthority,
        sub_account_v2::{
            SubAccountV2All, SubAccountV2Create, SubAccountV2Sign, SubAccountV2Toggle,
            SubAccountV2Withdraw,
        },
        Action, Permission,
    },
    authority::AuthorityType,
    sub_account_v2::SubAccountV2,
    swig::{sub_account_v2_asset_seeds, sub_account_v2_state_seeds, Swig, SwigWithRoles},
    Transmutable,
};

const CREATOR_ROLE_ID: u32 = 1;

/// Creates a swig with a root authority plus a role (id 1) holding a
/// `SubAccountV2Create` permission. Returns
/// (swig_key, root_keypair, creator_keypair, id).
fn setup_v2(context: &mut SwigTestContext) -> anyhow::Result<(Pubkey, Keypair, Keypair, [u8; 32])> {
    setup_v2_with_extra_actions(context, vec![])
}

/// As [`setup_v2`], with `extra` actions granted to the creator role alongside
/// `SubAccountV2Create`.
fn setup_v2_with_extra_actions(
    context: &mut SwigTestContext,
    extra: Vec<ClientAction>,
) -> anyhow::Result<(Pubkey, Keypair, Keypair, [u8; 32])> {
    let root = Keypair::new();
    let creator = Keypair::new();
    context.svm.airdrop(&root.pubkey(), 10_000_000_000).unwrap();
    context
        .svm
        .airdrop(&creator.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(context, &root, id)?;

    let mut actions = vec![ClientAction::SubAccountV2Create(SubAccountV2Create)];
    actions.extend(extra);
    add_authority_with_ed25519_root(
        context,
        &swig_key,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: creator.pubkey().as_ref(),
        },
        actions,
    )?;
    Ok((swig_key, root, creator, id))
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

/// Counts how many `SubAccountV2All` actions the role holds for `subacc_id`.
///
/// The auto-grant must never leave two: a role may hold at most one scoped V2
/// action per `(type, id)`, and a second copy is what
/// `reject_duplicate_v2_scoped` fails the whole create over.
fn role_all_scope_count(
    context: &SwigTestContext,
    swig_key: &Pubkey,
    role_id: u32,
    subacc_id: u32,
) -> usize {
    let data = context.svm.get_account(swig_key).unwrap().data;
    let swig = SwigWithRoles::from_bytes(&data).unwrap();
    let role = swig.get_role(role_id).unwrap().unwrap();
    let mut cursor = 0;
    let mut count = 0;
    for _ in 0..role.position.num_actions() {
        let header =
            unsafe { Action::load_unchecked(&role.actions[cursor..cursor + Action::LEN]).unwrap() };
        cursor += Action::LEN;
        let len = header.length() as usize;
        if header.permission().unwrap() == Permission::SubAccountV2All {
            let body = &role.actions[cursor..cursor + len];
            let read_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
            if read_id == subacc_id {
                count += 1;
            }
        }
        cursor += len;
    }
    count
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
    let (swig_key, _root, creator, id) = setup_v2(&mut context).unwrap();

    assert_eq!(decode_counter(&context, &swig_key), 0);

    let (state_pda, asset_pda) = create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();

    // Counter advanced.
    assert_eq!(decode_counter(&context, &swig_key), 1);

    // State account is program-owned and correctly populated.
    let state_acc = context.svm.get_account(&state_pda).unwrap();
    assert_eq!(state_acc.owner, program_id());
    assert_eq!(state_acc.data.len(), SubAccountV2::LEN);
    let state = unsafe { SubAccountV2::load_unchecked(&state_acc.data).unwrap() };
    assert!(state.is_enabled().unwrap());
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
fn test_create_sub_account_v2_accepts_prefunded_state_pda() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, _root, creator, id) = setup_v2(&mut context).unwrap();
    let (state_pda, _) = v2_state_pda(&id, 0);

    // A receiver does not sign a system transfer, so any account can pre-fund
    // the predictable state PDA.
    let prefund = solana_system_interface::instruction::transfer(&creator.pubkey(), &state_pda, 1);
    send(&mut context, &creator, prefund).unwrap();

    let (created_state, _asset) = create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();
    assert_eq!(created_state, state_pda);
    assert_eq!(decode_counter(&context, &swig_key), 1);
    let state_account = context.svm.get_account(&state_pda).unwrap();
    assert_eq!(state_account.owner, program_id());
    assert_eq!(state_account.data.len(), SubAccountV2::LEN);
}

#[test]
fn test_create_multiple_sub_accounts_from_one_role() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, _root, creator, id) = setup_v2(&mut context).unwrap();

    create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();
    create_v2(&mut context, &swig_key, &creator, &id, 1).unwrap();

    assert_eq!(decode_counter(&context, &swig_key), 2);
    assert!(role_has_all_scope(&context, &swig_key, CREATOR_ROLE_ID, 0));
    assert!(role_has_all_scope(&context, &swig_key, CREATOR_ROLE_ID, 1));
}

#[test]
fn test_withdraw_sol_from_sub_account_v2() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, _root, creator, id) = setup_v2(&mut context).unwrap();
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
fn test_withdraw_token_from_sub_account_v2() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, _root, creator, id) = setup_v2(&mut context).unwrap();
    let (state_pda, asset_pda) = create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();
    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_state::swig::swig_wallet_address_seeds(swig_key.as_ref()),
        &program_id(),
    );

    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let source_token =
        setup_ata(&mut context.svm, &mint, &asset_pda, &context.default_payer).unwrap();
    let destination_token = setup_ata(
        &mut context.svm,
        &mint,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint,
        &context.default_payer,
        &source_token,
        10_000,
    )
    .unwrap();

    let ix = WithdrawFromSubAccountV2Instruction::new_token_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        asset_pda,
        swig_wallet_address,
        source_token,
        destination_token,
        spl_token::ID,
        CREATOR_ROLE_ID,
        0,
        4_000,
    )
    .unwrap();
    send(&mut context, &creator, ix).unwrap();

    let source = context.svm.get_account(&source_token).unwrap();
    let destination = context.svm.get_account(&destination_token).unwrap();
    assert_eq!(
        spl_token::state::Account::unpack(&source.data)
            .unwrap()
            .amount,
        6_000
    );
    assert_eq!(
        spl_token::state::Account::unpack(&destination.data)
            .unwrap()
            .amount,
        4_000
    );
}

#[test]
fn test_toggle_disables_withdraw() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, _root, creator, id) = setup_v2(&mut context).unwrap();
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
    assert!(!decoded.is_enabled().unwrap());

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
fn test_toggle_rejects_invalid_enabled_byte() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, _root, creator, id) = setup_v2(&mut context).unwrap();
    let (state_pda, _asset_pda) = create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();

    let mut toggle = ToggleSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        CREATOR_ROLE_ID,
        0,
        false,
    )
    .unwrap();
    // SwigInstruction is u16, followed by the enabled wire byte.
    toggle.data[2] = 2;
    assert!(send(&mut context, &creator, toggle).is_err());

    let state = context.svm.get_account(&state_pda).unwrap();
    let decoded = unsafe { SubAccountV2::load_unchecked(&state.data).unwrap() };
    assert!(decoded.is_enabled().unwrap());
}

#[test]
fn test_invalid_stored_enabled_byte_is_rejected() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, _root, creator, id) = setup_v2(&mut context).unwrap();
    let (state_pda, asset_pda) = create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();
    context.svm.airdrop(&asset_pda, 1_000_000_000).unwrap();

    let mut state_account = context.svm.get_account(&state_pda).unwrap();
    state_account.data[3] = 2;
    context.svm.set_account(state_pda, state_account).unwrap();

    let recipient = Keypair::new();
    let inner =
        solana_system_interface::instruction::transfer(&asset_pda, &recipient.pubkey(), 1_000);
    let sign = SubAccountSignV2Instruction::new_with_ed25519_authority(
        swig_key,
        state_pda,
        asset_pda,
        creator.pubkey(),
        CREATOR_ROLE_ID,
        0,
        vec![inner],
    )
    .unwrap();
    assert!(
        send(&mut context, &creator, sign).is_err(),
        "runtime use must reject a non-canonical enabled value"
    );

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
    assert!(
        send(&mut context, &creator, toggle).is_err(),
        "toggle must not silently canonicalize corrupt state"
    );
}

#[test]
fn test_close_swig_allows_existing_sub_account_v2() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, root, creator, id) = setup_v2(&mut context).unwrap();
    create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();
    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_state::swig::swig_wallet_address_seeds(swig_key.as_ref()),
        &program_id(),
    );
    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();
    let close = CloseSwigV1Instruction::new_with_ed25519_authority(
        swig_key,
        swig_wallet_address,
        root.pubkey(),
        destination.pubkey(),
        0,
    )
    .unwrap();

    send(&mut context, &root, close).unwrap();
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    assert_eq!(
        swig_account.data[0],
        swig_state::Discriminator::ClosedSwigAccount as u8
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
    let (swig_key, _root, creator, id) = setup_v2(&mut context).unwrap();
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

/// Creating a V2 sub-account appends `SubAccountV2All { id }` to the creator's
/// role, which reallocs the swig account. When the creator is a *middle* role,
/// this shifts every role after it in the buffer. This test proves that neither
/// the shift nor the append corrupts any other role's authority or permissions.
///
/// Layout: role 0 = root (`All`), role 1 = creator (`SubAccountV2Create`),
/// role 2 = two permissions, role 3 = four permissions.
#[test]
fn test_create_sub_account_v2_preserves_other_roles_and_permissions() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    context.svm.airdrop(&root.pubkey(), 10_000_000_000).unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &root, id).unwrap();

    // Role 1: the creator (a middle role once 2 and 3 are added).
    let creator = Keypair::new();
    context
        .svm
        .airdrop(&creator.pubkey(), 10_000_000_000)
        .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: creator.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccountV2Create(SubAccountV2Create)],
    )
    .unwrap();

    // Role 2: two permissions (ManageAuthority + a scoped sign).
    let role2 = Keypair::new();
    context
        .svm
        .airdrop(&role2.pubkey(), 10_000_000_000)
        .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: role2.pubkey().as_ref(),
        },
        vec![
            ClientAction::ManageAuthority(ManageAuthority {}),
            ClientAction::SubAccountV2Sign(SubAccountV2Sign::new(100)),
        ],
    )
    .unwrap();

    // Role 3: four permissions of varied types with distinct scoped ids.
    let role3 = Keypair::new();
    context
        .svm
        .airdrop(&role3.pubkey(), 10_000_000_000)
        .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: role3.pubkey().as_ref(),
        },
        vec![
            ClientAction::SubAccountV2Create(SubAccountV2Create),
            ClientAction::SubAccountV2All(SubAccountV2All::new(101)),
            ClientAction::SubAccountV2Withdraw(SubAccountV2Withdraw::new(102)),
            ClientAction::SubAccountV2Toggle(SubAccountV2Toggle::new(103)),
        ],
    )
    .unwrap();

    // Snapshot the whole wallet before any sub-account exists.
    let id_creator = creator.pubkey().to_bytes();
    let id_role3 = role3.pubkey().to_bytes();
    let before = SwigSnapshot::capture(&context, &swig_key);
    assert_eq!(before.roles.len(), 4);
    assert_eq!(
        before.actions_of(&root.pubkey().to_bytes()).len(),
        1,
        "root: All"
    );
    assert_eq!(before.actions_of(&id_creator).len(), 1, "creator: Create");
    assert_eq!(
        before.actions_of(&role2.pubkey().to_bytes()).len(),
        2,
        "role 2: 2 perms"
    );
    assert_eq!(before.actions_of(&id_role3).len(), 4, "role 3: 4 perms");

    // Create sub-account 0 as the creator (a MIDDLE role): appends All{0} and
    // reallocs, shifting roles 2 and 3. Only the creator's role may change.
    create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();
    let after = SwigSnapshot::capture(&context, &swig_key);
    before.assert_others_stable(&after, &[id_creator]);
    assert_eq!(after.counter, before.counter + 1);
    let mut expected_creator = before.actions_of(&id_creator).clone();
    expected_creator.push((Permission::SubAccountV2All, scoped_v2_body(0)));
    assert_eq!(
        after.actions_of(&id_creator),
        &expected_creator,
        "creator's auto-granted All{{0}} is wrong"
    );

    // Functional proof: role 3's authority + SubAccountV2Create survived the
    // realloc and still work — it creates sub-account 1. Only role 3 changes.
    let (state_pda, state_bump) = v2_state_pda(&id, 1);
    let (asset_pda, asset_bump) = v2_asset_pda(&id, 1);
    let ix = CreateSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        role3.pubkey(),
        role3.pubkey(),
        state_pda,
        asset_pda,
        3,
        state_bump,
        asset_bump,
    )
    .unwrap();
    send(&mut context, &role3, ix).unwrap();
    let after2 = SwigSnapshot::capture(&context, &swig_key);
    after.assert_others_stable(&after2, &[id_role3]);
    assert_eq!(after2.counter, 2);

    // Repeat a MIDDLE-role realloc: the creator creates sub-account 2, shifting
    // roles 2 and 3 again. Everything except the creator stays byte-identical.
    create_v2(&mut context, &swig_key, &creator, &id, 2).unwrap();
    let after3 = SwigSnapshot::capture(&context, &swig_key);
    after2.assert_others_stable(&after3, &[id_creator]);
    assert_eq!(after3.counter, 3);
}

/// The design allows scoping a sub-account id before it exists. When the id the
/// counter then draws is that same id, the auto-grant must not append a second
/// `SubAccountV2All` — the duplicate check would fail the whole create.
#[test_log::test]
fn test_create_v2_when_creator_pre_granted_all_for_the_drawn_id() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, _root, creator, id) = setup_v2_with_extra_actions(
        &mut context,
        vec![ClientAction::SubAccountV2All(SubAccountV2All::new(0))],
    )
    .unwrap();

    // Pre-grant is in place before anything is created.
    assert_eq!(decode_counter(&context, &swig_key), 0);
    assert_eq!(
        role_all_scope_count(&context, &swig_key, CREATOR_ROLE_ID, 0),
        1
    );

    // Creating id 0 used to fail with DuplicateV2SubAccountAction (1009).
    let (state_pda, _asset_pda) = create_v2(&mut context, &swig_key, &creator, &id, 0)
        .expect("create must succeed when the scope is already granted");

    assert_eq!(decode_counter(&context, &swig_key), 1);
    assert_eq!(
        role_all_scope_count(&context, &swig_key, CREATOR_ROLE_ID, 0),
        1,
        "the pre-grant must be left alone, not duplicated"
    );

    // The sub-account really was created, and the scope still authorizes it.
    let state_acc = context.svm.get_account(&state_pda).unwrap();
    assert_eq!(state_acc.owner, program_id());
    let state = unsafe { SubAccountV2::load_unchecked(&state_acc.data).unwrap() };
    assert_eq!(state.subacc_id, 0);
    assert!(state.is_enabled().unwrap());
}

/// A pre-grant for a *different* id must not suppress the auto-grant: the role
/// ends up holding both scopes.
#[test_log::test]
fn test_create_v2_pre_grant_for_other_id_still_auto_grants() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, _root, creator, id) = setup_v2_with_extra_actions(
        &mut context,
        vec![ClientAction::SubAccountV2All(SubAccountV2All::new(5))],
    )
    .unwrap();

    create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();

    assert_eq!(
        role_all_scope_count(&context, &swig_key, CREATOR_ROLE_ID, 0),
        1,
        "the drawn id must still be auto-granted"
    );
    assert_eq!(
        role_all_scope_count(&context, &swig_key, CREATOR_ROLE_ID, 5),
        1,
        "the unrelated pre-grant must survive"
    );
}
