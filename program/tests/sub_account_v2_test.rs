#![cfg(not(feature = "program_scope_test"))]
//! End-to-end tests for V2 sub-accounts: creation (with auto-granted scoped
//! access), SOL withdrawal, the enabled kill-switch, and the default-deny rule
//! that `All` alone cannot create.
mod common;

use common::{
    stability::{scoped_v2_body, SwigSnapshot},
    *,
};
use litesvm_token::spl_token;
use solana_sdk::{
    instruction::InstructionError,
    message::{v0, VersionedMessage},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    sysvar::rent::Rent,
    transaction::{TransactionError, VersionedTransaction},
};
use swig::error::SwigError;
use swig_interface::{
    AddAuthorityInstruction, AuthorityConfig, ClientAction, CloseSubAccountV2Instruction,
    CloseSwigV1Instruction, CreateSubAccountV2Instruction, SignV2Instruction,
    SubAccountSignV2Instruction, ToggleSubAccountV2Instruction, UpdateAuthorityData,
    UpdateAuthorityInstruction, WithdrawFromSubAccountV2Instruction,
};
use swig_state::{
    action::{
        all::All,
        close_swig_authority::CloseSwigAuthority,
        manage_authority::ManageAuthority,
        program_all::ProgramAll,
        sol_limit::SolLimit,
        sub_account_v2::{SubAccountV2All, SubAccountV2Create, SubAccountV2Sign},
        Action, Permission,
    },
    authority::AuthorityType,
    sub_account_v2::SubAccountV2,
    swig::{
        sub_account_v2_asset_seeds, sub_account_v2_state_seeds, swig_wallet_address_seeds, Swig,
        SwigWithRoles,
    },
    tail::active_sub_account_count,
    SwigStateError, Transmutable,
};

const CREATOR_ROLE_ID: u32 = 1;

/// Creates a swig with a root authority plus a role (id 1) holding a
/// `SubAccountV2Create` permission. Returns
/// (swig_key, root_keypair, creator_keypair, id).
fn setup_v2(context: &mut SwigTestContext) -> anyhow::Result<(Pubkey, Keypair, Keypair, [u8; 32])> {
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

fn send_admin(
    context: &mut SwigTestContext,
    authority: &Keypair,
    ix: solana_sdk::instruction::Instruction,
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
        &[
            context.default_payer.insecure_clone(),
            authority.insecure_clone(),
        ],
    )
    .unwrap();
    context
        .svm
        .send_transaction(tx)
        .map(|_| ())
        .map_err(|error| error.err)
}

fn assert_nonexistent_scope_error(result: Result<(), TransactionError>) {
    assert_eq!(
        result,
        Err(TransactionError::InstructionError(
            0,
            InstructionError::Custom(
                SwigStateError::SubAccountV2PermissionTargetDoesNotExist as u32,
            ),
        ))
    );
}

fn assert_v1_swig_error(result: Result<(), TransactionError>) {
    assert_eq!(
        result,
        Err(TransactionError::InstructionError(
            0,
            InstructionError::Custom(SwigError::SignV2CannotBeUsedWithSwigV1 as u32),
        ))
    );
}

fn decode_counter(context: &SwigTestContext, swig_key: &Pubkey) -> u32 {
    let data = context.svm.get_account(swig_key).unwrap().data;
    let swig = unsafe { Swig::load_unchecked(&data[..Swig::LEN]).unwrap() };
    swig.sub_account_counter
}

fn overwrite_with_v1_counter_overlay(context: &mut SwigTestContext, swig_key: &Pubkey) {
    let (_, wallet_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());
    // V1 stored one reserved-lamports u64 over wallet_bump, padding, and the
    // V2 counter. This value is recognizably V1 but its upper word reads as a
    // counterfeit sub_account_counter == 1 if the generation is ignored.
    let reserved_lamports = (1u64 << 32) | (1u64 << 8) | u64::from(wallet_bump);
    let mut account = context.svm.get_account(swig_key).unwrap();
    account.data[Swig::LEN - 8..Swig::LEN].copy_from_slice(&reserved_lamports.to_le_bytes());
    context.svm.set_account(*swig_key, account).unwrap();
}

fn decode_active_count(context: &SwigTestContext, swig_key: &Pubkey) -> u32 {
    let data = context.svm.get_account(swig_key).unwrap().data;
    let parts = Swig::split_parts(&data).unwrap();
    active_sub_account_count::read(parts.tail).unwrap().unwrap()
}

fn strip_active_count_tail(context: &mut SwigTestContext, swig_key: &Pubkey) {
    let count = decode_active_count(context, swig_key);
    let mut account = context.svm.get_account(swig_key).unwrap();
    let parts = Swig::split_parts(&account.data).unwrap();
    assert!(parts
        .tail
        .ends_with(&active_sub_account_count::entry(count)));
    account
        .data
        .truncate(account.data.len() - active_sub_account_count::ENTRY_LEN);
    context.svm.set_account(*swig_key, account).unwrap();
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
fn test_close_swig_rejects_existing_sub_account_v2() {
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

    assert!(
        send(&mut context, &root, close).is_err(),
        "parent close must fail while a V2 sub-account is active"
    );
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    assert_eq!(
        swig_account.data[0],
        swig_state::Discriminator::SwigConfigAccount as u8
    );
    assert_eq!(decode_active_count(&context, &swig_key), 1);
}

#[test]
fn test_close_sub_account_v2_sweeps_lamports_and_unblocks_parent_close() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, root, creator, id) = setup_v2(&mut context).unwrap();
    let (state_pda, asset_pda) = create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();
    context.svm.airdrop(&asset_pda, 1_000_000_000).unwrap();
    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_state::swig::swig_wallet_address_seeds(swig_key.as_ref()),
        &program_id(),
    );

    let close_while_enabled = CloseSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        root.pubkey(),
        state_pda,
        asset_pda,
        swig_wallet_address,
        None,
        root.pubkey(),
        0,
        0,
    )
    .unwrap();
    assert!(send(&mut context, &root, close_while_enabled).is_err());
    assert_eq!(decode_active_count(&context, &swig_key), 1);
    context.svm.expire_blockhash();

    let disable = ToggleSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        CREATOR_ROLE_ID,
        0,
        false,
    )
    .unwrap();
    send(&mut context, &creator, disable).unwrap();

    let arbitrary_destination = Keypair::new();
    context
        .svm
        .airdrop(&arbitrary_destination.pubkey(), 1)
        .unwrap();
    let redirect_without_claimer = CloseSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        root.pubkey(),
        state_pda,
        asset_pda,
        swig_wallet_address,
        Some(arbitrary_destination.pubkey()),
        root.pubkey(),
        0,
        0,
    )
    .unwrap();
    assert!(send(&mut context, &root, redirect_without_claimer).is_err());
    assert_eq!(decode_active_count(&context, &swig_key), 1);
    context.svm.expire_blockhash();

    let wallet_before = context
        .svm
        .get_account(&swig_wallet_address)
        .unwrap()
        .lamports;
    let state_lamports = context.svm.get_account(&state_pda).unwrap().lamports;
    let asset_lamports = context.svm.get_account(&asset_pda).unwrap().lamports;
    let close_child = CloseSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        root.pubkey(),
        state_pda,
        asset_pda,
        swig_wallet_address,
        None,
        root.pubkey(),
        0,
        0,
    )
    .unwrap();
    assert_eq!(close_child.accounts[5].pubkey, program_id());
    assert!(!close_child.accounts[5].is_writable);
    assert_eq!(
        close_child.accounts[6].pubkey,
        solana_system_interface::program::ID
    );
    send(&mut context, &root, close_child).unwrap();

    assert!(context.svm.get_account(&state_pda).is_none());
    assert!(context.svm.get_account(&asset_pda).is_none());
    assert_eq!(decode_active_count(&context, &swig_key), 0);
    assert_eq!(
        context
            .svm
            .get_account(&swig_wallet_address)
            .unwrap()
            .lamports,
        wallet_before + state_lamports + asset_lamports
    );

    // Drain the parent wallet PDA before the existing CloseSwigV1 empty-wallet
    // check, then prove the zero-child guard permits final closure.
    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();
    let wallet_lamports = context
        .svm
        .get_account(&swig_wallet_address)
        .unwrap()
        .lamports;
    let drain = solana_system_interface::instruction::transfer(
        &swig_wallet_address,
        &destination.pubkey(),
        wallet_lamports,
    );
    let sign =
        SignV2Instruction::new_ed25519(swig_key, swig_wallet_address, root.pubkey(), drain, 0)
            .unwrap();
    send(&mut context, &root, sign).unwrap();

    let close_parent = CloseSwigV1Instruction::new_with_ed25519_authority(
        swig_key,
        swig_wallet_address,
        root.pubkey(),
        destination.pubkey(),
        0,
    )
    .unwrap();
    send(&mut context, &root, close_parent).unwrap();
    assert_eq!(
        context.svm.get_account(&swig_key).unwrap().data[0],
        swig_state::Discriminator::ClosedSwigAccount as u8
    );
}

#[test]
fn test_close_sub_account_v2_accepts_explicit_wallet_without_rent_claimer() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, root, creator, id) = setup_v2(&mut context).unwrap();
    let (state_pda, asset_pda) = create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();
    let disable = ToggleSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        CREATOR_ROLE_ID,
        0,
        false,
    )
    .unwrap();
    send(&mut context, &creator, disable).unwrap();
    let (wallet, _) = Pubkey::find_program_address(
        &swig_state::swig::swig_wallet_address_seeds(swig_key.as_ref()),
        &program_id(),
    );
    let close = CloseSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        root.pubkey(),
        state_pda,
        asset_pda,
        wallet,
        Some(wallet),
        root.pubkey(),
        0,
        0,
    )
    .unwrap();

    send(&mut context, &root, close).unwrap();
    assert!(context.svm.get_account(&state_pda).is_none());
    assert!(context.svm.get_account(&asset_pda).is_none());
    assert_eq!(decode_active_count(&context, &swig_key), 0);
}

#[test]
fn test_close_legacy_v2_sub_account_materializes_active_count() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, root, creator, id) = setup_v2(&mut context).unwrap();
    let claimer = Keypair::new();
    context.svm.airdrop(&claimer.pubkey(), 1).unwrap();
    set_rent_claimer_with_ed25519(&mut context, &swig_key, &root, 0, claimer.pubkey()).unwrap();
    let (state_pda, asset_pda) = create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();
    context.svm.airdrop(&state_pda, 500_000_000).unwrap();
    context.svm.airdrop(&asset_pda, 1_000_000_000).unwrap();
    strip_active_count_tail(&mut context, &swig_key);

    let legacy_account = context.svm.get_account(&swig_key).unwrap();
    let legacy_parts = Swig::split_parts(&legacy_account.data).unwrap();
    assert_eq!(
        active_sub_account_count::read(legacy_parts.tail).unwrap(),
        None
    );
    assert_eq!(
        swig_state::tail::rent_claimer::read_strict(legacy_parts.tail).unwrap(),
        Some(&claimer.pubkey().to_bytes())
    );

    let (wallet, _) = Pubkey::find_program_address(
        &swig_state::swig::swig_wallet_address_seeds(swig_key.as_ref()),
        &program_id(),
    );
    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();
    let close_parent = CloseSwigV1Instruction::new_with_ed25519_authority(
        swig_key,
        wallet,
        root.pubkey(),
        destination.pubkey(),
        0,
    )
    .unwrap();
    assert!(send(&mut context, &root, close_parent).is_err());
    context.svm.expire_blockhash();

    let disable = ToggleSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        CREATOR_ROLE_ID,
        0,
        false,
    )
    .unwrap();
    send(&mut context, &creator, disable).unwrap();
    let wallet_before = context.svm.get_account(&wallet).unwrap().lamports;
    let claimer_before = context.svm.get_account(&claimer.pubkey()).unwrap().lamports;
    let state_account = context.svm.get_account(&state_pda).unwrap();
    let asset_account = context.svm.get_account(&asset_pda).unwrap();
    let state_rent = Rent::default()
        .minimum_balance(state_account.data.len())
        .min(state_account.lamports);
    let asset_rent = Rent::default()
        .minimum_balance(asset_account.data.len())
        .min(asset_account.lamports);
    let total_lamports = state_account.lamports + asset_account.lamports;
    let total_rent = state_rent + asset_rent;
    let close_child = CloseSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        root.pubkey(),
        state_pda,
        asset_pda,
        wallet,
        Some(claimer.pubkey()),
        root.pubkey(),
        0,
        0,
    )
    .unwrap();
    send(&mut context, &root, close_child).unwrap();

    assert_eq!(decode_active_count(&context, &swig_key), 0);
    assert_eq!(
        context.svm.get_account(&wallet).unwrap().lamports,
        wallet_before + total_lamports - total_rent
    );
    assert_eq!(
        context.svm.get_account(&claimer.pubkey()).unwrap().lamports,
        claimer_before + total_rent
    );
    let account = context.svm.get_account(&swig_key).unwrap();
    let parts = Swig::split_parts(&account.data).unwrap();
    assert_eq!(
        swig_state::tail::rent_claimer::read_strict(parts.tail).unwrap(),
        Some(&claimer.pubkey().to_bytes())
    );
}

#[test]
fn test_close_sub_account_v2_rejects_omitted_or_wrong_rent_claimer() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, root, creator, id) = setup_v2(&mut context).unwrap();
    let (state_pda, asset_pda) = create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();
    let claimer = Keypair::new();
    let wrong_claimer = Keypair::new();
    context.svm.airdrop(&claimer.pubkey(), 1).unwrap();
    context.svm.airdrop(&wrong_claimer.pubkey(), 1).unwrap();
    set_rent_claimer_with_ed25519(&mut context, &swig_key, &root, 0, claimer.pubkey()).unwrap();
    let disable = ToggleSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        CREATOR_ROLE_ID,
        0,
        false,
    )
    .unwrap();
    send(&mut context, &creator, disable).unwrap();
    let (wallet, _) = Pubkey::find_program_address(
        &swig_state::swig::swig_wallet_address_seeds(swig_key.as_ref()),
        &program_id(),
    );
    let state_before = context.svm.get_account(&state_pda).unwrap();
    let asset_before = context.svm.get_account(&asset_pda).unwrap();

    let wrong_destination = CloseSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        root.pubkey(),
        state_pda,
        asset_pda,
        wallet,
        Some(wrong_claimer.pubkey()),
        root.pubkey(),
        0,
        0,
    )
    .unwrap();
    assert!(send(&mut context, &root, wrong_destination).is_err());
    assert_eq!(decode_active_count(&context, &swig_key), 1);
    assert_eq!(context.svm.get_account(&state_pda).unwrap(), state_before);
    assert_eq!(context.svm.get_account(&asset_pda).unwrap(), asset_before);

    context.svm.expire_blockhash();
    let omitted_destination = CloseSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        root.pubkey(),
        state_pda,
        asset_pda,
        wallet,
        None,
        root.pubkey(),
        0,
        0,
    )
    .unwrap();
    assert_eq!(omitted_destination.accounts[5].pubkey, program_id());
    assert!(send(&mut context, &root, omitted_destination).is_err());
    assert_eq!(decode_active_count(&context, &swig_key), 1);
    assert_eq!(context.svm.get_account(&state_pda).unwrap(), state_before);
    assert_eq!(context.svm.get_account(&asset_pda).unwrap(), asset_before);
}

#[test]
fn test_close_sub_account_v2_rejects_rent_destination_aliasing_source() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, root, creator, id) = setup_v2(&mut context).unwrap();
    let (state_pda, _) = v2_state_pda(&id, 0);
    let (asset_pda, _) = v2_asset_pda(&id, 0);
    set_rent_claimer_with_ed25519(&mut context, &swig_key, &root, 0, asset_pda).unwrap();
    create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();
    let disable = ToggleSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        creator.pubkey(),
        creator.pubkey(),
        state_pda,
        CREATOR_ROLE_ID,
        0,
        false,
    )
    .unwrap();
    send(&mut context, &creator, disable).unwrap();
    let (wallet, _) = Pubkey::find_program_address(
        &swig_state::swig::swig_wallet_address_seeds(swig_key.as_ref()),
        &program_id(),
    );
    let state_before = context.svm.get_account(&state_pda).unwrap();
    let asset_before = context.svm.get_account(&asset_pda).unwrap();
    let close = CloseSubAccountV2Instruction::new_with_ed25519_authority(
        swig_key,
        root.pubkey(),
        state_pda,
        asset_pda,
        wallet,
        Some(asset_pda),
        root.pubkey(),
        0,
        0,
    )
    .unwrap();

    assert!(send(&mut context, &root, close).is_err());
    assert_eq!(decode_active_count(&context, &swig_key), 1);
    assert_eq!(context.svm.get_account(&state_pda).unwrap(), state_before);
    assert_eq!(context.svm.get_account(&asset_pda).unwrap(), asset_before);
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

    // Role 2: two permissions.
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
            ClientAction::SolLimit(SolLimit { amount: 100 }),
        ],
    )
    .unwrap();

    // Role 3: four permissions of varied types.
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
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::SolLimit(SolLimit { amount: 101 }),
            ClientAction::CloseSwigAuthority(CloseSwigAuthority {}),
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

/// A scoped permission cannot be granted until its target id has been created.
#[test_log::test]
fn test_add_authority_rejects_future_scope_until_subaccount_exists() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, root, creator, id) = setup_v2(&mut context).unwrap();
    let scoped_authority = Keypair::new();

    let before_swig = context.svm.get_account(&swig_key).unwrap();
    let payer_key = context.default_payer.pubkey();
    let before_payer = context.svm.get_account(&payer_key).unwrap();
    let future_grant = AddAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        payer_key,
        root.pubkey(),
        0,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: scoped_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccountV2All(SubAccountV2All::new(0))],
    )
    .unwrap();

    assert_nonexistent_scope_error(send_admin(&mut context, &root, future_grant));
    assert_eq!(decode_counter(&context, &swig_key), 0);
    let after_swig = context.svm.get_account(&swig_key).unwrap();
    let after_payer = context.svm.get_account(&payer_key).unwrap();
    assert_eq!(after_swig.data, before_swig.data);
    assert_eq!(after_swig.lamports, before_swig.lamports);
    assert_eq!(before_payer.lamports - after_payer.lamports, 10_000);

    create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();
    let existing_grant = AddAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        payer_key,
        root.pubkey(),
        0,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: scoped_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccountV2All(SubAccountV2All::new(0))],
    )
    .unwrap();
    send_admin(&mut context, &root, existing_grant).unwrap();
    assert!(role_has_all_scope(&context, &swig_key, 2, 0));
}

/// Both update modes validate their resulting action list against the wallet's
/// current sub-account counter before committing a grant.
#[test_log::test]
fn test_update_authority_rejects_future_scope_for_replace_and_add() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, root, creator, id) = setup_v2(&mut context).unwrap();
    create_v2(&mut context, &swig_key, &creator, &id, 0).unwrap();

    let target = Keypair::new();
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: target.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1 })],
    )
    .unwrap();
    let target_role_id = 2;
    let payer_key = context.default_payer.pubkey();
    let before_swig = context.svm.get_account(&swig_key).unwrap();
    let before_payer = context.svm.get_account(&payer_key).unwrap();

    let replace = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        payer_key,
        root.pubkey(),
        0,
        target_role_id,
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::SubAccountV2Sign(
            SubAccountV2Sign::new(1),
        )]),
    )
    .unwrap();
    assert_nonexistent_scope_error(send_admin(&mut context, &root, replace));

    let add = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        payer_key,
        root.pubkey(),
        0,
        target_role_id,
        UpdateAuthorityData::AddActions(vec![ClientAction::SubAccountV2Sign(
            SubAccountV2Sign::new(1),
        )]),
    )
    .unwrap();
    assert_nonexistent_scope_error(send_admin(&mut context, &root, add));

    let after_swig = context.svm.get_account(&swig_key).unwrap();
    let after_payer = context.svm.get_account(&payer_key).unwrap();
    assert_eq!(after_swig.data, before_swig.data);
    assert_eq!(after_swig.lamports, before_swig.lamports);
    assert_eq!(before_payer.lamports - after_payer.lamports, 20_000);
}

/// V1's reserved-lamports high word must never be treated as an issued V2 id
/// counter by any authority grant path.
#[test_log::test]
fn test_v1_counter_overlay_cannot_authorize_future_scope_grants() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, root, _creator, _id) = setup_v2(&mut context).unwrap();
    overwrite_with_v1_counter_overlay(&mut context, &swig_key);
    assert_eq!(decode_counter(&context, &swig_key), 1);

    let payer_key = context.default_payer.pubkey();
    let before_swig = context.svm.get_account(&swig_key).unwrap();
    let before_payer = context.svm.get_account(&payer_key).unwrap();

    let future_authority = Keypair::new();
    let add_authority = AddAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        payer_key,
        root.pubkey(),
        0,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: future_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccountV2All(SubAccountV2All::new(0))],
    )
    .unwrap();
    assert_v1_swig_error(send_admin(&mut context, &root, add_authority));

    let replace = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        payer_key,
        root.pubkey(),
        0,
        CREATOR_ROLE_ID,
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::SubAccountV2Sign(
            SubAccountV2Sign::new(0),
        )]),
    )
    .unwrap();
    assert_v1_swig_error(send_admin(&mut context, &root, replace));

    let add_action = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        payer_key,
        root.pubkey(),
        0,
        CREATOR_ROLE_ID,
        UpdateAuthorityData::AddActions(vec![ClientAction::SubAccountV2Sign(
            SubAccountV2Sign::new(0),
        )]),
    )
    .unwrap();
    assert_v1_swig_error(send_admin(&mut context, &root, add_action));

    let after_swig = context.svm.get_account(&swig_key).unwrap();
    let after_payer = context.svm.get_account(&payer_key).unwrap();
    assert_eq!(after_swig.data, before_swig.data);
    assert_eq!(after_swig.lamports, before_swig.lamports);
    assert_eq!(before_payer.lamports - after_payer.lamports, 30_000);
}
