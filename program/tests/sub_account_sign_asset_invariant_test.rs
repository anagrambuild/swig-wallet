#![cfg(not(feature = "program_scope_test"))]
//! Audit #63: sub-account signing must not let the asset PDA leave System
//! ownership or keep data. Covers V1 and V2 with direct and batched
//! Assign/Allocate payloads, plus a transfer positive control.
mod common;

use common::*;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use solana_sdk::{
    instruction::{Instruction, InstructionError},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig::error::SwigError;
use swig_interface::{
    AuthorityConfig, ClientAction, CreateSubAccountV2Instruction, SubAccountSignInstruction,
    SubAccountSignV2Instruction,
};
use swig_state::{
    action::{sub_account::SubAccount, sub_account_v2::SubAccountV2Create},
    authority::AuthorityType,
    swig::{sub_account_v2_asset_seeds, sub_account_v2_state_seeds, swig_account_seeds},
};

const ROLE_ID: u32 = 1;
const ASSET_FUNDING: u64 = 5_000_000_000;
const TRANSFER_AMOUNT: u64 = 1_000_000;

/// Which sub-account signing handler a case runs against.
enum Child {
    V1 {
        swig: Pubkey,
        asset: Pubkey,
    },
    V2 {
        swig: Pubkey,
        state: Pubkey,
        asset: Pubkey,
    },
}

impl Child {
    fn asset(&self) -> Pubkey {
        match self {
            Child::V1 { asset, .. } | Child::V2 { asset, .. } => *asset,
        }
    }

    fn sign_ix(&self, authority: &Keypair, inner: Vec<Instruction>) -> Instruction {
        match self {
            Child::V1 { swig, asset } => SubAccountSignInstruction::new_with_ed25519_authority(
                *swig,
                *asset,
                authority.pubkey(),
                ROLE_ID,
                inner,
            )
            .unwrap(),
            Child::V2 { swig, state, asset } => {
                SubAccountSignV2Instruction::new_with_ed25519_authority(
                    *swig,
                    *state,
                    *asset,
                    authority.pubkey(),
                    ROLE_ID,
                    0,
                    inner,
                )
                .unwrap()
            },
        }
    }
}

fn send(
    context: &mut SwigTestContext,
    payer: &Keypair,
    ix: Instruction,
) -> Result<TransactionMetadata, FailedTransactionMetadata> {
    context.svm.expire_blockhash();
    let message =
        v0::Message::try_compile(&payer.pubkey(), &[ix], &[], context.svm.latest_blockhash())
            .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[payer]).unwrap();
    context.svm.send_transaction(tx)
}

fn add_role(context: &mut SwigTestContext, action: ClientAction) -> (Pubkey, Keypair, [u8; 32]) {
    let root = Keypair::new();
    let authority = Keypair::new();
    context.svm.airdrop(&root.pubkey(), 10_000_000_000).unwrap();
    context
        .svm
        .airdrop(&authority.pubkey(), 10_000_000_000)
        .unwrap();
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(context, &root, id).unwrap();
    add_authority_with_ed25519_root(
        context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority.pubkey().as_ref(),
        },
        vec![action],
    )
    .unwrap();
    (swig, authority, id)
}

/// Swig with a role holding only V1 `SubAccount` and an enabled, funded child.
fn setup_v1(context: &mut SwigTestContext) -> (Child, Keypair) {
    let (swig, authority, id) = add_role(
        context,
        ClientAction::SubAccount(SubAccount::new_for_creation()),
    );
    let asset = create_sub_account(context, &swig, &authority, ROLE_ID, id).unwrap();
    context.svm.airdrop(&asset, ASSET_FUNDING).unwrap();
    (Child::V1 { swig, asset }, authority)
}

/// Swig with a creator role that is auto-granted scoped `SubAccountV2Sign`
/// on the enabled, funded child it creates.
fn setup_v2(context: &mut SwigTestContext) -> (Child, Keypair) {
    let (swig, authority, _) = add_role(
        context,
        ClientAction::SubAccountV2Create(SubAccountV2Create),
    );
    let id_le = 0u32.to_le_bytes();
    let (state, _) = Pubkey::find_program_address(
        &sub_account_v2_state_seeds(swig.as_ref(), &id_le),
        &program_id(),
    );
    let (asset, _) = Pubkey::find_program_address(
        &sub_account_v2_asset_seeds(swig.as_ref(), &id_le),
        &program_id(),
    );
    let create = CreateSubAccountV2Instruction::new_with_ed25519_authority(
        swig,
        authority.pubkey(),
        authority.pubkey(),
        state,
        asset,
        ROLE_ID,
    )
    .unwrap();
    send(context, &authority, create).unwrap();
    context.svm.airdrop(&asset, ASSET_FUNDING).unwrap();
    (Child::V2 { swig, state, asset }, authority)
}

/// Sends `inner` through sub-account signing and asserts it fails with
/// `expected` while the asset keeps its owner, data and lamports.
fn assert_rejected_unchanged(
    context: &mut SwigTestContext,
    child: &Child,
    authority: &Keypair,
    inner: Vec<Instruction>,
    expected: Option<u32>,
) {
    let asset = child.asset();
    let before = context.svm.get_account(&asset).unwrap();
    assert_eq!(before.owner, solana_system_interface::program::ID);
    assert!(before.data.is_empty());

    let result = send(context, authority, child.sign_ix(authority, inner));
    let err = result
        .expect_err("asset owner/shape change must be rejected")
        .err;
    if let Some(code) = expected {
        assert_eq!(
            err,
            TransactionError::InstructionError(0, InstructionError::Custom(code))
        );
    }

    let after = context.svm.get_account(&asset).unwrap();
    assert_eq!(after.owner, before.owner, "owner change must roll back");
    assert_eq!(after.data, before.data, "data change must roll back");
    assert_eq!(after.lamports, before.lamports, "batch must roll back");
}

/// Positive control: an ordinary signed transfer still succeeds and leaves
/// the asset System-owned with zero data.
fn assert_transfer_still_works(context: &mut SwigTestContext, child: &Child, authority: &Keypair) {
    let asset = child.asset();
    let recipient = Pubkey::new_unique();
    let transfer =
        solana_system_interface::instruction::transfer(&asset, &recipient, TRANSFER_AMOUNT);
    send(context, authority, child.sign_ix(authority, vec![transfer]))
        .expect("signed transfer must still succeed");
    assert_eq!(
        context.svm.get_account(&recipient).unwrap().lamports,
        TRANSFER_AMOUNT
    );
    let after = context.svm.get_account(&asset).unwrap();
    assert_eq!(after.owner, solana_system_interface::program::ID);
    assert!(after.data.is_empty());
}

fn invariant_error() -> Option<u32> {
    Some(SwigError::WalletAddressInvariantViolation as u32)
}

fn run_cases(setup: fn(&mut SwigTestContext) -> (Child, Keypair)) {
    let attacker_program = Pubkey::new_unique();

    // Direct Assign to an attacker-owned program.
    let mut context = setup_test_context().unwrap();
    let (child, authority) = setup(&mut context);
    let asset = child.asset();
    let assign = solana_system_interface::instruction::assign(&asset, &attacker_program);
    assert_rejected_unchanged(
        &mut context,
        &child,
        &authority,
        vec![assign.clone()],
        invariant_error(),
    );
    assert_transfer_still_works(&mut context, &child, &authority);

    // Direct Allocate (nonce-sized data) on the System-owned asset.
    let allocate = solana_system_interface::instruction::allocate(&asset, 80);
    assert_rejected_unchanged(
        &mut context,
        &child,
        &authority,
        vec![allocate],
        invariant_error(),
    );

    // Valid transfer then Assign: the transfer must roll back with it.
    let transfer =
        solana_system_interface::instruction::transfer(&asset, &Pubkey::new_unique(), 1_000);
    assert_rejected_unchanged(
        &mut context,
        &child,
        &authority,
        vec![transfer.clone(), assign.clone()],
        invariant_error(),
    );

    // Assign then transfer: the System program already refuses to debit a
    // reassigned account, so only require failure and an unchanged asset.
    assert_rejected_unchanged(
        &mut context,
        &child,
        &authority,
        vec![assign, transfer],
        None,
    );

    assert_transfer_still_works(&mut context, &child, &authority);
}

#[test_log::test]
fn test_sub_account_sign_v1_preserves_system_owned_asset() {
    run_cases(setup_v1);
}

#[test_log::test]
fn test_sub_account_sign_v2_preserves_system_owned_asset() {
    run_cases(setup_v2);
}
