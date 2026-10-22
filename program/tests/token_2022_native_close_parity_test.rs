#![cfg(not(feature = "program_scope_test"))]
//! Regression: CloseTokenAccountV1 must enforce identical wrapped-native spend
//! accounting for Token-2022's native mint (9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP)
//! as it does for the legacy SPL Token program's native mint.
//!
//! Covers the reported bypass: a close-capable delegate could previously close
//! a funded Token-2022 native token account to any destination while consuming
//! neither TokenLimit nor TokenDestinationLimit.

mod common;
use common::*;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use solana_sdk::{
    instruction::InstructionError,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use std::str::FromStr;
use swig_interface::{AuthorityConfig, ClientAction, CloseTokenAccountV1Instruction};
use swig_state::{
    action::{
        close_swig_authority::CloseSwigAuthority, token_destination_limit::TokenDestinationLimit,
        token_limit::TokenLimit,
    },
    authority::AuthorityType,
    swig::{swig_wallet_address_seeds, SwigWithRoles},
    SwigAuthenticateError,
};

const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const NATIVE_2022: &str = "9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP";

fn funded_t22_native_ata(
    context: &mut SwigTestContext,
    wallet: &Pubkey,
    wrap_amount: u64,
) -> Pubkey {
    use litesvm_token::CreateAssociatedTokenAccount;
    use solana_system_interface::instruction::transfer as sol_transfer;
    use spl_token_2022_interface::instruction::create_native_mint;

    let token2022 = Pubkey::from_str(TOKEN_2022).unwrap();
    let native2022 = Pubkey::from_str(NATIVE_2022).unwrap();
    let create_mint = create_native_mint(&token2022, &context.default_payer.pubkey()).unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &context.default_payer.pubkey(),
                &[create_mint],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&context.default_payer],
    )
    .unwrap();
    context
        .svm
        .send_transaction(tx)
        .expect("create T22 native mint");

    let ata =
        CreateAssociatedTokenAccount::new(&mut context.svm, &context.default_payer, &native2022)
            .owner(wallet)
            .token_program_id(&token2022)
            .send()
            .expect("T22 native ATA for swig wallet");

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &context.default_payer.pubkey(),
                &[sol_transfer(
                    &context.default_payer.pubkey(),
                    &ata,
                    wrap_amount,
                )],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&context.default_payer],
    )
    .unwrap();
    context
        .svm
        .send_transaction(tx)
        .expect("fund T22 native ATA");

    let sync = spl_token_2022_interface::instruction::sync_native(&token2022, &ata).unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &context.default_payer.pubkey(),
                &[sync],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&context.default_payer],
    )
    .unwrap();
    context.svm.send_transaction(tx).expect("SyncNative");

    let account = context.svm.get_account(&ata).unwrap();
    assert_eq!(account.owner, token2022);
    assert_eq!(
        u64::from_le_bytes(account.data[64..72].try_into().unwrap()),
        wrap_amount
    );
    ata
}

fn read_role_action_amount(context: &SwigTestContext, swig: &Pubkey, key: &[u8]) -> u64 {
    let account = context.svm.get_account(swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let role = state.get_role(1).unwrap().unwrap();
    role.get_action::<TokenLimit>(key)
        .unwrap()
        .unwrap()
        .current_amount
}

fn read_destination_limit_amount(
    context: &SwigTestContext,
    swig: &Pubkey,
    native2022: &Pubkey,
    destination: &Pubkey,
) -> u64 {
    let account = context.svm.get_account(swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let role = state.get_role(1).unwrap().unwrap();
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(native2022.as_ref());
    key[32..].copy_from_slice(destination.as_ref());
    role.get_action::<TokenDestinationLimit>(&key)
        .unwrap()
        .unwrap()
        .amount
}

fn close_request(
    context: &mut SwigTestContext,
    swig: &Pubkey,
    wallet: &Pubkey,
    delegate: &Keypair,
    destination: &Pubkey,
    token_program: &Pubkey,
    token_accounts: &[Pubkey],
    role_id: u32,
) -> Result<TransactionMetadata, FailedTransactionMetadata> {
    let close = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        *swig,
        *wallet,
        delegate.pubkey(),
        *destination,
        *token_program,
        token_accounts.to_vec(),
        role_id,
    )
    .unwrap();
    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[close],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, delegate]).unwrap();
    context.svm.send_transaction(tx)
}

#[test_log::test]
fn t22_native_close_to_approved_destination_enforces_and_consumes_both_allowances() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let delegate = Keypair::new();
    let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
    let (wallet, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let native2022 = Pubkey::from_str(NATIVE_2022).unwrap();
    let token2022 = Pubkey::from_str(TOKEN_2022).unwrap();

    context.svm.airdrop(&delegate.pubkey(), 1_000_000).unwrap();
    context.svm.airdrop(&root.pubkey(), 1_000_000).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: delegate.pubkey().as_ref(),
        },
        vec![
            ClientAction::CloseSwigAuthority(CloseSwigAuthority {}),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: native2022.to_bytes(),
                current_amount: 2_000_000_000,
            }),
            ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                token_mint: native2022.to_bytes(),
                destination: root.pubkey().to_bytes(),
                amount: 2_000_000_000,
            }),
        ],
    )
    .unwrap();

    let ata = funded_t22_native_ata(&mut context, &wallet, 900_000_000);
    let ata_lamports = context.svm.get_account(&ata).unwrap().lamports;
    let destination_before = context.svm.get_account(&root.pubkey()).unwrap().lamports;

    close_request(
        &mut context,
        &swig,
        &wallet,
        &delegate,
        &root.pubkey(),
        &token2022,
        &[ata],
        1,
    )
    .unwrap();

    assert_eq!(
        context.svm.get_account(&root.pubkey()).unwrap().lamports - destination_before,
        ata_lamports
    );
    assert_eq!(context.svm.get_account(&ata).map_or(0, |a| a.lamports), 0);
    assert_eq!(
        read_role_action_amount(&context, &swig, native2022.as_ref()),
        2_000_000_000 - ata_lamports,
        "T22 native TokenLimit must be consumed by the close"
    );
    assert_eq!(
        read_destination_limit_amount(&context, &swig, &native2022, &root.pubkey()),
        2_000_000_000 - ata_lamports,
        "T22 native TokenDestinationLimit must be consumed by the close"
    );
}

#[test_log::test]
fn t22_native_close_to_unapproved_destination_is_denied() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let delegate = Keypair::new();
    let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
    let (wallet, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let native2022 = Pubkey::from_str(NATIVE_2022).unwrap();
    let token2022 = Pubkey::from_str(TOKEN_2022).unwrap();

    context.svm.airdrop(&delegate.pubkey(), 1_000_000).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: delegate.pubkey().as_ref(),
        },
        vec![
            ClientAction::CloseSwigAuthority(CloseSwigAuthority {}),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: native2022.to_bytes(),
                current_amount: 2_000_000_000,
            }),
            // Destination allowlist exists, but only for the root key.
            ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                token_mint: native2022.to_bytes(),
                destination: root.pubkey().to_bytes(),
                amount: 1,
            }),
        ],
    )
    .unwrap();

    let ata = funded_t22_native_ata(&mut context, &wallet, 900_000_000);
    let ata_lamports = context.svm.get_account(&ata).unwrap().lamports;

    let destination = Pubkey::new_unique();
    context.svm.airdrop(&destination, 1_000_000).unwrap();
    let error = close_request(
        &mut context,
        &swig,
        &wallet,
        &delegate,
        &destination,
        &token2022,
        &[ata],
        1,
    )
    .expect_err("unapproved destination must be denied");
    assert_eq!(
        error.err,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(
                SwigAuthenticateError::PermissionDeniedMissingPermission as u32
            )
        )
    );
    assert_eq!(
        context.svm.get_account(&ata).unwrap().lamports,
        ata_lamports,
        "token account must survive a denied close"
    );
}

#[test_log::test]
fn t22_native_close_beyond_delegated_budget_is_denied_and_does_not_bypass_accounting() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let delegate = Keypair::new();
    let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
    let (wallet, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let native2022 = Pubkey::from_str(NATIVE_2022).unwrap();
    let token2022 = Pubkey::from_str(TOKEN_2022).unwrap();

    context.svm.airdrop(&delegate.pubkey(), 1_000_000).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: delegate.pubkey().as_ref(),
        },
        vec![
            ClientAction::CloseSwigAuthority(CloseSwigAuthority {}),
            // Regressions from the reported bypass: a 1-lamport budget used to
            // be ignored entirely and the close still proceeded.
            ClientAction::TokenLimit(TokenLimit {
                token_mint: native2022.to_bytes(),
                current_amount: 1,
            }),
            ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                token_mint: native2022.to_bytes(),
                destination: root.pubkey().to_bytes(),
                amount: 2_000_000_000,
            }),
        ],
    )
    .unwrap();

    let ata = funded_t22_native_ata(&mut context, &wallet, 900_000_000);
    let ata_lamports = context.svm.get_account(&ata).unwrap().lamports;

    let error = close_request(
        &mut context,
        &swig,
        &wallet,
        &delegate,
        &root.pubkey(),
        &token2022,
        &[ata],
        1,
    )
    .expect_err("spend above the delegated budget must be denied");
    assert_eq!(
        error.err,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(
                SwigAuthenticateError::PermissionDeniedInsufficientBalance as u32
            )
        )
    );
    assert_eq!(
        context.svm.get_account(&ata).unwrap().lamports,
        ata_lamports
    );
    assert_eq!(
        read_role_action_amount(&context, &swig, native2022.as_ref()),
        1,
        "denied close must not consume the allowance"
    );
}

#[test_log::test]
fn t22_native_close_with_close_only_delegate_and_no_limits_is_denied() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let delegate = Keypair::new();
    let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
    let (wallet, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let token2022 = Pubkey::from_str(TOKEN_2022).unwrap();

    context.svm.airdrop(&delegate.pubkey(), 1_000_000).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: delegate.pubkey().as_ref(),
        },
        vec![ClientAction::CloseSwigAuthority(CloseSwigAuthority {})],
    )
    .unwrap();

    let ata = funded_t22_native_ata(&mut context, &wallet, 900_000_000);
    let ata_lamports = context.svm.get_account(&ata).unwrap().lamports;

    let destination = Pubkey::new_unique();
    context.svm.airdrop(&destination, 1_000_000).unwrap();
    let error = close_request(
        &mut context,
        &swig,
        &wallet,
        &delegate,
        &destination,
        &token2022,
        &[ata],
        1,
    )
    .expect_err("close-capable delegate without native spend limits must be denied");
    assert_eq!(
        error.err,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(
                SwigAuthenticateError::PermissionDeniedMissingPermission as u32
            )
        )
    );
    assert_eq!(
        context.svm.get_account(&ata).unwrap().lamports,
        ata_lamports
    );
}

#[test_log::test]
fn legacy_wsol_close_with_close_only_delegate_is_denied_control() {
    // Parity control mirroring the legacy negative control from the PoC: wide
    // seeds of the legacy native mint must keep rejecting a close-only
    // delegate. Uses a hand-built 165-byte native token account fixture.
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let delegate = Keypair::new();
    let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
    let (wallet, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    context.svm.airdrop(&delegate.pubkey(), 1_000_000).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: delegate.pubkey().as_ref(),
        },
        vec![ClientAction::CloseSwigAuthority(CloseSwigAuthority {})],
    )
    .unwrap();

    let native_legacy = Pubkey::from_str("So11111111111111111111111111111111111111112").unwrap();
    let token_program = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let reserve = 2_039_280u64;
    let amount = 900_000_000u64;
    let mut data = vec![0u8; 165];
    data[0..32].copy_from_slice(native_legacy.as_ref());
    data[32..64].copy_from_slice(wallet.as_ref());
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    data[108] = 1;
    data[109..113].copy_from_slice(&1u32.to_le_bytes());
    data[113..121].copy_from_slice(&reserve.to_le_bytes());
    let victim = Pubkey::new_unique();
    context
        .svm
        .set_account(
            victim,
            solana_sdk::account::Account {
                lamports: reserve + amount,
                data,
                owner: token_program,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    let destination = Pubkey::new_unique();
    context.svm.airdrop(&destination, 1_000_000).unwrap();
    let error = close_request(
        &mut context,
        &swig,
        &wallet,
        &delegate,
        &destination,
        &token_program,
        &[victim],
        1,
    )
    .expect_err("legacy WSOL close without spend limits must be denied");
    assert_eq!(
        error.err,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(
                SwigAuthenticateError::PermissionDeniedMissingPermission as u32
            )
        )
    );
    assert_eq!(
        context.svm.get_account(&victim).unwrap().lamports,
        reserve + amount
    );
}
