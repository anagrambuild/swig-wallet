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
use swig::error::SwigError;
use swig_interface::{
    AuthorityConfig, ClientAction, CloseTokenAccountV1Instruction, SignV2Instruction,
};
use swig_state::{
    action::{
        all::All, close_swig_authority::CloseSwigAuthority, program_all::ProgramAll,
        token_destination_limit::TokenDestinationLimit, token_limit::TokenLimit,
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

/// Independently confirm that 9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP is
/// Token-2022's wrapped-native SOL mint: it must (a) match the constant the
/// pinned SPL Token-2022 interface crate declares and (b) equal the program
/// address derived from seed "native-mint" with bump 255 under the
/// Token-2022 program. The legacy native mint is initialized at genesis and
/// has no such PDA derivation, so only the Token-2022 identity is asserted.
#[test]
fn token_2022_native_mint_identity() {
    let token_2022 = Pubkey::from_str(TOKEN_2022).unwrap();
    let native_2022 = Pubkey::from_str(NATIVE_2022).unwrap();

    // (a) The pinned SPL Token-2022 interface crate declares this mint.
    assert_eq!(spl_token_2022_interface::native_mint::id(), native_2022);

    // (b) PDA derivation: ["native-mint"] + bump 255, under the Token-2022
    // program — the only token program that supports on-chain native-mint
    // initialization via `create_native_mint`.
    let derived_2022 =
        Pubkey::create_program_address(&["native-mint".as_bytes(), &[255u8]], &token_2022).unwrap();
    assert_eq!(derived_2022, native_2022);
}

/// SignV2 must account Token-2022 native spending against the T22-native
/// TokenLimit exactly like legacy WSOL spending: a synced T22-native account
/// spending tokens consumes the delegate's allowance.
#[test_log::test]
fn sign_v2_t22_native_transfer_charges_t22_native_token_limit() {
    use litesvm_token::CreateAssociatedTokenAccount;

    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let delegate = Keypair::new();
    let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
    let (wallet, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let native2022 = Pubkey::from_str(NATIVE_2022).unwrap();
    let token2022 = Pubkey::from_str(TOKEN_2022).unwrap();
    let limit = 1_000_000u64;

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
            ClientAction::ProgramAll(ProgramAll),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: native2022.to_bytes(),
                current_amount: limit,
            }),
        ],
    )
    .unwrap();

    let ata = funded_t22_native_ata(&mut context, &wallet, 900_000_000);
    let destination =
        CreateAssociatedTokenAccount::new(&mut context.svm, &context.default_payer, &native2022)
            .owner(&root.pubkey())
            .token_program_id(&token2022)
            .send()
            .expect("destination T22 native ATA");

    let inner = spl_token_2022_interface::instruction::transfer(
        &token2022,
        &ata,
        &destination,
        &wallet,
        &[],
        limit,
    )
    .unwrap();
    let signv2 = SignV2Instruction::new_ed25519(swig, wallet, delegate.pubkey(), inner, 1).unwrap();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[signv2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, &delegate],
    )
    .unwrap();
    context
        .svm
        .send_transaction(tx)
        .expect("limited SignV2 T22 native transfer");

    assert_eq!(
        read_role_action_amount(&context, &swig, native2022.as_ref()),
        0,
        "the transfer must consume the T22 native TokenLimit"
    );
}

#[test_log::test]
fn sign_v2_t22_native_transfer_beyond_budget_is_denied() {
    use litesvm_token::CreateAssociatedTokenAccount;

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
            ClientAction::ProgramAll(ProgramAll),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: native2022.to_bytes(),
                current_amount: 1_000_000,
            }),
        ],
    )
    .unwrap();

    let ata = funded_t22_native_ata(&mut context, &wallet, 900_000_000);
    let ata_lamports = context.svm.get_account(&ata).unwrap().lamports;
    let destination =
        CreateAssociatedTokenAccount::new(&mut context.svm, &context.default_payer, &native2022)
            .owner(&root.pubkey())
            .token_program_id(&token2022)
            .send()
            .expect("destination T22 native ATA");

    let inner = spl_token_2022_interface::instruction::transfer(
        &token2022,
        &ata,
        &destination,
        &wallet,
        &[],
        1_000_001,
    )
    .unwrap();
    let signv2 = SignV2Instruction::new_ed25519(swig, wallet, delegate.pubkey(), inner, 1).unwrap();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[signv2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, &delegate],
    )
    .unwrap();
    let error = context
        .svm
        .send_transaction(tx)
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
        ata_lamports,
        "denied transfer must not move funds"
    );
    assert_eq!(
        read_role_action_amount(&context, &swig, native2022.as_ref()),
        1_000_000,
        "denied transfer must not consume the allowance"
    );
}

/// A batch close drains the entire token account's lamports. SignV2 must
/// charge the full wrapped-SOL value — the token balance plus any
/// unsynchronized lamport deposits — exactly like it does for the legacy
/// Token program's WSOL accounts.
#[test_log::test]
fn sign_v2_t22_native_batch_close_consumes_full_wrapped_sol_value() {
    use litesvm_token::CreateAssociatedTokenAccount;
    use solana_system_interface::instruction::transfer as sol_transfer;

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
            ClientAction::ProgramAll(ProgramAll),
            ClientAction::CloseSwigAuthority(CloseSwigAuthority {}),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: native2022.to_bytes(),
                current_amount: 1_000_000_000,
            }),
        ],
    )
    .unwrap();

    let ata = funded_t22_native_ata(&mut context, &wallet, 900_000_000);
    // Inject additional unsynchronized lamports on top of the synced balance.
    let injected = 2_000_000u64;
    context.svm.airdrop(&root.pubkey(), injected * 2).unwrap();
    let before = context.svm.get_account(&root.pubkey()).unwrap().lamports;
    let fund = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &root.pubkey(),
                &[sol_transfer(&root.pubkey(), &ata, injected)],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&root],
    )
    .unwrap();
    context.svm.send_transaction(fund).expect("inject lamports");
    assert_eq!(
        context.svm.get_account(&root.pubkey()).unwrap().lamports,
        before - injected - 5_000
    );
    let ata_lamports = context.svm.get_account(&ata).unwrap().lamports;

    let destination =
        CreateAssociatedTokenAccount::new(&mut context.svm, &context.default_payer, &native2022)
            .owner(&root.pubkey())
            .token_program_id(&token2022)
            .send()
            .expect("destination T22 native ATA");
    let destination_before = context.svm.get_account(&destination).unwrap().lamports;

    let inner = spl_token_2022_interface::instruction::close_account(
        &token2022,
        &ata,
        &destination,
        &wallet,
        &[],
    )
    .unwrap();
    let signv2 = SignV2Instruction::new_ed25519(swig, wallet, delegate.pubkey(), inner, 1).unwrap();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[signv2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, &delegate],
    )
    .unwrap();
    context
        .svm
        .send_transaction(tx)
        .expect("batch close of the T22 native account");

    assert_eq!(
        read_role_action_amount(&context, &swig, native2022.as_ref()),
        1_000_000_000 - ata_lamports,
        "the batch close must consume the full wrapped-SOL value"
    );
    // Closing reallocates the token account; lamports moved to the destination.
    assert_eq!(
        context.svm.get_account(&destination).unwrap().lamports,
        destination_before + ata_lamports,
        "destination must receive the token account's lamports"
    );
}

#[derive(Clone, Copy, Debug)]
enum NativeRefreshAction {
    Sync,
    Transfer(u64),
    Approve,
}

fn t22_native_refresh_case(
    personal_source: bool,
    rent_increases: bool,
    action: NativeRefreshAction,
    expected_error: Option<u32>,
) {
    use litesvm_token::CreateAssociatedTokenAccount;
    use solana_sdk::rent::Rent;
    use spl_token_2022_interface::instruction::{approve, sync_native, transfer};

    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let delegate = Keypair::new();
    let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
    let (wallet, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let native2022 = Pubkey::from_str(NATIVE_2022).unwrap();
    let token2022 = Pubkey::from_str(TOKEN_2022).unwrap();
    let limit = 1_000_000;
    context.svm.airdrop(&delegate.pubkey(), 10_000_000).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: delegate.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramAll(ProgramAll),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: native2022.to_bytes(),
                current_amount: limit,
            }),
        ],
    )
    .unwrap();

    let lower_rent = Rent::with_lamports_per_byte(3_480);
    let (old_rent, new_rent) = if rent_increases {
        (lower_rent, Rent::default())
    } else {
        (Rent::default(), lower_rent)
    };
    context.svm.set_sysvar(&old_rent);
    let owner = if personal_source {
        delegate.pubkey()
    } else {
        wallet
    };
    let source = funded_t22_native_ata(&mut context, &owner, 900_000_000);
    let destination =
        CreateAssociatedTokenAccount::new(&mut context.svm, &context.default_payer, &native2022)
            .owner(&root.pubkey())
            .token_program_id(&token2022)
            .send()
            .unwrap();
    // Keep the destination rent-exempt under either rent schedule.
    context.svm.airdrop(&destination, 10_000_000).unwrap();
    let before = context.svm.get_account(&source).unwrap();
    assert!(
        before.data.len() > 165,
        "exercise a real extension-sized ATA"
    );
    let old_reserve = u64::from_le_bytes(before.data[113..121].try_into().unwrap());
    assert_eq!(old_reserve, old_rent.minimum_balance(before.data.len()));
    let required = new_rent.minimum_balance(before.data.len());
    assert_ne!(required, old_reserve);
    assert_ne!(required, new_rent.minimum_balance(165));
    context.svm.set_sysvar(&new_rent);

    let mut inner = vec![sync_native(&token2022, &source).unwrap()];
    match action {
        NativeRefreshAction::Sync => {},
        NativeRefreshAction::Transfer(amount) => {
            inner.push(transfer(&token2022, &source, &destination, &owner, &[], amount).unwrap());
        },
        NativeRefreshAction::Approve => {
            inner
                .push(approve(&token2022, &source, &Pubkey::new_unique(), &owner, &[], 1).unwrap());
        },
    }
    let instruction_count = inner.len();
    let instructions: Vec<_> = inner
        .into_iter()
        .map(|instruction| {
            SignV2Instruction::new_ed25519_with_signers(
                swig,
                wallet,
                delegate.pubkey(),
                instruction,
                1,
                &[delegate.pubkey()],
            )
            .unwrap()
        })
        .collect();
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &instructions,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, &delegate],
    )
    .unwrap();
    let protected_keys = [source, destination, swig, wallet, delegate.pubkey()];
    let protected_before: Vec<_> = protected_keys
        .iter()
        .map(|key| context.svm.get_account(key))
        .collect();
    let result = context.svm.send_transaction(tx);
    let metadata = if let Some(error) = expected_error {
        let failure = result.expect_err("invalid spend or metadata mutation must roll back");
        assert_eq!(
            failure.err,
            TransactionError::InstructionError(1, InstructionError::Custom(error))
        );
        let protected_after: Vec<_> = protected_keys
            .iter()
            .map(|key| context.svm.get_account(key))
            .collect();
        assert_eq!(
            protected_after, protected_before,
            "roll back the earlier reserve refresh too"
        );
        failure.meta
    } else {
        let metadata = result.unwrap_or_else(|error| {
            panic!(
                "personal={personal_source}, rent increase={rent_increases}, {action:?}: {error:?}"
            )
        });
        let after = context.svm.get_account(&source).unwrap();
        let spent = match action {
            NativeRefreshAction::Transfer(amount) => amount,
            NativeRefreshAction::Sync => 0,
            NativeRefreshAction::Approve => unreachable!(),
        };
        assert_eq!(after.lamports, before.lamports - spent);
        assert_eq!(
            u64::from_le_bytes(after.data[113..121].try_into().unwrap()),
            required
        );
        assert_eq!(
            u64::from_le_bytes(after.data[64..72].try_into().unwrap()),
            after.lamports - required
        );
        // Only the amount and native reserve may change, including extension bytes.
        let mut expected_data = before.data.clone();
        expected_data[64..72].copy_from_slice(&(after.lamports - required).to_le_bytes());
        expected_data[113..121].copy_from_slice(&required.to_le_bytes());
        assert_eq!(after.data, expected_data);
        assert_eq!(after.owner, before.owner);
        assert_eq!(
            read_role_action_amount(&context, &swig, native2022.as_ref()),
            limit - spent
        );
        metadata
    };
    let token_success = format!("Program {token2022} success");
    assert_eq!(
        metadata
            .logs
            .iter()
            .filter(|line| **line == token_success)
            .count(),
        instruction_count,
        "Token-2022 must finish each CPI before Swig verifies its effects: {:?}",
        metadata.logs
    );
}

#[test_log::test]
fn t22_native_reserve_refresh_preserves_wallet_value() {
    for rent_increases in [false, true] {
        t22_native_refresh_case(false, rent_increases, NativeRefreshAction::Sync, None);
    }
}

#[test_log::test]
fn t22_native_reserve_refresh_preserves_personal_value() {
    for rent_increases in [false, true] {
        t22_native_refresh_case(true, rent_increases, NativeRefreshAction::Sync, None);
    }
}

#[test_log::test]
fn t22_native_reserve_refresh_preserves_exact_spend_limit_and_rolls_back_overspend() {
    for rent_increases in [false, true] {
        t22_native_refresh_case(
            false,
            rent_increases,
            NativeRefreshAction::Transfer(1_000_000),
            None,
        );
        t22_native_refresh_case(
            false,
            rent_increases,
            NativeRefreshAction::Transfer(1_000_001),
            Some(SwigAuthenticateError::PermissionDeniedInsufficientBalance as u32),
        );
    }
}

#[test_log::test]
fn t22_native_reserve_refresh_rejects_personal_spending_and_metadata_changes() {
    for rent_increases in [false, true] {
        for action in [
            NativeRefreshAction::Transfer(1),
            NativeRefreshAction::Approve,
        ] {
            t22_native_refresh_case(
                true,
                rent_increases,
                action,
                Some(SwigError::PermissionDeniedAuthorityExternalAssetChange as u32),
            );
        }
    }
}
