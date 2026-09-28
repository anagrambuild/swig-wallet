//! Regressions for funded WSOL close accounting.
mod common;

use common::*;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use litesvm_token::spl_token;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    rent::Rent,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{
    AuthorityConfig, ClientAction, CloseTokenAccountV1Instruction, SignV2Instruction,
};
use swig_state::{
    action::{
        close_swig_authority::CloseSwigAuthority, program_all::ProgramAll,
        token_destination_limit::TokenDestinationLimit, token_limit::TokenLimit,
        token_recurring_limit::TokenRecurringLimit,
    },
    authority::AuthorityType,
    swig::{swig_wallet_address_seeds, SwigWithRoles},
    SwigAuthenticateError,
};

const FIXTURE: Pubkey = Pubkey::from_str_const("BXAu5ZWHnGun2XZjUZ9nqwiZ5dNVmofPGYdMC4rx4qLV");

fn send(
    context: &mut Context,
    ix: Instruction,
    authority: &Keypair,
) -> Result<TransactionMetadata, Box<FailedTransactionMetadata>> {
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let signers = vec![&context.default_payer, authority];
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &signers).unwrap();
    context.svm.send_transaction(tx).map_err(Box::new)
}

fn add_role(
    context: &mut Context,
    swig: &Pubkey,
    root: &Keypair,
    authority: &Keypair,
    actions: Vec<ClientAction>,
) {
    add_authority_with_ed25519_root(
        context,
        swig,
        root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority.pubkey().as_ref(),
        },
        actions,
    )
    .unwrap();
}

fn assert_error(result: Result<TransactionMetadata, Box<FailedTransactionMetadata>>, code: u32) {
    assert_eq!(
        result.unwrap_err().err,
        TransactionError::InstructionError(0, InstructionError::Custom(code))
    );
}

#[derive(Clone, Copy, Debug)]
enum ClosePath {
    Direct,
    Nested,
    Dedicated,
}

// Native token classification is deliberately disabled by this existing
// feature.
#[cfg(not(feature = "program_scope_test"))]
fn wsol_close_case(
    path: ClosePath,
    unsynced: u64,
    allowance: Option<u64>,
    recurring: bool,
    destination_limit: bool,
) {
    let mut context = setup_test_context().unwrap();
    context
        .svm
        .add_program_from_file(FIXTURE, "../target/deploy/test_program_authority.so")
        .unwrap();
    let root = Keypair::new();
    let authority = Keypair::new();
    let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
    let wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;
    let destination = Pubkey::new_unique();
    context.svm.airdrop(&destination, 1_000_000).unwrap();
    let reserve = Rent::default().minimum_balance(165);
    let actual = 3_000_000_000 + reserve + unsynced;
    let mut actions = vec![
        ClientAction::ProgramAll(ProgramAll),
        ClientAction::CloseSwigAuthority(CloseSwigAuthority),
    ];
    if let Some(limit) = allowance {
        actions.push(if destination_limit {
            ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                token_mint: spl_token::native_mint::ID.to_bytes(),
                destination: destination.to_bytes(),
                amount: limit,
            })
        } else if recurring {
            ClientAction::TokenRecurringLimit(TokenRecurringLimit {
                token_mint: spl_token::native_mint::ID.to_bytes(),
                limit,
                current: limit,
                window: 100,
                last_reset: 0,
            })
        } else {
            ClientAction::TokenLimit(TokenLimit {
                token_mint: spl_token::native_mint::ID.to_bytes(),
                current_amount: limit,
            })
        });
    }
    add_role(&mut context, &swig, &root, &authority, actions);
    // Known rent-routing gap: SignV2 currently permits the direct/nested close
    // to send rent to a destination other than the configured claimer. Keep
    // that case in the WSOL budget matrix so the separate rent-claimer fix
    // makes this test fail until its expected result is changed to rejection.
    // A passing test here proves budget accounting, not valid rent routing.
    // Dedicated close already enforces its matching claimer.
    let claimer = if matches!(path, ClosePath::Dedicated) {
        destination
    } else {
        Pubkey::new_unique()
    };
    set_rent_claimer_with_ed25519(&mut context, &swig, &root, 0, claimer).unwrap();
    let source = Pubkey::new_unique();
    let token = spl_token::state::Account {
        mint: spl_token::native_mint::ID,
        owner: wallet,
        amount: 3_000_000_000,
        state: spl_token::state::AccountState::Initialized,
        is_native: COption::Some(reserve),
        ..Default::default()
    };
    let mut data = vec![0; spl_token::state::Account::LEN];
    spl_token::state::Account::pack(token, &mut data).unwrap();
    context
        .svm
        .set_account(
            source,
            Account {
                lamports: actual,
                data,
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    let ix = match path {
        ClosePath::Dedicated => CloseTokenAccountV1Instruction::new_with_ed25519_authority(
            swig,
            wallet,
            authority.pubkey(),
            destination,
            spl_token::ID,
            vec![source],
            1,
        )
        .unwrap(),
        _ => {
            let inner = if matches!(path, ClosePath::Nested) {
                Instruction {
                    program_id: FIXTURE,
                    accounts: vec![
                        AccountMeta::new(source, false),
                        AccountMeta::new(destination, false),
                        AccountMeta::new_readonly(wallet, true),
                        AccountMeta::new_readonly(spl_token::ID, false),
                    ],
                    data: b"closetok".to_vec(),
                }
            } else {
                spl_token::instruction::close_account(
                    &spl_token::ID,
                    &source,
                    &destination,
                    &wallet,
                    &[],
                )
                .unwrap()
            };
            SignV2Instruction::new_ed25519(swig, wallet, authority.pubkey(), inner, 1).unwrap()
        },
    };
    let before = [source, destination, wallet, swig].map(|key| context.svm.get_account(&key));
    let result = send(&mut context, ix, &authority);
    if allowance.is_some_and(|limit| limit >= actual)
        && (!destination_limit || matches!(path, ClosePath::Dedicated))
    {
        result.unwrap();
        assert_eq!(
            context.svm.get_balance(&destination).unwrap(),
            1_000_000 + actual
        );
        assert_eq!(context.svm.get_balance(&source).unwrap_or(0), 0);
        let account = context.svm.get_account(&swig).unwrap();
        let state = SwigWithRoles::from_bytes(&account.data).unwrap();
        let role = state.get_role(1).unwrap().unwrap();
        let remaining = if destination_limit {
            let mut key = [0u8; 64];
            key[..32].copy_from_slice(spl_token::native_mint::ID.as_ref());
            key[32..].copy_from_slice(destination.as_ref());
            role.get_action::<TokenDestinationLimit>(&key)
                .unwrap()
                .unwrap()
                .amount
        } else if recurring {
            role.get_action::<TokenRecurringLimit>(spl_token::native_mint::ID.as_ref())
                .unwrap()
                .unwrap()
                .current
        } else {
            role.get_action::<TokenLimit>(spl_token::native_mint::ID.as_ref())
                .unwrap()
                .unwrap()
                .current_amount
        };
        assert_eq!(remaining, allowance.unwrap() - actual);
    } else {
        let code = if allowance.is_none() || destination_limit {
            SwigAuthenticateError::PermissionDeniedMissingPermission as u32
        } else {
            SwigAuthenticateError::PermissionDeniedInsufficientBalance as u32
        };
        assert_error(result, code);
        assert_eq!(
            [source, destination, wallet, swig].map(|key| context.svm.get_account(&key)),
            before,
            "{path:?} must roll back accounts and limits"
        );
    }
}

#[test]
#[cfg(not(feature = "program_scope_test"))]
fn funded_wsol_close_requires_and_consumes_actual_lamport_budget() {
    let reserve = Rent::default().minimum_balance(165);
    for path in [ClosePath::Direct, ClosePath::Nested, ClosePath::Dedicated] {
        for unsynced in [0, 500_000_000] {
            let total = 3_000_000_000 + reserve + unsynced;
            for allowance in [
                None,
                Some(1),
                Some(total - 1),
                Some(total),
                Some(total + 10),
            ] {
                wsol_close_case(path, unsynced, allowance, false, false);
            }
        }
    }
}

#[test]
#[cfg(not(feature = "program_scope_test"))]
fn wsol_close_recurring_and_destination_limits() {
    let total = 3_000_000_000 + Rent::default().minimum_balance(165) + 500_000_000;
    for path in [ClosePath::Direct, ClosePath::Nested, ClosePath::Dedicated] {
        wsol_close_case(path, 500_000_000, Some(total), true, false);
        wsol_close_case(path, 500_000_000, Some(total), false, true);
    }
}

#[test]
#[cfg(not(feature = "program_scope_test"))]
fn dedicated_wsol_batch_rejection_restores_every_source_and_budget() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let authority = Keypair::new();
    let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
    let wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;
    let destination = Pubkey::new_unique();
    context.svm.airdrop(&destination, 1_000_000).unwrap();
    let reserve = Rent::default().minimum_balance(165);
    let per_source = 1_000_000_000 + reserve;
    add_role(
        &mut context,
        &swig,
        &root,
        &authority,
        vec![
            ClientAction::CloseSwigAuthority(CloseSwigAuthority),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: spl_token::native_mint::ID.to_bytes(),
                current_amount: 2 * per_source - 1,
            }),
        ],
    );
    let sources = [Pubkey::new_unique(), Pubkey::new_unique()];
    for source in sources {
        let token = spl_token::state::Account {
            mint: spl_token::native_mint::ID,
            owner: wallet,
            amount: 1_000_000_000,
            state: spl_token::state::AccountState::Initialized,
            is_native: COption::Some(reserve),
            ..Default::default()
        };
        let mut data = vec![0; spl_token::state::Account::LEN];
        spl_token::state::Account::pack(token, &mut data).unwrap();
        context
            .svm
            .set_account(
                source,
                Account {
                    lamports: per_source,
                    data,
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
    }
    let keys = [sources[0], sources[1], destination, wallet, swig];
    let before = keys.map(|key| context.svm.get_account(&key));
    let ix = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        swig,
        wallet,
        authority.pubkey(),
        destination,
        spl_token::ID,
        sources.to_vec(),
        1,
    )
    .unwrap();
    assert_error(
        send(&mut context, ix, &authority),
        SwigAuthenticateError::PermissionDeniedInsufficientBalance as u32,
    );
    assert_eq!(keys.map(|key| context.svm.get_account(&key)), before);
}
