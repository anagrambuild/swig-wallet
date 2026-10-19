#![cfg(not(feature = "program_scope_test"))]
//! Legacy creation requires unfunded config and wallet-address PDAs.
mod common;
#[path = "../src/error.rs"]
mod swig_error;

use common::*;
use solana_sdk::{
    account::Account,
    instruction::{Instruction, InstructionError},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use solana_system_interface::program as system_program;
use swig_error::SwigError;
use swig_interface::{AuthorityConfig, ClientAction, CloseSwigV1Instruction, CreateInstruction};
use swig_state::{
    action::all::All,
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
};

fn send(
    context: &mut SwigTestContext,
    authority: &Keypair,
    ix: Instruction,
) -> Result<(), TransactionError> {
    context.svm.expire_blockhash();
    let authority_signs = ix
        .accounts
        .iter()
        .any(|meta| meta.pubkey == authority.pubkey() && meta.is_signer);
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let mut signers = vec![&context.default_payer];
    if authority_signs {
        signers.push(authority);
    }
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &signers).unwrap();
    context.svm.send_transaction(tx).map(|_| ()).map_err(|e| {
        eprintln!("{}", e.meta.pretty_logs());
        e.err
    })
}

fn creation_context() -> (SwigTestContext, Keypair, Pubkey, Pubkey, Instruction) {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    context
        .svm
        .airdrop(&root.pubkey(), 100_000_000_000)
        .unwrap();
    let id = [42; 32];
    let (config, bump) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let (wallet, wallet_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(config.as_ref()), &program_id());
    let ix = CreateInstruction::new(
        config,
        bump,
        root.pubkey(),
        wallet,
        wallet_bump,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: root.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {})],
        id,
    )
    .unwrap();
    (context, root, config, wallet, ix)
}

fn assert_creation_rejected(
    context: &mut SwigTestContext,
    root: &Keypair,
    config: Pubkey,
    wallet: Pubkey,
    ix: Instruction,
    error: SwigError,
) {
    let before_config = context.svm.get_account(&config);
    let before_wallet = context.svm.get_account(&wallet);
    let before_payer = context.svm.get_account(&root.pubkey());
    assert_eq!(
        send(context, root, ix),
        Err(TransactionError::InstructionError(
            0,
            InstructionError::Custom(error as u32)
        ))
    );
    assert_eq!(context.svm.get_account(&config), before_config);
    assert_eq!(context.svm.get_account(&wallet), before_wallet);
    assert_eq!(context.svm.get_account(&root.pubkey()), before_payer);
}

#[test]
fn creation_rejects_payer_without_writable_signer_flags() {
    for (writable, signer) in [(true, false), (false, true), (false, false)] {
        let (mut context, root, config, wallet, mut ix) = creation_context();
        for meta in &mut ix.accounts {
            if meta.pubkey == root.pubkey() {
                meta.is_writable = writable;
                meta.is_signer = signer;
            }
        }
        assert_creation_rejected(
            &mut context,
            &root,
            config,
            wallet,
            ix,
            SwigError::PayerMustBeWritableSigner,
        );
    }
}

#[test]
fn creation_rejects_prefunded_pdas_without_mutation() {
    // Even one lamport must reject, as must partial and excess rent funding.
    for (fund_config, fund_wallet) in [(true, false), (false, true), (true, true)] {
        for lamports in [1, 890_880, 1_000_000_000] {
            let (mut context, root, config, wallet, ix) = creation_context();
            // A plain SOL transfer leaves the destination system-owned and empty.
            for address in [fund_config.then_some(config), fund_wallet.then_some(wallet)]
                .into_iter()
                .flatten()
            {
                context
                    .svm
                    .set_account(
                        address,
                        Account {
                            lamports,
                            data: vec![],
                            owner: system_program::id(),
                            executable: false,
                            rent_epoch: 0,
                        },
                    )
                    .unwrap();
            }
            assert_creation_rejected(
                &mut context,
                &root,
                config,
                wallet,
                ix,
                SwigError::AccountNotEmptySwigAccount,
            );
        }
    }
}

#[test]
fn creation_succeeds_on_unfunded_pdas_and_rejects_recreation() {
    let (mut context, root, config, wallet, ix) = creation_context();
    send(&mut context, &root, ix.clone()).unwrap();
    let account = context.svm.get_account(&config).unwrap();
    assert_eq!(account.owner, program_id());
    let swig = SwigWithRoles::from_bytes(&account.data).unwrap();
    assert_eq!(swig.state.id, [42; 32]);
    assert_eq!(swig.state.roles, 1);
    assert_eq!(
        account.lamports,
        context
            .svm
            .minimum_balance_for_rent_exemption(account.data.len())
    );
    let wallet_account = context.svm.get_account(&wallet).unwrap();
    assert_eq!(wallet_account.owner, system_program::id());
    assert!(wallet_account.data.is_empty());
    assert_eq!(
        wallet_account.lamports,
        context.svm.minimum_balance_for_rent_exemption(0)
    );
    assert_creation_rejected(
        &mut context,
        &root,
        config,
        wallet,
        ix,
        SwigError::OwnerMismatchSwigAccount,
    );
}

#[test]
fn creation_rejects_populated_or_foreign_owned_accounts_without_mutation() {
    for foreign_owned in [false, true] {
        let (mut context, root, config, wallet, ix) = creation_context();
        context
            .svm
            .set_account(
                config,
                Account {
                    lamports: 1_000_000,
                    data: vec![7; 16],
                    owner: if foreign_owned {
                        litesvm_token::spl_token::ID
                    } else {
                        system_program::id()
                    },
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let error = if foreign_owned {
            SwigError::OwnerMismatchSwigAccount
        } else {
            SwigError::AccountNotEmptySwigAccount
        };
        assert_creation_rejected(&mut context, &root, config, wallet, ix, error);
    }
}

#[test]
fn creation_rejects_recreation_at_closed_swig_address() {
    let (mut context, root, config, wallet, ix) = creation_context();
    send(&mut context, &root, ix.clone()).unwrap();
    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();
    let close_ix = CloseSwigV1Instruction::new_with_ed25519_authority(
        config,
        wallet,
        root.pubkey(),
        destination.pubkey(),
        0,
    )
    .unwrap();
    send(&mut context, &root, close_ix).unwrap();
    let closed = context.svm.get_account(&config).unwrap();
    assert_eq!(closed.owner, program_id());
    assert_eq!(closed.data, vec![255]);
    assert_creation_rejected(
        &mut context,
        &root,
        config,
        wallet,
        ix,
        SwigError::OwnerMismatchSwigAccount,
    );
}
