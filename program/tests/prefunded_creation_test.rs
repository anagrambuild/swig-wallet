#![cfg(not(feature = "program_scope_test"))]
//! Creation must tolerate SOL transferred to the config/wallet-address PDAs
//! before creation, while refusing to initialize over a populated or closed
//! account.
mod common;
#[path = "../src/error.rs"]
mod swig_error;

use common::*;
use litesvm_token::spl_token;
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
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, authority],
    )
    .unwrap();
    context.svm.send_transaction(tx).map(|_| ()).map_err(|e| {
        eprintln!("{}", e.meta.pretty_logs());
        e.err
    })
}

fn pdas_for(id: &[u8; 32]) -> (Pubkey, u8, Pubkey, u8) {
    let (config, bump) = Pubkey::find_program_address(&swig_account_seeds(id), &program_id());
    let (wallet, wallet_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(config.as_ref()), &program_id());
    (config, bump, wallet, wallet_bump)
}

fn create_instruction(
    config: Pubkey,
    bump: u8,
    wallet: Pubkey,
    wallet_bump: u8,
    authority: &Keypair,
    id: [u8; 32],
) -> Instruction {
    CreateInstruction::new(
        config,
        bump,
        authority.pubkey(),
        wallet,
        wallet_bump,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {})],
        id,
    )
    .unwrap()
}

fn creation_context() -> (SwigTestContext, Keypair) {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    context.svm.airdrop(&root.pubkey(), 100_000_000_000).unwrap();
    (context, root)
}

/// A config PDA pre-funded via a plain SOL transfer (empty data, system owned)
/// must not brick creation. The pre-funded lamports are kept and only the rent
/// shortfall, if any, is topped up by the payer.
#[test]
fn creation_succeeds_on_prefunded_config_pda() {
    let (mut context, root) = creation_context();
    let id = [42; 32];
    let (config, bump, wallet, wallet_bump) = pdas_for(&id);

    // Griefer transfers SOL to the config PDA before the wallet is created.
    context.svm.airdrop(&config, 1_000_000_000).unwrap();

    send(
        &mut context,
        &root,
        create_instruction(config, bump, wallet, wallet_bump, &root, id),
    )
    .unwrap();

    let account = context.svm.get_account(&config).unwrap();
    assert_eq!(account.owner, program_id());
    let swig = SwigWithRoles::from_bytes(&account.data).unwrap();
    assert_eq!(swig.state.id, id);
    assert_eq!(swig.state.roles, 1);
    // Pre-funded balance is preserved; no top-up was required.
    assert_eq!(account.lamports, 1_000_000_000);
}

/// A partially pre-funded config PDA must end up exactly rent-exempt.
#[test]
fn creation_tops_up_partially_prefunded_config_pda_to_rent_exempt() {
    let (mut context, root) = creation_context();
    let id = [43; 32];
    let (config, bump, wallet, wallet_bump) = pdas_for(&id);

    // Pre-fund below the rent needed for the final swig size (0-byte rent
    // exempt minimum), so creation must top up the shortfall.
    context
        .svm
        .airdrop(&config, context.svm.minimum_balance_for_rent_exemption(0))
        .unwrap();

    send(
        &mut context,
        &root,
        create_instruction(config, bump, wallet, wallet_bump, &root, id),
    )
    .unwrap();

    let account = context.svm.get_account(&config).unwrap();
    assert_eq!(account.owner, program_id());
    let expected = context
        .svm
        .minimum_balance_for_rent_exemption(account.data.len());
    assert_eq!(account.lamports, expected);
}

/// A pre-funded wallet-address PDA must not block creation either; the rent
/// top-up to the 0-space system account already tolerates existing lamports.
#[test]
fn creation_succeeds_on_prefunded_wallet_address_pda() {
    let (mut context, root) = creation_context();
    let id = [44; 32];
    let (config, bump, wallet, wallet_bump) = pdas_for(&id);

    context.svm.airdrop(&wallet, 5_000_000_000).unwrap();

    send(
        &mut context,
        &root,
        create_instruction(config, bump, wallet, wallet_bump, &root, id),
    )
    .unwrap();

    let wallet_account = context.svm.get_account(&wallet).unwrap();
    assert_eq!(wallet_account.owner, system_program::id());
    assert_eq!(wallet_account.data.len(), 0);
    assert_eq!(wallet_account.lamports, 5_000_000_000);
}

/// Creation must refuse an account carrying data, even when it is owned by the
/// system program (allocated without assignment). The rejection must leave the
/// account untouched.
#[test]
fn creation_rejects_populated_system_account_without_mutation() {
    let (mut context, root) = creation_context();
    let id = [45; 32];
    let (config, bump, wallet, wallet_bump) = pdas_for(&id);

    context
        .svm
        .set_account(
            config,
            Account {
                lamports: 1_000_000,
                data: vec![7u8; 16],
                owner: system_program::id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    let ix = create_instruction(config, bump, wallet, wallet_bump, &root, id);
    let before = context.svm.get_account(&config).unwrap();
    assert_eq!(
        send(&mut context, &root, ix),
        Err(TransactionError::InstructionError(
            0,
            InstructionError::Custom(SwigError::AccountNotEmptySwigAccount as u32)
        ))
    );
    assert_eq!(context.svm.get_account(&config).unwrap(), before);
}

/// Creation must refuse an account owned by another program.
#[test]
fn creation_rejects_foreign_owned_account_without_mutation() {
    let (mut context, root) = creation_context();
    let id = [46; 32];
    let (config, bump, wallet, wallet_bump) = pdas_for(&id);

    context
        .svm
        .set_account(
            config,
            Account {
                lamports: 1_000_000,
                data: vec![0u8; 165],
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    let ix = create_instruction(config, bump, wallet, wallet_bump, &root, id);
    let before = context.svm.get_account(&config).unwrap();
    assert_eq!(
        send(&mut context, &root, ix),
        Err(TransactionError::InstructionError(
            0,
            InstructionError::Custom(SwigError::OwnerMismatchSwigAccount as u32)
        ))
    );
    assert_eq!(context.svm.get_account(&config).unwrap(), before);
}

/// A closed Swig remains owned by this program with a one-byte closed
/// discriminator, so its address can never be re-created as a new wallet.
#[test]
fn creation_rejects_recreation_at_closed_swig_address() {
    let (mut context, root) = creation_context();
    let id = [47; 32];
    let (config, bump, wallet, wallet_bump) = pdas_for(&id);

    send(
        &mut context,
        &root,
        create_instruction(config, bump, wallet, wallet_bump, &root, id),
    )
    .unwrap();

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

    let ix = create_instruction(config, bump, wallet, wallet_bump, &root, id);
    assert_eq!(
        send(&mut context, &root, ix),
        Err(TransactionError::InstructionError(
            0,
            InstructionError::Custom(SwigError::OwnerMismatchSwigAccount as u32)
        ))
    );
}
