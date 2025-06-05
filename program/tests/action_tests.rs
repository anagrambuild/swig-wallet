#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.

mod common;

use common::*;
use solana_sdk::{
    account::ReadableAccount,
    address_lookup_table::{state::AddressLookupTable, AddressLookupTableAccount},
    commitment_config::CommitmentConfig,
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    keccak::hash,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    rent::Rent,
    signature::{read_keypair_file, Keypair, Signature},
    signer::{Signer, SignerError},
    system_instruction,
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state_x::{
    action::{all::All, manage_authority::ManageAuthority, sol_limit::SolLimit},
    authority::AuthorityType,
    swig::{swig_account_seeds, SwigWithRoles},
};

#[test_log::test]
fn test_multiple_actions_with_multiple_actions() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    let amount = 1_000_000_000;
    context
        .svm
        .airdrop(&swig_authority.pubkey(), amount)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let secondary_authority = Keypair::new();
    context
        .svm
        .airdrop(&secondary_authority.pubkey(), amount)
        .unwrap();
    let bench = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ManageAuthority(ManageAuthority {}),
            ClientAction::SolLimit(SolLimit { amount: amount / 2 }),
        ],
    )
    .unwrap();

    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 2);
    assert_eq!(swig.state.role_counter, 2);
    let role_id = swig
        .lookup_role_id(secondary_authority.pubkey().as_ref())
        .unwrap()
        .unwrap();

    let role = swig.get_role(role_id).unwrap().unwrap();
    assert_eq!(role.position.num_actions(), 2);

    use swig_state_x::role::Role;
    if (Role::get_action::<ManageAuthority>(&role, &[]).unwrap()).is_some() {
        println!("Manage Authority action found");
    }
    if (Role::get_action::<SolLimit>(&role, &[]).unwrap()).is_some() {
        println!("Sol Limit action found");
    }

    let actions = role.get_all_actions().unwrap();

    println!("actions: {:?}", actions);
    assert!(actions.len() == 2);
}

#[test_log::test]
fn test_multiple_actions_with_transfer_and_manage_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::SolLimit(SolLimit {
                amount: 10_000_000_000,
            }),
            ClientAction::ManageAuthority(ManageAuthority {}),
        ],
    )
    .unwrap();
    let swig_lamports_balance = context.svm.get_account(&swig).unwrap().lamports;
    let initial_swig_balance = 10_000_000_000;
    context.svm.airdrop(&swig, initial_swig_balance).unwrap();
    assert!(swig_create_txn.is_ok());

    let amount = 5_000_000_000; // 5 SOL
    let ixd = system_instruction::transfer(&swig, &recipient.pubkey(), amount);
    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        ixd,
        1,
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    let res = context.svm.send_transaction(transfer_tx);
    assert!(res.is_ok());
    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    let swig_account_after = context.svm.get_account(&swig).unwrap();
    assert_eq!(recipient_account.lamports, 10_000_000_000 + amount);

    assert_eq!(
        swig_account_after.lamports,
        swig_lamports_balance + initial_swig_balance - amount
    );
    let swig_state = SwigWithRoles::from_bytes(&swig_account_after.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();
    assert!(role.get_action::<SolLimit>(&[]).unwrap().is_some());
    assert!(role.get_action::<ManageAuthority>(&[]).unwrap().is_some());

    let third_authority = Keypair::new();
    context
        .svm
        .airdrop(&third_authority.pubkey(), 10_000_000_000)
        .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &second_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: third_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit {
            amount: 10_000_000_000,
        })],
    )
    .unwrap();

    let swig_account_after = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account_after.data).unwrap();
    let role = swig_state.get_role(2).unwrap().unwrap();
    assert!(role.get_action::<SolLimit>(&[]).unwrap().is_some());
}
