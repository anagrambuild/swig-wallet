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
use swig_interface::{AuthorityConfig, ClientAction, RemoveAuthorityInstruction};
use swig_state::{
    action::{
        all::All, manage_authority::ManageAuthority, program::Program, sol_limit::SolLimit,
        Actionable,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, SwigWithRoles},
    IntoBytes, Transmutable,
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
    assert_eq!(swig.state.roles, 3);
    assert_eq!(swig.state.role_counter, 3);
    let role_id = swig
        .lookup_role_id(secondary_authority.pubkey().as_ref())
        .unwrap()
        .unwrap();

    let role = swig.get_role(role_id).unwrap().unwrap();
    assert_eq!(role.position.num_actions(), 2);

    use swig_state::role::Role;
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
    convert_swig_to_v1(&mut context, &swig);

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
            ClientAction::Program(Program {
                program_id: solana_sdk::system_program::ID.to_bytes(),
            }),
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
        2,
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
    println!("transfer_tx: {:?}", res);
    assert!(res.is_ok());
    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    let swig_account_after = context.svm.get_account(&swig).unwrap();
    assert_eq!(recipient_account.lamports, 10_000_000_000 + amount);

    assert_eq!(
        swig_account_after.lamports,
        swig_lamports_balance + initial_swig_balance - amount
    );
    let swig_state = SwigWithRoles::from_bytes(&swig_account_after.data).unwrap();
    let role = swig_state.get_role(2).unwrap().unwrap();
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

#[test_log::test]
fn test_action_boundaries_after_role_removal() {
    use solana_sdk::{
        message::{v0, VersionedMessage},
        signature::Keypair,
        signer::Signer,
        transaction::VersionedTransaction,
    };
    use swig_interface::RemoveAuthorityInstruction;
    use swig_state::action::token_limit::TokenLimit;

    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let second_authority = Keypair::new();
    let third_authority = Keypair::new();
    let fourth_authority = Keypair::new();

    // Airdrop to all authorities
    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&third_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&fourth_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with the root authority (role 0)
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    // Add second authority (role 2) with TokenLimit and SolLimit actions
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::TokenLimit(TokenLimit {
                token_mint: [2; 32],
                current_amount: 1000,
            }),
            ClientAction::SolLimit(SolLimit { amount: 2000 }),
        ],
    )
    .unwrap();

    // Add third authority (role 3) with TokenLimit and SolLimit actions
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: third_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::TokenLimit(TokenLimit {
                token_mint: [3; 32],
                current_amount: 3000,
            }),
            ClientAction::SolLimit(SolLimit { amount: 4000 }),
        ],
    )
    .unwrap();

    // Verify we have four authorities
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 4);

    println!("swig: {:?}", swig.state.roles);

    // Look up the actual role IDs for each authority
    let root_role_id = swig
        .lookup_role_id(root_authority.pubkey().as_ref())
        .unwrap()
        .expect("Root authority should exist");
    let second_role_id = swig
        .lookup_role_id(second_authority.pubkey().as_ref())
        .unwrap()
        .expect("Second authority should exist");
    let third_role_id = swig
        .lookup_role_id(third_authority.pubkey().as_ref())
        .unwrap()
        .expect("Third authority should exist");

    println!(
        "Role IDs: root={}, second={}, third={}",
        root_role_id, second_role_id, third_role_id
    );

    // Verify the third authority's actions are accessible before removal
    let third_role = swig.get_role(third_role_id).unwrap().unwrap();
    println!("third_role: {:?}", third_role.get_all_actions());
    assert!(third_role
        .get_action::<TokenLimit>(&[3; 32])
        .unwrap()
        .is_some());
    assert!(third_role.get_action::<SolLimit>(&[]).unwrap().is_some());

    // Remove the second authority (the middle one) using RemoveAuthorityInstruction
    let remove_ix = RemoveAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        root_role_id,   // Acting role ID (root authority)
        second_role_id, // Authority to remove (second authority)
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &root_authority],
    )
    .unwrap();

    context.svm.send_transaction(tx).unwrap();

    // Verify that only three authorities remain
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 3);

    // Verify the second authority no longer exists
    let second_role = swig.get_role(second_role_id);
    assert!(second_role.is_ok());
    assert!(second_role.unwrap().is_none());

    // Verify root authority and third authority still exist
    let root_role = swig.get_role(root_role_id).unwrap();
    let third_role = swig.get_role(third_role_id).unwrap();
    assert!(root_role.is_some());
    assert!(third_role.is_some());

    // CRITICAL TEST: Verify the third authority's actions are still accessible and
    // correct This is the key test - after removing the middle role, the third
    // role's actions should still be accessible with correct boundaries
    let third_role = third_role.unwrap();

    // Check TokenLimit action
    let token_limit = third_role
        .get_action::<TokenLimit>(&[3; 32])
        .unwrap()
        .unwrap();
    assert_eq!(token_limit.token_mint, [3; 32]);
    assert_eq!(token_limit.current_amount, 3000);

    // Check SolLimit action
    let sol_limit = third_role.get_action::<SolLimit>(&[]).unwrap().unwrap();
    assert_eq!(sol_limit.amount, 4000);

    println!(
        "SUCCESS: Third authority's actions are still accessible after middle authority removal!"
    );

    // Sanity check, we want to ensure boundaries are correct after adding another
    // new authority after removing the original one.
    println!("Now runnig a sanity check to ensure we can add a new role");
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: fourth_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::TokenLimit(TokenLimit {
                token_mint: [4; 32],
                current_amount: 4000,
            }),
            ClientAction::SolLimit(SolLimit { amount: 5000 }),
        ],
    )
    .unwrap();

    // Verify we have three authorities
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 4);

    let fourth_role_id = swig
        .lookup_role_id(fourth_authority.pubkey().as_ref())
        .unwrap()
        .expect("Fouth authority should exist");

    assert_eq!(fourth_role_id, 4);

    println!(
        "Role IDs: root={}, third={}, fourth={}",
        root_role_id, third_role_id, fourth_role_id
    );

    // Verify the fourth authority's actions are accessible before removal
    let fourth_role = swig.get_role(fourth_role_id).unwrap().unwrap();
    println!("fourth_role: {:?}", fourth_role.get_all_actions());
    assert!(fourth_role
        .get_action::<TokenLimit>(&[4; 32])
        .unwrap()
        .is_some());
    assert!(third_role.get_action::<SolLimit>(&[]).unwrap().is_some());
    println!(
        "SUCCESS: Fourth authority is assigned properly and has the correct boundaries for its \
         actions!"
    );
}
