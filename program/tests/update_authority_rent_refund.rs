#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use solana_sdk::{
    message::{v0, VersionedMessage},
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{
    AuthorityConfig, ClientAction, RemoveAuthorityInstruction, UpdateAuthorityData,
    UpdateAuthorityInstruction,
};
use swig_state::{
    action::{all::All, sol_limit::SolLimit, Permission},
    authority::AuthorityType,
};

#[test]
fn shrinking_actions_refunds_only_released_rent_and_preserves_surplus() {
    for operation in [
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::All(All {})]),
        UpdateAuthorityData::RemoveActionsByType(vec![Permission::SolLimit as u8]),
        UpdateAuthorityData::RemoveActionsByIndex(vec![1]),
    ] {
        let mut context = setup_test_context().unwrap();
        let root = Keypair::new();
        let target = Keypair::new();
        let refund_payer = Keypair::new();
        context
            .svm
            .airdrop(&refund_payer.pubkey(), 1_000_000_000)
            .unwrap();
        let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
        add_authority_with_ed25519_root(
            &mut context,
            &swig,
            &root,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: target.pubkey().as_ref(),
            },
            vec![
                ClientAction::All(All {}),
                ClientAction::SolLimit(SolLimit { amount: 1 }),
            ],
        )
        .unwrap();
        context.svm.airdrop(&swig, 1_000_000_000).unwrap();
        let before = context.svm.get_account(&swig).unwrap();
        let before_payer = context.svm.get_account(&refund_payer.pubkey()).unwrap();
        let rent = context.svm.get_sysvar::<solana_sdk::rent::Rent>();
        let surplus = before.lamports - rent.minimum_balance(before.data.len());
        let instruction = UpdateAuthorityInstruction::new_with_ed25519_authority(
            swig,
            refund_payer.pubkey(),
            root.pubkey(),
            0,
            1,
            operation,
        )
        .unwrap();
        let message = v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[instruction],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap();
        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[&context.default_payer, &refund_payer, &root],
        )
        .unwrap();
        let result = context.svm.send_transaction(tx);
        assert!(result.is_ok(), "{result:?}");
        let after = context.svm.get_account(&swig).unwrap();
        let after_payer = context.svm.get_account(&refund_payer.pubkey()).unwrap();
        assert!(after.data.len() < before.data.len());
        let released_rent =
            rent.minimum_balance(before.data.len()) - rent.minimum_balance(after.data.len());
        assert_eq!(after_payer.lamports - before_payer.lamports, released_rent);
        assert_eq!(
            after.lamports - rent.minimum_balance(after.data.len()),
            surplus
        );
    }
}

#[test]
fn growth_and_removal_preserve_configuration_sol_through_the_full_lifecycle() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let delegate = Keypair::new();
    let refund_payer = Keypair::new();
    context
        .svm
        .airdrop(&refund_payer.pubkey(), 1_000_000_000)
        .unwrap();
    let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
    context.svm.airdrop(&swig, 1_000_000_000).unwrap();
    let rent = context.svm.get_sysvar::<solana_sdk::rent::Rent>();
    let initial = context.svm.get_account(&swig).unwrap();
    let surplus = initial.lamports - rent.minimum_balance(initial.data.len());
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: delegate.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {})],
    )
    .unwrap();
    let added = context.svm.get_account(&swig).unwrap();
    assert_eq!(
        added.lamports - rent.minimum_balance(added.data.len()),
        surplus
    );

    let instructions = [
        UpdateAuthorityInstruction::new_with_ed25519_authority(
            swig,
            refund_payer.pubkey(),
            root.pubkey(),
            0,
            1,
            UpdateAuthorityData::AddActions(vec![ClientAction::SolLimit(SolLimit { amount: 1 })]),
        )
        .unwrap(),
        UpdateAuthorityInstruction::new_with_ed25519_authority(
            swig,
            refund_payer.pubkey(),
            root.pubkey(),
            0,
            1,
            UpdateAuthorityData::RemoveActionsByIndex(vec![1]),
        )
        .unwrap(),
        RemoveAuthorityInstruction::new_with_ed25519_authority(
            swig,
            refund_payer.pubkey(),
            root.pubkey(),
            0,
            1,
        )
        .unwrap(),
    ];
    for instruction in instructions {
        let before = context.svm.get_account(&swig).unwrap();
        let payer_before = context
            .svm
            .get_account(&refund_payer.pubkey())
            .unwrap()
            .lamports;
        let message = v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[instruction],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap();
        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[&context.default_payer, &refund_payer, &root],
        )
        .unwrap();
        let result = context.svm.send_transaction(tx);
        assert!(result.is_ok(), "{result:?}");
        let after = context.svm.get_account(&swig).unwrap();
        let payer_after = context
            .svm
            .get_account(&refund_payer.pubkey())
            .unwrap()
            .lamports;
        assert_eq!(
            after.lamports - rent.minimum_balance(after.data.len()),
            surplus
        );
        assert_eq!(
            i128::from(payer_after) - i128::from(payer_before),
            i128::from(rent.minimum_balance(before.data.len()))
                - i128::from(rent.minimum_balance(after.data.len())),
        );
    }
    let final_account = context.svm.get_account(&swig).unwrap();
    assert_eq!(final_account.data.len(), initial.data.len());
    assert_eq!(final_account.lamports, initial.lamports);
}
