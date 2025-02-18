mod common;
use borsh::BorshDeserialize;
use common::*;

use litesvm_token::spl_token::{self, instruction::TokenInstruction};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::AuthorityConfig;
use swig_state::{Action, AuthorityType, Role, SolAction, Swig};

#[test_log::test]
fn test_create_add_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();

    let (swig_key, swig_create_txn) =
        create_swig_ed25519(&mut context, &swig_authority, &id).unwrap();
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![Action::ManageAuthority],
        0,
        0,
    )
    .unwrap();
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();
    assert_eq!(swig.roles.len(), 2);
    assert_eq!(
        swig.roles[0],
        Role::new_with_size(
            AuthorityType::Ed25519,
            swig_authority.pubkey().as_ref().to_vec(),
            0,
            0,
            vec![Action::All],
        )
    );
    assert_eq!(
        swig.roles[1],
        Role::new_with_size(
            AuthorityType::Ed25519,
            second_authority.pubkey().as_ref().to_vec(),
            0,
            0,
            vec![Action::ManageAuthority],
        )
    );
}
