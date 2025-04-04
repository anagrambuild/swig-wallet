mod common;

use common::*;
use solana_sdk::{signature::Keypair, signer::Signer};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state_x::{
    action::manage_authority::ManageAuthority,
    authority::{ed25519::ED25519Authority, AuthorityType},
    swig::SwigWithRoles,
};

#[test_log::test]
fn test_create_add_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    let (swig_key, swig_create_txn) =
        create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
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
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 2);
    assert_eq!(swig.state.role_counter, 2);
    let role_0 = swig.get_role(0).unwrap().unwrap();
    assert_eq!(role_0.authority.authority_type(), AuthorityType::Ed25519);
    assert_eq!(role_0.authority.session_based(), false);
    assert_eq!(
        role_0.position.authority_type().unwrap(),
        AuthorityType::Ed25519
    );
    assert_eq!(role_0.position.authority_length(), 32);
    assert_eq!(role_0.position.num_actions(), 1);
}
