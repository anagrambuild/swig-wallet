#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use solana_sdk::{
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ClientAction, CreateInstruction};
use swig_state::{
    action::all::All,
    authority::{
        programexec::session::{CreateProgramExecSessionAuthority, ProgramExecSessionAuthority},
        AuthorityType,
    },
    role::Role,
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
    IntoBytes, Transmutable,
};

fn creation_payload(padded: bool) -> Vec<u8> {
    let input = CreateProgramExecSessionAuthority::new(
        [9; 32],
        40,
        [7; 40],
        Keypair::new().pubkey().to_bytes(),
        240,
    );
    let mut bytes = input.into_bytes().unwrap().to_vec();
    assert_eq!(bytes.len(), 120);
    if padded {
        bytes.extend_from_slice(&[0; 8]);
    }
    bytes
}

fn check_stored_session(role: &Role, input: &[u8]) {
    assert_eq!(
        role.authority.authority_type(),
        AuthorityType::ProgramExecSession
    );
    assert_eq!(role.authority.length(), 128);
    let authority = role
        .authority
        .as_any()
        .downcast_ref::<ProgramExecSessionAuthority>()
        .unwrap();
    assert_eq!(authority.program_id, [9; 32]);
    assert_eq!(authority.instruction_prefix_len, 40);
    assert_eq!(authority.instruction_prefix, [7; 40]);
    assert_eq!(&authority.session_key, &input[80..112]);
    assert_eq!(authority.max_session_length, 240);
    assert_eq!(authority.current_session_expiration, 0);
    assert_eq!(ProgramExecSessionAuthority::LEN, 128);
}

#[test]
fn create_accepts_both_session_encodings_and_preserves_stored_layout() {
    for padded in [false, true] {
        let mut context = setup_test_context().unwrap();
        let id = rand::random::<[u8; 32]>();
        let (config, bump) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
        let (wallet, wallet_bump) = Pubkey::find_program_address(
            &swig_wallet_address_seeds(config.as_ref()),
            &program_id(),
        );
        let input = creation_payload(padded);
        let create = CreateInstruction::new(
            config,
            bump,
            context.default_payer.pubkey(),
            wallet,
            wallet_bump,
            AuthorityConfig {
                authority_type: AuthorityType::ProgramExecSession,
                authority: &input,
            },
            vec![ClientAction::All(All {})],
            id,
        )
        .unwrap();
        let message = v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[create],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap();
        let tx =
            VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])
                .unwrap();
        context.svm.send_transaction(tx).unwrap();
        let account = context.svm.get_account(&config).unwrap();
        let parsed = SwigWithRoles::from_bytes(&account.data).unwrap();
        check_stored_session(&parsed.get_role(0).unwrap().unwrap(), &input);
        assert_eq!(parsed.state.roles, 1);
    }
}

#[test]
fn add_accepts_both_session_encodings_and_preserves_next_role_offset() {
    for padded in [false, true] {
        let mut context = setup_test_context().unwrap();
        let root = Keypair::new();
        let (config, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
        let input = creation_payload(padded);
        add_authority_with_ed25519_root(
            &mut context,
            &config,
            &root,
            AuthorityConfig {
                authority_type: AuthorityType::ProgramExecSession,
                authority: &input,
            },
            vec![ClientAction::All(All {})],
        )
        .unwrap();
        let next = Keypair::new();
        add_authority_with_ed25519_root(
            &mut context,
            &config,
            &root,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: &next.pubkey().to_bytes(),
            },
            vec![ClientAction::All(All {})],
        )
        .unwrap();
        let account = context.svm.get_account(&config).unwrap();
        let parsed = SwigWithRoles::from_bytes(&account.data).unwrap();
        check_stored_session(&parsed.get_role(1).unwrap().unwrap(), &input);
        assert_eq!(
            parsed
                .get_role(2)
                .unwrap()
                .unwrap()
                .authority
                .identity()
                .unwrap(),
            next.pubkey().as_ref()
        );
        assert_eq!(parsed.state.roles, 3);
    }
}
