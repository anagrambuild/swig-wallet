#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use solana_sdk::{
    account::Account,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use spl_token_2022_interface::{
    extension::{BaseStateWithExtensionsMut, StateWithExtensionsMut},
    state::Mint,
};
use swig_interface::{AuthorityConfig, ClientAction, SignV2Instruction};
use swig_state::{
    action::program_curated::ProgramCurated, authority::AuthorityType,
    swig::swig_wallet_address_seeds,
};

#[test]
fn curated_programs_match_the_canonical_four_program_ids() {
    let expected = [
        solana_system_interface::program::ID.to_bytes(),
        litesvm_token::spl_token::ID.to_bytes(),
        spl_token_2022_interface::ID.to_bytes(),
        solana_stake_interface::program::ID.to_bytes(),
    ];
    assert_eq!(ProgramCurated::get_curated_programs(), &expected);
    for id in expected {
        assert!(ProgramCurated::is_curated_program(&id));
    }
    assert!(!ProgramCurated::is_curated_program(&[0xff; 32]));
}

#[test]
fn curated_permission_admits_real_token2022_and_stake_cpis() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let delegate = Keypair::new();
    let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
    let wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;
    context.svm.airdrop(&wallet, 1_000_000_000).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: delegate.pubkey().as_ref(),
        },
        vec![ClientAction::ProgramCurated(ProgramCurated::new())],
    )
    .unwrap();

    let mint_key = Pubkey::new_unique();
    let mut mint_data = vec![0; 82];
    let mut mint = StateWithExtensionsMut::<Mint>::unpack_uninitialized(&mut mint_data).unwrap();
    mint.base = Mint {
        is_initialized: true,
        ..Mint::default()
    };
    mint.pack_base();
    context
        .svm
        .set_account(
            mint_key,
            Account {
                lamports: 1_000_000_000,
                data: mint_data,
                owner: spl_token_2022_interface::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    for cpi in [
        spl_token_2022_interface::instruction::get_account_data_size(
            &spl_token_2022_interface::ID,
            &mint_key,
            &[],
        )
        .unwrap(),
        solana_stake_interface::instruction::get_minimum_delegation(),
    ] {
        let invoked_program = cpi.program_id;
        let instruction =
            SignV2Instruction::new_ed25519(swig, wallet, delegate.pubkey(), cpi, 1).unwrap();
        let message = v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[instruction],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap();
        let transaction = VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[&context.default_payer, &delegate],
        )
        .unwrap();
        let result = context.svm.send_transaction(transaction).unwrap();
        assert!(result
            .logs
            .iter()
            .any(|line| line == &format!("Program {invoked_program} success")));
    }
}
