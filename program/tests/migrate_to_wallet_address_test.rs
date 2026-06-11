#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig::actions::migrate_to_wallet_address_v1::MigrateToWalletAddressV1Args;
use swig_state::{
    swig::{swig_wallet_address_seeds, Swig},
    IntoBytes, Transmutable,
};

fn migrate_instruction(
    swig: Pubkey,
    authority: Pubkey,
    payer: Pubkey,
    swig_wallet_address: Pubkey,
    wallet_address_bump: u8,
    authority_is_signer: bool,
) -> Instruction {
    let mut data = MigrateToWalletAddressV1Args::new(wallet_address_bump, 0)
        .into_bytes()
        .expect("migrate args should serialize")
        .to_vec();
    data.push(1);

    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(swig, false),
            AccountMeta::new_readonly(authority, authority_is_signer),
            AccountMeta::new(payer, true),
            AccountMeta::new(swig_wallet_address, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ],
        data,
    }
}

fn setup_unmigrated_swig() -> (SwigTestContext, Keypair, Pubkey, Pubkey, u8) {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig, _bench) = create_swig_ed25519(&mut context, &authority, id).unwrap();
    convert_swig_to_v1(&mut context, &swig);

    let (swig_wallet_address, wallet_address_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    (
        context,
        authority,
        swig,
        swig_wallet_address,
        wallet_address_bump,
    )
}

#[test_log::test]
fn test_migration_rejects_nonsigner_authority() {
    let (mut context, authority, swig, swig_wallet_address, wallet_address_bump) =
        setup_unmigrated_swig();

    let migrate_ix = migrate_instruction(
        swig,
        authority.pubkey(),
        context.default_payer.pubkey(),
        swig_wallet_address,
        wallet_address_bump,
        false,
    );

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                migrate_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer]).unwrap();

    let result = context.svm.send_transaction(tx);

    assert!(
        result.is_err(),
        "migration must fail when the role authority does not sign"
    );
}

#[test_log::test]
fn test_migration_accepts_authenticated_authority() {
    let (mut context, authority, swig, swig_wallet_address, wallet_address_bump) =
        setup_unmigrated_swig();

    let migrate_ix = migrate_instruction(
        swig,
        authority.pubkey(),
        context.default_payer.pubkey(),
        swig_wallet_address,
        wallet_address_bump,
        true,
    );

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                migrate_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &authority]).unwrap();

    let result = context.svm.send_transaction(tx);

    assert!(
        result.is_ok(),
        "authenticated migration should succeed: {:?}",
        result.err()
    );

    let swig_account = context.svm.get_account(&swig).unwrap();
    let migrated_swig = unsafe { Swig::load_unchecked(&swig_account.data[..Swig::LEN]).unwrap() };
    assert_eq!(migrated_swig.wallet_bump, wallet_address_bump);
}
