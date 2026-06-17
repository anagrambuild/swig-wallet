#![cfg(not(feature = "program_scope_test"))]

mod common;
use common::*;
use litesvm_token::spl_token;
use solana_sdk::{
    message::{v0, VersionedMessage},
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ClientAction, SignV2Instruction};
use swig_state::{
    action::{
        all::All, program_all::ProgramAll, sol_destination_limit::SolDestinationLimit,
        sol_limit::SolLimit, token_destination_limit::TokenDestinationLimit,
        token_limit::TokenLimit,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds},
};

const TRANSFER_LAMPORTS: u64 = LAMPORTS_PER_SOL / 10;
const TOKEN_TRANSFER_AMOUNT: u64 = 100;

#[test_log::test]
fn compare_sign_v2_role_compute_units() {
    let all = sign_with_all_role_cu();
    let sol_limit = sign_with_sol_limit_role_cu();
    let sol_limit_destination = sign_with_sol_limit_destination_role_cu();
    let token_limit = sign_with_token_limit_role_cu();
    let token_limit_destination = sign_with_token_limit_destination_role_cu();

    println!("CU_COMPARE all {}", all);
    println!("CU_COMPARE sol_limit {}", sol_limit);
    println!("CU_COMPARE sol_limit_destination {}", sol_limit_destination);
    println!("CU_COMPARE token_limit {}", token_limit);
    println!(
        "CU_COMPARE token_limit_destination {}",
        token_limit_destination
    );
}

fn sign_with_all_role_cu() -> u64 {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&authority.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    create_swig_ed25519(&mut context, &authority, id).unwrap();
    context
        .svm
        .airdrop(&swig_wallet_address, LAMPORTS_PER_SOL)
        .unwrap();

    let inner_ix = solana_system_interface::instruction::transfer(
        &swig_wallet_address,
        &recipient.pubkey(),
        TRANSFER_LAMPORTS,
    );

    send_sign_v2(
        &mut context,
        &authority,
        swig,
        swig_wallet_address,
        inner_ix,
        0,
    )
}

fn sign_with_sol_limit_role_cu() -> u64 {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let limited_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    context
        .svm
        .airdrop(&limited_authority.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    create_swig_ed25519(&mut context, &root_authority, id).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: limited_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::SolLimit(SolLimit {
                amount: LAMPORTS_PER_SOL,
            }),
        ],
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, LAMPORTS_PER_SOL)
        .unwrap();

    let inner_ix = solana_system_interface::instruction::transfer(
        &swig_wallet_address,
        &recipient.pubkey(),
        TRANSFER_LAMPORTS,
    );

    send_sign_v2(
        &mut context,
        &limited_authority,
        swig,
        swig_wallet_address,
        inner_ix,
        1,
    )
}

fn sign_with_sol_limit_destination_role_cu() -> u64 {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let limited_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    context
        .svm
        .airdrop(&limited_authority.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    create_swig_ed25519(&mut context, &root_authority, id).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: limited_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::SolLimit(SolLimit {
                amount: LAMPORTS_PER_SOL,
            }),
            ClientAction::SolDestinationLimit(SolDestinationLimit {
                destination: recipient.pubkey().to_bytes(),
                amount: LAMPORTS_PER_SOL,
            }),
        ],
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, LAMPORTS_PER_SOL)
        .unwrap();

    let inner_ix = solana_system_interface::instruction::transfer(
        &swig_wallet_address,
        &recipient.pubkey(),
        TRANSFER_LAMPORTS,
    );

    send_sign_v2(
        &mut context,
        &limited_authority,
        swig,
        swig_wallet_address,
        inner_ix,
        1,
    )
}

fn sign_with_token_limit_role_cu() -> u64 {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let limited_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    context
        .svm
        .airdrop(&limited_authority.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint,
        &context.default_payer,
        &swig_ata,
        1_000,
    )
    .unwrap();

    create_swig_ed25519(&mut context, &root_authority, id).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: limited_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint.to_bytes(),
                current_amount: 1_000,
            }),
        ],
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, LAMPORTS_PER_SOL)
        .unwrap();

    let inner_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig_wallet_address,
        &[],
        TOKEN_TRANSFER_AMOUNT,
    )
    .unwrap();

    send_sign_v2(
        &mut context,
        &limited_authority,
        swig,
        swig_wallet_address,
        inner_ix,
        1,
    )
}

fn sign_with_token_limit_destination_role_cu() -> u64 {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let limited_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    context
        .svm
        .airdrop(&limited_authority.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint,
        &context.default_payer,
        &swig_ata,
        1_000,
    )
    .unwrap();

    create_swig_ed25519(&mut context, &root_authority, id).unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: limited_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint.to_bytes(),
                current_amount: 1_000,
            }),
            ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                token_mint: mint.to_bytes(),
                destination: recipient_ata.to_bytes(),
                amount: 1_000,
            }),
        ],
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, LAMPORTS_PER_SOL)
        .unwrap();

    let inner_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig_wallet_address,
        &[],
        TOKEN_TRANSFER_AMOUNT,
    )
    .unwrap();

    send_sign_v2(
        &mut context,
        &limited_authority,
        swig,
        swig_wallet_address,
        inner_ix,
        1,
    )
}

fn send_sign_v2(
    context: &mut SwigTestContext,
    authority: &Keypair,
    swig: Pubkey,
    swig_wallet_address: Pubkey,
    inner_ix: solana_sdk::instruction::Instruction,
    role_id: u32,
) -> u64 {
    let sign_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        authority.pubkey(),
        inner_ix,
        role_id,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[authority]).unwrap();
    context
        .svm
        .send_transaction(tx)
        .unwrap()
        .compute_units_consumed
}
