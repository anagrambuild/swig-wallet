#![cfg(not(feature = "program_scope_test"))]
//! Tests for wildcard token limits with SignV2.
//!
//! Wildcard keys (all-0xFF) in the mint and/or destination fields of token
//! limit actions let a single action cover any mint and/or any destination.
//! Every applicable exact and wildcard scope is charged, including both
//! one-shot and recurring ledgers. Rejected spends roll back all ledgers.

mod common;
use common::*;
use litesvm_token::spl_token;
use solana_sdk::{
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{AuthorityConfig, ClientAction, SignV2Instruction};
use swig_state::{
    action::{
        program_all::ProgramAll, token_destination_limit::TokenDestinationLimit,
        token_limit::TokenLimit, token_recurring_destination_limit::TokenRecurringDestinationLimit,
        token_recurring_limit::TokenRecurringLimit, wildcard::WILDCARD,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
};

/// Sends a spl_token::transfer signed via SignV2 by `authority`.
#[allow(clippy::type_complexity)]
fn send_token_transfer(
    context: &mut SwigTestContext,
    swig: &Pubkey,
    swig_wallet_address: &Pubkey,
    authority: &Keypair,
    source_ata: &Pubkey,
    destination_ata: &Pubkey,
    amount: u64,
) -> anyhow::Result<std::result::Result<(), TransactionError>> {
    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        source_ata,
        destination_ata,
        swig_wallet_address,
        &[],
        amount,
    )
    .unwrap();

    let sign_ix = SignV2Instruction::new_ed25519(
        *swig,
        *swig_wallet_address,
        authority.pubkey(),
        transfer_ix,
        1,
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

    Ok(context
        .svm
        .send_transaction(tx)
        .map(|_| ())
        .map_err(|e| e.err))
}

/// Runs `f` against role 1 of the current swig state for readbacks.
fn with_role_1<R>(
    context: &SwigTestContext,
    swig: &Pubkey,
    f: impl FnOnce(&swig_state::role::Role) -> R,
) -> anyhow::Result<R> {
    let swig_account = context
        .svm
        .get_account(swig)
        .ok_or_else(|| anyhow::anyhow!("Swig account not found"))?;
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role = swig_state
        .get_role(1)
        .map_err(|e| anyhow::anyhow!("Failed to get role {:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("role 1 missing"))?;
    Ok(f(&role))
}

/// Reads the token balance of a token account.
fn token_balance(context: &SwigTestContext, ata: &Pubkey) -> u64 {
    u64::from_le_bytes(
        context
            .svm
            .get_account(ata)
            .unwrap()
            .data
            .get(64..72)
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

/// A wildcard one-shot limit covers every mint; each spend drafts the
/// shared wildcard budget.
#[test_log::test]
fn test_wildcard_general_limit_covers_any_mint() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&recipient.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let mint_a = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let mint_b = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata_a = setup_ata(
        &mut context.svm,
        &mint_a,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let swig_ata_b = setup_ata(
        &mut context.svm,
        &mint_b,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata_a = setup_ata(
        &mut context.svm,
        &mint_a,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata_b = setup_ata(
        &mut context.svm,
        &mint_b,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    mint_to(
        &mut context.svm,
        &mint_a,
        &context.default_payer,
        &swig_ata_a,
        1000,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint_b,
        &context.default_payer,
        &swig_ata_b,
        1000,
    )
    .unwrap();

    let _ = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let wildcard_general_amount = 100u64;
    let _txn = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: WILDCARD,
                current_amount: wildcard_general_amount,
            }),
        ],
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();

    // Sanity: the wildcard limit itself was stored.
    let remaining = with_role_1(&context, &swig, |role| {
        let count = {
            let mut n = 0;
            let mut cursor = 0usize;
            let actions = role.actions;
            while cursor + 8 <= actions.len() {
                let len = u16::from_le_bytes(actions[cursor + 2..cursor + 4].try_into().unwrap())
                    as usize;
                n += 1;
                cursor += 8 + len;
            }
            n
        };
        let wildcard = role
            .get_action::<TokenLimit>(&WILDCARD)
            .unwrap()
            .map(|a| a.current_amount);
        (count, wildcard)
    })
    .unwrap();
    assert_eq!(remaining, (2, Some(100)));

    // First spend (mint A) succeeds and drafts the shared budget.
    send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata_a,
        &recipient_ata_a,
        30,
    )
    .unwrap()
    .unwrap();

    assert_eq!(token_balance(&context, &recipient_ata_a), 30);
    let remaining = with_role_1(&context, &swig, |role| {
        role.get_action::<TokenLimit>(&WILDCARD)
            .unwrap()
            .unwrap()
            .current_amount
    })
    .unwrap();
    assert_eq!(remaining, 70);

    // A second spend of a different mint hits the same bucket.
    send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata_b,
        &recipient_ata_b,
        20,
    )
    .unwrap()
    .unwrap();

    assert_eq!(token_balance(&context, &recipient_ata_b), 20);
    let remaining = with_role_1(&context, &swig, |role| {
        role.get_action::<TokenLimit>(&WILDCARD)
            .unwrap()
            .unwrap()
            .current_amount
    })
    .unwrap();
    assert_eq!(remaining, 50);

    // Overspending the exhausted bucket fails for any mint.
    let res = send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata_a,
        &recipient_ata_a,
        51,
    )
    .unwrap();
    assert!(res.is_err());

    // State remains intact after the failure.
    let remaining = with_role_1(&context, &swig, |role| {
        role.get_action::<TokenLimit>(&WILDCARD)
            .unwrap()
            .unwrap()
            .current_amount
    })
    .unwrap();
    assert_eq!(remaining, 50);

    // Spending exactly the remaining allowance succeeds.
    send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata_a,
        &recipient_ata_a,
        50,
    )
    .unwrap()
    .unwrap();

    let remaining = with_role_1(&context, &swig, |role| {
        role.get_action::<TokenLimit>(&WILDCARD)
            .unwrap()
            .unwrap()
            .current_amount
    })
    .unwrap();
    assert_eq!(remaining, 0);
}

/// Exact and wildcard mint limits both charge; neither bypasses the other.
#[test_log::test]
fn test_exact_mint_limit_stacks_with_wildcard() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&recipient.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let mint_a = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let mint_b = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata_a = setup_ata(
        &mut context.svm,
        &mint_a,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let swig_ata_b = setup_ata(
        &mut context.svm,
        &mint_b,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata_a = setup_ata(
        &mut context.svm,
        &mint_a,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata_b = setup_ata(
        &mut context.svm,
        &mint_b,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    mint_to(
        &mut context.svm,
        &mint_a,
        &context.default_payer,
        &swig_ata_a,
        1000,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint_b,
        &context.default_payer,
        &swig_ata_b,
        1000,
    )
    .unwrap();

    let _ = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    // Wildcard of 100 for any mint; the risky mint A gets a tighter
    // dedicated cap of 10.
    let _txn = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: WILDCARD,
                current_amount: 100,
            }),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint_a.to_bytes(),
                current_amount: 10,
            }),
        ],
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();

    // Mint A spends charge both the exact and the wildcard limits.
    send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata_a,
        &recipient_ata_a,
        7,
    )
    .unwrap()
    .unwrap();

    let exact = with_role_1(&context, &swig, |role| {
        role.get_action::<TokenLimit>(mint_a.to_bytes().as_ref())
            .unwrap()
            .unwrap()
            .current_amount
    })
    .unwrap();
    assert_eq!(exact, 3);
    let wildcard = with_role_1(&context, &swig, |role| {
        role.get_action::<TokenLimit>(&WILDCARD)
            .unwrap()
            .unwrap()
            .current_amount
    })
    .unwrap();
    assert_eq!(wildcard, 93);

    // The exact cap is enforced.
    let res = send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata_a,
        &recipient_ata_a,
        4,
    )
    .unwrap();
    assert!(res.is_err());

    // Mint B has no exact limit, so only the wildcard budget applies.
    send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata_b,
        &recipient_ata_b,
        30,
    )
    .unwrap()
    .unwrap();

    let wildcard = with_role_1(&context, &swig, |role| {
        role.get_action::<TokenLimit>(&WILDCARD)
            .unwrap()
            .unwrap()
            .current_amount
    })
    .unwrap();
    assert_eq!(wildcard, 63);
    let exact = with_role_1(&context, &swig, |role| {
        role.get_action::<TokenLimit>(mint_a.to_bytes().as_ref())
            .unwrap()
            .unwrap()
            .current_amount
    })
    .unwrap();
    assert_eq!(exact, 3);
}

/// A wildcard-mint recurring limit charges every mint and resets once the
/// window expires.
#[test_log::test]
fn test_wildcard_recurring_limit_resets_per_window() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&recipient.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let mint_a = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let mint_b = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata_a = setup_ata(
        &mut context.svm,
        &mint_a,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let swig_ata_b = setup_ata(
        &mut context.svm,
        &mint_b,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata_a = setup_ata(
        &mut context.svm,
        &mint_a,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata_b = setup_ata(
        &mut context.svm,
        &mint_b,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    mint_to(
        &mut context.svm,
        &mint_a,
        &context.default_payer,
        &swig_ata_a,
        1000,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint_b,
        &context.default_payer,
        &swig_ata_b,
        1000,
    )
    .unwrap();

    let _ = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let window = 10u64;
    let recurring_amount = 5u64;
    // litesvm boots at a high slot; capture it so warps always move forward.
    let start_slot = context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    let _txn = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenRecurringLimit(TokenRecurringLimit {
                token_mint: WILDCARD,
                window,
                limit: recurring_amount,
                current: recurring_amount,
                last_reset: 0,
            }),
        ],
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();

    // Spend across both mints within one window drains the shared bucket.
    send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata_a,
        &recipient_ata_a,
        2,
    )
    .unwrap()
    .unwrap();
    send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata_b,
        &recipient_ata_b,
        3,
    )
    .unwrap()
    .unwrap();

    let recurring = with_role_1(&context, &swig, |role| {
        let a = role
            .get_action::<TokenRecurringLimit>(&WILDCARD)
            .unwrap()
            .unwrap();
        (a.current, a.limit, a.window, a.last_reset)
    })
    .unwrap();
    assert_eq!(recurring.0, 0);

    // Within the window further spends fail.
    let res = send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata_a,
        &recipient_ata_a,
        1,
    )
    .unwrap();
    assert!(res.is_err());

    // After the window expires the limit resets and mints flow again.
    context.svm.warp_to_slot(start_slot + window + 1);

    send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata_a,
        &recipient_ata_a,
        5,
    )
    .unwrap()
    .unwrap();

    assert_eq!(token_balance(&context, &recipient_ata_a), 7);
    let recurring = with_role_1(&context, &swig, |role| {
        let a = role
            .get_action::<TokenRecurringLimit>(&WILDCARD)
            .unwrap()
            .unwrap();
        (a.current, a.limit, a.window, a.last_reset)
    })
    .unwrap();
    assert_eq!(recurring.0, 0);
}

/// A token destination limit with a wildcard destination covers transfers
/// of that mint to any recipient token account.
#[test_log::test]
fn test_wildcard_destination_limit_covers_any_destination() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient_1 = Keypair::new();
    let recipient_2 = Keypair::new();

    for kp in [&recipient_1, &recipient_2, &swig_authority] {
        context.svm.airdrop(&kp.pubkey(), 1_000_000_000).unwrap();
    }

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata_1 = setup_ata(
        &mut context.svm,
        &mint,
        &recipient_1.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata_2 = setup_ata(
        &mut context.svm,
        &mint,
        &recipient_2.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    mint_to(
        &mut context.svm,
        &mint,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();

    let _ = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    // 50 tokens of `mint` may go to ANY destination.
    let _txn = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                token_mint: mint.to_bytes(),
                destination: WILDCARD,
                amount: 50,
            }),
        ],
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();

    send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata,
        &recipient_ata_1,
        20,
    )
    .unwrap()
    .unwrap();
    send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata,
        &recipient_ata_2,
        20,
    )
    .unwrap()
    .unwrap();

    let limit_action = with_role_1(&context, &swig, |role| {
        role.get_action::<TokenDestinationLimit>(&[mint.to_bytes(), WILDCARD].concat())
            .unwrap()
            .unwrap()
            .amount
    })
    .unwrap();
    assert_eq!(limit_action, 10);

    // A transfer exceeding the remainder of the wildcard bucket fails.
    let res = send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata,
        &recipient_ata_1,
        11,
    )
    .unwrap();
    assert!(res.is_err());
}

/// A destination limit with both fields wildcarded covers any mint to any
/// destination.
#[test_log::test]
fn test_fully_wildcard_destination_limit() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient_1 = Keypair::new();
    let recipient_2 = Keypair::new();

    for kp in [&recipient_1, &recipient_2, &swig_authority] {
        context.svm.airdrop(&kp.pubkey(), 1_000_000_000).unwrap();
    }

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let mint_a = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let mint_b = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata_a = setup_ata(
        &mut context.svm,
        &mint_a,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let swig_ata_b = setup_ata(
        &mut context.svm,
        &mint_b,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata_a = setup_ata(
        &mut context.svm,
        &mint_a,
        &recipient_1.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata_b = setup_ata(
        &mut context.svm,
        &mint_b,
        &recipient_2.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    mint_to(
        &mut context.svm,
        &mint_a,
        &context.default_payer,
        &swig_ata_a,
        1000,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint_b,
        &context.default_payer,
        &swig_ata_b,
        1000,
    )
    .unwrap();

    let _ = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let _txn = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                token_mint: WILDCARD,
                destination: WILDCARD,
                amount: 60,
            }),
        ],
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();

    // Any mint to any destination drafts the shared bucket.
    send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata_a,
        &recipient_ata_a,
        30,
    )
    .unwrap()
    .unwrap();
    send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata_b,
        &recipient_ata_b,
        20,
    )
    .unwrap()
    .unwrap();

    let limit_action = with_role_1(&context, &swig, |role| {
        role.get_action::<TokenDestinationLimit>(&[WILDCARD, WILDCARD].concat())
            .unwrap()
            .unwrap()
            .amount
    })
    .unwrap();
    assert_eq!(limit_action, 10);

    // The bucket is mint-agnostic and shared.
    let res = send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata_b,
        &recipient_ata_b,
        11,
    )
    .unwrap();
    assert!(res.is_err());
}

/// Exact pairs stack with (mint, wildcard) and (wildcard, destination);
/// uncovered destinations
/// remain rejected even when wildcard limits for other pairs exist.
#[test_log::test]
fn test_destination_wildcard_specificity_and_coverage() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient_1 = Keypair::new();
    let recipient_2 = Keypair::new();
    let recipient_3 = Keypair::new();
    let recipient_4 = Keypair::new();

    for kp in [
        &recipient_1,
        &recipient_2,
        &recipient_3,
        &recipient_4,
        &swig_authority,
    ] {
        context.svm.airdrop(&kp.pubkey(), 1_000_000_000).unwrap();
    }

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let mint_x = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let mint_y = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata_x = setup_ata(
        &mut context.svm,
        &mint_x,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let swig_ata_y = setup_ata(
        &mut context.svm,
        &mint_y,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let dest_x_1 = setup_ata(
        &mut context.svm,
        &mint_x,
        &recipient_1.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    let dest_x_3 = setup_ata(
        &mut context.svm,
        &mint_x,
        &recipient_3.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    let dest_y_2 = setup_ata(
        &mut context.svm,
        &mint_y,
        &recipient_2.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    let dest_y_4 = setup_ata(
        &mut context.svm,
        &mint_y,
        &recipient_4.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    mint_to(
        &mut context.svm,
        &mint_x,
        &context.default_payer,
        &swig_ata_x,
        1000,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint_y,
        &context.default_payer,
        &swig_ata_y,
        1000,
    )
    .unwrap();

    let _ = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    // Tiers:
    //   (mint_x, dest_x_1): 20   exact pair
    //   (mint_x, WILD):     100  any destination for mint_x
    //   (WILD, dest_y_2):   30   any mint into dest_y_2
    let _txn = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                token_mint: mint_x.to_bytes(),
                destination: dest_x_1.to_bytes(),
                amount: 20,
            }),
            ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                token_mint: WILDCARD,
                destination: dest_y_2.to_bytes(),
                amount: 30,
            }),
            ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                token_mint: mint_x.to_bytes(),
                destination: WILDCARD,
                amount: 100,
            }),
        ],
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();

    // 1. The exact pair and the mint-wide wildcard both charge.
    send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata_x,
        &dest_x_1,
        15,
    )
    .unwrap()
    .unwrap();

    let exact = with_role_1(&context, &swig, |role| {
        role.get_action::<TokenDestinationLimit>(
            [mint_x.to_bytes(), dest_x_1.to_bytes()].concat().as_ref(),
        )
        .unwrap()
        .unwrap()
        .amount
    })
    .unwrap();
    assert_eq!(exact, 5);
    let mint_wild = with_role_1(&context, &swig, |role| {
        role.get_action::<TokenDestinationLimit>([mint_x.to_bytes(), WILDCARD].concat().as_ref())
            .unwrap()
            .unwrap()
            .amount
    })
    .unwrap();
    assert_eq!(mint_wild, 85);

    // 2. A different destination for mint_x drafts (mint_x, WILD).
    send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata_x,
        &dest_x_3,
        40,
    )
    .unwrap()
    .unwrap();

    let mint_wild = with_role_1(&context, &swig, |role| {
        role.get_action::<TokenDestinationLimit>([mint_x.to_bytes(), WILDCARD].concat().as_ref())
            .unwrap()
            .unwrap()
            .amount
    })
    .unwrap();
    assert_eq!(mint_wild, 45);

    // 3. mint_y into dest_y_2 drafts (WILD, dest_y_2).
    send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata_y,
        &dest_y_2,
        25,
    )
    .unwrap()
    .unwrap();

    let wild_mint = with_role_1(&context, &swig, |role| {
        role.get_action::<TokenDestinationLimit>([WILDCARD, dest_y_2.to_bytes()].concat().as_ref())
            .unwrap()
            .unwrap()
            .amount
    })
    .unwrap();
    assert_eq!(wild_mint, 5);

    // 4. A destination covered by no wildcard tier stays rejected even
    // though wildcard limits exist for this role.
    let res = send_token_transfer(
        &mut context,
        &swig,
        &swig_wallet_address,
        &second_authority,
        &swig_ata_y,
        &dest_y_4,
        1,
    )
    .unwrap();
    assert!(res.is_err());
}

/// All four destination scopes and both general scopes hold independent
/// lifetime/window pairs. Narrower scopes never bypass the shared budgets.
#[test_log::test]
fn every_applicable_scope_and_pair_charges_atomically_across_windows() {
    for reverse in [false, true] {
        let mut context = setup_test_context().unwrap();
        let root = Keypair::new();
        let signer = Keypair::new();
        for key in [&root, &signer] {
            context.svm.airdrop(&key.pubkey(), 1_000_000_000).unwrap();
        }
        let id = rand::random();
        let (swig, _) = create_swig_ed25519(&mut context, &root, id).unwrap();
        let wallet =
            Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id())
                .0;
        let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
        let source = setup_ata(&mut context.svm, &mint, &wallet, &context.default_payer).unwrap();
        let destination = setup_ata(
            &mut context.svm,
            &mint,
            &signer.pubkey(),
            &context.default_payer,
        )
        .unwrap();
        mint_to(
            &mut context.svm,
            &mint,
            &context.default_payer,
            &source,
            100,
        )
        .unwrap();
        context.svm.warp_to_slot(100);
        let scopes = [
            (mint.to_bytes(), destination.to_bytes(), 18, 5),
            (mint.to_bytes(), WILDCARD, 16, 4),
            (WILDCARD, destination.to_bytes(), 14, 3),
            (WILDCARD, WILDCARD, 12, 2),
        ];
        let mut actions = vec![ClientAction::ProgramAll(ProgramAll {})];
        for (key, lifetime, window) in [(mint.to_bytes(), 20, 6), (WILDCARD, 30, 9)] {
            actions.push(ClientAction::TokenLimit(TokenLimit {
                token_mint: key,
                current_amount: lifetime,
            }));
            actions.push(ClientAction::TokenRecurringLimit(TokenRecurringLimit {
                token_mint: key,
                window: 10,
                limit: window,
                current: window,
                last_reset: 0,
            }));
        }
        for (key, dest, lifetime, window) in scopes {
            actions.push(ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                token_mint: key,
                destination: dest,
                amount: lifetime,
            }));
            actions.push(ClientAction::TokenRecurringDestinationLimit(
                TokenRecurringDestinationLimit {
                    token_mint: key,
                    destination: dest,
                    recurring_amount: window,
                    window: 10,
                    current_amount: window,
                    last_reset: 0,
                },
            ));
        }
        if reverse {
            actions.reverse();
        }
        add_authority_with_ed25519_root(
            &mut context,
            &swig,
            &root,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: signer.pubkey().as_ref(),
            },
            actions,
        )
        .unwrap();
        for window in 0..6 {
            context.svm.warp_to_slot(100 + window * 11);
            context.svm.expire_blockhash();
            send_token_transfer(
                &mut context,
                &swig,
                &wallet,
                &signer,
                &source,
                &destination,
                2,
            )
            .unwrap()
            .unwrap();
            with_role_1(&context, &swig, |role| {
                for (key, dest, lifetime, recurring) in scopes {
                    let key = [key, dest].concat();
                    assert_eq!(
                        role.get_action::<TokenDestinationLimit>(&key)
                            .unwrap()
                            .unwrap()
                            .amount,
                        lifetime - 2 * (window + 1)
                    );
                    assert_eq!(
                        role.get_action::<TokenRecurringDestinationLimit>(&key)
                            .unwrap()
                            .unwrap()
                            .current_amount,
                        recurring - 2
                    );
                }
                for (key, lifetime, recurring) in [(mint.to_bytes(), 20, 6), (WILDCARD, 30, 9)] {
                    assert_eq!(
                        role.get_action::<TokenLimit>(&key)
                            .unwrap()
                            .unwrap()
                            .current_amount,
                        lifetime - 2 * (window + 1)
                    );
                    assert_eq!(
                        role.get_action::<TokenRecurringLimit>(&key)
                            .unwrap()
                            .unwrap()
                            .current,
                        recurring - 2
                    );
                }
            })
            .unwrap();
            let before = context.svm.get_account(&swig).unwrap().data;
            let balance = token_balance(&context, &source);
            let error = send_token_transfer(
                &mut context,
                &swig,
                &wallet,
                &signer,
                &source,
                &destination,
                1,
            )
            .unwrap()
            .unwrap_err();
            assert!(matches!(
                error,
                TransactionError::InstructionError(
                    0,
                    solana_sdk::instruction::InstructionError::Custom(_)
                )
            ));
            assert_eq!(context.svm.get_account(&swig).unwrap().data, before);
            assert_eq!(token_balance(&context, &source), balance);
        }
        // A fresh recurring window cannot replenish the exhausted wildcard lifetime.
        context.svm.warp_to_slot(200);
        context.svm.expire_blockhash();
        assert!(send_token_transfer(
            &mut context,
            &swig,
            &wallet,
            &signer,
            &source,
            &destination,
            1
        )
        .unwrap()
        .is_err());
        assert_eq!(token_balance(&context, &destination), 12);
    }
}
