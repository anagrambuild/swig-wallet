#![cfg(not(feature = "program_scope_test"))]
//! Wildcard token limits: an all-0xFF mint or destination in any token limit
//! action. Wildcard mints are unlimited; exact-mint ledgers are still charged,
//! and rejected spends roll back every ledger.

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
    swig::{swig_wallet_address_seeds, SwigWithRoles},
};

const SOL: u64 = 1_000_000_000;

fn airdrop(context: &mut SwigTestContext, keys: &[&Keypair]) {
    for key in keys {
        context.svm.airdrop(&key.pubkey(), SOL).unwrap();
    }
}

/// Creates a swig owned by `root` and funds its wallet address.
fn new_swig(context: &mut SwigTestContext, root: &Keypair) -> (Pubkey, Pubkey) {
    airdrop(context, &[root]);
    let (swig, _) = create_swig_ed25519(context, root, rand::random()).unwrap();
    let (wallet, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    context.svm.airdrop(&wallet, 2 * SOL).unwrap();
    (swig, wallet)
}

/// Adds a second role with `actions` and returns its signer.
fn add_role(
    context: &mut SwigTestContext,
    swig: &Pubkey,
    root: &Keypair,
    actions: Vec<ClientAction>,
) -> Keypair {
    let authority = Keypair::new();
    airdrop(context, &[&authority]);
    add_authority_with_ed25519_root(
        context,
        swig,
        root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority.pubkey().as_ref(),
        },
        actions,
    )
    .unwrap();
    authority
}

/// Creates an ATA and optionally mints `amount` into it.
fn token_account(
    context: &mut SwigTestContext,
    mint: &Pubkey,
    owner: &Pubkey,
    amount: u64,
) -> Pubkey {
    let ata = setup_ata(&mut context.svm, mint, owner, &context.default_payer).unwrap();
    if amount > 0 {
        mint_to(&mut context.svm, mint, &context.default_payer, &ata, amount).unwrap();
    }
    ata
}

fn send_token_transfer(
    context: &mut SwigTestContext,
    swig: &Pubkey,
    wallet: &Pubkey,
    authority: &Keypair,
    source: &Pubkey,
    destination: &Pubkey,
    amount: u64,
) -> anyhow::Result<std::result::Result<(), TransactionError>> {
    let transfer =
        spl_token::instruction::transfer(&spl_token::ID, source, destination, wallet, &[], amount)
            .unwrap();
    let sign =
        SignV2Instruction::new_ed25519(*swig, *wallet, authority.pubkey(), transfer, 1).unwrap();
    let message = v0::Message::try_compile(
        &authority.pubkey(),
        &[sign],
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

fn with_role_1<R>(
    context: &SwigTestContext,
    swig: &Pubkey,
    f: impl FnOnce(&swig_state::role::Role) -> R,
) -> R {
    let account = context.svm.get_account(swig).unwrap();
    let state = SwigWithRoles::from_bytes(&account.data).unwrap();
    let role = state.get_role(1).unwrap().unwrap();
    f(&role)
}

fn token_balance(context: &SwigTestContext, account: &Pubkey) -> u64 {
    let data = context.svm.get_account(account).unwrap().data;
    u64::from_le_bytes(data[64..72].try_into().unwrap())
}

fn token_limit(context: &SwigTestContext, swig: &Pubkey, mint: &[u8]) -> u64 {
    with_role_1(context, swig, |role| {
        role.get_action::<TokenLimit>(mint)
            .unwrap()
            .unwrap()
            .current_amount
    })
}

/// Returns `(current, limit, window, last_reset)`.
fn recurring_limit(context: &SwigTestContext, swig: &Pubkey, mint: &[u8]) -> (u64, u64, u64, u64) {
    with_role_1(context, swig, |role| {
        let limit = role
            .get_action::<TokenRecurringLimit>(mint)
            .unwrap()
            .unwrap();
        (limit.current, limit.limit, limit.window, limit.last_reset)
    })
}

fn destination_limit(
    context: &SwigTestContext,
    swig: &Pubkey,
    mint: &[u8],
    destination: &[u8],
) -> u64 {
    let key = [mint, destination].concat();
    with_role_1(context, swig, |role| {
        role.get_action::<TokenDestinationLimit>(&key)
            .unwrap()
            .unwrap()
            .amount
    })
}

#[test_log::test]
fn wildcard_mint_is_unlimited() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let recipient = Keypair::new();
    airdrop(&mut context, &[&recipient]);
    let (swig, wallet) = new_swig(&mut context, &root);

    let mint_a = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let mint_b = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let source_a = token_account(&mut context, &mint_a, &wallet, 1_000);
    let source_b = token_account(&mut context, &mint_b, &wallet, 1_000);
    let destination_a = token_account(&mut context, &mint_a, &recipient.pubkey(), 0);
    let destination_b = token_account(&mut context, &mint_b, &recipient.pubkey(), 0);

    let authority = add_role(
        &mut context,
        &swig,
        &root,
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: WILDCARD,
                current_amount: 100,
            }),
        ],
    );

    // Any mint spends without changing the wildcard's stored amount.
    for (source, destination, amount) in [
        (&source_a, &destination_a, 30),
        (&source_b, &destination_b, 20),
        (&source_a, &destination_a, 101),
        (&source_a, &destination_a, 50),
    ] {
        send_token_transfer(
            &mut context,
            &swig,
            &wallet,
            &authority,
            source,
            destination,
            amount,
        )
        .unwrap()
        .unwrap();
        assert_eq!(token_limit(&context, &swig, &WILDCARD), 100);
    }
    assert_eq!(token_balance(&context, &destination_a), 181);
    assert_eq!(token_balance(&context, &destination_b), 20);
}

#[test_log::test]
fn exact_mint_stacks_with_wildcard() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let recipient = Keypair::new();
    airdrop(&mut context, &[&recipient]);
    let (swig, wallet) = new_swig(&mut context, &root);

    let mint_a = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let mint_b = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let source_a = token_account(&mut context, &mint_a, &wallet, 1_000);
    let source_b = token_account(&mut context, &mint_b, &wallet, 1_000);
    let destination_a = token_account(&mut context, &mint_a, &recipient.pubkey(), 0);
    let destination_b = token_account(&mut context, &mint_b, &recipient.pubkey(), 0);

    let authority = add_role(
        &mut context,
        &swig,
        &root,
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: WILDCARD,
                current_amount: 0,
            }),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint_a.to_bytes(),
                current_amount: 10,
            }),
        ],
    );

    // Mint A charges its exact ledger even though the wildcard also matches.
    send_token_transfer(
        &mut context,
        &swig,
        &wallet,
        &authority,
        &source_a,
        &destination_a,
        7,
    )
    .unwrap()
    .unwrap();
    assert_eq!(token_limit(&context, &swig, mint_a.to_bytes().as_ref()), 3);
    assert_eq!(token_limit(&context, &swig, &WILDCARD), 0);

    let over = send_token_transfer(
        &mut context,
        &swig,
        &wallet,
        &authority,
        &source_a,
        &destination_a,
        4,
    )
    .unwrap();
    assert!(over.is_err());

    // Mint B has no exact limit, so the wildcard leaves it unlimited.
    send_token_transfer(
        &mut context,
        &swig,
        &wallet,
        &authority,
        &source_b,
        &destination_b,
        30,
    )
    .unwrap()
    .unwrap();
    assert_eq!(token_limit(&context, &swig, mint_a.to_bytes().as_ref()), 3);
    assert_eq!(token_limit(&context, &swig, &WILDCARD), 0);
}

#[test_log::test]
fn wildcard_recurring_is_unlimited() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let recipient = Keypair::new();
    airdrop(&mut context, &[&recipient]);
    let (swig, wallet) = new_swig(&mut context, &root);

    let mint_a = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let mint_b = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let source_a = token_account(&mut context, &mint_a, &wallet, 1_000);
    let source_b = token_account(&mut context, &mint_b, &wallet, 1_000);
    let destination_a = token_account(&mut context, &mint_a, &recipient.pubkey(), 0);
    let destination_b = token_account(&mut context, &mint_b, &recipient.pubkey(), 0);

    let start_slot = context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    let (window, allowance) = (10u64, 5u64);
    let authority = add_role(
        &mut context,
        &swig,
        &root,
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenRecurringLimit(TokenRecurringLimit {
                token_mint: WILDCARD,
                window,
                limit: allowance,
                current: allowance,
                last_reset: 0,
            }),
        ],
    );

    send_token_transfer(
        &mut context,
        &swig,
        &wallet,
        &authority,
        &source_a,
        &destination_a,
        2,
    )
    .unwrap()
    .unwrap();
    send_token_transfer(
        &mut context,
        &swig,
        &wallet,
        &authority,
        &source_b,
        &destination_b,
        3,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        recurring_limit(&context, &swig, &WILDCARD),
        (allowance, allowance, window, 0)
    );

    // A spend larger than the stored window allowance still succeeds.
    send_token_transfer(
        &mut context,
        &swig,
        &wallet,
        &authority,
        &source_a,
        &destination_a,
        6,
    )
    .unwrap()
    .unwrap();

    // Crossing a window neither resets nor debits a wildcard ledger.
    context.svm.warp_to_slot(start_slot + window + 1);
    send_token_transfer(
        &mut context,
        &swig,
        &wallet,
        &authority,
        &source_a,
        &destination_a,
        5,
    )
    .unwrap()
    .unwrap();
    assert_eq!(token_balance(&context, &destination_a), 13);
    assert_eq!(
        recurring_limit(&context, &swig, &WILDCARD),
        (allowance, allowance, window, 0)
    );
}

#[test_log::test]
fn wildcard_destination_covers_any_account() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let recipient_1 = Keypair::new();
    let recipient_2 = Keypair::new();
    airdrop(&mut context, &[&recipient_1, &recipient_2]);
    let (swig, wallet) = new_swig(&mut context, &root);

    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let source = token_account(&mut context, &mint, &wallet, 1_000);
    let destination_1 = token_account(&mut context, &mint, &recipient_1.pubkey(), 0);
    let destination_2 = token_account(&mut context, &mint, &recipient_2.pubkey(), 0);

    let authority = add_role(
        &mut context,
        &swig,
        &root,
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                token_mint: mint.to_bytes(),
                destination: WILDCARD,
                amount: 50,
            }),
        ],
    );

    for destination in [&destination_1, &destination_2] {
        send_token_transfer(
            &mut context,
            &swig,
            &wallet,
            &authority,
            &source,
            destination,
            20,
        )
        .unwrap()
        .unwrap();
    }
    let mint_bytes = mint.to_bytes();
    assert_eq!(
        destination_limit(&context, &swig, mint_bytes.as_ref(), &WILDCARD),
        10
    );

    let over = send_token_transfer(
        &mut context,
        &swig,
        &wallet,
        &authority,
        &source,
        &destination_1,
        11,
    )
    .unwrap();
    assert!(over.is_err());
}

#[test_log::test]
fn fully_wildcarded_destination_is_unlimited() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let recipient_1 = Keypair::new();
    let recipient_2 = Keypair::new();
    airdrop(&mut context, &[&recipient_1, &recipient_2]);
    let (swig, wallet) = new_swig(&mut context, &root);

    let mint_a = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let mint_b = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let source_a = token_account(&mut context, &mint_a, &wallet, 1_000);
    let source_b = token_account(&mut context, &mint_b, &wallet, 1_000);
    let destination_a = token_account(&mut context, &mint_a, &recipient_1.pubkey(), 0);
    let destination_b = token_account(&mut context, &mint_b, &recipient_2.pubkey(), 0);

    let authority = add_role(
        &mut context,
        &swig,
        &root,
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                token_mint: WILDCARD,
                destination: WILDCARD,
                amount: 60,
            }),
        ],
    );

    send_token_transfer(
        &mut context,
        &swig,
        &wallet,
        &authority,
        &source_a,
        &destination_a,
        30,
    )
    .unwrap()
    .unwrap();
    send_token_transfer(
        &mut context,
        &swig,
        &wallet,
        &authority,
        &source_b,
        &destination_b,
        20,
    )
    .unwrap()
    .unwrap();
    assert_eq!(destination_limit(&context, &swig, &WILDCARD, &WILDCARD), 60);

    // The stored amount does not cap a fully wildcarded destination.
    send_token_transfer(
        &mut context,
        &swig,
        &wallet,
        &authority,
        &source_b,
        &destination_b,
        61,
    )
    .unwrap()
    .unwrap();
}

#[test_log::test]
fn wildcard_destination_scopes_stack_and_stay_scoped() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let recipients = [
        Keypair::new(),
        Keypair::new(),
        Keypair::new(),
        Keypair::new(),
    ];
    let recipient_refs: Vec<&Keypair> = recipients.iter().collect();
    airdrop(&mut context, &recipient_refs);
    let (swig, wallet) = new_swig(&mut context, &root);

    let mint_x = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let mint_y = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let source_x = token_account(&mut context, &mint_x, &wallet, 1_000);
    let source_y = token_account(&mut context, &mint_y, &wallet, 1_000);
    let dest_x_1 = token_account(&mut context, &mint_x, &recipients[0].pubkey(), 0);
    let dest_x_3 = token_account(&mut context, &mint_x, &recipients[2].pubkey(), 0);
    let dest_y_2 = token_account(&mut context, &mint_y, &recipients[1].pubkey(), 0);
    let dest_y_4 = token_account(&mut context, &mint_y, &recipients[3].pubkey(), 0);

    let authority = add_role(
        &mut context,
        &swig,
        &root,
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
    );

    let mint_x_bytes = mint_x.to_bytes();
    let dest_x_1_bytes = dest_x_1.to_bytes();
    let dest_y_2_bytes = dest_y_2.to_bytes();

    // The exact pair and the mint-wide wildcard both charge.
    send_token_transfer(
        &mut context,
        &swig,
        &wallet,
        &authority,
        &source_x,
        &dest_x_1,
        15,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        destination_limit(&context, &swig, &mint_x_bytes, &dest_x_1_bytes),
        5
    );
    assert_eq!(
        destination_limit(&context, &swig, &mint_x_bytes, &WILDCARD),
        85
    );

    // Another destination for mint X only charges the mint-wide wildcard.
    send_token_transfer(
        &mut context,
        &swig,
        &wallet,
        &authority,
        &source_x,
        &dest_x_3,
        40,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        destination_limit(&context, &swig, &mint_x_bytes, &WILDCARD),
        45
    );

    // Mint Y into dest_y_2 is unlimited within the wildcard-mint scope.
    send_token_transfer(
        &mut context,
        &swig,
        &wallet,
        &authority,
        &source_y,
        &dest_y_2,
        25,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        destination_limit(&context, &swig, &WILDCARD, &dest_y_2_bytes),
        30
    );

    // An uncovered destination stays rejected even though wildcards exist.
    let uncovered = send_token_transfer(
        &mut context,
        &swig,
        &wallet,
        &authority,
        &source_y,
        &dest_y_4,
        1,
    )
    .unwrap();
    assert!(uncovered.is_err());
}

#[test_log::test]
fn all_scopes_charge_atomically_across_windows() {
    for reverse in [false, true] {
        let mut context = setup_test_context().unwrap();
        let root = Keypair::new();
        let (swig, wallet) = new_swig(&mut context, &root);
        let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
        let source = token_account(&mut context, &mint, &wallet, 100);
        let recipient = Keypair::new();
        airdrop(&mut context, &[&recipient]);
        let destination = token_account(&mut context, &mint, &recipient.pubkey(), 0);

        context.svm.warp_to_slot(100);
        let scopes = [
            (mint.to_bytes(), destination.to_bytes(), 18, 5),
            (mint.to_bytes(), WILDCARD, 16, 4),
            (WILDCARD, destination.to_bytes(), 14, 3),
            (WILDCARD, WILDCARD, 12, 2),
        ];
        let general = [(mint.to_bytes(), 20, 6), (WILDCARD, 30, 9)];
        let mut actions = vec![ClientAction::ProgramAll(ProgramAll {})];
        for (key, lifetime, window) in general {
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
        let authority = add_role(&mut context, &swig, &root, actions);

        for window in 0..4 {
            context.svm.warp_to_slot(100 + window * 11);
            context.svm.expire_blockhash();
            send_token_transfer(
                &mut context,
                &swig,
                &wallet,
                &authority,
                &source,
                &destination,
                4,
            )
            .unwrap()
            .unwrap();

            with_role_1(&context, &swig, |role| {
                for (mint, dest, lifetime, recurring) in scopes {
                    let spent = if mint == WILDCARD { 0 } else { 4 };
                    assert_eq!(
                        role.get_action::<TokenDestinationLimit>(&[mint, dest].concat())
                            .unwrap()
                            .unwrap()
                            .amount,
                        lifetime - spent * (window + 1)
                    );
                    assert_eq!(
                        role.get_action::<TokenRecurringDestinationLimit>(&[mint, dest].concat())
                            .unwrap()
                            .unwrap()
                            .current_amount,
                        recurring - spent
                    );
                }
                for (mint, lifetime, recurring) in general {
                    let spent = if mint == WILDCARD { 0 } else { 4 };
                    assert_eq!(
                        role.get_action::<TokenLimit>(&mint)
                            .unwrap()
                            .unwrap()
                            .current_amount,
                        lifetime - spent * (window + 1)
                    );
                    assert_eq!(
                        role.get_action::<TokenRecurringLimit>(&mint)
                            .unwrap()
                            .unwrap()
                            .current,
                        recurring - spent
                    );
                }
            });

            // A debit that exceeds any applicable ledger changes nothing.
            let before = context.svm.get_account(&swig).unwrap().data;
            let balance = token_balance(&context, &source);
            let error = send_token_transfer(
                &mut context,
                &swig,
                &wallet,
                &authority,
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

        // A fresh window cannot refill an exhausted exact-mint lifetime.
        context.svm.warp_to_slot(200);
        context.svm.expire_blockhash();
        assert!(send_token_transfer(
            &mut context,
            &swig,
            &wallet,
            &authority,
            &source,
            &destination,
            1
        )
        .unwrap()
        .is_err());
        assert_eq!(token_balance(&context, &destination), 16);
    }
}
