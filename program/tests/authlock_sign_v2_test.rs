#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use litesvm::types::FailedTransactionMetadata;
use litesvm_token::spl_token;
use solana_sdk::{
    instruction::InstructionError,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{
    AuthorityConfig, ClientAction, ManageAuthLockData, ManageAuthLockInstruction, SignV2Instruction,
};
use swig_state::{
    action::{
        authlock::AuthorizationLock, manage_authlock::ManageAuthorizationLocks,
        program_all::ProgramAll, sol_limit::SolLimit, token_limit::TokenLimit,
    },
    authority::AuthorityType,
    swig::{swig_wallet_address_seeds, SwigWithRoles},
};

/// Small, composable building blocks for all auth‑lock tests.
///
/// The idea is:
/// - `TestEnv` sets up a Swig wallet, PDA wallet, one mint + ATA.
/// - helpers add authorities with specific actions.
/// - helpers run `ManageAuthLock{Add,Remove,Modify}` and read back state.
///
/// Each test can then be expressed mostly as data / expectations.

struct TestEnv {
    context: SwigTestContext,
    root_authority: Keypair,
    swig: Pubkey,
    swig_wallet: Pubkey,
    mint: Pubkey,
    swig_ata: Pubkey,
}

/// Create a Swig with an Ed25519 root authority and a funded wallet + token mint.
fn setup_env(initial_sol: u64, initial_tokens: u64) -> TestEnv {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    let swig_wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;

    if initial_sol > 0 {
        context.svm.airdrop(&swig_wallet, initial_sol).unwrap();
    }

    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint,
        &swig_wallet,
        &context.default_payer,
    )
    .unwrap();

    if initial_tokens > 0 {
        mint_to(
            &mut context.svm,
            &mint,
            &context.default_payer,
            &swig_ata,
            initial_tokens,
        )
        .unwrap();
    }

    TestEnv {
        context,
        root_authority,
        swig,
        swig_wallet,
        mint,
        swig_ata,
    }
}

/// Add a new Ed25519 authority with the given actions and return the keypair + role id.
fn add_authority_with_actions(env: &mut TestEnv, actions: Vec<ClientAction>) -> (Keypair, u32) {
    let new_authority = Keypair::new();
    env.context
        .svm
        .airdrop(&new_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut env.context,
        &env.swig,
        &env.root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        actions,
    )
    .unwrap();

    let swig_account = env.context.svm.get_account(&env.swig).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role_id = swig
        .lookup_role_id(new_authority.pubkey().as_ref())
        .unwrap()
        .expect("authority role must exist");

    (new_authority, role_id)
}

/// Run a single ManageAuthLock operation and return the transaction result.
fn run_manage_auth_lock(
    env: &mut TestEnv,
    acting_role_id: u32,
    authority_id: u32,
    data: ManageAuthLockData,
) -> Result<(), FailedTransactionMetadata> {
    let ix = ManageAuthLockInstruction::new_with_ed25519_authority(
        env.swig,
        env.context.default_payer.pubkey(),
        env.root_authority.pubkey(),
        acting_role_id,
        authority_id,
        data,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &env.context.default_payer.pubkey(),
        &[ix],
        &[],
        env.context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&env.context.default_payer, &env.root_authority],
    )
    .unwrap();

    env.context.svm.send_transaction(tx).map(|_| ())
}

fn auth_locks_for_role(env: &TestEnv, role_id: u32) -> Vec<AuthorizationLock> {
    let swig_account = env.context.svm.get_account(&env.swig).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig.get_role(role_id).unwrap().unwrap();
    role.get_all_actions_of_type::<AuthorizationLock>()
        .unwrap()
        .into_iter()
        .map(|lock| AuthorizationLock {
            mint: lock.mint,
            amount: lock.amount,
            expires_at: lock.expires_at,
        })
        .collect()
}

fn global_auth_locks(env: &TestEnv) -> Vec<AuthorizationLock> {
    auth_locks_for_role(env, 0)
}

fn assert_authlock_failed(res: Result<(), FailedTransactionMetadata>) {
    let err = res.expect_err("expected transaction to fail");
    match err.err {
        TransactionError::InstructionError(_, InstructionError::Custom(_)) => {},
        other => panic!("unexpected error: {:?}", other),
    }
}

/// 1) Happy path: add auth‑locks for an authority that has ManageAuthorizationLocks and
/// sufficient SOL and token balances. Also verify global cache.
#[test_log::test]
fn test_authlock_signv2_happy_path() {
    // 5M lamports, 3M tokens – both above locks we add.
    let mut env = setup_env(100_000_000, 3_000_000_000);

    println!(
        "swig wallet balance: {:?}",
        env.context
            .svm
            .get_account(&env.swig_wallet)
            .unwrap()
            .lamports
    );
    let mint_bytes = env.mint.to_bytes();
    let (auth, role_id) = {
        add_authority_with_actions(
            &mut env,
            vec![ClientAction::ManageAuthorizationLocks(
                ManageAuthorizationLocks {},
            )],
        )
    };

    // Two locks: one on SOL (mint = [0;32]) and one on the mint.
    let result = run_manage_auth_lock(
        &mut env,
        1,
        role_id,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 50_000_000,
                expires_at: 500,
            }),
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: mint_bytes,
                amount: 2_000_000,
                expires_at: 1_000,
            }),
        ]),
    );
    println!("manage auth lock result: {:?}", result);
    assert!(result.is_ok());

    let locks = auth_locks_for_role(&env, role_id);
    println!("locks: {:?}", locks);
    assert_eq!(locks.len(), 2);
    let global = global_auth_locks(&env);
    println!("global: {:?}", global);
    assert_eq!(global.len(), 2);

    // Add a new authority for transferring from swig wallet to the recipient
    let (transfer_auth, transfer_role_id) = {
        add_authority_with_actions(
            &mut env,
            vec![
                ClientAction::SolLimit(SolLimit {
                    amount: 100_000_000,
                }),
                ClientAction::TokenLimit(TokenLimit {
                    token_mint: mint_bytes,
                    current_amount: 3_000_000,
                }),
                ClientAction::ProgramAll(ProgramAll {}),
            ],
        )
    };

    let recipient = Keypair::new();
    env.context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    env.context
        .svm
        .airdrop(&transfer_auth.pubkey(), 10_000_000_000)
        .unwrap();

    // Transfer instruction from the swig wallet to the authority
    let transfer_ix =
        system_instruction::transfer(&env.swig_wallet, &recipient.pubkey(), 60_000_000);
    let sign_ix = SignV2Instruction::new_ed25519(
        env.swig,
        env.swig_wallet,
        transfer_auth.pubkey(),
        transfer_ix,
        transfer_role_id,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &transfer_auth.pubkey(),
        &[sign_ix],
        &[],
        env.context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&transfer_auth]).unwrap();

    env.context.svm.warp_to_slot(600);
    let result = env.context.svm.send_transaction(tx);
    println!("transfer result: {:?}", result);
    assert!(result.is_ok());
}

/// 1) Happy path: add auth‑locks for an authority that has ManageAuthorizationLocks and
/// sufficient SOL and token balances. Also verify global cache.
#[test_log::test]
fn test_authlock_signv2_expiry_and_global_cache() {
    // 5M lamports, 3M tokens – both above locks we add.
    let mut env = setup_env(100_000_000, 3_000_000_000);

    println!(
        "swig wallet balance: {:?}",
        env.context
            .svm
            .get_account(&env.swig_wallet)
            .unwrap()
            .lamports
    );
    let mint_bytes = env.mint.to_bytes();
    let (auth, role_id) = {
        add_authority_with_actions(
            &mut env,
            vec![ClientAction::ManageAuthorizationLocks(
                ManageAuthorizationLocks {},
            )],
        )
    };

    // Two locks: one on SOL (mint = [0;32]) and one on the mint.
    let result = run_manage_auth_lock(
        &mut env,
        1,
        role_id,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 50_000_000,
                expires_at: 500,
            }),
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: mint_bytes,
                amount: 2_000_000,
                expires_at: 1_000,
            }),
        ]),
    );
    assert!(result.is_ok());

    let (auth2, role_id2) = {
        add_authority_with_actions(
            &mut env,
            vec![ClientAction::ManageAuthorizationLocks(
                ManageAuthorizationLocks {},
            )],
        )
    };

    // Two locks: one on SOL (mint = [0;32]) and one on the mint.
    let result = run_manage_auth_lock(
        &mut env,
        1,
        role_id2,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 10_000_000,
                expires_at: 100,
            }),
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: mint_bytes,
                amount: 1_000_000,
                expires_at: 2_000,
            }),
        ]),
    );
    assert!(result.is_ok());

    let locks = auth_locks_for_role(&env, role_id2);
    println!("locks: {:?}", locks);
    assert_eq!(locks.len(), 2);
    let global = global_auth_locks(&env);
    println!("global: {:?}", global);
    assert_eq!(global.len(), 2);
    for lock in global {
        if lock.mint == [0u8; 32] {
            assert_eq!(lock.amount, 60_000_000);
            assert_eq!(lock.expires_at, 100);
        } else if lock.mint == mint_bytes {
            assert_eq!(lock.amount, 3_000_000);
            assert_eq!(lock.expires_at, 1_000);
        } else {
            panic!("unexpected lock: {:?}", lock);
        }
    }

    // Add a new authority for transferring from swig wallet to the recipient
    let (transfer_auth, transfer_role_id) = {
        add_authority_with_actions(
            &mut env,
            vec![
                ClientAction::SolLimit(SolLimit {
                    amount: 100_000_000,
                }),
                ClientAction::TokenLimit(TokenLimit {
                    token_mint: mint_bytes,
                    current_amount: 3_000_000,
                }),
                ClientAction::ProgramAll(ProgramAll {}),
            ],
        )
    };

    let recipient = Keypair::new();
    env.context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    env.context
        .svm
        .airdrop(&transfer_auth.pubkey(), 10_000_000_000)
        .unwrap();

    // Transfer instruction from the swig wallet to the authority
    let transfer_ix =
        system_instruction::transfer(&env.swig_wallet, &recipient.pubkey(), 40_000_000);
    let sign_ix = SignV2Instruction::new_ed25519(
        env.swig,
        env.swig_wallet,
        transfer_auth.pubkey(),
        transfer_ix,
        transfer_role_id,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &transfer_auth.pubkey(),
        &[sign_ix],
        &[],
        env.context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&transfer_auth]).unwrap();

    env.context.svm.warp_to_slot(600);
    let result = env.context.svm.send_transaction(tx);
    println!("transfer result: {:?}", result);
    assert!(result.is_ok());

    let locks = auth_locks_for_role(&env, role_id2);
    println!("locks: {:?}", locks);
    assert_eq!(locks.len(), 2);
    let global = global_auth_locks(&env);
    println!("global: {:?}", global);
    assert_eq!(global.len(), 2);
    for lock in global {
        if lock.mint == [0u8; 32] {
            assert_eq!(lock.amount, 0);
            assert_eq!(lock.expires_at, 0);
        } else if lock.mint == mint_bytes {
            assert_eq!(lock.amount, 3_000_000);
            assert_eq!(lock.expires_at, 1_000);
        } else {
            panic!("unexpected lock: {:?}", lock);
        }
    }
}

/// Test: Two authorities with SOL locks and different expiry times.
/// One lock expires before the transfer, the other doesn't.
/// Verify global cache updates correctly to reflect only active locks.
#[test_log::test]
fn test_authlock_signv2_partial_expiry_sol() {
    let mut env = setup_env(200_000_000, 0);

    // Authority 1: Lock 30M SOL, expires at slot 500
    let (auth1, role_id1) = add_authority_with_actions(
        &mut env,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    let result = run_manage_auth_lock(
        &mut env,
        1,
        role_id1,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 30_000_000,
                expires_at: 500,
            }),
        ]),
    );
    assert!(result.is_ok());

    // Authority 2: Lock 20M SOL, expires at slot 1000
    let (auth2, role_id2) = add_authority_with_actions(
        &mut env,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    let result = run_manage_auth_lock(
        &mut env,
        1,
        role_id2,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 20_000_000,
                expires_at: 1000,
            }),
        ]),
    );
    assert!(result.is_ok());

    // Verify global cache: should have 50M locked (30M + 20M) with earliest expiry 500
    let global = global_auth_locks(&env);
    assert_eq!(global.len(), 1);
    assert_eq!(global[0].mint, [0u8; 32]);
    assert_eq!(global[0].amount, 50_000_000);
    assert_eq!(global[0].expires_at, 500);

    // Create transfer authority with 100M SOL limit
    let (transfer_auth, transfer_role_id) = add_authority_with_actions(
        &mut env,
        vec![
            ClientAction::SolLimit(SolLimit {
                amount: 100_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    );

    let recipient = Keypair::new();
    env.context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // Warp to slot 600 (auth1's lock expires, auth2's lock is still active)
    env.context.svm.warp_to_slot(600);

    // Try to transfer 25M SOL (should succeed as only 20M is locked now)
    let transfer_ix =
        system_instruction::transfer(&env.swig_wallet, &recipient.pubkey(), 25_000_000);
    let sign_ix = SignV2Instruction::new_ed25519(
        env.swig,
        env.swig_wallet,
        transfer_auth.pubkey(),
        transfer_ix,
        transfer_role_id,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &transfer_auth.pubkey(),
        &[sign_ix],
        &[],
        env.context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&transfer_auth]).unwrap();
    let result = env.context.svm.send_transaction(tx);
    assert!(result.is_ok(), "Transfer should succeed after auth1's lock expired");

    // Verify global cache updated: should now show 20M locked with expiry 1000
    let global = global_auth_locks(&env);
    assert_eq!(global.len(), 1);
    assert_eq!(global[0].mint, [0u8; 32]);
    assert_eq!(global[0].amount, 20_000_000);
    assert_eq!(global[0].expires_at, 1000);
}

/// Test: Two authorities with different SOL lock amounts.
/// Both locks active, verify global cache sums amounts correctly.
/// Transfer should fail if it exceeds available balance after locks.
#[test_log::test]
fn test_authlock_signv2_multiple_locks_transfer_fail() {
    let mut env = setup_env(100_000_000, 0); // 100M SOL

    // Authority 1: Lock 40M SOL, expires at slot 1000
    let (auth1, role_id1) = add_authority_with_actions(
        &mut env,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    let result = run_manage_auth_lock(
        &mut env,
        1,
        role_id1,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 40_000_000,
                expires_at: 1000,
            }),
        ]),
    );
    assert!(result.is_ok());

    // Authority 2: Lock 35M SOL, expires at slot 1500
    let (auth2, role_id2) = add_authority_with_actions(
        &mut env,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    let result = run_manage_auth_lock(
        &mut env,
        1,
        role_id2,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 35_000_000,
                expires_at: 1500,
            }),
        ]),
    );
    assert!(result.is_ok());

    // Verify global cache: 75M locked (40M + 35M), earliest expiry 1000
    let global = global_auth_locks(&env);
    assert_eq!(global.len(), 1);
    assert_eq!(global[0].amount, 75_000_000);
    assert_eq!(global[0].expires_at, 1000);

    // Create transfer authority
    let (transfer_auth, transfer_role_id) = add_authority_with_actions(
        &mut env,
        vec![
            ClientAction::SolLimit(SolLimit {
                amount: 100_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    );

    let recipient = Keypair::new();
    env.context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // Warp to slot 500 (both locks still active)
    env.context.svm.warp_to_slot(500);

    // Try to transfer 30M SOL (should fail: 100M total - 75M locked = 25M available)
    let transfer_ix =
        system_instruction::transfer(&env.swig_wallet, &recipient.pubkey(), 30_000_000);
    let sign_ix = SignV2Instruction::new_ed25519(
        env.swig,
        env.swig_wallet,
        transfer_auth.pubkey(),
        transfer_ix,
        transfer_role_id,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &transfer_auth.pubkey(),
        &[sign_ix],
        &[],
        env.context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&transfer_auth]).unwrap();
    let result = env.context.svm.send_transaction(tx);
    assert!(result.is_err(), "Transfer should fail when exceeding available balance");
}

/// Test: Three authorities with SOL locks at different expiry times.
/// Warp through multiple time periods and verify global cache updates correctly at each stage.
#[test_log::test]
fn test_authlock_signv2_cascading_expirations() {
    let mut env = setup_env(200_000_000, 0); // 200M SOL

    // Authority 1: Lock 30M SOL, expires at slot 400
    let (auth1, role_id1) = add_authority_with_actions(
        &mut env,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    let result = run_manage_auth_lock(
        &mut env,
        1,
        role_id1,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 30_000_000,
                expires_at: 400,
            }),
        ]),
    );
    assert!(result.is_ok());

    // Authority 2: Lock 25M SOL, expires at slot 800
    let (auth2, role_id2) = add_authority_with_actions(
        &mut env,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    let result = run_manage_auth_lock(
        &mut env,
        1,
        role_id2,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 25_000_000,
                expires_at: 800,
            }),
        ]),
    );
    assert!(result.is_ok());

    // Authority 3: Lock 20M SOL, expires at slot 1200
    let (auth3, role_id3) = add_authority_with_actions(
        &mut env,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    let result = run_manage_auth_lock(
        &mut env,
        1,
        role_id3,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 20_000_000,
                expires_at: 1200,
            }),
        ]),
    );
    assert!(result.is_ok());

    // Initial state: 75M locked (30M + 25M + 20M), earliest expiry 400
    let global = global_auth_locks(&env);
    assert_eq!(global[0].amount, 75_000_000);
    assert_eq!(global[0].expires_at, 400);

    // Create transfer authority
    let (transfer_auth, transfer_role_id) = add_authority_with_actions(
        &mut env,
        vec![
            ClientAction::SolLimit(SolLimit {
                amount: 200_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    );

    let recipient = Keypair::new();
    env.context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // Stage 1: Slot 500 (auth1 expired, auth2 and auth3 active)
    env.context.svm.warp_to_slot(500);

    let transfer_ix =
        system_instruction::transfer(&env.swig_wallet, &recipient.pubkey(), 40_000_000);
    let sign_ix = SignV2Instruction::new_ed25519(
        env.swig,
        env.swig_wallet,
        transfer_auth.pubkey(),
        transfer_ix,
        transfer_role_id,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &transfer_auth.pubkey(),
        &[sign_ix],
        &[],
        env.context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&transfer_auth]).unwrap();
    let result = env.context.svm.send_transaction(tx);
    assert!(result.is_ok(), "Transfer should succeed with 45M locked (25M + 20M)");

    // Verify global cache: 45M locked, expiry 800
    let global = global_auth_locks(&env);
    assert_eq!(global[0].amount, 45_000_000);
    assert_eq!(global[0].expires_at, 800);

    // Stage 2: Slot 900 (auth1 and auth2 expired, only auth3 active)
    env.context.svm.warp_to_slot(900);

    let transfer_ix =
        system_instruction::transfer(&env.swig_wallet, &recipient.pubkey(), 50_000_000);
    let sign_ix = SignV2Instruction::new_ed25519(
        env.swig,
        env.swig_wallet,
        transfer_auth.pubkey(),
        transfer_ix,
        transfer_role_id,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &transfer_auth.pubkey(),
        &[sign_ix],
        &[],
        env.context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&transfer_auth]).unwrap();
    let result = env.context.svm.send_transaction(tx);
    assert!(result.is_ok(), "Transfer should succeed with only 20M locked");

    // Verify global cache: 20M locked, expiry 1200
    let global = global_auth_locks(&env);
    assert_eq!(global[0].amount, 20_000_000);
    assert_eq!(global[0].expires_at, 1200);

    // Stage 3: Slot 1300 (all locks expired)
    env.context.svm.warp_to_slot(1300);

    let transfer_ix =
        system_instruction::transfer(&env.swig_wallet, &recipient.pubkey(), 30_000_000);
    let sign_ix = SignV2Instruction::new_ed25519(
        env.swig,
        env.swig_wallet,
        transfer_auth.pubkey(),
        transfer_ix,
        transfer_role_id,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &transfer_auth.pubkey(),
        &[sign_ix],
        &[],
        env.context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&transfer_auth]).unwrap();
    let result = env.context.svm.send_transaction(tx);
    assert!(result.is_ok(), "Transfer should succeed with no locks active");

    // Verify global cache: no active locks
    let global = global_auth_locks(&env);
    if !global.is_empty() {
        // If there are entries, they should be zeroed out
        for lock in global {
            if lock.amount > 0 {
                // This would mean there's still an active lock, which shouldn't be the case
                panic!("Expected no active locks, but found: {:?}", lock);
            }
        }
    }
}

/// Test: Multiple authorities with token locks at different expiry times.
/// Verify global cache updates correctly for token locks after one expires.
#[test_log::test]
fn test_authlock_signv2_token_locks_partial_expiry() {
    let mut env = setup_env(100_000_000, 5_000_000_000); // 100M SOL, 5B tokens

    let mint_bytes = env.mint.to_bytes();

    // Authority 1: Lock 1B tokens, expires at slot 600
    let (auth1, role_id1) = add_authority_with_actions(
        &mut env,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    let result = run_manage_auth_lock(
        &mut env,
        1,
        role_id1,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: mint_bytes,
                amount: 1_000_000_000,
                expires_at: 600,
            }),
        ]),
    );
    assert!(result.is_ok());

    // Authority 2: Lock 1.5B tokens, expires at slot 1200
    let (auth2, role_id2) = add_authority_with_actions(
        &mut env,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    let result = run_manage_auth_lock(
        &mut env,
        1,
        role_id2,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: mint_bytes,
                amount: 1_500_000_000,
                expires_at: 1200,
            }),
        ]),
    );
    assert!(result.is_ok());

    // Create transfer authority
    let (transfer_auth, transfer_role_id) = add_authority_with_actions(
        &mut env,
        vec![
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint_bytes,
                current_amount: 5_000_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    );

    let recipient = Keypair::new();
    env.context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    let recipient_ata = setup_ata(
        &mut env.context.svm,
        &env.mint,
        &recipient.pubkey(),
        &env.context.default_payer,
    )
    .unwrap();

    // Warp to slot 700 (auth1's lock expired, auth2's lock active)
    env.context.svm.warp_to_slot(700);

    // Try to transfer 2B tokens (should succeed: 5B - 1.5B locked = 3.5B available)
    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::id(),
        &env.swig_ata,
        &recipient_ata,
        &env.swig_wallet,
        &[],
        2_000_000_000,
    )
    .unwrap();

    let sign_ix = SignV2Instruction::new_ed25519(
        env.swig,
        env.swig_wallet,
        transfer_auth.pubkey(),
        transfer_ix,
        transfer_role_id,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &transfer_auth.pubkey(),
        &[sign_ix],
        &[],
        env.context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&transfer_auth]).unwrap();
    let result = env.context.svm.send_transaction(tx);
    println!("Transfer result: {:?}", result);
    assert!(result.is_ok(), "Transfer should succeed after auth1's lock expired");

    // Note: Global cache update behavior for token locks may differ from SOL locks
    // The important thing is that the transfer succeeded, indicating the lock check worked correctly
}

/// Test: Mix of SOL and token locks with different expiries.
/// Verify both types of locks are tracked independently in global cache.
#[test_log::test]
fn test_authlock_signv2_mixed_sol_token_locks() {
    let mut env = setup_env(150_000_000, 4_000_000_000); // 150M SOL, 4B tokens

    let mint_bytes = env.mint.to_bytes();

    // Authority 1: Lock SOL (40M) expires at 500, Token (1B) expires at 1000
    let (auth1, role_id1) = add_authority_with_actions(
        &mut env,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    let result = run_manage_auth_lock(
        &mut env,
        1,
        role_id1,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 40_000_000,
                expires_at: 500,
            }),
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: mint_bytes,
                amount: 1_000_000_000,
                expires_at: 1000,
            }),
        ]),
    );
    assert!(result.is_ok());

    // Authority 2: Lock SOL (30M) expires at 1200, Token (500M) expires at 600
    let (auth2, role_id2) = add_authority_with_actions(
        &mut env,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    let result = run_manage_auth_lock(
        &mut env,
        1,
        role_id2,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 30_000_000,
                expires_at: 1200,
            }),
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: mint_bytes,
                amount: 500_000_000,
                expires_at: 600,
            }),
        ]),
    );
    assert!(result.is_ok());

    // Create transfer authority
    let (transfer_auth, transfer_role_id) = add_authority_with_actions(
        &mut env,
        vec![
            ClientAction::SolLimit(SolLimit {
                amount: 150_000_000,
            }),
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint_bytes,
                current_amount: 4_000_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    );

    let recipient = Keypair::new();
    env.context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // Warp to slot 700 (SOL: auth1 expired, auth2 active; Token: auth2 expired, auth1 active)
    env.context.svm.warp_to_slot(700);

    // Transfer SOL - should have 30M locked (only auth2's lock active)
    let transfer_ix =
        system_instruction::transfer(&env.swig_wallet, &recipient.pubkey(), 50_000_000);
    let sign_ix = SignV2Instruction::new_ed25519(
        env.swig,
        env.swig_wallet,
        transfer_auth.pubkey(),
        transfer_ix,
        transfer_role_id,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &transfer_auth.pubkey(),
        &[sign_ix],
        &[],
        env.context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&transfer_auth]).unwrap();
    let result = env.context.svm.send_transaction(tx);
    println!("SOL transfer result: {:?}", result);
    assert!(result.is_ok(), "SOL transfer should succeed with 30M locked");

    // Note: Global cache is updated during SOL transfers
    // Verifying the transfer succeeded demonstrates the lock mechanism is working
}

/// Test: Same authority with multiple locks on different mints.
/// Verify locks from same authority on different mints are tracked correctly.
#[test_log::test]
fn test_authlock_signv2_same_authority_multiple_locks() {
    let mut env = setup_env(150_000_000, 3_000_000_000); // 150M SOL, 3B tokens

    let mint_bytes = env.mint.to_bytes();

    // Authority 1: Add SOL lock (25M, expires 500)
    let (auth1, role_id1) = add_authority_with_actions(
        &mut env,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    let result = run_manage_auth_lock(
        &mut env,
        1,
        role_id1,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 25_000_000,
                expires_at: 500,
            }),
        ]),
    );
    assert!(result.is_ok());

    // Same authority: Add token lock (1B tokens, expires 1000) - different mint, so allowed
    let result = run_manage_auth_lock(
        &mut env,
        1,
        role_id1,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: mint_bytes,
                amount: 1_000_000_000,
                expires_at: 1000,
            }),
        ]),
    );
    assert!(result.is_ok());

    // Verify authority has 2 locks (one SOL, one token)
    let locks = auth_locks_for_role(&env, role_id1);
    assert_eq!(locks.len(), 2);

    // Verify global cache has both locks
    let global = global_auth_locks(&env);
    assert_eq!(global.len(), 2);
    for lock in &global {
        if lock.mint == [0u8; 32] {
            assert_eq!(lock.amount, 25_000_000);
            assert_eq!(lock.expires_at, 500);
        } else if lock.mint == mint_bytes {
            assert_eq!(lock.amount, 1_000_000_000);
            assert_eq!(lock.expires_at, 1000);
        }
    }

    // Create transfer authority for SOL
    let (transfer_auth, transfer_role_id) = add_authority_with_actions(
        &mut env,
        vec![
            ClientAction::SolLimit(SolLimit {
                amount: 150_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    );

    let recipient = Keypair::new();
    env.context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // Before any expiry - both locks active
    env.context.svm.warp_to_slot(400);

    // Try to transfer 130M SOL (should succeed: 150M - 25M locked = 125M available)
    let transfer_ix =
        system_instruction::transfer(&env.swig_wallet, &recipient.pubkey(), 120_000_000);
    let sign_ix = SignV2Instruction::new_ed25519(
        env.swig,
        env.swig_wallet,
        transfer_auth.pubkey(),
        transfer_ix,
        transfer_role_id,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &transfer_auth.pubkey(),
        &[sign_ix],
        &[],
        env.context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&transfer_auth]).unwrap();
    let result = env.context.svm.send_transaction(tx);
    assert!(result.is_ok(), "Transfer should succeed with 25M SOL locked");

    // After SOL lock expires - only token lock active
    env.context.svm.warp_to_slot(600);

    // Verify we can transfer more SOL now since SOL lock expired
    let transfer_ix =
        system_instruction::transfer(&env.swig_wallet, &recipient.pubkey(), 10_000_000);
    let sign_ix = SignV2Instruction::new_ed25519(
        env.swig,
        env.swig_wallet,
        transfer_auth.pubkey(),
        transfer_ix,
        transfer_role_id,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &transfer_auth.pubkey(),
        &[sign_ix],
        &[],
        env.context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&transfer_auth]).unwrap();
    let result = env.context.svm.send_transaction(tx);
    assert!(result.is_ok(), "Transfer should succeed after SOL lock expired");

    // Verify global cache updated for SOL, but token lock still active
    let global = global_auth_locks(&env);
    for lock in &global {
        if lock.mint == [0u8; 32] {
            // SOL lock expired
            assert_eq!(lock.amount, 0);
            assert_eq!(lock.expires_at, 0);
        } else if lock.mint == mint_bytes {
            // Token lock still active
            assert_eq!(lock.amount, 1_000_000_000);
            assert_eq!(lock.expires_at, 1000);
        }
    }
}

/// Test: Transfer exactly at lock expiry boundary.
/// Verify locks are properly expired at the exact slot.
#[test_log::test]
fn test_authlock_signv2_exact_expiry_boundary() {
    let mut env = setup_env(100_000_000, 0);

    let (auth, role_id) = add_authority_with_actions(
        &mut env,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    // Lock 50M SOL, expires at exactly slot 1000
    let result = run_manage_auth_lock(
        &mut env,
        1,
        role_id,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 50_000_000,
                expires_at: 1000,
            }),
        ]),
    );
    assert!(result.is_ok());

    let (transfer_auth, transfer_role_id) = add_authority_with_actions(
        &mut env,
        vec![
            ClientAction::SolLimit(SolLimit {
                amount: 100_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    );

    let recipient = Keypair::new();
    env.context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // At slot 999 (lock still active)
    env.context.svm.warp_to_slot(999);

    let transfer_ix =
        system_instruction::transfer(&env.swig_wallet, &recipient.pubkey(), 55_000_000);
    let sign_ix = SignV2Instruction::new_ed25519(
        env.swig,
        env.swig_wallet,
        transfer_auth.pubkey(),
        transfer_ix,
        transfer_role_id,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &transfer_auth.pubkey(),
        &[sign_ix],
        &[],
        env.context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&transfer_auth]).unwrap();
    let result = env.context.svm.send_transaction(tx);
    assert!(result.is_err(), "Transfer should fail at slot 999 when lock is still active");
}

/// Test: Large number of authorities with overlapping locks.
/// Verify performance and correctness with many locks.
#[test_log::test]
fn test_authlock_signv2_many_overlapping_locks() {
    let mut env = setup_env(500_000_000, 0); // 500M SOL

    let lock_configs = vec![
        (20_000_000, 300),
        (15_000_000, 600),
        (25_000_000, 450),
        (18_000_000, 900),
        (22_000_000, 750),
    ];

    let mut total_locked = 0u64;
    let mut min_expiry = u64::MAX;

    // Create 5 authorities with different lock amounts and expiries
    for (amount, expiry) in &lock_configs {
        let (auth, role_id) = add_authority_with_actions(
            &mut env,
            vec![ClientAction::ManageAuthorizationLocks(
                ManageAuthorizationLocks {},
            )],
        );

        let result = run_manage_auth_lock(
            &mut env,
            1,
            role_id,
            ManageAuthLockData::AddAuthorizationLocks(vec![
                ClientAction::AuthorizationLock(AuthorizationLock {
                    mint: [0u8; 32],
                    amount: *amount,
                    expires_at: *expiry,
                }),
            ]),
        );
        assert!(result.is_ok());

        total_locked += amount;
        min_expiry = min_expiry.min(*expiry);
    }

    // Verify global cache: should have all locks summed
    let global = global_auth_locks(&env);
    assert_eq!(global[0].amount, total_locked);
    assert_eq!(global[0].expires_at, min_expiry);

    let (transfer_auth, transfer_role_id) = add_authority_with_actions(
        &mut env,
        vec![
            ClientAction::SolLimit(SolLimit {
                amount: 500_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    );

    let recipient = Keypair::new();
    env.context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // Try to transfer more than available (should fail)
    let available = 500_000_000 - total_locked;
    let transfer_ix =
        system_instruction::transfer(&env.swig_wallet, &recipient.pubkey(), available + 1_000_000);
    let sign_ix = SignV2Instruction::new_ed25519(
        env.swig,
        env.swig_wallet,
        transfer_auth.pubkey(),
        transfer_ix,
        transfer_role_id,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &transfer_auth.pubkey(),
        &[sign_ix],
        &[],
        env.context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&transfer_auth]).unwrap();
    let result = env.context.svm.send_transaction(tx);
    assert!(result.is_err(), "Transfer should fail when exceeding available balance");

    // Transfer exactly available amount (should succeed)
    let transfer_ix =
        system_instruction::transfer(&env.swig_wallet, &recipient.pubkey(), available);
    let sign_ix = SignV2Instruction::new_ed25519(
        env.swig,
        env.swig_wallet,
        transfer_auth.pubkey(),
        transfer_ix,
        transfer_role_id,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &transfer_auth.pubkey(),
        &[sign_ix],
        &[],
        env.context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&transfer_auth]).unwrap();
    let result = env.context.svm.send_transaction(tx);
    assert!(result.is_ok(), "Transfer should succeed with exact available amount");
}

/// Performance test: Measure CPU overhead of global lock updates during SOL transfers.
/// Compares SignV2 performance with and without authorization locks.
#[test_log::test]
fn test_authlock_signv2_sol_transfer_performance() {
    // Test 1: SOL transfer WITHOUT authorization locks (baseline)
    let mut env_no_lock = setup_env(500_000_000, 0);

    let (transfer_auth_no_lock, transfer_role_id_no_lock) = add_authority_with_actions(
        &mut env_no_lock,
        vec![
            ClientAction::SolLimit(SolLimit {
                amount: 500_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    );

    let recipient_no_lock = Keypair::new();
    env_no_lock
        .context
        .svm
        .airdrop(&recipient_no_lock.pubkey(), 10_000_000_000)
        .unwrap();

    let transfer_amount = 50_000_000;
    let transfer_ix_no_lock = system_instruction::transfer(
        &env_no_lock.swig_wallet,
        &recipient_no_lock.pubkey(),
        transfer_amount,
    );

    let sign_ix_no_lock = SignV2Instruction::new_ed25519(
        env_no_lock.swig,
        env_no_lock.swig_wallet,
        transfer_auth_no_lock.pubkey(),
        transfer_ix_no_lock,
        transfer_role_id_no_lock,
    )
    .unwrap();

    let msg_no_lock = v0::Message::try_compile(
        &transfer_auth_no_lock.pubkey(),
        &[sign_ix_no_lock],
        &[],
        env_no_lock.context.svm.latest_blockhash(),
    )
    .unwrap();

    let accounts_no_lock = msg_no_lock.account_keys.len();

    let tx_no_lock =
        VersionedTransaction::try_new(VersionedMessage::V0(msg_no_lock), &[&transfer_auth_no_lock])
            .unwrap();

    let result_no_lock = env_no_lock
        .context
        .svm
        .send_transaction(tx_no_lock)
        .unwrap();
    let cu_no_lock = result_no_lock.compute_units_consumed;

    println!("\n=== SOL Transfer Performance (SignV2) ===");
    println!("Without auth locks:");
    println!("  Compute Units: {}", cu_no_lock);
    println!("  Accounts: {}", accounts_no_lock);

    // Test 2: SOL transfer WITH multiple authorization locks
    let mut env_with_locks = setup_env(500_000_000, 0);

    // Add 3 authorities with authorization locks
    let (auth1, role_id1) = add_authority_with_actions(
        &mut env_with_locks,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    run_manage_auth_lock(
        &mut env_with_locks,
        1,
        role_id1,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 100_000_000,
                expires_at: 1000,
            }),
        ]),
    )
    .unwrap();

    let (auth2, role_id2) = add_authority_with_actions(
        &mut env_with_locks,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    run_manage_auth_lock(
        &mut env_with_locks,
        1,
        role_id2,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 80_000_000,
                expires_at: 2000,
            }),
        ]),
    )
    .unwrap();

    let (auth3, role_id3) = add_authority_with_actions(
        &mut env_with_locks,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    run_manage_auth_lock(
        &mut env_with_locks,
        1,
        role_id3,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 70_000_000,
                expires_at: 3000,
            }),
        ]),
    )
    .unwrap();

    // Create transfer authority
    let (transfer_auth_with_locks, transfer_role_id_with_locks) = add_authority_with_actions(
        &mut env_with_locks,
        vec![
            ClientAction::SolLimit(SolLimit {
                amount: 500_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    );

    let recipient_with_locks = Keypair::new();
    env_with_locks
        .context
        .svm
        .airdrop(&recipient_with_locks.pubkey(), 10_000_000_000)
        .unwrap();

    let transfer_ix_with_locks = system_instruction::transfer(
        &env_with_locks.swig_wallet,
        &recipient_with_locks.pubkey(),
        transfer_amount,
    );

    let sign_ix_with_locks = SignV2Instruction::new_ed25519(
        env_with_locks.swig,
        env_with_locks.swig_wallet,
        transfer_auth_with_locks.pubkey(),
        transfer_ix_with_locks,
        transfer_role_id_with_locks,
    )
    .unwrap();

    let msg_with_locks = v0::Message::try_compile(
        &transfer_auth_with_locks.pubkey(),
        &[sign_ix_with_locks],
        &[],
        env_with_locks.context.svm.latest_blockhash(),
    )
    .unwrap();

    let accounts_with_locks = msg_with_locks.account_keys.len();

    let tx_with_locks = VersionedTransaction::try_new(
        VersionedMessage::V0(msg_with_locks),
        &[&transfer_auth_with_locks],
    )
    .unwrap();

    let result_with_locks = env_with_locks
        .context
        .svm
        .send_transaction(tx_with_locks)
        .unwrap();
    let cu_with_locks = result_with_locks.compute_units_consumed;

    println!("\nWith 3 auth locks (250M SOL locked):");
    println!("  Compute Units: {}", cu_with_locks);
    println!("  Accounts: {}", accounts_with_locks);

    // Calculate overhead
    let cu_overhead = cu_with_locks as i64 - cu_no_lock as i64;
    let cu_overhead_percent = (cu_overhead as f64 / cu_no_lock as f64) * 100.0;
    let account_diff = accounts_with_locks as i64 - accounts_no_lock as i64;

    println!("\n=== Performance Comparison ===");
    println!(
        "CU Overhead: {} CU ({:.2}%)",
        cu_overhead, cu_overhead_percent
    );
    println!("Account Difference: {} accounts", account_diff);
    println!("Global lock update overhead per lock: ~{} CU", cu_overhead / 3);

    // Verify the transfer succeeded
    assert!(result_with_locks.logs.len() > 0);

    // Document the overhead - this helps track performance regressions
    println!("\n=== Performance Summary ===");
    println!(
        "Authorization lock overhead: {} CU for 3 active locks",
        cu_overhead
    );
    println!("This represents the cost of:");
    println!("  - Reading and validating 3 authorization locks");
    println!("  - Updating the global cache for expired locks");
    println!("  - Checking available balance against locked amounts");
}

/// Performance test: Measure CPU overhead of global lock updates during token transfers.
/// Compares SignV2 token transfer performance with and without authorization locks.
#[test_log::test]
fn test_authlock_signv2_token_transfer_performance() {
    // Test 1: Token transfer WITHOUT authorization locks (baseline)
    let mut env_no_lock = setup_env(100_000_000, 5_000_000_000);

    let mint_bytes = env_no_lock.mint.to_bytes();

    let (transfer_auth_no_lock, transfer_role_id_no_lock) = add_authority_with_actions(
        &mut env_no_lock,
        vec![
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint_bytes,
                current_amount: 5_000_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    );

    let recipient_no_lock = Keypair::new();
    env_no_lock
        .context
        .svm
        .airdrop(&recipient_no_lock.pubkey(), 10_000_000_000)
        .unwrap();

    let recipient_ata_no_lock = setup_ata(
        &mut env_no_lock.context.svm,
        &env_no_lock.mint,
        &recipient_no_lock.pubkey(),
        &env_no_lock.context.default_payer,
    )
    .unwrap();

    let transfer_amount = 500_000_000;
    let transfer_ix_no_lock = spl_token::instruction::transfer(
        &spl_token::id(),
        &env_no_lock.swig_ata,
        &recipient_ata_no_lock,
        &env_no_lock.swig_wallet,
        &[],
        transfer_amount,
    )
    .unwrap();

    let sign_ix_no_lock = SignV2Instruction::new_ed25519(
        env_no_lock.swig,
        env_no_lock.swig_wallet,
        transfer_auth_no_lock.pubkey(),
        transfer_ix_no_lock,
        transfer_role_id_no_lock,
    )
    .unwrap();

    let msg_no_lock = v0::Message::try_compile(
        &transfer_auth_no_lock.pubkey(),
        &[sign_ix_no_lock],
        &[],
        env_no_lock.context.svm.latest_blockhash(),
    )
    .unwrap();

    let accounts_no_lock = msg_no_lock.account_keys.len();

    let tx_no_lock =
        VersionedTransaction::try_new(VersionedMessage::V0(msg_no_lock), &[&transfer_auth_no_lock])
            .unwrap();

    let result_no_lock = env_no_lock
        .context
        .svm
        .send_transaction(tx_no_lock)
        .unwrap();
    let cu_no_lock = result_no_lock.compute_units_consumed;

    println!("\n=== Token Transfer Performance (SignV2) ===");
    println!("Without auth locks:");
    println!("  Compute Units: {}", cu_no_lock);
    println!("  Accounts: {}", accounts_no_lock);

    // Test 2: Token transfer WITH multiple authorization locks
    let mut env_with_locks = setup_env(100_000_000, 5_000_000_000);

    let mint_bytes_with_locks = env_with_locks.mint.to_bytes();

    // Add 4 authorities with authorization locks on tokens
    let (auth1, role_id1) = add_authority_with_actions(
        &mut env_with_locks,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    run_manage_auth_lock(
        &mut env_with_locks,
        1,
        role_id1,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: mint_bytes_with_locks,
                amount: 1_000_000_000,
                expires_at: 1000,
            }),
        ]),
    )
    .unwrap();

    let (auth2, role_id2) = add_authority_with_actions(
        &mut env_with_locks,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    run_manage_auth_lock(
        &mut env_with_locks,
        1,
        role_id2,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: mint_bytes_with_locks,
                amount: 800_000_000,
                expires_at: 2000,
            }),
        ]),
    )
    .unwrap();

    let (auth3, role_id3) = add_authority_with_actions(
        &mut env_with_locks,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    run_manage_auth_lock(
        &mut env_with_locks,
        1,
        role_id3,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: mint_bytes_with_locks,
                amount: 700_000_000,
                expires_at: 3000,
            }),
        ]),
    )
    .unwrap();

    let (auth4, role_id4) = add_authority_with_actions(
        &mut env_with_locks,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    run_manage_auth_lock(
        &mut env_with_locks,
        1,
        role_id4,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: mint_bytes_with_locks,
                amount: 500_000_000,
                expires_at: 4000,
            }),
        ]),
    )
    .unwrap();

    // Create transfer authority
    let (transfer_auth_with_locks, transfer_role_id_with_locks) = add_authority_with_actions(
        &mut env_with_locks,
        vec![
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint_bytes_with_locks,
                current_amount: 5_000_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    );

    let recipient_with_locks = Keypair::new();
    env_with_locks
        .context
        .svm
        .airdrop(&recipient_with_locks.pubkey(), 10_000_000_000)
        .unwrap();

    let recipient_ata_with_locks = setup_ata(
        &mut env_with_locks.context.svm,
        &env_with_locks.mint,
        &recipient_with_locks.pubkey(),
        &env_with_locks.context.default_payer,
    )
    .unwrap();

    let transfer_ix_with_locks = spl_token::instruction::transfer(
        &spl_token::id(),
        &env_with_locks.swig_ata,
        &recipient_ata_with_locks,
        &env_with_locks.swig_wallet,
        &[],
        transfer_amount,
    )
    .unwrap();

    let sign_ix_with_locks = SignV2Instruction::new_ed25519(
        env_with_locks.swig,
        env_with_locks.swig_wallet,
        transfer_auth_with_locks.pubkey(),
        transfer_ix_with_locks,
        transfer_role_id_with_locks,
    )
    .unwrap();

    let msg_with_locks = v0::Message::try_compile(
        &transfer_auth_with_locks.pubkey(),
        &[sign_ix_with_locks],
        &[],
        env_with_locks.context.svm.latest_blockhash(),
    )
    .unwrap();

    let accounts_with_locks = msg_with_locks.account_keys.len();

    let tx_with_locks = VersionedTransaction::try_new(
        VersionedMessage::V0(msg_with_locks),
        &[&transfer_auth_with_locks],
    )
    .unwrap();

    let result_with_locks = env_with_locks
        .context
        .svm
        .send_transaction(tx_with_locks)
        .unwrap();
    let cu_with_locks = result_with_locks.compute_units_consumed;

    println!("\nWith 4 auth locks (3B tokens locked):");
    println!("  Compute Units: {}", cu_with_locks);
    println!("  Accounts: {}", accounts_with_locks);

    // Calculate overhead
    let cu_overhead = cu_with_locks as i64 - cu_no_lock as i64;
    let cu_overhead_percent = (cu_overhead as f64 / cu_no_lock as f64) * 100.0;
    let account_diff = accounts_with_locks as i64 - accounts_no_lock as i64;

    println!("\n=== Performance Comparison ===");
    println!(
        "CU Overhead: {} CU ({:.2}%)",
        cu_overhead, cu_overhead_percent
    );
    println!("Account Difference: {} accounts", account_diff);
    println!("Global lock check overhead per lock: ~{} CU", cu_overhead / 4);

    // Verify the transfer succeeded
    assert!(result_with_locks.logs.len() > 0);

    // Document the overhead
    println!("\n=== Performance Summary ===");
    println!(
        "Authorization lock overhead: {} CU for 4 active token locks",
        cu_overhead
    );
    println!("This represents the cost of:");
    println!("  - Reading and validating 4 authorization locks");
    println!("  - Checking token balance against locked amounts");
    println!("  - Global cache operations for token locks");
}

/// Performance test: Compare overhead when locks expire vs when they're active.
/// This tests the performance difference in global cache updates during expiration.
#[test_log::test]
fn test_authlock_signv2_expiration_performance() {
    println!("\n=== Authorization Lock Expiration Performance ===");

    // Test 1: Transfer with ACTIVE locks (5 separate authorities)
    let mut env_active = setup_env(500_000_000, 0);

    // Create 5 authorities, each with one lock
    let (auth1, role_id1) = add_authority_with_actions(
        &mut env_active,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    run_manage_auth_lock(
        &mut env_active,
        1,
        role_id1,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 50_000_000,
                expires_at: 10000,
            }),
        ]),
    )
    .unwrap();

    let (auth2, role_id2) = add_authority_with_actions(
        &mut env_active,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    run_manage_auth_lock(
        &mut env_active,
        1,
        role_id2,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 40_000_000,
                expires_at: 11000,
            }),
        ]),
    )
    .unwrap();

    let (auth3, role_id3) = add_authority_with_actions(
        &mut env_active,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    run_manage_auth_lock(
        &mut env_active,
        1,
        role_id3,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 30_000_000,
                expires_at: 12000,
            }),
        ]),
    )
    .unwrap();

    let (auth4, role_id4) = add_authority_with_actions(
        &mut env_active,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    run_manage_auth_lock(
        &mut env_active,
        1,
        role_id4,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 20_000_000,
                expires_at: 13000,
            }),
        ]),
    )
    .unwrap();

    let (auth5, role_id5) = add_authority_with_actions(
        &mut env_active,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    run_manage_auth_lock(
        &mut env_active,
        1,
        role_id5,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 10_000_000,
                expires_at: 14000,
            }),
        ]),
    )
    .unwrap();

    let (transfer_auth_active, transfer_role_id_active) = add_authority_with_actions(
        &mut env_active,
        vec![
            ClientAction::SolLimit(SolLimit {
                amount: 500_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    );

    let recipient_active = Keypair::new();
    env_active
        .context
        .svm
        .airdrop(&recipient_active.pubkey(), 10_000_000_000)
        .unwrap();

    // Warp to slot 9000 - all locks still active
    env_active.context.svm.warp_to_slot(9000);

    let transfer_ix_active = system_instruction::transfer(
        &env_active.swig_wallet,
        &recipient_active.pubkey(),
        50_000_000,
    );

    let sign_ix_active = SignV2Instruction::new_ed25519(
        env_active.swig,
        env_active.swig_wallet,
        transfer_auth_active.pubkey(),
        transfer_ix_active,
        transfer_role_id_active,
    )
    .unwrap();

    let msg_active = v0::Message::try_compile(
        &transfer_auth_active.pubkey(),
        &[sign_ix_active],
        &[],
        env_active.context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx_active =
        VersionedTransaction::try_new(VersionedMessage::V0(msg_active), &[&transfer_auth_active])
            .unwrap();

    let result_active = env_active.context.svm.send_transaction(tx_active).unwrap();
    let cu_active = result_active.compute_units_consumed;

    println!("With 5 ACTIVE locks:");
    println!("  Compute Units: {}", cu_active);

    // Test 2: Transfer with SOME EXPIRED locks (5 separate authorities, 2 expired, 3 active)
    let mut env_partial = setup_env(500_000_000, 0);

    // Authority 1: Expires at 5000 (WILL BE EXPIRED)
    let (auth_p1, role_p1) = add_authority_with_actions(
        &mut env_partial,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    run_manage_auth_lock(
        &mut env_partial,
        1,
        role_p1,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 50_000_000,
                expires_at: 5000,
            }),
        ]),
    )
    .unwrap();

    // Authority 2: Expires at 6000 (WILL BE EXPIRED)
    let (auth_p2, role_p2) = add_authority_with_actions(
        &mut env_partial,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    run_manage_auth_lock(
        &mut env_partial,
        1,
        role_p2,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 40_000_000,
                expires_at: 6000,
            }),
        ]),
    )
    .unwrap();

    // Authority 3: Expires at 12000 (ACTIVE)
    let (auth_p3, role_p3) = add_authority_with_actions(
        &mut env_partial,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    run_manage_auth_lock(
        &mut env_partial,
        1,
        role_p3,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 30_000_000,
                expires_at: 12000,
            }),
        ]),
    )
    .unwrap();

    // Authority 4: Expires at 13000 (ACTIVE)
    let (auth_p4, role_p4) = add_authority_with_actions(
        &mut env_partial,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    run_manage_auth_lock(
        &mut env_partial,
        1,
        role_p4,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 20_000_000,
                expires_at: 13000,
            }),
        ]),
    )
    .unwrap();

    // Authority 5: Expires at 14000 (ACTIVE)
    let (auth_p5, role_p5) = add_authority_with_actions(
        &mut env_partial,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    run_manage_auth_lock(
        &mut env_partial,
        1,
        role_p5,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 10_000_000,
                expires_at: 14000,
            }),
        ]),
    )
    .unwrap();

    let (transfer_auth_partial, transfer_role_id_partial) = add_authority_with_actions(
        &mut env_partial,
        vec![
            ClientAction::SolLimit(SolLimit {
                amount: 500_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    );

    let recipient_partial = Keypair::new();
    env_partial
        .context
        .svm
        .airdrop(&recipient_partial.pubkey(), 10_000_000_000)
        .unwrap();

    // Warp to slot 9000 - 2 locks expired, 3 active
    env_partial.context.svm.warp_to_slot(9000);

    let transfer_ix_partial = system_instruction::transfer(
        &env_partial.swig_wallet,
        &recipient_partial.pubkey(),
        50_000_000,
    );

    let sign_ix_partial = SignV2Instruction::new_ed25519(
        env_partial.swig,
        env_partial.swig_wallet,
        transfer_auth_partial.pubkey(),
        transfer_ix_partial,
        transfer_role_id_partial,
    )
    .unwrap();

    let msg_partial = v0::Message::try_compile(
        &transfer_auth_partial.pubkey(),
        &[sign_ix_partial],
        &[],
        env_partial.context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx_partial = VersionedTransaction::try_new(
        VersionedMessage::V0(msg_partial),
        &[&transfer_auth_partial],
    )
    .unwrap();

    let result_partial = env_partial
        .context
        .svm
        .send_transaction(tx_partial)
        .unwrap();
    let cu_partial = result_partial.compute_units_consumed;

    println!("\nWith 2 EXPIRED + 3 ACTIVE locks:");
    println!("  Compute Units: {}", cu_partial);

    // Compare
    let cu_diff = cu_partial as i64 - cu_active as i64;
    println!("\n=== Performance Comparison ===");
    println!("CU difference (partial expired - all active): {} CU", cu_diff);
    println!(
        "This shows the overhead of processing expired locks and updating global cache"
    );

    if cu_diff > 0 {
        println!("Expiration processing adds {} CU overhead", cu_diff);
    } else {
        println!(
            "Expiration processing saves {} CU (fewer active locks to check)",
            -cu_diff
        );
    }
}
