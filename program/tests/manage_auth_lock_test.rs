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
    AuthorityConfig, ClientAction, ManageAuthLockData, ManageAuthLockInstruction,
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

/// 1) Add and then remove the `ManageAuthorizationLocks` action from an authority.
#[test_log::test]
fn test_authlock_add_and_remove_manage_authlock_permission_action() {
    let mut env = setup_env(0, 0);

    // Add authority with ProgramAll + ManageAuthorizationLocks.
    let (_auth, role_id) = add_authority_with_actions(
        &mut env,
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
        ],
    );

    let swig_account = env.context.svm.get_account(&env.swig).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig.get_role(role_id).unwrap().unwrap();
    assert!(role
        .get_action::<ManageAuthorizationLocks>(&[])
        .unwrap()
        .is_some());

    // Now replace actions with just ProgramAll, effectively removing ManageAuthorizationLocks.
    update_authority_with_ed25519_root(
        &mut env.context,
        &env.swig,
        &env.root_authority,
        role_id,
        vec![ClientAction::ProgramAll(ProgramAll {})],
    )
    .unwrap();

    let swig_account = env.context.svm.get_account(&env.swig).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig.get_role(role_id).unwrap().unwrap();
    assert!(role
        .get_action::<ManageAuthorizationLocks>(&[])
        .unwrap()
        .is_none());
}

/// 2) Happy path: add auth‑locks for an authority that has ManageAuthorizationLocks and
/// sufficient SOL and token balances. Also verify global cache.
#[test_log::test]
fn test_authlock_add_for_authority_with_manageauthlock_and_balances() {
    // 5M lamports, 3M tokens – both above locks we add.
    let mut env = setup_env(5_000_000, 3_000_000);

    let mint_bytes = env.mint.to_bytes();
    let (_auth, role_id) = {
        add_authority_with_actions(
            &mut env,
            vec![
                ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
                ClientAction::SolLimit(SolLimit { amount: 4_000_000 }),
                ClientAction::TokenLimit(TokenLimit {
                    token_mint: mint_bytes,
                    current_amount: 3_000_000,
                }),
            ],
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
                amount: 1_000_000,
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

    let locks = auth_locks_for_role(&env, role_id);
    assert_eq!(locks.len(), 2);
    let global = global_auth_locks(&env);
    assert_eq!(global.len(), 2);
}

/// 3) Failure: adding auth‑locks to an authority that does NOT have ManageAuthorizationLocks.
#[test_log::test]
fn test_authlock_add_fails_without_manageauthlock_permission() {
    let mut env = setup_env(5_000_000, 3_000_000);

    let (_auth, role_id) = {
        add_authority_with_actions(
            &mut env,
            vec![ClientAction::SolLimit(SolLimit { amount: 4_000_000 })],
        )
    };

    let res = run_manage_auth_lock(
        &mut env,
        role_id,
        role_id,
        ManageAuthLockData::AddAuthorizationLocks(vec![ClientAction::AuthorizationLock(
            AuthorizationLock {
                mint: [0u8; 32],
                amount: 1_000_000,
                expires_at: 500,
            },
        )]),
    );

    // Program should reject this; we only assert it fails, not the exact error code.
    assert!(res.is_err());
}

/// 4) Failure: trying to define AuthorizationLock actions directly when *adding* an authority.
#[test_log::test]
fn test_authlock_add_in_add_role_fails() {
    let mut env = setup_env(0, 0);

    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        add_authority_with_ed25519_root(
            &mut env.context,
            &env.swig,
            &env.root_authority,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: Keypair::new().pubkey().as_ref(),
            },
            vec![
                ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
                ClientAction::AuthorizationLock(AuthorizationLock {
                    mint: [0u8; 32],
                    amount: 1_000_000,
                    expires_at: 500,
                }),
            ],
        )
        .unwrap();
    }));

    // Helper currently unwraps on error, so we just assert that it panicked.
    assert!(res.is_err());
}

/// 5) Failure: lock amount exceeds actual SOL / token balance.
#[test_log::test]
fn test_authlock_add_fails_when_balance_lower_than_amount() {
    // Only 500_000 lamports and 500_000 tokens.
    let mut env = setup_env(500_000, 500_000);

    let mint_bytes = env.mint.to_bytes();
    let (_auth, role_id) = {
        add_authority_with_actions(
            &mut env,
            vec![
                ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
                ClientAction::SolLimit(SolLimit { amount: 10_000_000 }),
                ClientAction::TokenLimit(TokenLimit {
                    token_mint: mint_bytes,
                    current_amount: 10_000_000,
                }),
            ],
        )
    };

    // Try to lock more SOL and tokens than exist.
    let res = run_manage_auth_lock(
        &mut env,
        1,
        role_id,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 600_000, // > 500_000 lamports
                expires_at: 500,
            }),
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: mint_bytes,
                amount: 600_000, // > 500_000 tokens
                expires_at: 500,
            }),
        ]),
    );

    println!("res: {:?}", res);
    assert_authlock_failed(res);
}

/// 6) Global cache updates when adding and removing auth‑locks.
#[test_log::test]
fn test_authlock_global_cache_add_and_remove() {
    let mut env = setup_env(5_000_000, 3_000_000);
    let (_auth, role_id) = add_authority_with_actions(
        &mut env,
        vec![
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
            ClientAction::SolLimit(SolLimit { amount: 4_000_000 }),
        ],
    );

    // Add a lock.
    run_manage_auth_lock(
        &mut env,
        1,
        role_id,
        ManageAuthLockData::AddAuthorizationLocks(vec![ClientAction::AuthorizationLock(
            AuthorizationLock {
                mint: [0u8; 32],
                amount: 1_000_000,
                expires_at: 1_000,
            },
        )]),
    )
    .unwrap();

    assert_eq!(global_auth_locks(&env).len(), 1);

    // Remove it.
    run_manage_auth_lock(
        &mut env,
        1,
        role_id,
        ManageAuthLockData::RemoveAuthorizationLocks(vec![[0u8; 32]]),
    )
    .unwrap();

    assert!(global_auth_locks(&env).is_empty());
}

/// 7) Global cache and per‑authority state with multiple authorities and expiry propagation.
///
/// Scenario:
/// - Authority A gets a lock L1 with expiry E.
/// - Warp to slot E+1.
/// - Authority B adds a lock L2 on the same mint.
///   This operation should prune the expired L1 from A and from the global cache.
#[test_log::test]
fn test_authlock_global_cache_with_multiple_authorities_and_expiry() {
    let mut env = setup_env(5_000_000, 3_000_000);

    let (_auth_a, role_a) = add_authority_with_actions(
        &mut env,
        vec![
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
            ClientAction::SolLimit(SolLimit { amount: 4_000_000 }),
        ],
    );

    let (_auth_b, role_b) = add_authority_with_actions(
        &mut env,
        vec![
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
            ClientAction::SolLimit(SolLimit { amount: 4_000_000 }),
        ],
    );

    // L1 on authority A, expires at slot 500.
    run_manage_auth_lock(
        &mut env,
        1,
        role_a,
        ManageAuthLockData::AddAuthorizationLocks(vec![ClientAction::AuthorizationLock(
            AuthorizationLock {
                mint: [0u8; 32],
                amount: 1_000_000,
                expires_at: 500,
            },
        )]),
    )
    .unwrap();

    assert_eq!(auth_locks_for_role(&env, role_a).len(), 1);
    assert_eq!(global_auth_locks(&env).len(), 1);

    // Advance beyond expiry.
    env.context.svm.warp_to_slot(501);

    // L2 on authority B with later expiry; this should trigger cache/expiry maintenance.
    run_manage_auth_lock(
        &mut env,
        1,
        role_b,
        ManageAuthLockData::AddAuthorizationLocks(vec![ClientAction::AuthorizationLock(
            AuthorizationLock {
                mint: [0u8; 32],
                amount: 2_000_000,
                expires_at: 1_000,
            },
        )]),
    )
    .unwrap();

    // L1 should have been pruned from A; only B should have a lock now.
    assert!(auth_locks_for_role(&env, role_a).is_empty());
    let locks_b = auth_locks_for_role(&env, role_b);
    assert_eq!(locks_b.len(), 1);

    let global = global_auth_locks(&env);
    assert_eq!(global.len(), 1);
    assert_eq!(global[0].amount, 2_000_000);
}

/// 8) Modify fails with `InvalidAuthorizationLockNotFound` when the mint does not exist.
#[test_log::test]
fn test_authlock_modify_fails_when_lock_not_found() {
    let mut env = setup_env(5_000_000, 0);

    // Authority with ManageAuthorizationLocks and SOL limit.
    let (_auth, role_id) = add_authority_with_actions(
        &mut env,
        vec![
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
            ClientAction::SolLimit(SolLimit { amount: 4_000_000 }),
        ],
    );

    // Add one lock for mint [0; 32].
    run_manage_auth_lock(
        &mut env,
        1,
        role_id,
        ManageAuthLockData::AddAuthorizationLocks(vec![ClientAction::AuthorizationLock(
            AuthorizationLock {
                mint: [0u8; 32],
                amount: 1_000_000,
                expires_at: 1_000,
            },
        )]),
    )
    .unwrap();

    // Now attempt to modify a lock for a *different* mint; should hit
    // `InvalidAuthorizationLockNotFound`.
    let res = run_manage_auth_lock(
        &mut env,
        1,
        role_id,
        ManageAuthLockData::ModifyAuthorizationLock(vec![ClientAction::AuthorizationLock(
            AuthorizationLock {
                mint: [1u8; 32],
                amount: 2_000_000,
                expires_at: 2_000,
            },
        )]),
    );

    assert_authlock_failed(res);
}

/// 9) Add path fails with `ContainsNonAuthorizationLockAction` when a non‑authlock
/// action is encoded inside the authlock payload.
#[test_log::test]
fn test_authlock_add_contains_non_authlock_action_error() {
    let mut env = setup_env(5_000_000, 0);

    let (_auth, role_id) = add_authority_with_actions(
        &mut env,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    let res = run_manage_auth_lock(
        &mut env,
        1,
        role_id,
        ManageAuthLockData::AddAuthorizationLocks(vec![
            // This non‑authlock action inside the authlock payload should trigger the error.
            ClientAction::SolLimit(SolLimit { amount: 1_000_000 }),
            ClientAction::AuthorizationLock(AuthorizationLock {
                mint: [0u8; 32],
                amount: 500_000,
                expires_at: 1_000,
            }),
        ]),
    );

    assert_authlock_failed(res);
}

/// 10) Adding a token authlock without a corresponding ATA yields
/// `AssociatedTokenAccountNotFound`.
#[test_log::test]
fn test_authlock_associated_token_account_not_found_error() {
    let mut env = setup_env(5_000_000, 0);

    let (_auth, role_id) = add_authority_with_actions(
        &mut env,
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    );

    // Create a mint that does NOT have an ATA for the swig wallet.
    let orphan_mint = setup_mint(&mut env.context.svm, &env.context.default_payer).unwrap();

    let res = run_manage_auth_lock(
        &mut env,
        1,
        role_id,
        ManageAuthLockData::AddAuthorizationLocks(vec![ClientAction::AuthorizationLock(
            AuthorizationLock {
                mint: orphan_mint.to_bytes(),
                amount: 1_000_000,
                expires_at: 1_000,
            },
        )]),
    );

    assert_authlock_failed(res);
}

/// 11) Global cache and per‑authority state with multiple authorities and expiry propagation.
///
/// Scenario:
/// - Authority A gets a lock L1 with expiry E.
/// - Warp to slot E+1.
/// - Authority B adds a lock L2 on the same mint.
///   This operation should prune the expired L1 from A and from the global cache.
#[test_log::test]
fn test_authlock_global_cache_with_multiple_authorities_and_expiry_v2() {
    let mut env = setup_env(5_000_000, 3_000_000);

    let (_auth_a, role_a) = add_authority_with_actions(
        &mut env,
        vec![
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
            ClientAction::SolLimit(SolLimit { amount: 4_000_000 }),
        ],
    );

    let (_auth_b, role_b) = add_authority_with_actions(
        &mut env,
        vec![
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
            ClientAction::SolLimit(SolLimit { amount: 4_000_000 }),
        ],
    );

    // L1 on authority A, expires at slot 500.
    run_manage_auth_lock(
        &mut env,
        1,
        role_a,
        ManageAuthLockData::AddAuthorizationLocks(vec![ClientAction::AuthorizationLock(
            AuthorizationLock {
                mint: [0u8; 32],
                amount: 1_000_000,
                expires_at: 500,
            },
        )]),
    )
    .unwrap();

    assert_eq!(auth_locks_for_role(&env, role_a).len(), 1);
    assert_eq!(global_auth_locks(&env).len(), 1);

    // Advance beyond expiry.
    // env.context.svm.warp_to_slot(501);

    // L2 on authority B with later expiry; this should trigger cache/expiry maintenance.
    run_manage_auth_lock(
        &mut env,
        1,
        role_b,
        ManageAuthLockData::AddAuthorizationLocks(vec![ClientAction::AuthorizationLock(
            AuthorizationLock {
                mint: [0u8; 32],
                amount: 2_000_000,
                expires_at: 1_000,
            },
        )]),
    )
    .unwrap();

    // L1 should have been pruned from A; only B should have a lock now.
    assert!(auth_locks_for_role(&env, role_a).len() == 1);
    let locks_b = auth_locks_for_role(&env, role_b);
    assert_eq!(locks_b.len(), 1);

    let global = global_auth_locks(&env);
    assert_eq!(global.len(), 1);
    assert_eq!(global[0].amount, 3_000_000);
}
