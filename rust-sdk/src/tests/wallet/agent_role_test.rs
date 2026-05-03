use solana_sdk::signature::{Keypair, Signer};
use swig_state::authority::AuthorityType;

use super::*;
use crate::{
    agent_role::{AgentProgramPermission, AgentRoleConfig},
    types::Permission,
};

/// Validates that AgentRoleConfig can be used end-to-end with SwigWallet:
/// build the config, add a ProgramExec authority, and verify the role
/// was persisted with the expected permissions.
#[test_log::test]
fn should_create_agent_role_with_program_all_and_sol_limit() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Verify initial state: only one role (the creator)
    let initial_role_count = swig_wallet.get_role_count().unwrap();
    assert_eq!(initial_role_count, 1, "wallet should start with 1 role");

    // Build an agent role config with ProgramAll + SolLimit
    let oracle_program_id = [1u8; 32]; // placeholder oracle program id
    let oracle_discriminator = vec![0x76, 0x61, 0x6c, 0x74, 0x72, 0x61, 0x64, 0x65]; // "valtrade"

    let config = AgentRoleConfig {
        oracle_program_id,
        oracle_discriminator: oracle_discriminator.clone(),
        sol_limit: Some(1_000_000_000), // 1 SOL
        sol_recurring_limit: None,
        token_limits: vec![],
        program_permission: AgentProgramPermission::Any,
        session_max_length: None,
    };

    // Build produces (AuthorityType, authority_data, Vec<ClientAction>)
    let (auth_type, auth_data, actions) = config.build();
    assert_eq!(auth_type, AuthorityType::ProgramExec);
    assert!(!auth_data.is_empty());
    assert_eq!(actions.len(), 2, "should have ProgramAll + SolLimit actions");

    // Add the ProgramExec authority to the wallet.
    // The wallet's add_authority takes Permission enums, so we pass the
    // equivalent Permission variants that match what AgentRoleConfig produced.
    swig_wallet
        .add_authority(
            auth_type,
            &auth_data,
            vec![
                Permission::ProgramAll,
                Permission::Sol {
                    amount: 1_000_000_000,
                    recurring: None,
                },
            ],
        )
        .unwrap();

    // Verify role count increased
    let updated_role_count = swig_wallet.get_role_count().unwrap();
    assert_eq!(
        updated_role_count, 2,
        "wallet should now have 2 roles after adding agent"
    );

    // Look up the new role by its identity (the oracle discriminator bytes)
    let role_id = swig_wallet
        .get_role_id(&oracle_discriminator)
        .unwrap();

    // Verify permissions on the agent role
    let role_permissions = swig_wallet.get_role_permissions(role_id).unwrap();

    let has_program_all = role_permissions
        .iter()
        .any(|p| matches!(p, Permission::ProgramAll));
    assert!(has_program_all, "agent role should have ProgramAll permission");

    let has_sol_limit = role_permissions.iter().any(|p| {
        matches!(
            p,
            Permission::Sol {
                amount: 1_000_000_000,
                recurring: None,
            }
        )
    });
    assert!(has_sol_limit, "agent role should have Sol limit of 1 SOL");
}
