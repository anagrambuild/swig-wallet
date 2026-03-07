//! Helper for configuring AI agent roles with confinement permissions.
//!
//! This module provides a high-level builder ([`AgentRoleConfig`]) that makes it easy
//! to create a confined AI agent role -- one that uses ProgramExec authority (bound to
//! a slippage oracle) and has spending limits.

use swig_interface::ClientAction;
use swig_state::{
    action::{
        program::Program,
        program_all::ProgramAll,
        program_curated::ProgramCurated,
        sol_limit::SolLimit,
        sol_recurring_limit::SolRecurringLimit,
        token_limit::TokenLimit,
        token_recurring_limit::TokenRecurringLimit,
    },
    authority::{programexec::ProgramExecAuthority, AuthorityType},
};

/// What programs the agent is allowed to CPI into.
pub enum AgentProgramPermission {
    /// Any program (ProgramAll)
    Any,
    /// Only curated programs (ProgramCurated)
    Curated,
    /// Specific programs only
    Specific(Vec<[u8; 32]>),
}

/// Token limit configuration for an agent role.
pub struct AgentTokenLimit {
    pub mint: [u8; 32],
    pub amount: u64,
    /// If set, makes this a recurring limit with the given window in slots.
    pub recurring_window: Option<u64>,
}

/// Configuration for creating a confined AI agent role.
///
/// Use [`AgentRoleConfig::build`] to produce the authority type, serialized authority
/// data, and the vector of [`ClientAction`] permissions that can be passed to
/// [`SwigWallet::add_authority`](crate::wallet::SwigWallet).
pub struct AgentRoleConfig {
    /// The slippage oracle program ID that must vouch for trades.
    pub oracle_program_id: [u8; 32],
    /// The oracle instruction discriminator to match.
    pub oracle_discriminator: Vec<u8>,
    /// Maximum SOL the agent can spend (absolute).
    pub sol_limit: Option<u64>,
    /// Recurring SOL limit (amount, window_slots).
    pub sol_recurring_limit: Option<(u64, u64)>,
    /// Per-token spending limits.
    pub token_limits: Vec<AgentTokenLimit>,
    /// Which programs the agent can interact with.
    pub program_permission: AgentProgramPermission,
    /// If set, creates a ProgramExecSession authority with this max session length.
    pub session_max_length: Option<u64>,
}

impl AgentRoleConfig {
    /// Build the authority type, authority data, and client actions for this agent role.
    ///
    /// Returns a tuple of:
    /// - `AuthorityType` -- either `ProgramExec` or `ProgramExecSession`
    /// - `Vec<u8>` -- serialized authority data suitable for `add_authority`
    /// - `Vec<ClientAction>` -- the set of permissions/actions for the role
    pub fn build(&self) -> (AuthorityType, Vec<u8>, Vec<ClientAction>) {
        let authority_data = ProgramExecAuthority::create_authority_data(
            &self.oracle_program_id,
            &self.oracle_discriminator,
        );

        let authority_type = if self.session_max_length.is_some() {
            AuthorityType::ProgramExecSession
        } else {
            AuthorityType::ProgramExec
        };

        let mut actions: Vec<ClientAction> = Vec::new();

        // Program permission
        match &self.program_permission {
            AgentProgramPermission::Any => {
                actions.push(ClientAction::ProgramAll(ProgramAll {}));
            }
            AgentProgramPermission::Curated => {
                actions.push(ClientAction::ProgramCurated(ProgramCurated {
                    _reserved: [0; 32],
                }));
            }
            AgentProgramPermission::Specific(programs) => {
                for program_id in programs {
                    actions.push(ClientAction::Program(Program {
                        program_id: *program_id,
                    }));
                }
            }
        }

        // SOL limits
        if let Some(amount) = self.sol_limit {
            actions.push(ClientAction::SolLimit(SolLimit { amount }));
        }
        if let Some((amount, window)) = self.sol_recurring_limit {
            actions.push(ClientAction::SolRecurringLimit(SolRecurringLimit {
                recurring_amount: amount,
                current_amount: amount,
                window,
                last_reset: 0,
            }));
        }

        // Token limits
        for tl in &self.token_limits {
            if let Some(window) = tl.recurring_window {
                actions.push(ClientAction::TokenRecurringLimit(TokenRecurringLimit {
                    token_mint: tl.mint,
                    limit: tl.amount,
                    current: tl.amount,
                    window,
                    last_reset: 0,
                }));
            } else {
                actions.push(ClientAction::TokenLimit(TokenLimit {
                    token_mint: tl.mint,
                    current_amount: tl.amount,
                }));
            }
        }

        (authority_type, authority_data, actions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_produces_correct_actions() {
        let config = AgentRoleConfig {
            oracle_program_id: [1u8; 32],
            oracle_discriminator: vec![0x76, 0x61, 0x6c, 0x74, 0x72, 0x61, 0x64, 0x65],
            sol_limit: Some(1_000_000_000),
            sol_recurring_limit: None,
            token_limits: vec![],
            program_permission: AgentProgramPermission::Any,
            session_max_length: None,
        };

        let (auth_type, auth_data, actions) = config.build();

        assert_eq!(auth_type, AuthorityType::ProgramExec);
        assert!(!auth_data.is_empty());
        assert!(actions
            .iter()
            .any(|a| matches!(a, ClientAction::ProgramAll(_))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ClientAction::SolLimit(_))));
    }

    #[test]
    fn test_build_with_session_returns_session_type() {
        let config = AgentRoleConfig {
            oracle_program_id: [1u8; 32],
            oracle_discriminator: vec![1, 2, 3, 4],
            sol_limit: None,
            sol_recurring_limit: None,
            token_limits: vec![],
            program_permission: AgentProgramPermission::Any,
            session_max_length: Some(1000),
        };

        let (auth_type, _, _) = config.build();
        assert_eq!(auth_type, AuthorityType::ProgramExecSession);
    }

    #[test]
    fn test_build_with_token_limits() {
        let mint = [42u8; 32];
        let config = AgentRoleConfig {
            oracle_program_id: [1u8; 32],
            oracle_discriminator: vec![1, 2, 3, 4],
            sol_limit: None,
            sol_recurring_limit: None,
            token_limits: vec![
                AgentTokenLimit {
                    mint,
                    amount: 500_000,
                    recurring_window: None,
                },
                AgentTokenLimit {
                    mint,
                    amount: 1_000_000,
                    recurring_window: Some(100),
                },
            ],
            program_permission: AgentProgramPermission::Curated,
            session_max_length: None,
        };

        let (_, _, actions) = config.build();

        assert!(actions
            .iter()
            .any(|a| matches!(a, ClientAction::ProgramCurated(_))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ClientAction::TokenLimit(_))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ClientAction::TokenRecurringLimit(_))));
    }

    #[test]
    fn test_build_with_sol_recurring_limit() {
        let config = AgentRoleConfig {
            oracle_program_id: [1u8; 32],
            oracle_discriminator: vec![1, 2, 3, 4],
            sol_limit: None,
            sol_recurring_limit: Some((500_000_000, 216_000)),
            token_limits: vec![],
            program_permission: AgentProgramPermission::Any,
            session_max_length: None,
        };

        let (_, _, actions) = config.build();

        assert!(actions
            .iter()
            .any(|a| matches!(a, ClientAction::SolRecurringLimit(_))));
    }

    #[test]
    fn test_build_with_specific_programs() {
        let prog1 = [10u8; 32];
        let prog2 = [20u8; 32];
        let config = AgentRoleConfig {
            oracle_program_id: [1u8; 32],
            oracle_discriminator: vec![1, 2, 3, 4],
            sol_limit: None,
            sol_recurring_limit: None,
            token_limits: vec![],
            program_permission: AgentProgramPermission::Specific(vec![prog1, prog2]),
            session_max_length: None,
        };

        let (_, _, actions) = config.build();

        let program_count = actions
            .iter()
            .filter(|a| matches!(a, ClientAction::Program(_)))
            .count();
        assert_eq!(program_count, 2);
    }
}
