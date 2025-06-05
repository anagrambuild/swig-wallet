use solana_program::pubkey::Pubkey;
use swig_interface::ClientAction;
use swig_state_x::action::{
    all::All,
    manage_authority::ManageAuthority,
    program::Program,
    program_scope::{NumericType, ProgramScope, ProgramScopeType},
    sol_limit::SolLimit,
    sol_recurring_limit::SolRecurringLimit,
    stake_all::StakeAll,
    stake_limit::StakeLimit,
    stake_recurring_limit::StakeRecurringLimit,
    sub_account::SubAccount,
    token_limit::TokenLimit,
    token_recurring_limit::TokenRecurringLimit,
};

use crate::SwigError;

/// Configuration for recurring limits that reset after a specified time window
#[derive(Debug, Clone)]
pub struct RecurringConfig {
    /// The time window in slots after which the limit resets
    pub window: u64,
    pub last_reset: u64,
    pub current_amount: u64,
}

impl RecurringConfig {
    pub fn new(window: u64) -> Self {
        Self {
            window,
            last_reset: 0,
            current_amount: 0,
        }
    }
}

/// Represents the permissions that can be granted to a wallet authority.
/// Each permission type maps to specific actions that can be performed on the
/// wallet.
#[derive(Debug, Clone)]
pub enum Permission {
    /// Full permissions for all actions. This is the highest level of
    /// permission that grants unrestricted access to all wallet operations.
    All,

    /// Permission to manage authorities. This allows adding or removing
    /// authorities from the wallet and modifying their permissions.
    ManageAuthority,

    /// Permission to interact with specific tokens. Can be configured with
    /// either a fixed limit or a recurring limit that resets after a
    /// specified period.
    Token {
        /// The mint address of the token
        mint: Pubkey,
        /// The maximum amount that can be transferred
        amount: u64,
        /// Optional recurring configuration. If provided, the amount becomes a
        /// recurring limit that resets after the specified window
        /// period. If None, amount is treated as a fixed limit.
        recurring: Option<RecurringConfig>,
    },

    /// Permission to manage SOL transactions. Can be configured with either
    /// a fixed limit or a recurring limit that resets after a specified period.
    Sol {
        /// The maximum amount of SOL (in lamports) that can be transferred
        amount: u64,
        /// Optional recurring configuration. If provided, the amount becomes a
        /// recurring limit that resets after the specified window
        /// period. If None, amount is treated as a fixed limit.
        recurring: Option<RecurringConfig>,
    },

    /// Permission to interact with specific programs. This allows the wallet
    /// to execute instructions for the specified program.
    Program {
        /// The program ID that this permission grants access to
        program_id: Pubkey,
    },

    /// Permission to interact with specific programs. This allows the wallet
    /// to execute instructions for the specified program.
    ProgramScope {
        program_id: Pubkey,
        target_account: Pubkey,
        numeric_type: u64,
        limit: Option<u64>,
        window: Option<u64>,
        balance_field_start: Option<u64>,
        balance_field_end: Option<u64>,
    },

    /// Permission to manage sub-accounts. This allows creating and managing
    /// hierarchical wallet structures through sub-accounts.
    SubAccount { sub_account: [u8; 32] },

    /// Permission to manage stake accounts with a fixed limit
    Stake {
        /// The maximum amount of stake (in lamports) that can be managed
        amount: u64,
        /// Optional recurring configuration. If provided, the amount becomes a
        /// recurring limit that resets after the specified window
        /// period. If None, amount is treated as a fixed limit.
        recurring: Option<RecurringConfig>,
    },

    /// Permission to manage all stake-related operations without limits
    StakeAll,
}

impl Permission {
    /// Converts a vector of high-level Permission enums into the internal
    /// ClientAction representation
    ///
    /// For recurring limits, current_amount/current is set to the recurring
    /// amount/limit, and last_reset is always set to 0 upon initialization.
    pub fn to_client_actions(permissions: Vec<Permission>) -> Vec<ClientAction> {
        let mut actions = Vec::new();
        for permission in permissions {
            match permission {
                Permission::All => {
                    actions.push(ClientAction::All(All {}));
                },
                Permission::ManageAuthority => {
                    actions.push(ClientAction::ManageAuthority(ManageAuthority {}));
                },
                Permission::Token {
                    mint,
                    amount,
                    recurring,
                } => match recurring {
                    Some(config) => {
                        actions.push(ClientAction::TokenRecurringLimit(TokenRecurringLimit {
                            token_mint: mint.to_bytes(),
                            window: config.window,
                            limit: amount,
                            current: amount,
                            last_reset: 0,
                        }));
                    },
                    None => {
                        actions.push(ClientAction::TokenLimit(TokenLimit {
                            token_mint: mint.to_bytes(),
                            current_amount: amount,
                        }));
                    },
                },
                Permission::Sol { amount, recurring } => match recurring {
                    Some(config) => {
                        actions.push(ClientAction::SolRecurringLimit(SolRecurringLimit {
                            recurring_amount: amount,
                            window: config.window,
                            last_reset: 0,
                            current_amount: amount,
                        }));
                    },
                    None => {
                        actions.push(ClientAction::SolLimit(SolLimit { amount }));
                    },
                },
                Permission::Program { program_id } => {
                    actions.push(ClientAction::Program(Program {
                        program_id: program_id.to_bytes(),
                    }));
                },
                Permission::ProgramScope {
                    program_id,
                    target_account,
                    numeric_type,
                    window,
                    limit,
                    balance_field_start,
                    balance_field_end,
                } => {
                    let (scope_type, window, limit) = match (window, limit) {
                        (Some(window), Some(limit)) => {
                            (ProgramScopeType::RecurringLimit as u64, window, limit)
                        },
                        (None, Some(limit)) => (ProgramScopeType::Limit as u64, 0, limit),
                        (None, None) => (ProgramScopeType::Basic as u64, 0, 0),
                        (Some(_), None) => (ProgramScopeType::Basic as u64, 0, 0),
                    };

                    actions.push(ClientAction::ProgramScope(ProgramScope {
                        program_id: program_id.to_bytes(),
                        target_account: target_account.to_bytes(),
                        scope_type: scope_type as u64,
                        numeric_type: numeric_type as u64,
                        current_amount: 0 as u128,
                        limit: limit as u128,
                        window: window as u64,
                        last_reset: 0,
                        balance_field_start: balance_field_start.unwrap_or(0) as u64,
                        balance_field_end: balance_field_end.unwrap_or(0) as u64,
                    }));
                },
                Permission::SubAccount { sub_account } => {
                    actions.push(ClientAction::SubAccount(SubAccount { sub_account }));
                },
                Permission::Stake { amount, recurring } => match recurring {
                    Some(config) => {
                        actions.push(ClientAction::StakeRecurringLimit(StakeRecurringLimit {
                            recurring_amount: amount,
                            window: config.window,
                            last_reset: 0,
                            current_amount: amount,
                        }));
                    },
                    None => {
                        actions.push(ClientAction::StakeLimit(StakeLimit { amount }));
                    },
                },
                Permission::StakeAll => {
                    actions.push(ClientAction::StakeAll(StakeAll {}));
                },
            }
        }
        actions
    }
}
