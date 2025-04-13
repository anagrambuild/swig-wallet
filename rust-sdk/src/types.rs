use solana_program::pubkey::Pubkey;
use swig_interface::ClientAction;
use swig_state_x::action::{
    all::All, manage_authority::ManageAuthority, program::Program, sol_limit::SolLimit,
    sol_recurring_limit::SolRecurringLimit, sub_account::SubAccount, token_limit::TokenLimit,
    token_recurring_limit::TokenRecurringLimit,
};

/// Represents the authority type for a Swig wallet
#[derive(Debug, Clone)]
pub enum WalletAuthority {
    /// Ed25519 authority represented by a Solana public key
    Ed25519(Pubkey),
    /// Secp256k1 authority represented by a 64-byte array
    Secp256k1([u8; 64]),
}

/// Configuration for recurring limits that reset after a specified time window
#[derive(Debug, Clone)]
pub struct RecurringConfig {
    /// The time window in slots after which the limit resets
    pub window: u64,
}

/// Represents the permissions that can be granted to a wallet authority.
/// Each permission type maps to specific actions that can be performed on the wallet.
#[derive(Debug, Clone)]
pub enum Permission {
    /// Full permissions for all actions. This is the highest level of permission
    /// that grants unrestricted access to all wallet operations.
    All,

    /// Permission to manage authorities. This allows adding or removing authorities
    /// from the wallet and modifying their permissions.
    ManageAuthority,

    /// Permission to interact with specific tokens. Can be configured with either
    /// a fixed limit or a recurring limit that resets after a specified period.
    Token {
        /// The mint address of the token
        mint: Pubkey,
        /// The maximum amount that can be transferred
        amount: u64,
        /// Optional recurring configuration. If provided, the amount becomes a recurring
        /// limit that resets after the specified window period. If None, amount is
        /// treated as a fixed limit.
        recurring: Option<RecurringConfig>,
    },

    /// Permission to manage SOL transactions. Can be configured with either
    /// a fixed limit or a recurring limit that resets after a specified period.
    Sol {
        /// The maximum amount of SOL (in lamports) that can be transferred
        amount: u64,
        /// Optional recurring configuration. If provided, the amount becomes a recurring
        /// limit that resets after the specified window period. If None, amount is
        /// treated as a fixed limit.
        recurring: Option<RecurringConfig>,
    },

    /// Permission to interact with specific programs. This allows the wallet
    /// to execute instructions for the specified program.
    Program {
        /// The program ID that this permission grants access to
        program_id: Pubkey,
    },

    /// Permission to manage sub-accounts. This allows creating and managing
    /// hierarchical wallet structures through sub-accounts.
    SubAccount {
        /// The public key of the sub-account
        sub_account: Pubkey,
    },
}

impl Permission {
    /// Converts a vector of high-level Permission enums into the internal ClientAction representation
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
                            current: 0,
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
                            current_amount: 0,
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
                Permission::SubAccount { sub_account } => {
                    actions.push(ClientAction::SubAccount(SubAccount {
                        sub_account: sub_account.to_bytes(),
                    }));
                },
            }
        }
        actions
    }
}
