use solana_client::{rpc_client::RpcClient, rpc_request::TokenAccountsFilter};
use solana_program::pubkey::{self, Pubkey};
use swig_interface::ClientAction;
use swig_state::{
    action::{
        all::All,
        all_but_manage_authority::AllButManageAuthority,
        manage_authority::ManageAuthority,
        program::Program,
        program_all::ProgramAll,
        program_curated::ProgramCurated,
        program_scope::{NumericType, ProgramScope, ProgramScopeType},
        sol_destination_limit::SolDestinationLimit,
        sol_limit::SolLimit,
        sol_recurring_destination_limit::SolRecurringDestinationLimit,
        sol_recurring_limit::SolRecurringLimit,
        stake_all::StakeAll,
        stake_limit::StakeLimit,
        stake_recurring_limit::StakeRecurringLimit,
        sub_account::SubAccount,
        token_destination_limit::TokenDestinationLimit,
        token_limit::TokenLimit,
        token_recurring_destination_limit::TokenRecurringDestinationLimit,
        token_recurring_limit::TokenRecurringLimit,
    },
    role::Role,
    swig::SwigWithRoles,
    Transmutable,
};

use crate::{client_role::ClientRole, SwigError, SwigInstructionBuilder};
#[cfg(all(feature = "rust_sdk_test", test))]
use litesvm::LiteSVM;
use solana_sdk::signature::Keypair;

/// Configuration for recurring limits that reset after a specified time window
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Permission to interact with specific tokens to specific destinations.
    /// Can be configured with either a fixed limit or a recurring limit
    /// that resets after a specified period.
    TokenDestination {
        /// The mint address of the token
        mint: Pubkey,
        /// The destination token account
        destination: Pubkey,
        /// The maximum amount that can be transferred to this destination
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

    /// Permission to manage SOL transactions to specific destinations. Can be
    /// configured with either a fixed limit or a recurring limit that
    /// resets after a specified period.
    SolDestination {
        /// The destination pubkey
        destination: Pubkey,
        /// The maximum amount of SOL (in lamports) that can be transferred to
        /// this destination
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

    /// Permission to interact with any program (unrestricted CPI access).
    /// This is the most permissive program permission and should be used with
    /// caution.
    ProgramAll,

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

    /// Permission to interact with curated programs only
    ProgramCurated,

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

    /// Permission to perform all actions except authority management.
    /// This grants access to all wallet operations but excludes the ability
    /// to add, remove, or modify authorities/subaccounts.
    AllButManageAuthority,
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
                Permission::TokenDestination {
                    mint,
                    destination,
                    amount,
                    recurring,
                } => match recurring {
                    Some(config) => {
                        actions.push(ClientAction::TokenRecurringDestinationLimit(
                            TokenRecurringDestinationLimit {
                                token_mint: mint.to_bytes(),
                                destination: destination.to_bytes(),
                                recurring_amount: amount,
                                window: config.window,
                                last_reset: 0,
                                current_amount: amount,
                            },
                        ));
                    },
                    None => {
                        actions.push(ClientAction::TokenDestinationLimit(TokenDestinationLimit {
                            token_mint: mint.to_bytes(),
                            destination: destination.to_bytes(),
                            amount,
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
                Permission::SolDestination {
                    destination,
                    amount,
                    recurring,
                } => match recurring {
                    Some(config) => {
                        actions.push(ClientAction::SolRecurringDestinationLimit(
                            SolRecurringDestinationLimit {
                                destination: destination.to_bytes(),
                                recurring_amount: amount,
                                window: config.window,
                                last_reset: 0,
                                current_amount: amount,
                            },
                        ));
                    },
                    None => {
                        actions.push(ClientAction::SolDestinationLimit(SolDestinationLimit {
                            destination: destination.to_bytes(),
                            amount,
                        }));
                    },
                },
                Permission::Program { program_id } => {
                    actions.push(ClientAction::Program(Program {
                        program_id: program_id.to_bytes(),
                    }));
                },
                Permission::ProgramAll => {
                    actions.push(ClientAction::ProgramAll(ProgramAll {}));
                },
                Permission::ProgramCurated => {
                    actions.push(ClientAction::ProgramCurated(ProgramCurated {
                        _reserved: [0; 32],
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
                    actions.push(ClientAction::SubAccount(SubAccount::new(sub_account)));
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
                Permission::AllButManageAuthority => {
                    actions.push(ClientAction::AllButManageAuthority(
                        AllButManageAuthority {},
                    ));
                },
            }
        }
        actions
    }

    /// Converts a Role reference to a vector of Permission types
    ///
    /// # Arguments
    ///
    /// * `role` - Reference to a Role
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing a vector of permissions or a `SwigError`
    pub fn from_role<'a>(role: &swig_state::role::Role<'a>) -> Result<Vec<Permission>, SwigError> {
        let mut permissions = Vec::new();

        // Check for All permission
        if swig_state::role::Role::get_action::<All>(role, &[])
            .map_err(|_| SwigError::InvalidSwigData)?
            .is_some()
        {
            permissions.push(Permission::All);
        }

        // Check for ManageAuthority permission
        if swig_state::role::Role::get_action::<ManageAuthority>(role, &[])
            .map_err(|_| SwigError::InvalidSwigData)?
            .is_some()
        {
            permissions.push(Permission::ManageAuthority);
        }

        // Check for SolLimit permission
        if let Some(action) = swig_state::role::Role::get_action::<SolLimit>(role, &[])
            .map_err(|_| SwigError::InvalidSwigData)?
        {
            permissions.push(Permission::Sol {
                amount: action.amount,
                recurring: None,
            });
        }

        // Check for SolRecurringLimit permission
        if let Some(action) = swig_state::role::Role::get_action::<SolRecurringLimit>(role, &[])
            .map_err(|_| SwigError::InvalidSwigData)?
        {
            permissions.push(Permission::Sol {
                amount: action.recurring_amount,
                recurring: Some(RecurringConfig {
                    window: action.window,
                    last_reset: action.last_reset,
                    current_amount: action.current_amount,
                }),
            });
        }

        // Check for TokenLimit permissions
        let token_limits = swig_state::role::Role::get_all_actions_of_type::<TokenLimit>(role)
            .map_err(|_| SwigError::InvalidSwigData)?;
        for action in token_limits {
            permissions.push(Permission::Token {
                mint: Pubkey::new_from_array(action.token_mint),
                amount: action.current_amount,
                recurring: None,
            });
        }

        // Check for TokenRecurringLimit permissions
        let token_recurring_limits =
            swig_state::role::Role::get_all_actions_of_type::<TokenRecurringLimit>(role)
                .map_err(|_| SwigError::InvalidSwigData)?;
        for action in token_recurring_limits {
            permissions.push(Permission::Token {
                mint: Pubkey::new_from_array(action.token_mint),
                amount: action.limit,
                recurring: Some(RecurringConfig {
                    window: action.window,
                    last_reset: action.last_reset,
                    current_amount: action.current,
                }),
            });
        }

        // Check for TokenDestinationLimit permissions
        let token_destination_limits =
            swig_state::role::Role::get_all_actions_of_type::<TokenDestinationLimit>(role)
                .map_err(|_| SwigError::InvalidSwigData)?;
        for action in token_destination_limits {
            permissions.push(Permission::TokenDestination {
                mint: Pubkey::new_from_array(action.token_mint),
                destination: Pubkey::new_from_array(action.destination),
                amount: action.amount,
                recurring: None,
            });
        }

        // Check for TokenRecurringDestinationLimit permissions
        let token_recurring_destination_limits =
            swig_state::role::Role::get_all_actions_of_type::<TokenRecurringDestinationLimit>(role)
                .map_err(|_| SwigError::InvalidSwigData)?;
        for action in token_recurring_destination_limits {
            permissions.push(Permission::TokenDestination {
                mint: Pubkey::new_from_array(action.token_mint),
                destination: Pubkey::new_from_array(action.destination),
                amount: action.recurring_amount,
                recurring: Some(RecurringConfig {
                    window: action.window,
                    last_reset: action.last_reset,
                    current_amount: action.current_amount,
                }),
            });
        }

        // Check for SolDestinationLimit permissions
        let sol_destination_limits =
            swig_state::role::Role::get_all_actions_of_type::<SolDestinationLimit>(role)
                .map_err(|_| SwigError::InvalidSwigData)?;
        for action in sol_destination_limits {
            permissions.push(Permission::SolDestination {
                destination: Pubkey::new_from_array(action.destination),
                amount: action.amount,
                recurring: None,
            });
        }

        // Check for SolRecurringDestinationLimit permissions
        let sol_recurring_destination_limits =
            swig_state::role::Role::get_all_actions_of_type::<SolRecurringDestinationLimit>(role)
                .map_err(|_| SwigError::InvalidSwigData)?;
        for action in sol_recurring_destination_limits {
            permissions.push(Permission::SolDestination {
                destination: Pubkey::new_from_array(action.destination),
                amount: action.recurring_amount,
                recurring: Some(RecurringConfig {
                    window: action.window,
                    last_reset: action.last_reset,
                    current_amount: action.current_amount,
                }),
            });
        }

        // Check for ProgramAll permission
        if swig_state::role::Role::get_action::<ProgramAll>(role, &[])
            .map_err(|_| SwigError::InvalidSwigData)?
            .is_some()
        {
            permissions.push(Permission::ProgramAll);
        }

        if swig_state::role::Role::get_action::<ProgramCurated>(role, &[])
            .map_err(|_| SwigError::InvalidSwigData)?
            .is_some()
        {
            permissions.push(Permission::ProgramCurated);
        }

        // Check for Program permissions by iterating through all actions
        let custom_program_actions = role
            .get_all_actions_of_type::<Program>()
            .map_err(|_| SwigError::InvalidSwigData)?;
        for program_action in custom_program_actions {
            permissions.push(Permission::Program {
                program_id: Pubkey::new_from_array(program_action.program_id),
            });
        }

        // Check for ProgramScope permission
        if let Some(action) =
            swig_state::role::Role::get_action::<ProgramScope>(role, &spl_token::ID.to_bytes())
                .map_err(|_| SwigError::InvalidSwigData)?
        {
            permissions.push(Permission::ProgramScope {
                program_id: Pubkey::new_from_array(action.program_id),
                target_account: Pubkey::new_from_array(action.target_account),
                numeric_type: action.numeric_type,
                limit: if action.scope_type > 0 {
                    Some(action.limit as u64)
                } else {
                    None
                },
                window: if action.scope_type == 2 {
                    Some(action.window)
                } else {
                    None
                },
                balance_field_start: Some(action.balance_field_start),
                balance_field_end: Some(action.balance_field_end),
            });
        }

        // Check for SubAccount permission
        if let Some(action) = swig_state::role::Role::get_action::<SubAccount>(role, &[])
            .map_err(|_| SwigError::InvalidSwigData)?
        {
            permissions.push(Permission::SubAccount {
                sub_account: action.sub_account,
            });
        }

        // Check for StakeLimit permission
        if let Some(action) = swig_state::role::Role::get_action::<StakeLimit>(role, &[])
            .map_err(|_| SwigError::InvalidSwigData)?
        {
            permissions.push(Permission::Stake {
                amount: action.amount,
                recurring: None,
            });
        }

        // Check for StakeRecurringLimit permission
        if let Some(action) = swig_state::role::Role::get_action::<StakeRecurringLimit>(role, &[])
            .map_err(|_| SwigError::InvalidSwigData)?
        {
            permissions.push(Permission::Stake {
                amount: action.recurring_amount,
                recurring: Some(RecurringConfig {
                    window: action.window,
                    last_reset: action.last_reset,
                    current_amount: action.current_amount,
                }),
            });
        }

        // Check for StakeAll permission
        if swig_state::role::Role::get_action::<StakeAll>(role, &[])
            .map_err(|_| SwigError::InvalidSwigData)?
            .is_some()
        {
            permissions.push(Permission::StakeAll);
        }

        // Check for AllButManageAuthority permission
        if swig_state::role::Role::get_action::<AllButManageAuthority>(role, &[])
            .map_err(|_| SwigError::InvalidSwigData)?
            .is_some()
        {
            permissions.push(Permission::AllButManageAuthority);
        }

        Ok(permissions)
    }

    pub fn to_action_type(&self) -> u8 {
        match self {
            Permission::All => 7,
            Permission::ManageAuthority => 8,
            Permission::Sol {
                amount: _,
                recurring,
            } => {
                if recurring.is_some() {
                    2 // SolRecurringLimit
                } else {
                    1 // SolLimit
                }
            },
            Permission::SolDestination {
                destination: _,
                amount: _,
                recurring,
            } => {
                if recurring.is_some() {
                    17 // SolRecurringDestinationLimit
                } else {
                    16 // SolDestinationLimit
                }
            },
            Permission::Token {
                mint: _,
                amount: _,
                recurring,
            } => {
                if recurring.is_some() {
                    6 // TokenRecurringLimit
                } else {
                    5 // TokenLimit
                }
            },
            Permission::TokenDestination {
                mint: _,
                destination: _,
                amount: _,
                recurring,
            } => {
                if recurring.is_some() {
                    19 // TokenRecurringDestinationLimit
                } else {
                    18 // TokenDestinationLimit
                }
            },
            Permission::Program { program_id: _ } => 3,
            Permission::ProgramAll => 13,
            Permission::ProgramCurated => 14,
            Permission::ProgramScope {
                program_id: _,
                target_account: _,
                numeric_type: _,
                limit: _,
                window: _,
                balance_field_start: _,
                balance_field_end: _,
            } => 4,
            Permission::SubAccount { sub_account: _ } => 9,
            Permission::Stake {
                amount: _,
                recurring,
            } => {
                if recurring.is_some() {
                    11 // StakeRecurringLimit
                } else {
                    10 // StakeLimit
                }
            },
            Permission::StakeAll => 12,
            Permission::AllButManageAuthority => 15,
        }
    }
}

/// Represents the data that can be updated for an authority
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateAuthorityData {
    ReplaceAll(Vec<Permission>),
    AddActions(Vec<Permission>),
    RemoveActionsByType(Vec<Permission>),
    RemoveActionsByIndex(Vec<u16>),
}

use swig_interface::UpdateAuthorityData as InterfaceUpdateAuthorityData;

impl UpdateAuthorityData {
    pub fn to_interface_data(&self) -> InterfaceUpdateAuthorityData {
        match self {
            UpdateAuthorityData::ReplaceAll(permissions) => {
                InterfaceUpdateAuthorityData::ReplaceAll(Permission::to_client_actions(
                    permissions.clone(),
                ))
            },
            UpdateAuthorityData::AddActions(permissions) => {
                InterfaceUpdateAuthorityData::AddActions(Permission::to_client_actions(
                    permissions.clone(),
                ))
            },
            UpdateAuthorityData::RemoveActionsByType(action_types) => {
                let action_types_vec = action_types
                    .iter()
                    .map(|action| action.to_action_type())
                    .collect::<Vec<u8>>();
                InterfaceUpdateAuthorityData::RemoveActionsByType(action_types_vec)
            },
            UpdateAuthorityData::RemoveActionsByIndex(indices) => {
                InterfaceUpdateAuthorityData::RemoveActionsByIndex(indices.clone())
            },
        }
    }
}

/// Configuration for creating or loading a Swig wallet
///
/// This struct simplifies parameter passing when creating or loading wallets.
/// It encapsulates all the necessary configuration in a single struct.
pub struct WalletConfig<'a> {
    /// The unique identifier for the Swig account
    pub swig_id: [u8; 32],
    /// The client role implementation specifying the type of signing authority
    pub client_role: Box<dyn ClientRole>,
    /// The keypair that will pay for transactions
    pub fee_payer: &'a Keypair,
    /// The URL of the Solana RPC endpoint
    pub rpc_url: String,
    /// Optional authority keypair (required for Ed25519 authorities)
    pub authority_keypair: Option<&'a Keypair>,
    /// (test only) The LiteSVM instance for testing
    #[cfg(all(feature = "rust_sdk_test", test))]
    pub litesvm: Option<LiteSVM>,
}

#[derive(Debug, PartialEq)]
pub struct SwigInfo {
    pub swig_id: [u8; 32],
    pub swig_config_address: Pubkey,
    pub swig_wallet_address: Pubkey,

    pub wallet_balance: u64,
    pub token_balances: Option<Vec<TokenBalance>>,
    pub roles_count: u16,
    pub role_counter: u32,

    pub roles: Vec<RoleInfo>,
}

#[derive(Debug, PartialEq)]
pub struct TokenBalance {
    pub mint: Pubkey,
    pub amount: u64,
    pub decimal: u8,
}

use swig_state::authority::AuthorityType;

#[derive(Debug, PartialEq)]
pub struct RoleInfo {
    pub role_id: u32,
    pub num_actions: u16,
    pub authority_type: AuthorityType,
    pub authority_identity: Vec<u8>,
    pub permissions: Vec<Permission>,
    pub session_based: bool,
}

impl SwigInfo {
    pub fn from_swig_with_roles(rpc_url: &str, swig_id: [u8; 32]) -> Result<Self, SwigError> {
        let swig_config_address = SwigInstructionBuilder::swig_key(&swig_id);

        let rpc_client = RpcClient::new(rpc_url);

        let swig_data = rpc_client.get_account_data(&swig_config_address)?;
        let swig_with_roles = SwigWithRoles::from_bytes(&swig_data)
            .map_err(|e| SwigError::InterfaceError(format!("{:?}", e)))?;

        let swig_wallet_address = SwigInstructionBuilder::swig_wallet_address_from_id(&swig_id);

        let wallet_balance = rpc_client.get_balance(&swig_wallet_address)?;

        //Todo: Get token balances

        let roles_count = swig_with_roles.state.roles;
        let role_counter = swig_with_roles.state.role_counter;
        let mut roles = Vec::new();
        for i in 0..swig_with_roles.state.role_counter {
            let role = swig_with_roles
                .get_role(i)
                .map_err(|e| SwigError::InterfaceError(format!("{:?}", e)))?;
            if let Some(role) = role {
                roles.push(RoleInfo {
                    role_id: i,
                    num_actions: role.position.num_actions,
                    authority_type: role.authority.authority_type(),
                    authority_identity: role.authority.identity().unwrap_or_default().to_vec(),
                    permissions: Permission::from_role(&role)?,
                    session_based: role.authority.session_based(),
                });
            }
        }

        Ok(Self {
            swig_id,
            swig_config_address,
            swig_wallet_address,
            wallet_balance,
            token_balances: None,
            roles_count,
            role_counter,
            roles,
        })
    }
}
