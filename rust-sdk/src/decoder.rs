use crate::{
    types::{Permission, UpdateAuthorityData},
    wallet::TOKEN_22_PROGRAM_ID,
    Ed25519ClientRole, SwigInstructionBuilder, SwigWallet,
};
use solana_account_decoder_client_types::{UiAccount, UiAccountData, UiAccountEncoding};
use solana_client::rpc_request::TokenAccountsFilter;
use solana_program::{
    decode_error::DecodeError,
    program_error::{PrintProgramError, ProgramError},
};
use solana_sdk::{instruction::Instruction, pubkey::Pubkey, transaction::VersionedTransaction};
use spl_token::ID as TOKEN_PROGRAM_ID;
use swig_state::authority::AuthorityType;

use crate::SwigError;

#[derive(Debug)]
pub enum InstructionType {
    CreateSwig {
        swig_id: [u8; 32],
        new_authority_type: AuthorityType,
        new_authority: Vec<u8>,
        permissions: Vec<Permission>,
    },
    AddAuthority {
        new_authority_type: AuthorityType,
        new_authority: Vec<u8>,
        permissions: Vec<Permission>,
    },
    RemoveAuthority {
        authority_to_remove_id: u32,
    },
    UpdateAuthority {
        authority_to_replace_id: u32,
        update_data: UpdateAuthorityData,
    },
    Sign {
        inner_instructions: Vec<Instruction>,
    },
    CreateSubAccount,
    CreateSession,
    SignWithSubAccount,
    WithdrawFromSubAccount,
    WithdrawTokenFromSubAccount,
    ToggleSubAccount,
    WithdrawSol,
    WithdrawToken,
}

impl fmt::Display for InstructionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let InstructionType::Sign { .. } = self {
            write!(f, "Sign")
        } else {
            write!(f, "{:?}", self)
        }
    }
}

#[derive(Debug)]
pub struct DecodedTransaction {
    /// The type of SWIG instruction
    pub instruction_type: InstructionType,
    /// Human-readable description of what the instruction does
    pub description: String,
    /// Role ID used for this instruction
    pub role_id: u32,
    /// Authority type used
    pub authority_type: AuthorityType,
    /// Additional instruction-specific data
    pub data: Option<serde_json::Value>,
    /// Fee payer
    pub fee_payer: String,
    /// Summary of account changes
    pub account_summary: Option<Vec<AccountChange>>,
}

#[derive(Debug)]
pub struct AccountChange {
    pub account_id: String,
    pub account_name: Option<String>,
    pub pre_balance: u64,
    pub post_balance: u64,
    pub balance_change: i64,
}

pub fn authority_type_to_string(authority_type: AuthorityType) -> String {
    match authority_type {
        AuthorityType::Ed25519 => "Ed25519".to_string(),
        AuthorityType::Secp256k1 => "Secp256k1".to_string(),
        AuthorityType::Secp256r1 => "Secp256r1".to_string(),
        AuthorityType::Ed25519Session => "Ed25519Session".to_string(),
        AuthorityType::Secp256k1Session => "Secp256k1Session".to_string(),
        AuthorityType::Secp256r1Session => "Secp256r1Session".to_string(),
        AuthorityType::None => "None".to_string(),
    }
}

impl DecodedTransaction {
    pub fn new(
        instruction_type: InstructionType,
        description: String,
        swig_wallet: &mut SwigWallet,
        tx: VersionedTransaction,
    ) -> Result<Self, SwigError> {
        let account_summary = get_account_summary(swig_wallet, tx)?;

        let decoded_tx = Self {
            instruction_type,
            description,
            role_id: swig_wallet.current_role.role_id,
            authority_type: swig_wallet.current_role.authority_type.clone(),
            data: None,
            fee_payer: swig_wallet.get_fee_payer().to_string(),
            account_summary: Some(account_summary),
        };

        Ok(decoded_tx)
    }
}

use std::fmt;

impl fmt::Display for DecodedTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "\nSWIG Transaction Decoded")?;
        writeln!(f, "========================")?;
        writeln!(f, "Description: {}", self.description)?;
        writeln!(f, "Instruction Type: {}", self.instruction_type)?;
        writeln!(f, "Role ID: {}", self.role_id)?;
        writeln!(
            f,
            "Authority Type: {}",
            authority_type_to_string(self.authority_type.clone())
        )?;
        writeln!(f, "Fee Payer: {}", self.fee_payer)?;

        if let Some(data) = &self.data {
            writeln!(
                f,
                "Additional Data: {}",
                serde_json::to_string_pretty(data).unwrap_or_else(|_| "Invalid JSON".to_string())
            )?;
        }

        if let Some(account_summary) = &self.account_summary {
            if !account_summary.is_empty() {
                writeln!(f, "\nAccount Changes:")?;
                writeln!(f, "----------------")?;
                for change in account_summary {
                    let account_name = change.account_name.as_deref().unwrap_or("Unknown");
                    let change_sign = if change.balance_change >= 0 { "+" } else { "" };
                    writeln!(
                        f,
                        "{} ({}): {}  → {} ({} {}{})",
                        account_name,
                        change.account_id,
                        change.pre_balance,
                        change.post_balance,
                        change_sign,
                        change.balance_change,
                        "tokens"
                    )?;
                }
            }
        }

        Ok(())
    }
}

pub fn get_account_summary(
    swig_wallet: &mut SwigWallet,
    tx: VersionedTransaction,
) -> Result<Vec<AccountChange>, SwigError> {
    let initial_accounts = capture_pre_accounts(swig_wallet, &tx)?;
    let post_accounts = capture_post_accounts(swig_wallet, &tx)?;

    let account_summary = compare_account_balances(&initial_accounts, &post_accounts)?;
    Ok(account_summary)
}

fn capture_post_accounts(
    swig_wallet: &mut SwigWallet,
    tx: &solana_sdk::transaction::VersionedTransaction,
) -> Result<Vec<(solana_sdk::pubkey::Pubkey, u64, bool)>, SwigError> {
    let mut balances = Vec::new();

    #[cfg(not(all(feature = "rust_sdk_test", test)))]
    {
        let simulation_result = swig_wallet.rpc_client.simulate_transaction(&tx.clone())?;

        // Extract account keys from the transaction
        let account_keys = match &tx.message {
            solana_sdk::message::VersionedMessage::V0(msg) => &msg.account_keys,
            solana_sdk::message::VersionedMessage::Legacy(msg) => &msg.account_keys,
        };

        // Get post-transaction accounts
        if let Some(accounts) = simulation_result.value.accounts {
            for (i, account_opt) in accounts.iter().enumerate() {
                if let Some(account) = account_opt {
                    let pubkey = account_keys[i];
                    if account.owner == TOKEN_PROGRAM_ID.to_string() {
                        // For token accounts, we need to parse the data differently
                        // The balance is stored in the account data at specific offsets
                        match &account.data {
                            solana_account_decoder_client_types::UiAccountData::Binary(
                                data,
                                encoding,
                            ) => {
                                if UiAccountEncoding::Base58 == *encoding && data.len() >= 72 {
                                    let base58_data = bs58::decode(data)
                                        .into_vec()
                                        .map_err(|_| SwigError::DecoderError)?;
                                    let balance = u64::from_le_bytes(
                                        base58_data[64..72]
                                            .try_into()
                                            .map_err(|_| SwigError::DecoderError)?,
                                    );
                                    balances.push((pubkey, balance, false));
                                }
                            },
                            _ => {
                                // For non-binary data, use lamports as fallback
                                balances.push((pubkey, account.lamports, false));
                            },
                        }
                    } else {
                        balances.push((pubkey, account.lamports, false));
                    }
                }
            }
        }
    }
    #[cfg(all(feature = "rust_sdk_test", test))]
    {
        use solana_sdk::account::ReadableAccount;
        let result = swig_wallet
            .litesvm()
            .simulate_transaction(tx.clone())
            .map_err(|_| SwigError::DecodeSimulationError)?;
        let post_accounts = result.post_accounts;

        for (pubkey, final_account) in post_accounts {
            if *final_account.owner() == TOKEN_PROGRAM_ID {
                let balance = u64::from_le_bytes(
                    final_account.data()[64..72]
                        .try_into()
                        .map_err(|_| SwigError::DecoderError)?,
                );
                balances.push((pubkey, balance, false));
            } else {
                balances.push((pubkey, final_account.lamports(), false));
            }
        }
    }

    Ok(balances)
}

/// Capture the current balances of all accounts that will be affected by the transaction
fn capture_pre_accounts(
    swig_wallet: &mut SwigWallet,
    tx: &solana_sdk::transaction::VersionedTransaction,
) -> Result<Vec<(solana_sdk::pubkey::Pubkey, u64, bool)>, SwigError> {
    let mut balances = Vec::new();

    // Extract account keys and their writable status from the transaction
    let (account_keys, writable_accounts) = match &tx.message {
        solana_sdk::message::VersionedMessage::V0(msg) => {
            let writable = msg.header.num_required_signatures as usize
                + msg.header.num_readonly_signed_accounts as usize;
            let readonly = msg.account_keys.len() - writable;
            let writable_accounts: std::collections::HashSet<_> =
                msg.account_keys[..writable].iter().collect();
            (&msg.account_keys, writable_accounts)
        },
        solana_sdk::message::VersionedMessage::Legacy(msg) => {
            let writable = msg.header.num_required_signatures as usize
                + msg.header.num_readonly_signed_accounts as usize;
            let readonly = msg.account_keys.len() - writable;
            let writable_accounts: std::collections::HashSet<_> =
                msg.account_keys[..writable].iter().collect();
            (&msg.account_keys, writable_accounts)
        },
    };

    for pubkey in account_keys {
        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        {
            // RPC client returns Result<Account, ClientError>
            match swig_wallet.rpc_client.get_account(&pubkey) {
                Ok(account) => {
                    if account.owner == TOKEN_PROGRAM_ID {
                        let balance = u64::from_le_bytes(
                            account.data[64..72]
                                .try_into()
                                .map_err(|_| SwigError::DecoderError)?,
                        );
                        balances.push((*pubkey, balance, writable_accounts.contains(pubkey)));
                    } else {
                        balances.push((
                            *pubkey,
                            account.lamports,
                            writable_accounts.contains(pubkey),
                        ));
                    }
                },
                Err(_) => {
                    // Account doesn't exist, treat as having 0 balance
                    balances.push((*pubkey, 0, writable_accounts.contains(pubkey)));
                },
            }
        }
        #[cfg(all(feature = "rust_sdk_test", test))]
        {
            // Litesvm returns Option<Account>
            match swig_wallet.litesvm().get_account(&pubkey) {
                Some(account) => {
                    if account.owner == TOKEN_PROGRAM_ID {
                        let balance = u64::from_le_bytes(
                            account.data[64..72]
                                .try_into()
                                .map_err(|_| SwigError::DecoderError)?,
                        );
                        balances.push((*pubkey, balance, writable_accounts.contains(pubkey)));
                    } else {
                        balances.push((
                            *pubkey,
                            account.lamports,
                            writable_accounts.contains(pubkey),
                        ));
                    }
                },
                None => {
                    // Account doesn't exist, treat as having 0 balance
                    balances.push((*pubkey, 0, writable_accounts.contains(pubkey)));
                },
            }
        }
    }

    Ok(balances)
}

/// Compare initial and final account balances and show the changes
fn compare_account_balances(
    initial_balances: &[(solana_sdk::pubkey::Pubkey, u64, bool)],
    final_balances: &[(solana_sdk::pubkey::Pubkey, u64, bool)],
) -> Result<Vec<AccountChange>, SwigError> {
    let mut account_changes = Vec::new();

    // Create a map of initial balances for quick lookup
    let initial_map: std::collections::HashMap<_, _> = initial_balances
        .iter()
        .map(|(pk, bal, writable)| (*pk, (*bal, *writable)))
        .collect();

    for (pubkey, final_balance, writable) in final_balances {
        let (initial_balance, _) = initial_map
            .get(pubkey)
            .copied()
            .ok_or(SwigError::DecoderError)?;
        let change = *final_balance as i64 - initial_balance as i64;

        account_changes.push(AccountChange {
            account_id: pubkey.to_string(),
            account_name: None, // Could be enhanced to provide meaningful names
            pre_balance: initial_balance,
            post_balance: *final_balance,
            balance_change: change,
        });
    }

    Ok(account_changes)
}
