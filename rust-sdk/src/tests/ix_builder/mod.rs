use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use common::*;
use litesvm::{types::TransactionMetadata, LiteSVM};
use litesvm_token::spl_token;
use solana_sdk::{
    account::ReadableAccount,
    clock::Clock,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use solana_system_interface::instruction as system_instruction;
use swig_interface::{
    program_id, AuthorityConfig, ClientAction, CreateInstruction, CreateSessionInstruction,
    SignInstruction,
};
use swig_state::{
    action::{
        all::All, manage_authority::ManageAuthority,
        sol_limit::SolLimit, sol_recurring_limit::SolRecurringLimit, sub_account::SubAccount,
    },
    authority::{
        ed25519::{CreateEd25519SessionAuthority, ED25519Authority, Ed25519SessionAuthority},
        secp256k1::{
            CreateSecp256k1SessionAuthority, Secp256k1Authority, Secp256k1SessionAuthority,
        },
        secp256r1::{
            CreateSecp256r1SessionAuthority, Secp256r1Authority, Secp256r1SessionAuthority,
        },
        AuthorityType,
    },
    role::Role,
    swig::{swig_account_seeds, SwigWithRoles},
    IntoBytes,
};

use super::*;
use crate::{
    error::SwigError,
    types::{Permission, UpdateAuthorityData},
    RecurringConfig, SwigInstructionBuilder, SwigWallet,
};

pub mod authority_tests;
pub mod destination_tests;
pub mod program_all_tests;
pub mod program_scope_tests;
pub mod secp256r1_tests;
pub mod session_tests;
pub mod sign_v1_tests;
pub mod sign_v2_tests;
pub mod sub_account_test;
pub mod swig_account_tests;

use solana_sdk::account::Account;
pub fn display_swig(swig_pubkey: Pubkey, swig_account: &Account) -> Result<(), SwigError> {
    let swig_with_roles =
        SwigWithRoles::from_bytes(&swig_account.data).map_err(|e| SwigError::InvalidSwigData)?;

    println!("╔══════════════════════════════════════════════════════════════════");
    println!("║ SWIG WALLET DETAILS");
    println!("╠══════════════════════════════════════════════════════════════════");
    println!("║ Account Address: {}", swig_pubkey);
    println!("║ Total Roles: {}", swig_with_roles.state.role_counter);
    println!(
        "║ Balance: {} SOL",
        swig_account.lamports() as f64 / 1_000_000_000.0
    );

    println!("╠══════════════════════════════════════════════════════════════════");
    println!("║ ROLES & PERMISSIONS");
    println!("╠══════════════════════════════════════════════════════════════════");

    for i in 0..swig_with_roles.state.role_counter {
        let role = swig_with_roles
            .get_role(i)
            .map_err(|e| SwigError::AuthorityNotFound)?;

        if let Some(role) = role {
            println!("║");
            println!("║ Role ID: {}", i);
            println!(
                "║ ├─ Type: {}",
                if role.authority.session_based() {
                    "Session-based Authority"
                } else {
                    "Permanent Authority"
                }
            );
            println!("║ ├─ Authority Type: {:?}", role.authority.authority_type());
            println!(
                "║ ├─ Authority: {}",
                match role.authority.authority_type() {
                    AuthorityType::Ed25519 | AuthorityType::Ed25519Session => {
                        let authority = role.authority.identity().unwrap();
                        let authority = bs58::encode(authority).into_string();
                        authority
                    },
                    AuthorityType::Secp256k1 | AuthorityType::Secp256k1Session => {
                        let authority = role.authority.identity().unwrap();
                        let authority_hex = hex::encode([&[0x4].as_slice(), authority].concat());
                        // get eth address from public key
                        let mut hasher = solana_sdk::keccak::Hasher::default();
                        hasher.hash(authority_hex.as_bytes());
                        let hash = hasher.result();
                        let address = format!("0x{}", hex::encode(&hash.as_bytes()[12..32]));
                        format!(
                            "{} \n║ │  ├─ odometer: {:?}",
                            address,
                            role.authority.signature_odometer()
                        )
                    },
                    AuthorityType::Secp256r1 | AuthorityType::Secp256r1Session => {
                        let authority = role.authority.identity().unwrap();
                        let authority_hex = hex::encode(authority);
                        format!(
                            "Secp256r1: {} \n║ │  ├─ odometer: {:?}",
                            authority_hex,
                            role.authority.signature_odometer()
                        )
                    },
                    _ => "Unknown authority type".to_string(),
                }
            );

            println!("║ ├─ Permissions:");

            // Check All permission
            if (Role::get_action::<All>(&role, &[]).map_err(|_| SwigError::AuthorityNotFound)?)
                .is_some()
            {
                println!("║ │  ├─ Full Access (All Permissions)");
            }

            // Check Manage Authority permission
            if (Role::get_action::<ManageAuthority>(&role, &[])
                .map_err(|_| SwigError::AuthorityNotFound)?)
            .is_some()
            {
                println!("║ │  ├─ Manage Authority");
            }

            // Check Sol Limit
            if let Some(action) = Role::get_action::<SolLimit>(&role, &[])
                .map_err(|_| SwigError::AuthorityNotFound)?
            {
                println!(
                    "║ │  ├─ SOL Limit: {} SOL",
                    action.amount as f64 / 1_000_000_000.0
                );
            }

            // Check Sol Recurring Limit
            if let Some(action) = Role::get_action::<SolRecurringLimit>(&role, &[])
                .map_err(|_| SwigError::AuthorityNotFound)?
            {
                println!("║ │  ├─ Recurring SOL Limit:");
                println!(
                    "║ │  │  ├─ Amount: {} SOL",
                    action.recurring_amount as f64 / 1_000_000_000.0
                );
                println!("║ │  │  ├─ Window: {} slots", action.window);
                println!(
                    "║ │  │  ├─ Current Usage: {} SOL",
                    action.current_amount as f64 / 1_000_000_000.0
                );
                println!("║ │  │  └─ Last Reset: Slot {}", action.last_reset);
            }

            // Check SubAccount permission
            let actions = Role::get_all_actions_of_type::<SubAccount>(&role)
                .map_err(|_| SwigError::AuthorityNotFound)?;
            if !actions.is_empty() {
                {
                    println!("║ │  ├─ SubAccount");
                    for action in actions {
                        println!(
                            "║ │  │  ├─ SubAccount: {}",
                            Pubkey::from(action.sub_account)
                        );
                        println!("║ │  │  ├─ Enabled: {}", action.enabled);
                        println!("║ │  │  ├─ Role ID: {}", action.role_id);
                        println!("║ │  │  └─ Swig ID: {}", Pubkey::from(action.swig_id));
                    }
                }
            }

            // Check Program Scope
            // Use find_program_scope_in_role instead of Role::get_action because ProgramScope
            // contains u128 fields that require 16-byte alignment, but action data in the swig
            // account may not be properly aligned for off-chain use.
            if let Some(action) = crate::types::find_program_scope_in_role(&role, &spl_token::ID.to_bytes()) {
                let program_id = Pubkey::from(action.program_id);
                let target_account = Pubkey::from(action.target_account);
                println!("║ │  ├─ Program Scope");
                println!("║ │  │  ├─ Program ID: {}", program_id);
                println!("║ │  │  ├─ Target Account: {}", target_account);
                println!(
                    "║ │  │  ├─ Scope Type: {}",
                    match action.scope_type {
                        0 => "Basic",
                        1 => "Limit",
                        2 => "Recurring Limit",
                        _ => "Unknown",
                    }
                );
                println!(
                    "║ │  │  ├─ Numeric Type: {}",
                    match action.numeric_type {
                        0 => "U64",
                        1 => "U128",
                        2 => "F64",
                        _ => "Unknown",
                    }
                );
                if action.scope_type > 0 {
                    println!("║ │  │  ├─ Limit: {} ", action.limit);
                    println!("║ │  │  ├─ Current Usage: {} ", action.current_amount);
                }
                if action.scope_type == 2 {
                    println!("║ │  │  ├─ Window: {} slots", action.window);
                    println!("║ │  │  ├─ Last Reset: Slot {}", action.last_reset);
                }
                println!("║ │  │  ");
            }
            println!("║ │  ");
        }
    }

    println!("╚══════════════════════════════════════════════════════════════════");

    Ok(())
}
