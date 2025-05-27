use alloy_primitives::{Address, B256};
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use anyhow::{anyhow, Result};
use colored::*;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password, Select};
use solana_sdk::{
    pubkey::Pubkey, signature::Keypair, signer::Signer, system_instruction::transfer,
};
use std::{collections::HashMap, str::FromStr};
use swig_sdk::{
    authority::{ed25519::CreateEd25519SessionAuthority, AuthorityType},
    swig::SwigWithRoles,
    AuthorityManager, Permission, RecurringConfig, SwigError, SwigWallet,
};

use crate::SwigCliContext;

pub fn run_interactive_mode(ctx: &mut SwigCliContext) -> Result<()> {
    println!(
        "\n{}",
        "Welcome to SWIG CLI Interactive Mode".bright_blue().bold()
    );

    loop {
        let mut actions = if ctx.wallet.is_none() {
            vec!["Create New Wallet", "Exit"]
        } else {
            vec![
                "Add Authority",
                "Remove Authority",
                "View Wallet",
                "Transfer",
                "Switch Authority",
                "Exit",
            ]
        };

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose an action")
            .items(&actions)
            .default(0)
            .interact()?;

        if ctx.wallet.is_none() {
            match selection {
                0 => create_wallet_interactive(ctx)?,
                1 => break,
                _ => unreachable!(),
            }
        } else {
            match selection {
                0 => add_authority_interactive(ctx)?,
                1 => remove_authority_interactive(ctx)?,
                2 => view_wallet_interactive(ctx)?,
                3 => transfer_interactive(ctx)?,
                4 => switch_authority_interactive(ctx)?,
                5 => break,
                _ => unreachable!(),
            }
        }
    }

    Ok(())
}

fn create_wallet_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Creating new SWIG wallet...".bright_blue().bold());

    let use_random_id = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Use random SWIG ID?")
        .default(true)
        .interact()?;

    let swig_id = if use_random_id {
        None
    } else {
        Some(
            Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter SWIG ID")
                .interact_text()?,
        )
    }
    .map(|i| format!("{:0<32}", i).as_bytes()[..32].try_into().unwrap())
    .unwrap_or_else(rand::random);

    println!("SWIG ID: {}", bs58::encode(swig_id).into_string());

    let authority_type = get_authority_type()?;

    let (authority_manager, fee_payer) = match authority_type {
        AuthorityType::Ed25519 => {
            let authority_keypair = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter authority keypair")
                .interact()?;

            let authority = Keypair::from_base58_string(&authority_keypair);
            let authority_pubkey = authority.pubkey();
            println!("Authority public key: {}", authority_pubkey);
            (
                AuthorityManager::Ed25519(authority_pubkey),
                authority.insecure_clone(),
            )
        },
        AuthorityType::Secp256k1 => {
            let authority_keypair = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter Secp256k1 authority keypair")
                .interact()?;

            let wallet = LocalSigner::from_str(&authority_keypair)?;

            let eth_pubkey = wallet
                .credential()
                .verifying_key()
                .to_encoded_point(false)
                .to_bytes();

            let eth_address = Address::from_raw_public_key(&eth_pubkey[1..]);

            println!("Wallet: {:?}", wallet);
            println!("Eth pubkey: {:?}", eth_pubkey);
            println!("Eth address: {:?}", eth_address);
            let secp_pubkey = wallet.address().to_checksum_buffer(None);

            let sign_fn = move |payload: &[u8]| -> [u8; 65] {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&payload[..32]);
                let hash = B256::from(hash);
                let tsig = wallet
                    .sign_hash_sync(&hash)
                    .map_err(|_| SwigError::InvalidSecp256k1)
                    .unwrap()
                    .as_bytes();
                let mut sig = [0u8; 65];
                sig.copy_from_slice(&tsig);
                sig
            };

            let fee_payer_kp_str = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter Fee payer keypair")
                .interact()?;
            let fee_payer_keypair = Keypair::from_base58_string(&fee_payer_kp_str);

            (
                AuthorityManager::Secp256k1(eth_pubkey, Box::new(sign_fn)),
                fee_payer_keypair,
            )
        },
        _ => todo!(),
    };

    let fee_payer = Box::leak(Box::new(fee_payer));
    let wallet = SwigWallet::new(
        swig_id,
        authority_manager,
        fee_payer,
        fee_payer,
        "http://localhost:8899".to_string(),
    )
    .unwrap();

    wallet.display_swig()?;

    ctx.wallet = Some(Box::new(wallet));
    ctx.payer = fee_payer.insecure_clone();

    Ok(())
}

fn add_authority_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Adding new authority...".bright_blue().bold());

    if ctx.wallet.is_none() {
        return Err(anyhow!(
            "No wallet loaded. Please create or load a wallet first."
        ));
    }

    let authority_type = get_authority_type()?;

    let authority = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter authority public key")
        .interact_text()?;

    let authority = format_authority(&authority, &authority_type)?;

    let permissions = get_permissions_interactive()?;

    let signature =
        ctx.wallet
            .as_mut()
            .unwrap()
            .add_authority(authority_type, &authority, permissions);

    if let Ok(signature) = signature {
        println!("\n{}", "Authority added successfully!".bright_green());
        println!("Signature: {}", signature);
    } else {
        println!("\n{}", "Failed to add authority".bright_red());
        println!("Error: {}", signature.err().unwrap());
    }

    Ok(())
}

fn remove_authority_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Removing authority...".bright_blue().bold());

    if ctx.wallet.is_none() {
        return Err(anyhow!(
            "No wallet loaded. Please create or load a wallet first."
        ));
    }

    let authorities = get_authorities(ctx)?;
    println!("\nAvailable authorities:");

    let authority_keys: Vec<String> = authorities.keys().cloned().collect();
    if authority_keys.is_empty() {
        return Err(anyhow!("No authorities found to remove"));
    }

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose authority to remove")
        .items(&authority_keys)
        .default(0)
        .interact()?;

    let authority = &authority_keys[selection];

    println!("Removing authority: {:?}", authority);

    ctx.wallet
        .as_mut()
        .unwrap()
        .remove_authority(authorities.get(authority).unwrap())?;

    println!("\n{}", "Authority removed successfully!".bright_green());
    Ok(())
}

fn switch_authority_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Switching authority...".bright_blue().bold());

    let role_id = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter authority role ID")
        .interact_text()?;

    let authority_keypair = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter authority keypair")
        .interact()?;

    let authority_types = vec![
        "Ed25519 (Recommended for standard usage)",
        "Secp256k1 (For Ethereum/Bitcoin compatibility)",
        "Ed25519Session (For temporary session-based auth)",
        "Secp256k1Session (For temporary session-based auth with Ethereum/Bitcoin)",
    ];

    let authority_type_idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose authority type")
        .items(&authority_types)
        .default(0)
        .interact()?;

    let authority_type = match authority_type_idx {
        0 => AuthorityType::Ed25519,
        1 => AuthorityType::Secp256k1,
        2 => AuthorityType::Ed25519Session,
        3 => AuthorityType::Secp256k1Session,
        _ => unreachable!(),
    };

    let role_id = u32::from_str(&role_id)?;

    let authority = Keypair::from_base58_string(&authority_keypair);
    let authority_pubkey = authority.pubkey();

    let authority_manager = match authority_type {
        AuthorityType::Ed25519 => {
            let pubkey = authority_pubkey;
            println!("Authority: {}", authority_pubkey);
            println!("Authority type: {:?}", authority_type);
            println!("Authority pubkey: {}", pubkey);
            AuthorityManager::Ed25519(pubkey)
        },
        AuthorityType::Ed25519Session => {
            let create_session_authority = CreateEd25519SessionAuthority::new(
                authority_pubkey.to_bytes(),
                authority_pubkey.to_bytes(),
                100,
            );
            AuthorityManager::Ed25519Session(create_session_authority)
        },
        _ => {
            return Err(anyhow!("Session-based authorities not supported for root"));
        },
    };

    // Store the authority keypair in the context
    ctx.authority = Some(authority.insecure_clone());

    ctx.wallet
        .as_mut()
        .unwrap()
        .switch_authority(role_id, authority_manager, None)?;
    Ok(())
}

fn view_wallet_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Viewing wallet details...".bright_blue().bold());

    if ctx.wallet.is_none() {
        return Err(anyhow!("Wallet not found"));
    }

    ctx.wallet.as_ref().unwrap().display_swig()?;

    Ok(())
}

fn transfer_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Transferring...".bright_blue().bold());

    let recipient = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter recipient address")
        .interact_text()?;

    let amount = Input::<u64>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter amount")
        .interact_text()?;

    let transfer_instruction = transfer(
        &ctx.wallet.as_ref().unwrap().get_swig_account()?,
        &Pubkey::from_str(&recipient)?,
        amount,
    );

    let signature = ctx
        .wallet
        .as_mut()
        .unwrap()
        .sign(vec![transfer_instruction], None)?;

    println!("Signature: {}", signature);

    Ok(())
}

pub fn get_authority_type() -> Result<AuthorityType> {
    let authority_types = vec![
        "Ed25519 (Recommended for standard usage)",
        "Secp256k1 (For Ethereum/Bitcoin compatibility)",
        "Ed25519Session (For temporary session-based auth)",
        "Secp256k1Session (For temporary session-based auth with Ethereum/Bitcoin)",
    ];

    let authority_type_idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose authority type")
        .items(&authority_types)
        .default(0)
        .interact()?;

    let authority_type = match authority_type_idx {
        0 => AuthorityType::Ed25519,
        1 => AuthorityType::Secp256k1,
        2 => AuthorityType::Ed25519Session,
        3 => AuthorityType::Secp256k1Session,
        _ => unreachable!(),
    };

    Ok(authority_type)
}

pub fn get_permissions_interactive() -> Result<Vec<Permission>> {
    let permission_types = vec![
        "All (Full access to all operations)",
        "Manage Authority (Add/remove authorities)",
        "Token (Token-specific permissions)",
        "SOL (SOL transfer permissions)",
        "Program (Program interaction permissions)",
        "Program Scope (Token program scope permissions)",
        "Sub Account (Sub-account management)",
    ];

    let mut permissions = Vec::new();

    loop {
        let permission_type_idx = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose permission type")
            .items(&permission_types)
            .default(0)
            .interact()?;

        let permission = match permission_type_idx {
            0 => Permission::All,
            1 => Permission::ManageAuthority,
            2 => {
                // Get token mint address
                let mint_str: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter token mint address")
                    .interact_text()?;
                let mint = Pubkey::from_str(&mint_str)?;

                // Get amount
                let amount: u64 = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter token amount limit")
                    .interact_text()?;

                // Check if recurring
                let is_recurring = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Make this a recurring limit?")
                    .default(false)
                    .interact()?;

                let recurring = if is_recurring {
                    let window: u64 = Input::with_theme(&ColorfulTheme::default())
                        .with_prompt("Enter time window in slots")
                        .interact_text()?;
                    Some(RecurringConfig::new(window))
                } else {
                    None
                };

                Permission::Token {
                    mint,
                    amount,
                    recurring,
                }
            },
            3 => {
                // Get SOL amount
                let amount: u64 = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter SOL amount limit (in lamports)")
                    .interact_text()?;

                // Check if recurring
                let is_recurring = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Make this a recurring limit?")
                    .default(false)
                    .interact()?;

                let recurring = if is_recurring {
                    let window: u64 = Input::with_theme(&ColorfulTheme::default())
                        .with_prompt("Enter time window in slots")
                        .interact_text()?;
                    Some(RecurringConfig::new(window))
                } else {
                    None
                };

                Permission::Sol { amount, recurring }
            },
            4 => {
                // Get program ID
                let program_id_str: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter program ID")
                    .interact_text()?;
                let program_id = Pubkey::from_str(&program_id_str)?;

                Permission::Program { program_id }
            },
            5 => {
                // Program Scope for Token Programs
                let token_programs = vec!["SPL Token", "Token2022"];
                let program_idx = Select::with_theme(&ColorfulTheme::default())
                    .with_prompt("Choose token program")
                    .items(&token_programs)
                    .default(0)
                    .interact()?;

                let program_id = match program_idx {
                    0 => spl_token::ID,
                    1 => todo!("Token2022 program ID"), // Add Token2022 program ID when available
                    _ => unreachable!(),
                };

                // Get target account (ATA)
                let target_account_str: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter target token account address (ATA)")
                    .interact_text()?;
                let target_account = Pubkey::from_str(&target_account_str)?;

                // Check if recurring limit should be set
                let has_limit = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Set a recurring transfer limit?")
                    .default(false)
                    .interact()?;

                let (limit, window) = if has_limit {
                    let limit: u64 = Input::with_theme(&ColorfulTheme::default())
                        .with_prompt("Enter transfer limit amount")
                        .interact_text()?;

                    let window: u64 = Input::with_theme(&ColorfulTheme::default())
                        .with_prompt("Enter time window in slots")
                        .interact_text()?;

                    (Some(limit), Some(window))
                } else {
                    (None, None)
                };

                Permission::ProgramScope {
                    program_id,
                    target_account,
                    numeric_type: 2, // U64 for token amounts
                    limit,
                    window,
                    balance_field_start: Some(64), // Fixed for SPL token accounts
                    balance_field_end: Some(72),   // Fixed for SPL token accounts
                }
            },
            6 => {
                // Get sub-account address
                let sub_account_str: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter sub-account address")
                    .interact_text()?;
                let sub_account = Pubkey::from_str(&sub_account_str)?;

                Permission::SubAccount {
                    sub_account: sub_account.to_bytes(),
                }
            },
            _ => unreachable!(),
        };

        permissions.push(permission);

        // Ask if user wants to add more permissions
        let add_more = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Add more permissions?")
            .default(false)
            .interact()?;

        if !add_more {
            break;
        }
    }

    Ok(permissions)
}

pub fn format_authority(authority: &str, authority_type: &AuthorityType) -> Result<Vec<u8>> {
    match authority_type {
        AuthorityType::Ed25519 | AuthorityType::Ed25519Session => {
            let authority = Pubkey::from_str(authority)?;
            Ok(authority.to_bytes().to_vec())
        },
        AuthorityType::Secp256k1 | AuthorityType::Secp256k1Session => {
            let wallet = LocalSigner::random();

            let secp_pubkey = wallet
                .credential()
                .verifying_key()
                .to_encoded_point(false)
                .to_bytes();

            println!("Secp256k1 public key: {:?}", wallet.address());
            Ok(secp_pubkey.as_ref()[1..].to_vec())
        },
        _ => Err(anyhow!("Unsupported authority type")),
    }
}

pub fn get_authorities(ctx: &mut SwigCliContext) -> Result<HashMap<String, Vec<u8>>> {
    let swig_pubkey = ctx.wallet.as_ref().unwrap().get_swig_account()?;

    let swig_account = ctx
        .wallet
        .as_ref()
        .unwrap()
        .rpc_client
        .get_account(&swig_pubkey)?;

    let swig_data = swig_account.data;

    let swig_with_roles = SwigWithRoles::from_bytes(&swig_data).unwrap();

    let mut authorities = HashMap::new();

    for i in 0..swig_with_roles.state.role_counter {
        let role = swig_with_roles
            .get_role(i)
            .map_err(|e| SwigError::AuthorityNotFound)?;

        if let Some(role) = role {
            match role.authority.authority_type() {
                AuthorityType::Ed25519 | AuthorityType::Ed25519Session => {
                    let authority = role.authority.identity().unwrap();
                    let authority = bs58::encode(authority).into_string();
                    let authority_pubkey = Pubkey::from_str(&authority)?;
                    authorities.insert(authority, authority_pubkey.to_bytes().to_vec());
                },
                AuthorityType::Secp256k1 | AuthorityType::Secp256k1Session => {
                    // Implementation for Secp256k1 authorities
                },
                _ => todo!(),
            }
        }
    }

    Ok(authorities)
}
