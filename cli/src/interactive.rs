use std::{collections::HashMap, str::FromStr};

use alloy_primitives::{Address, B256};
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use anyhow::{anyhow, Result};
use colored::*;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password, Select};
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    nid::Nid,
};
use solana_sdk::{
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction::{self, transfer},
};
use solana_secp256r1_program;
use swig_sdk::authority::{
    secp256k1::CreateSecp256k1SessionAuthority, secp256r1::CreateSecp256r1SessionAuthority,
};
use swig_sdk::Secp256k1SessionClientRole;
use swig_sdk::{
    authority::{ed25519::CreateEd25519SessionAuthority, AuthorityType},
    client_role::{Secp256r1ClientRole, Secp256r1SessionClientRole},
    swig::SwigWithRoles,
    ClientRole, Ed25519ClientRole, Permission, RecurringConfig, Secp256k1ClientRole, SwigError,
    SwigWallet,
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
                "Sub Accounts",
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
                5 => sub_accounts_interactive(ctx)?,
                6 => break,
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

    let client_role = match authority_type {
        AuthorityType::Ed25519 => {
            let authority_keypair = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter authority keypair")
                .interact()?;

            let authority = Keypair::from_base58_string(&authority_keypair);
            let authority_pubkey = authority.pubkey();
            println!("Authority public key: {}", authority_pubkey);

            Box::new(Ed25519ClientRole::new(authority_pubkey)) as Box<dyn ClientRole>
        },
        AuthorityType::Secp256k1 | AuthorityType::Secp256k1Session => {
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

            if authority_type == AuthorityType::Secp256k1 {
                Box::new(Secp256k1ClientRole::new(
                    eth_pubkey[1..].to_vec().into_boxed_slice(),
                    Box::new(sign_fn),
                )) as Box<dyn ClientRole>
            } else {
                let create_session_authority = CreateSecp256k1SessionAuthority::new(
                    eth_pubkey[1..].to_vec().try_into().unwrap(),
                    [0; 32], // session key
                    100,     // max session length
                );
                Box::new(Secp256k1SessionClientRole::new(
                    create_session_authority,
                    Box::new(sign_fn),
                )) as Box<dyn ClientRole>
            }
        },
        AuthorityType::Secp256r1 => {
            let authority_keypair = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter Secp256r1 authority keypair (PEM format in hex)")
                .interact()?;

            let pem_decoded = hex::decode(authority_keypair)
                .map_err(|_| anyhow!("Invalid hex format for Secp256r1 keypair"))?;

            let signing_key = openssl::ec::EcKey::private_key_from_pem(&pem_decoded)
                .map_err(|_| anyhow!("Invalid PEM format for Secp256r1 keypair"))?;

            // Get the compressed public key
            let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
                .map_err(|_| anyhow!("Failed to create EC group"))?;
            let mut ctx = openssl::bn::BigNumContext::new()
                .map_err(|_| anyhow!("Failed to create BigNum context"))?;
            let pubkey_bytes = signing_key
                .public_key()
                .to_bytes(
                    &group,
                    openssl::ec::PointConversionForm::COMPRESSED,
                    &mut ctx,
                )
                .map_err(|_| anyhow!("Failed to get public key bytes"))?;

            let compressed_pubkey: [u8; 33] = pubkey_bytes
                .try_into()
                .map_err(|_| anyhow!("Invalid public key length"))?;

            // Proper signing function using solana_secp256r1_program
            let signing_key_clone = signing_key.clone();
            let signing_fn = Box::new(move |message_hash: &[u8]| -> [u8; 64] {
                use solana_secp256r1_program::sign_message;
                let signature = sign_message(
                    message_hash,
                    &signing_key_clone.private_key_to_der().unwrap(),
                )
                .unwrap();
                signature
            });

            Box::new(Secp256r1ClientRole::new(compressed_pubkey, signing_fn)) as Box<dyn ClientRole>
        },
        AuthorityType::Secp256r1Session => {
            let authority_keypair = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter Secp256r1 authority keypair (DER format in hex)")
                .interact()?;

            // Parse the Secp256r1 keypair (DER format in hex)
            let clean_keypair = authority_keypair.trim_start_matches("0x");
            let der_bytes = hex::decode(clean_keypair)
                .map_err(|_| anyhow!("Invalid hex format for Secp256r1 keypair"))?;

            // Create an EcKey from the DER bytes
            let signing_key = openssl::ec::EcKey::private_key_from_der(&der_bytes)
                .map_err(|_| anyhow!("Invalid DER format for Secp256r1 keypair"))?;

            // Get the compressed public key
            let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
                .map_err(|_| anyhow!("Failed to create EC group"))?;
            let mut ctx = openssl::bn::BigNumContext::new()
                .map_err(|_| anyhow!("Failed to create BigNum context"))?;
            let pubkey_bytes = signing_key
                .public_key()
                .to_bytes(
                    &group,
                    openssl::ec::PointConversionForm::COMPRESSED,
                    &mut ctx,
                )
                .map_err(|_| anyhow!("Failed to get public key bytes"))?;

            let compressed_pubkey: [u8; 33] = pubkey_bytes
                .try_into()
                .map_err(|_| anyhow!("Invalid public key length"))?;

            let create_session_authority = CreateSecp256r1SessionAuthority::new(
                compressed_pubkey,
                [0; 32], // session key
                100,     // max session length
            );

            // Proper signing function using solana_secp256r1_program
            let signing_key_clone = signing_key.clone();
            let sign_fn = move |payload: &[u8]| -> [u8; 64] {
                let signature = solana_secp256r1_program::sign_message(
                    payload,
                    &signing_key_clone.private_key_to_der().unwrap(),
                )
                .unwrap();
                signature
            };

            Box::new(Secp256r1SessionClientRole::new(
                create_session_authority,
                Box::new(sign_fn),
            )) as Box<dyn ClientRole>
        },
        _ => todo!(),
    };

    let fee_payer_str = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter Fee payer keypair (Solana Ed25519 keypair in base58 format)")
        .interact()?;
    let fee_payer_keypair = Keypair::from_base58_string(&fee_payer_str);

    let fee_payer_static: &mut Keypair = Box::leak(Box::new(fee_payer_keypair));

    // For Secp256k1 and Secp256r1 authorities, we don't need the authority keypair as a transaction signer
    // since the signature is provided in the instruction data
    let authority_keypair_static: Option<&Keypair> = match authority_type {
        AuthorityType::Ed25519 | AuthorityType::Ed25519Session => {
            Some(Box::leak(Box::new(fee_payer_static.insecure_clone())))
        },
        _ => None,
    };

    let wallet = SwigWallet::new(
        swig_id,
        client_role,
        fee_payer_static,
        "http://localhost:8899".to_string(),
        authority_keypair_static,
    )
    .unwrap();

    wallet.display_swig()?;

    ctx.wallet = Some(Box::new(wallet));
    ctx.payer = fee_payer_static.insecure_clone();

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

    // Validate Secp256r1 public key if applicable
    if matches!(
        authority_type,
        AuthorityType::Secp256r1 | AuthorityType::Secp256r1Session
    ) {
        if authority.len() == 33 {
            let pubkey_array: [u8; 33] = authority.clone().try_into().unwrap();
            if let Err(e) = validate_secp256r1_public_key(&pubkey_array) {
                println!("Warning: {}", e);
                println!("The public key might not be valid for Secp256r1 operations.");
            } else {
                println!("✓ Secp256r1 public key validation passed");
            }
        }
    }

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
        println!("Authority: {:?}", authority);
        println!("Signature: {:?}", signature);
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

    let authority_types = vec![
        "Ed25519 (Recommended for standard usage)",
        "Secp256k1 (For Ethereum/Bitcoin compatibility)",
        "Secp256r1 (For passkey/WebAuthn support)",
        "Ed25519Session (For temporary session-based auth)",
        "Secp256k1Session (For temporary session-based auth with Ethereum/Bitcoin)",
        "Secp256r1Session (For temporary session-based auth with passkey/WebAuthn)",
    ];

    let authority_type_idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose authority type")
        .items(&authority_types)
        .default(0)
        .interact()?;

    let authority_type = match authority_type_idx {
        0 => AuthorityType::Ed25519,
        1 => AuthorityType::Secp256k1,
        2 => AuthorityType::Secp256r1,
        3 => AuthorityType::Ed25519Session,
        4 => AuthorityType::Secp256k1Session,
        5 => AuthorityType::Secp256r1Session,
        _ => unreachable!(),
    };

    let authority_keypair = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter authority keypair")
        .interact()?;

    let role_id = u32::from_str(&role_id)?;

    let authority = Keypair::from_base58_string(&authority_keypair);
    let authority_pubkey = authority.pubkey();

    let client_role: Box<dyn ClientRole> = match authority_type {
        AuthorityType::Ed25519 => {
            let pubkey = authority_pubkey;
            println!("Authority: {}", authority_pubkey);
            println!("Authority type: {:?}", authority_type);
            println!("Authority pubkey: {}", pubkey);
            Box::new(Ed25519ClientRole::new(pubkey))
        },
        AuthorityType::Ed25519Session => {
            let create_session_authority = CreateEd25519SessionAuthority::new(
                authority_pubkey.to_bytes(),
                authority_pubkey.to_bytes(),
                100,
            );
            Box::new(swig_sdk::Ed25519SessionClientRole::new(
                create_session_authority,
            ))
        },
        AuthorityType::Secp256r1 => {
            let authority_keypair = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter Secp256r1 authority keypair (DER format in hex)")
                .interact()?;

            // Parse the Secp256r1 keypair (DER format in hex)
            let clean_keypair = authority_keypair.trim_start_matches("0x");
            let der_bytes = hex::decode(clean_keypair)
                .map_err(|_| anyhow!("Invalid hex format for Secp256r1 keypair"))?;

            // Create an EcKey from the DER bytes
            let signing_key = openssl::ec::EcKey::private_key_from_der(&der_bytes)
                .map_err(|_| anyhow!("Invalid DER format for Secp256r1 keypair"))?;

            // Get the compressed public key
            let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
                .map_err(|_| anyhow!("Failed to create EC group"))?;
            let mut ctx = openssl::bn::BigNumContext::new()
                .map_err(|_| anyhow!("Failed to create BigNum context"))?;
            let pubkey_bytes = signing_key
                .public_key()
                .to_bytes(
                    &group,
                    openssl::ec::PointConversionForm::COMPRESSED,
                    &mut ctx,
                )
                .map_err(|_| anyhow!("Failed to get public key bytes"))?;

            let compressed_pubkey: [u8; 33] = pubkey_bytes
                .try_into()
                .map_err(|_| anyhow!("Invalid public key length"))?;

            // Proper signing function using solana_secp256r1_program
            let signing_key_clone = signing_key.clone();
            let sign_fn = move |payload: &[u8]| -> [u8; 64] {
                let signature = solana_secp256r1_program::sign_message(
                    payload,
                    &signing_key_clone.private_key_to_der().unwrap(),
                )
                .unwrap();
                signature
            };

            println!("Authority type: {:?}", authority_type);
            println!("Authority pubkey: 0x{}", hex::encode(compressed_pubkey));
            Box::new(Secp256r1ClientRole::new(
                compressed_pubkey,
                Box::new(sign_fn),
            ))
        },
        AuthorityType::Secp256r1Session => {
            let authority_keypair = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter Secp256r1 authority keypair (DER format in hex)")
                .interact()?;

            // Parse the Secp256r1 keypair (DER format in hex)
            let clean_keypair = authority_keypair.trim_start_matches("0x");
            let der_bytes = hex::decode(clean_keypair)
                .map_err(|_| anyhow!("Invalid hex format for Secp256r1 keypair"))?;

            // Create an EcKey from the DER bytes
            let signing_key = openssl::ec::EcKey::private_key_from_der(&der_bytes)
                .map_err(|_| anyhow!("Invalid DER format for Secp256r1 keypair"))?;

            // Get the compressed public key
            let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
                .map_err(|_| anyhow!("Failed to create EC group"))?;
            let mut ctx = openssl::bn::BigNumContext::new()
                .map_err(|_| anyhow!("Failed to create BigNum context"))?;
            let pubkey_bytes = signing_key
                .public_key()
                .to_bytes(
                    &group,
                    openssl::ec::PointConversionForm::COMPRESSED,
                    &mut ctx,
                )
                .map_err(|_| anyhow!("Failed to get public key bytes"))?;

            let compressed_pubkey: [u8; 33] = pubkey_bytes
                .try_into()
                .map_err(|_| anyhow!("Invalid public key length"))?;

            let create_session_authority = CreateSecp256r1SessionAuthority::new(
                compressed_pubkey,
                [0; 32], // session key
                100,     // max session length
            );

            // Proper signing function using solana_secp256r1_program
            let signing_key_clone = signing_key.clone();
            let sign_fn = move |payload: &[u8]| -> [u8; 64] {
                let signature = solana_secp256r1_program::sign_message(
                    payload,
                    &signing_key_clone.private_key_to_der().unwrap(),
                )
                .unwrap();
                signature
            };

            println!("✓ Secp256r1 session authority keypair parsed successfully");
            println!("Note: You now need to provide a separate Solana Ed25519 keypair for transaction fees");

            let fee_payer_kp_str = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter Fee payer keypair (Solana Ed25519 keypair in base58 format)")
                .interact()?;
            let fee_payer_keypair = Keypair::from_base58_string(&fee_payer_kp_str);

            Box::new(Secp256r1SessionClientRole::new(
                create_session_authority,
                Box::new(sign_fn),
            )) as Box<dyn ClientRole>
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
        .switch_authority(role_id, client_role, None)?;
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
        "Secp256r1 (For passkey/WebAuthn support)",
        "Ed25519Session (For temporary session-based auth)",
        "Secp256k1Session (For temporary session-based auth with Ethereum/Bitcoin)",
        "Secp256r1Session (For temporary session-based auth with passkey/WebAuthn)",
    ];

    let authority_type_idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose authority type")
        .items(&authority_types)
        .default(0)
        .interact()?;

    let authority_type = match authority_type_idx {
        0 => AuthorityType::Ed25519,
        1 => AuthorityType::Secp256k1,
        2 => AuthorityType::Secp256r1,
        3 => AuthorityType::Ed25519Session,
        4 => AuthorityType::Secp256k1Session,
        5 => AuthorityType::Secp256r1Session,
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
            6 => Permission::SubAccount {
                sub_account: [0; 32],
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

pub fn sub_accounts_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Sub Accounts...".bright_blue().bold());

    let actions = vec![
        "Create sub-account",
        "Transfer from sub-account",
        "Toggle sub-account",
        "Withdraw from sub-account to Swig wallet",
        "Exit",
    ];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose an action")
        .items(&actions)
        .default(0)
        .interact()?;

    match selection {
        0 => create_sub_account_interactive(ctx)?,
        1 => transfer_from_sub_account_interactive(ctx)?,
        2 => toggle_sub_account_interactive(ctx)?,
        3 => withdraw_from_sub_account_interactive(ctx)?,
        _ => unreachable!(),
    }
    Ok(())
}

fn create_sub_account_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Checking for sub-account...".bright_blue().bold());

    let sub_account = ctx.wallet.as_mut().unwrap().get_sub_account()?;
    if let Some(sub_account) = sub_account {
        println!("Sub-account already exists: {}", sub_account);
    } else {
        println!("Sub-account does not exist, creating...");
        let signature = ctx.wallet.as_mut().unwrap().create_sub_account()?;
        println!("Sub-account created: {}", signature);
    }

    Ok(())
}

fn transfer_from_sub_account_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!(
        "\n{}",
        "Transferring from sub-account...".bright_blue().bold()
    );
    let recipient = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter recipient address")
        .interact_text()?;
    let recipient = Pubkey::from_str(&recipient)?;
    let amount = Input::<u64>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter amount")
        .interact_text()?;
    let sub_account = ctx.wallet.as_mut().unwrap().get_sub_account()?;
    if let Some(sub_account) = sub_account {
        let transfer_ix = system_instruction::transfer(&sub_account, &recipient, amount);

        let signature = ctx
            .wallet
            .as_mut()
            .unwrap()
            .sign_with_sub_account(vec![transfer_ix], None)
            .unwrap();

        println!("Signature: {}", signature);
    } else {
        println!("Sub-account does not exist!");
    }

    Ok(())
}

pub fn withdraw_from_sub_account_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!(
        "\n{}",
        "Withdrawing from sub-account...".bright_blue().bold()
    );

    let sub_account = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter Sub account address")
        .interact_text()?;
    let sub_account = Pubkey::from_str(&sub_account)?;

    let amount = Input::<u64>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter amount")
        .interact_text()?;

    ctx.wallet
        .as_mut()
        .unwrap()
        .withdraw_from_sub_account(sub_account, amount)?;

    Ok(())
}

fn toggle_sub_account_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Toggling sub-account...".bright_blue().bold());

    let sub_account = ctx.wallet.as_mut().unwrap().get_sub_account()?;
    if let Some(sub_account) = sub_account {
        ctx.wallet
            .as_mut()
            .unwrap()
            .toggle_sub_account(sub_account, true)?;
    }

    Ok(())
}

pub fn format_authority(authority: &str, authority_type: &AuthorityType) -> Result<Vec<u8>> {
    match authority_type {
        AuthorityType::Ed25519 | AuthorityType::Ed25519Session => {
            let authority = Pubkey::from_str(authority)?;
            Ok(authority.to_bytes().to_vec())
        },
        AuthorityType::Secp256k1 | AuthorityType::Secp256k1Session => {
            // For Secp256k1, the authority should be a hex string of the public key
            // Remove 0x prefix if present
            let clean_authority = authority.trim_start_matches("0x");

            // Parse as hex bytes
            let authority_bytes = hex::decode(clean_authority)
                .map_err(|_| anyhow!("Invalid hex string for Secp256k1 authority"))?;

            // For Secp256k1, we expect the uncompressed public key without the 0x04 prefix
            if authority_bytes.len() == 65 && authority_bytes[0] == 0x04 {
                // Remove the 0x04 prefix
                Ok(authority_bytes[1..].to_vec())
            } else if authority_bytes.len() == 64 {
                // Already in the correct format
                Ok(authority_bytes)
            } else {
                Err(anyhow!("Invalid Secp256k1 public key format"))
            }
        },
        AuthorityType::Secp256r1 | AuthorityType::Secp256r1Session => {
            // For Secp256r1, the authority should be a hex string of the compressed public key
            // Remove 0x prefix if present
            let clean_authority = authority.trim_start_matches("0x");

            // Parse as hex bytes
            let authority_bytes = hex::decode(clean_authority)
                .map_err(|_| anyhow!("Invalid hex string for Secp256r1 authority"))?;

            // For Secp256r1, we expect the compressed public key (33 bytes)
            if authority_bytes.len() == 33 {
                Ok(authority_bytes)
            } else {
                Err(anyhow!(
                    "Invalid Secp256r1 public key format - expected 33 bytes"
                ))
            }
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
                    let authority = role.authority.identity().unwrap();
                    // For Secp256k1, encode as hex string
                    let authority_hex = hex::encode(authority);
                    authorities.insert(format!("0x{}", authority_hex), authority.to_vec());
                },
                AuthorityType::Secp256r1 | AuthorityType::Secp256r1Session => {
                    let authority = role.authority.identity().unwrap();
                    // For Secp256r1, encode as hex string
                    let authority_hex = hex::encode(authority);
                    authorities.insert(format!("0x{}", authority_hex), authority.to_vec());
                },
                _ => todo!(),
            }
        }
    }

    Ok(authorities)
}

/// Validates if a Secp256r1 public key is a valid point on the curve
fn validate_secp256r1_public_key(public_key: &[u8; 33]) -> Result<(), anyhow::Error> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|e| anyhow!("Failed to create EC group: {}", e))?;

    let mut ctx =
        BigNumContext::new().map_err(|e| anyhow!("Failed to create BigNum context: {}", e))?;

    let point = EcPoint::from_bytes(&group, public_key, &mut ctx)
        .map_err(|e| anyhow!("Invalid Secp256r1 public key: {}", e))?;

    // Check if the point is at infinity
    if point.is_infinity(&group) {
        return Err(anyhow!("Secp256r1 public key is at infinity"));
    }

    Ok(())
}
