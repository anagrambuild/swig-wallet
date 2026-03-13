use std::{collections::HashMap, str::FromStr};

use alloy_primitives::{Address, B256};
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use anyhow::{anyhow, Result};
use colored::*;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password, Select};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    nid::Nid,
};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction::{self, transfer},
};
use solana_secp256r1_program;
use swig_sdk::{
    authority::{
        ed25519::CreateEd25519SessionAuthority, secp256k1::CreateSecp256k1SessionAuthority,
        secp256r1::CreateSecp256r1SessionAuthority, AuthorityType,
    },
    client_role::{Secp256r1ClientRole, Secp256r1SessionClientRole},
    swig::SwigWithRoles,
    types::UpdateAuthorityData,
    ClientRole, Ed25519ClientRole, Permission, RecurringConfig, Secp256k1ClientRole,
    Secp256k1SessionClientRole, SwigError, SwigWallet,
};
use swig_state::authority::secp256k1::Secp256k1SessionAuthority;
use swig_state::authority::secp256r1::Secp256r1SessionAuthority;
use swig_state::{authority::ed25519::Ed25519SessionAuthority, IntoBytes};

use crate::SwigCliContext;

pub fn run_interactive_mode(ctx: &mut SwigCliContext) -> Result<()> {
    println!(
        "\n{}",
        "Welcome to SWIG CLI Interactive Mode".bright_blue().bold()
    );

    loop {
        let mut actions = if ctx.wallet.is_none() {
            vec!["Load/Create Wallet", "Exit"]
        } else {
            vec![
                "Add Authority",
                "Remove Authority",
                "Update Authority",
                "View Wallet",
                "Transfer",
                "Switch Authority",
                "Session Operations",
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
                0 => load_or_create_wallet_interactive(ctx)?,
                1 => break,
                _ => unreachable!(),
            }
        } else {
            match selection {
                0 => add_authority_interactive(ctx)?,
                1 => remove_authority_interactive(ctx)?,
                2 => update_authority_interactive(ctx)?,
                3 => view_wallet_interactive(ctx)?,
                4 => transfer_interactive(ctx)?,
                5 => switch_authority_interactive(ctx)?,
                6 => session_operations_interactive(ctx)?,
                7 => sub_accounts_interactive(ctx)?,
                8 => break,
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

    let (client_role, authority_keypair) = get_client_role(&authority_type, None)?;

    let fee_payer_str = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter Fee payer keypair (Solana Ed25519 keypair in base58 format)")
        .interact()?;
    let fee_payer_keypair = Keypair::from_base58_string(&fee_payer_str);

    let fee_payer_static: &mut Keypair = Box::leak(Box::new(fee_payer_keypair));

    // For Secp256k1 and Secp256r1 authorities, we don't need the authority keypair
    // as a transaction signer since the signature is provided in the
    // instruction data
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
    ctx.authority = authority_keypair;
    ctx.payer = fee_payer_static.insecure_clone();

    Ok(())
}

fn load_or_create_wallet_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!(
        "\n{}",
        "Loading or Creating SWIG wallet...".bright_blue().bold()
    );

    let use_random_id = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Use random SWIG ID?")
        .default(false)
        .interact()?;

    let swig_id = if use_random_id {
        rand::random()
    } else {
        let swig_id_str = Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter SWIG ID")
            .interact_text()?;
        format!("{:0<32}", swig_id_str).as_bytes()[..32]
            .try_into()
            .unwrap()
    };

    let rpc_client = RpcClient::new("http://localhost:8899".to_string());

    let swig_config_address = SwigWallet::get_swig_pda(swig_id)?;
    let swig_account = rpc_client.get_account(&swig_config_address);

    if swig_account.is_ok() {
        // Check if this is a newly created wallet or existing one
        // We can check by looking at the role counter
        let swig_account = swig_account.unwrap();
        let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
        println!("✓ SWIG wallet found! Loading existing wallet...");
        load_existing_wallet_interactive(ctx, swig_id, swig_with_roles)?;
    } else {
        println!("SWIG wallet not found. Creating new wallet...");
        create_new_wallet_interactive(ctx, swig_id)?;
    }

    Ok(())
}

fn get_client_role(
    authority_type: &AuthorityType,
    swig_with_roles: Option<&SwigWithRoles>,
) -> Result<(Box<dyn ClientRole>, Option<Keypair>)> {
    Ok((match authority_type {
        &AuthorityType::Ed25519 | &AuthorityType::Ed25519Session => {
            let authority_keypair = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter authority keypair")
                .interact()?;

            let authority = Keypair::from_base58_string(&authority_keypair);
            let authority_pubkey = authority.pubkey();
            println!("Authority public key: {}", authority_pubkey);

            if authority_type == &AuthorityType::Ed25519 {
                (
                    Box::new(Ed25519ClientRole::new(authority_pubkey)) as Box<dyn ClientRole>,
                    Some(authority),
                )
            } else {
                let mut session_pubkey = None;
                let mut max_session_length = None;
                if swig_with_roles.is_none() {
                    // For Ed25519Session, we need the main authority pubkey and session key
                    let session_pubkey_str: String = Input::with_theme(&ColorfulTheme::default())
                        .with_prompt(
                            "Enter session public key (Ed25519 public key in base58 format)",
                        )
                        .interact_text()?;
                    session_pubkey = Pubkey::from_str(&session_pubkey_str)
                        .map_err(|_| anyhow!("Invalid public key format"))
                        .ok();

                    max_session_length = Input::with_theme(&ColorfulTheme::default())
                        .with_prompt("Enter max session length (in slots)")
                        .default(100)
                        .interact_text()
                        .ok();
                } else {
                    let swig_with_roles = swig_with_roles.unwrap();
                    let role_id = swig_with_roles
                        .lookup_role_id(&authority_pubkey.to_bytes())
                        .unwrap();

                    if role_id.is_none() {
                        return Err(anyhow!("Authority not found"));
                    }

                    let role = swig_with_roles.get_role(role_id.unwrap()).unwrap().unwrap();

                    // get the Ed25519SessionClientRole from the role and set the session key and max session length
                    let session_authority = role
                        .authority
                        .as_any()
                        .downcast_ref::<Ed25519SessionAuthority>()
                        .ok_or_else(|| {
                            anyhow!("Failed to cast authority to Ed25519SessionAuthority")
                        })?;

                    session_pubkey = Some(Pubkey::from(session_authority.session_key));
                    max_session_length = Some(session_authority.max_session_length);
                }

                (
                    Box::new(swig_sdk::Ed25519SessionClientRole::new(
                        authority_pubkey,
                        session_pubkey.unwrap(),
                        max_session_length.unwrap(),
                    )) as Box<dyn ClientRole>,
                    Some(authority),
                )
            }
        },
        &AuthorityType::Secp256k1 | &AuthorityType::Secp256k1Session => {
            let authority_keypair = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter Secp256k1 authority keypair")
                .interact()?;

            let wallet = LocalSigner::from_str(&authority_keypair)?;

            let secp_pubkey_bytes = wallet
                .credential()
                .verifying_key()
                .to_encoded_point(false)
                .to_bytes();

            let eth_address = Address::from_raw_public_key(&secp_pubkey_bytes[1..]);

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

            if authority_type == &AuthorityType::Secp256k1 {
                (
                    Box::new(Secp256k1ClientRole::new(
                        secp_pubkey_bytes[1..].to_vec().into_boxed_slice(),
                        Box::new(sign_fn),
                    )) as Box<dyn ClientRole>,
                    None,
                )
            } else {
                let mut session_pubkey = None;
                let mut max_session_length = None;
                if swig_with_roles.is_none() {
                    // For Secp256k1Session, we need session key and max session length
                    let session_pubkey_str: String = Input::with_theme(&ColorfulTheme::default())
                        .with_prompt(
                            "Enter session public key (Ed25519 public key in base58 format)",
                        )
                        .interact_text()?;
                    session_pubkey = Pubkey::from_str(&session_pubkey_str)
                        .map_err(|_| anyhow!("Invalid public key format"))
                        .ok();

                    max_session_length = Input::with_theme(&ColorfulTheme::default())
                        .with_prompt("Enter max session length (in slots)")
                        .default(100)
                        .interact_text()
                        .ok();
                } else {
                    let swig_with_roles = swig_with_roles.unwrap();

                    // For Secp256k1Session, extract session info from existing role
                    let role_id = swig_with_roles
                        .lookup_role_id(&secp_pubkey_bytes[1..])
                        .unwrap();

                    if role_id.is_none() {
                        return Err(anyhow!("Authority not found"));
                    }

                    let role = swig_with_roles.get_role(role_id.unwrap()).unwrap().unwrap();

                    // Extract session information from the role
                    let session_authority = role
                        .authority
                        .as_any()
                        .downcast_ref::<Secp256k1SessionAuthority>()
                        .ok_or_else(|| {
                            anyhow!("Failed to cast authority to Secp256k1SessionAuthority")
                        })?;

                    session_pubkey = Some(Pubkey::from(session_authority.session_key));
                    max_session_length = Some(session_authority.max_session_age);
                }

                (
                    Box::new(Secp256k1SessionClientRole::new(
                        secp_pubkey_bytes[1..].try_into().unwrap(),
                        session_pubkey.unwrap(),
                        max_session_length.unwrap(),
                        Box::new(sign_fn),
                    )) as Box<dyn ClientRole>,
                    None,
                )
            }
        },
        AuthorityType::Secp256r1 | AuthorityType::Secp256r1Session => {
            let hex_private_key = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter Secp256r1 authority keypair")
                .interact()?;

            let hex_key = hex_private_key
                .trim()
                .strip_prefix("0x")
                .unwrap_or(hex_private_key.trim());

            // Decode hex string to bytes
            let mut key_bytes =
                hex::decode(hex_key).map_err(|_| anyhow!("Invalid hex format for private key"))?;

            // Pad to 32 bytes if necessary (left-pad with zeros)
            if key_bytes.len() < 32 {
                let mut padded = vec![0u8; 32 - key_bytes.len()];
                padded.extend_from_slice(&key_bytes);
                key_bytes = padded;
            } else if key_bytes.len() > 32 {
                return Err(anyhow!("Private key too long (expected 32 bytes or less)"));
            }

            // Create BigNum from bytes
            let private_key_bn = BigNum::from_slice(&key_bytes)
                .map_err(|_| anyhow!("Failed to create BigNum from private key bytes"))?;

            // Create EC group for secp256r1 (P-256)
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                .map_err(|_| anyhow!("Failed to create EC group"))?;

            // Compute the public key: pub_key = private_key * generator
            let mut ctx = openssl::bn::BigNumContext::new()
                .map_err(|_| anyhow!("Failed to create BigNum context"))?;
            let mut pub_key = openssl::ec::EcPoint::new(&group)
                .map_err(|_| anyhow!("Failed to create EC point"))?;
            pub_key
                .mul_generator(&group, &private_key_bn, &ctx)
                .map_err(|_| anyhow!("Failed to compute public key"))?;

            // Create EcKey from private key and computed public key
            let signing_key = EcKey::from_private_components(&group, &private_key_bn, &pub_key)
                .map_err(|_| anyhow!("Failed to create EcKey from private key"))?;

            // Verify the key is valid
            signing_key
                .check_key()
                .map_err(|_| anyhow!("Private key validation failed"))?;
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

            if authority_type == &AuthorityType::Secp256r1 {
                (
                    Box::new(Secp256r1ClientRole::new(compressed_pubkey, signing_fn))
                        as Box<dyn ClientRole>,
                    None,
                )
            } else {
                let mut session_pubkey = None;
                let mut max_session_length = None;
                if swig_with_roles.is_none() {
                    let session_pubkey_str: String = Input::with_theme(&ColorfulTheme::default())
                        .with_prompt(
                            "Enter session public key (Ed25519 public key in base58 format)",
                        )
                        .interact_text()?;
                    session_pubkey = Pubkey::from_str(&session_pubkey_str)
                        .map_err(|_| anyhow!("Invalid public key format"))
                        .ok();
                    max_session_length = Input::with_theme(&ColorfulTheme::default())
                        .with_prompt("Enter max session length (in slots)")
                        .default(100)
                        .interact_text()
                        .ok();
                } else {
                    let swig_with_roles = swig_with_roles.unwrap();
                    let role_id = swig_with_roles.lookup_role_id(&compressed_pubkey).unwrap();

                    if role_id.is_none() {
                        return Err(anyhow!("Authority not found"));
                    }

                    let role = swig_with_roles.get_role(role_id.unwrap()).unwrap().unwrap();

                    let session_authority = role
                        .authority
                        .as_any()
                        .downcast_ref::<Secp256r1SessionAuthority>()
                        .ok_or_else(|| {
                            anyhow!("Failed to cast authority to Secp256r1SessionAuthority")
                        })?;

                    session_pubkey = Some(Pubkey::from(session_authority.session_key));
                    max_session_length = Some(session_authority.max_session_age);
                }
                (
                    Box::new(Secp256r1SessionClientRole::new(
                        compressed_pubkey,
                        session_pubkey.unwrap(),
                        max_session_length.unwrap(),
                        signing_fn,
                    )) as Box<dyn ClientRole>,
                    None,
                )
            }
        },

        _ => {
            return Err(anyhow!("Unsupported authority type: {:?}", authority_type));
        },
    }))
}

fn load_existing_wallet_interactive(
    ctx: &mut SwigCliContext,
    swig_id: [u8; 32],
    swig_with_roles: SwigWithRoles,
) -> Result<()> {
    // For now, we'll ask the user to select an authority type and enter credentials
    // In a more advanced implementation, we could parse the existing authorities
    println!("\n{}", "Loading existing wallet...".bright_green().bold());
    println!("Please enter the authority type you want to use:");

    let authority_type = get_authority_type()?;

    let (client_role, authority_keypair) =
        get_client_role(&authority_type, Some(&swig_with_roles))?;

    // Ask for fee payer
    let fee_payer_str = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter Fee payer keypair (Solana Ed25519 keypair in base58 format)")
        .interact()?;
    let fee_payer_keypair = Keypair::from_base58_string(&fee_payer_str);

    let wallet = SwigWallet::new(
        swig_id,
        client_role,
        Box::leak(Box::new(fee_payer_keypair)),
        "http://localhost:8899".to_string(),
        None,
    )?;

    wallet.display_swig()?;

    ctx.authority = authority_keypair;

    ctx.wallet = Some(Box::new(wallet));

    Ok(())
}

fn create_new_wallet_interactive(ctx: &mut SwigCliContext, swig_id: [u8; 32]) -> Result<()> {
    // This is essentially the same as the original create_wallet_interactive
    // but with a pre-determined swig_id
    let authority_type = get_authority_type()?;

    let (client_role, authority_keypair) = get_client_role(&authority_type, None)?;

    let fee_payer_str = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter Fee payer keypair (Solana Ed25519 keypair in base58 format)")
        .interact()?;
    let fee_payer_keypair = Keypair::from_base58_string(&fee_payer_str);

    let fee_payer_static: &mut Keypair = Box::leak(Box::new(fee_payer_keypair));

    // For Secp256k1 and Secp256r1 authorities, we don't need the authority keypair
    // as a transaction signer since the signature is provided in the
    // instruction data
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
    ctx.authority = authority_keypair;

    Ok(())
}

fn create_client_role_for_existing_authority(
    authority_type: &AuthorityType,
    authority_keypair: &Keypair,
    fee_payer_keypair: &Keypair,
    session_data: Option<([u8; 32], u64)>,
) -> Result<Box<dyn ClientRole>> {
    match authority_type {
        AuthorityType::Ed25519 => {
            Ok(Box::new(Ed25519ClientRole::new(authority_keypair.pubkey())) as Box<dyn ClientRole>)
        },
        AuthorityType::Ed25519Session => {
            // For session authorities, we need to ask for session details
            Ok(Box::new(swig_sdk::Ed25519SessionClientRole::new(
                authority_keypair.pubkey(),
                Pubkey::from(session_data.unwrap().0),
                session_data.unwrap().1,
            )) as Box<dyn ClientRole>)
        },
        _ => {
            // For other authority types, we need more complex setup
            // For now, return an error and ask user to create new authority
            Err(anyhow!("Complex authority types require creating new authority. Please select 'Create New Authority' instead."))
        },
    }
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

    let mut authority = crate::format_authority(&authority, &authority_type)?;

    // For session authorities, wrap identity with session parameters
    if authority_type == AuthorityType::Ed25519Session {
        let session_key = Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter session public key (Ed25519 public key in base58 format)")
            .interact_text()?;
        let session_key =
            Pubkey::from_str(&session_key).map_err(|_| anyhow!("Invalid public key format"))?;

        let max_duration: u64 = Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter max session duration (in slots)")
            .default("100".to_string())
            .interact_text()?
            .parse::<u64>()
            .map_err(|_| anyhow!("Invalid max session duration format"))?;

        let session_data = CreateEd25519SessionAuthority::new(
            authority.try_into().unwrap(),
            session_key.to_bytes(),
            max_duration,
        );

        let session_data = session_data.into_bytes().unwrap();
        authority = session_data.to_vec();
    }

    if authority_type == AuthorityType::Secp256k1Session {
        let session_key = Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter session public key (Ed25519 public key in base58 format)")
            .interact_text()?;
        let session_key =
            Pubkey::from_str(&session_key).map_err(|_| anyhow!("Invalid public key format"))?;

        let max_duration: u64 = Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter max session duration (in slots)")
            .default("100".to_string())
            .interact_text()?
            .parse::<u64>()
            .map_err(|_| anyhow!("Invalid max session duration format"))?;

        let session_data = CreateSecp256k1SessionAuthority::new(
            authority.try_into().unwrap(),
            session_key.to_bytes(),
            max_duration,
        );

        let session_data = session_data.into_bytes().unwrap();
        authority = session_data.to_vec();
    }

    if authority_type == AuthorityType::Secp256r1Session {
        let session_key = Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter session public key (Ed25519 public key in base58 format)")
            .interact_text()?;
        let session_key =
            Pubkey::from_str(&session_key).map_err(|_| anyhow!("Invalid public key format"))?;

        let max_duration: u64 = Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter max session duration (in slots)")
            .default("100".to_string())
            .interact_text()?
            .parse::<u64>()
            .map_err(|_| anyhow!("Invalid max session duration format"))?;

        let session_data = CreateSecp256r1SessionAuthority::new(
            authority.try_into().unwrap(),
            session_key.to_bytes(),
            max_duration,
        );

        let session_data = session_data.into_bytes().unwrap();
        authority = session_data.to_vec();
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

fn update_authority_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Updating authority...".bright_blue().bold());

    if ctx.wallet.is_none() {
        return Err(anyhow!(
            "No wallet loaded. Please create or load a wallet first."
        ));
    }

    // Get the authority to update
    let authorities = get_authorities(ctx)?;
    println!("\nAvailable authorities:");

    let authority_keys: Vec<String> = authorities.keys().cloned().collect();
    if authority_keys.is_empty() {
        return Err(anyhow!("No authorities found to update"));
    }

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose authority to update")
        .items(&authority_keys)
        .default(0)
        .interact()?;

    let authority = &authority_keys[selection];
    let authority_bytes = authorities.get(authority).unwrap();

    // Get the role ID for the selected authority
    let role_id = ctx.wallet.as_ref().unwrap().get_role_id(authority_bytes)?;

    // Cannot update root authority (ID 0)
    if role_id == 0 {
        return Err(anyhow!("Cannot update root authority (ID 0)"));
    }

    println!("Updating authority: {:?} (Role ID: {})", authority, role_id);

    // Choose update operation
    let operations = vec![
        "Replace All (Replace all permissions with new ones)",
        "Add Actions (Add new permissions to existing ones)",
        "Remove Actions By Type (Remove permissions by type)",
        "Remove Actions By Index (Remove permissions by index)",
    ];

    let operation_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose update operation")
        .items(&operations)
        .default(0)
        .interact()?;

    let update_data = match operation_selection {
        0 => {
            // Replace All
            let permissions = get_permissions_interactive()?;
            UpdateAuthorityData::ReplaceAll(permissions)
        },
        1 => {
            // Add Actions
            let permissions = get_permissions_interactive()?;
            UpdateAuthorityData::AddActions(permissions)
        },
        2 => {
            // Remove Actions By Type
            let permission_types = vec![
                "All",
                "Manage Authority",
                "SOL",
                "Token",
                "SOL Destination",
                "Token Destination",
                "Program",
                "Program All",
                "Program Scope",
                "Sub Account",
                "Stake",
                "Stake All",
                "All But Manage Authority",
                "Program Curated",
            ];

            let mut selected_types = Vec::new();
            loop {
                let type_selection = Select::with_theme(&ColorfulTheme::default())
                    .with_prompt("Choose permission type to remove")
                    .items(&permission_types)
                    .default(0)
                    .interact()?;

                let permission = match type_selection {
                    0 => Permission::All,
                    1 => Permission::ManageAuthority,
                    2 => Permission::Sol {
                        amount: 0,
                        recurring: None,
                    },
                    3 => Permission::Token {
                        mint: Pubkey::default(),
                        amount: 0,
                        recurring: None,
                    },
                    4 => Permission::SolDestination {
                        destination: Pubkey::default(),
                        amount: 0,
                        recurring: None,
                    },
                    5 => Permission::TokenDestination {
                        mint: Pubkey::default(),
                        destination: Pubkey::default(),
                        amount: 0,
                        recurring: None,
                    },
                    6 => Permission::Program {
                        program_id: Pubkey::default(),
                    },
                    7 => Permission::ProgramAll,
                    8 => Permission::ProgramScope {
                        program_id: Pubkey::default(),
                        target_account: Pubkey::default(),
                        numeric_type: 0,
                        limit: None,
                        window: None,
                        balance_field_start: None,
                        balance_field_end: None,
                    },
                    9 => Permission::SubAccount {
                        sub_account: [0; 32],
                    },
                    10 => Permission::Stake {
                        amount: 0,
                        recurring: None,
                    },
                    11 => Permission::StakeAll,
                    12 => Permission::AllButManageAuthority,
                    13 => Permission::ProgramCurated,
                    _ => unreachable!(),
                };

                selected_types.push(permission);

                let add_more = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Remove more permission types?")
                    .default(false)
                    .interact()?;

                if !add_more {
                    break;
                }
            }

            UpdateAuthorityData::RemoveActionsByType(selected_types)
        },
        3 => {
            // Remove Actions By Index
            let indices_input: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter indices to remove (comma-separated, e.g., 0,1,2)")
                .interact_text()?;

            let indices: Vec<u16> = indices_input
                .split(',')
                .map(|s| s.trim().parse::<u16>())
                .collect::<Result<Vec<u16>, _>>()
                .map_err(|_| anyhow!("Invalid indices format"))?;

            UpdateAuthorityData::RemoveActionsByIndex(indices)
        },
        _ => unreachable!(),
    };

    let signature = ctx
        .wallet
        .as_mut()
        .unwrap()
        .update_authority(role_id, update_data);

    if let Ok(signature) = signature {
        println!("\n{}", "Authority updated successfully!".bright_green());
        println!("Signature: {}", signature);
    } else {
        println!("\n{}", "Failed to update authority".bright_red());
        println!("Error: {}", signature.err().unwrap());
    }

    Ok(())
}

fn switch_authority_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Switching authority...".bright_blue().bold());

    let role_id = Input::<u32>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter authority role ID")
        .interact_text()?;

    let swig_data = ctx
        .wallet
        .as_ref()
        .unwrap()
        .rpc_client
        .get_account(&ctx.wallet.as_ref().unwrap().get_swig_account()?)?;
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_data.data).unwrap();

    let role = swig_with_roles.get_role(role_id).unwrap().unwrap();
    let authority_type = role.authority.authority_type();

    let (client_role, authority_keypair) = get_client_role(&authority_type, None)?;

    ctx.authority = authority_keypair;

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

    let swig_wallet_address = ctx.wallet.as_ref().unwrap().get_swig_wallet_address()?;
    let transfer_instruction =
        transfer(&swig_wallet_address, &Pubkey::from_str(&recipient)?, amount);

    // Always use sign_v2 for transfers
    let signature = ctx
        .wallet
        .as_mut()
        .unwrap()
        .sign_v2(vec![transfer_instruction], None)?;

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
        "All But Manage Authority (All permissions except authority management)",
        "Token (Token-specific permissions)",
        "SOL (SOL transfer permissions)",
        "Token Destination (Token transfer permissions to specific destinations)",
        "SOL Destination (SOL transfer permissions to specific destinations)",
        "Program (Program interaction permissions)",
        "Program All (Unrestricted program access)",
        "Program Scope (Token program scope permissions)",
        "Program Curated (Curated program permissions)",
        "Sub Account (Sub-account management)",
        "Stake (Stake management permissions)",
        "Stake All (All stake management permissions)",
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
            2 => Permission::AllButManageAuthority,
            3 => {
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
            4 => {
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
            5 => {
                // Get token mint address
                let mint_str: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter token mint address")
                    .interact_text()?;
                let mint = Pubkey::from_str(&mint_str)?;

                // Get destination address
                let destination_str: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter destination token account address")
                    .interact_text()?;
                let destination = Pubkey::from_str(&destination_str)?;

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

                Permission::TokenDestination {
                    mint,
                    destination,
                    amount,
                    recurring,
                }
            },
            6 => {
                // Get SOL destination
                let destination_str: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter destination address")
                    .interact_text()?;
                let destination = Pubkey::from_str(&destination_str)?;

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

                Permission::SolDestination {
                    destination,
                    amount,
                    recurring,
                }
            },
            7 => {
                // Get program ID
                let program_id_str: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter program ID")
                    .interact_text()?;
                let program_id = Pubkey::from_str(&program_id_str)?;

                Permission::Program { program_id }
            },
            8 => Permission::ProgramAll,
            9 => {
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
            10 => Permission::ProgramCurated,
            11 => Permission::SubAccount {
                sub_account: [0; 32],
            },
            12 => Permission::Stake {
                amount: 0,
                recurring: None,
            },
            13 => Permission::StakeAll,
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

pub fn session_operations_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Session Operations...".bright_blue().bold());

    if ctx.wallet.is_none() {
        return Err(anyhow!(
            "No wallet loaded. Please create or load a wallet first."
        ));
    }

    let actions = vec![
        "Create Session",
        "Transfer with Session",
        "Check Session Status",
        "Exit",
    ];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose a session operation")
        .items(&actions)
        .default(0)
        .interact()?;

    match selection {
        0 => create_session_interactive(ctx),
        1 => transfer_with_session_interactive(ctx),
        2 => check_session_status_interactive(ctx),
        3 => Ok(()),
        _ => unreachable!(),
    }
}

fn create_session_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Creating session...".bright_blue().bold());

    let session_pubkey_str: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter session public key (Ed25519 public key in base58 format)")
        .interact_text()?;
    let session_pubkey =
        Pubkey::from_str(&session_pubkey_str).map_err(|_| anyhow!("Invalid public key format"))?;

    let max_session_length: u64 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter session length (in slots)")
        .default(100)
        .interact_text()?;

    let signature = ctx
        .wallet
        .as_mut()
        .unwrap()
        .create_session(session_pubkey, max_session_length)?;

    println!("\n{}", "Session created successfully!".bright_green());
    println!("Session key: {}", session_pubkey);
    println!("Max session length: {} slots", max_session_length);

    Ok(())
}

fn transfer_with_session_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Transferring with session...".bright_blue().bold());

    let recipient = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter recipient address")
        .interact_text()?;

    let amount = Input::<u64>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter amount (in lamports)")
        .interact_text()?;

    // Ask for the session keypair (we need the private key to sign)
    let session_keypair_str = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter session keypair (Ed25519 keypair in base58 format)")
        .interact()?;
    let session_keypair = Keypair::from_base58_string(&session_keypair_str);

    let swig_wallet_address = ctx.wallet.as_ref().unwrap().get_swig_wallet_address()?;
    let transfer_instruction =
        system_instruction::transfer(&swig_wallet_address, &Pubkey::from_str(&recipient)?, amount);

    // Store the original fee payer
    let original_payer = ctx.payer.insecure_clone();

    // Create static references for the session keypair
    let session_keypair_static: &Keypair = Box::leak(Box::new(session_keypair));

    // Switch to using the session keypair as the fee payer
    ctx.wallet
        .as_mut()
        .unwrap()
        .switch_payer(session_keypair_static)?;
    ctx.payer = session_keypair_static.insecure_clone();

    // Use sign_v2 for session-based transfers
    let signature = ctx
        .wallet
        .as_mut()
        .unwrap()
        .sign_v2(vec![transfer_instruction], None)?;

    // Restore the original fee payer
    let original_payer_static: &Keypair = Box::leak(Box::new(original_payer));
    ctx.wallet
        .as_mut()
        .unwrap()
        .switch_payer(original_payer_static)?;
    ctx.payer = original_payer_static.insecure_clone();

    println!("\n{}", "Transfer successful!".bright_green());
    println!("Signature: {}", signature);
    println!("Amount: {} lamports", amount);
    println!("Recipient: {}", recipient);

    Ok(())
}

fn check_session_status_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Checking session status...".bright_blue().bold());

    // Get current role ID to check if it's session-based
    let current_role_id = ctx.wallet.as_ref().unwrap().get_current_role_id()?;
    let is_session_based = ctx
        .wallet
        .as_ref()
        .unwrap()
        .is_session_based(current_role_id)?;

    if is_session_based {
        println!("✓ Current authority is session-based");
        println!("Role ID: {}", current_role_id);

        // Try to get session info if available
        let role_count = ctx.wallet.as_ref().unwrap().get_role_count()?;
        println!("Total roles: {}", role_count);
    } else {
        println!("ℹ Current authority is not session-based");
        println!("Role ID: {}", current_role_id);
    }

    Ok(())
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
        2 => {
            let sub_account_role_id = Input::<u32>::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter sub-account role ID")
                .interact_text()?;
            toggle_sub_account_interactive(ctx, sub_account_role_id)?;
        },
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

fn toggle_sub_account_interactive(
    ctx: &mut SwigCliContext,
    sub_account_role_id: u32,
) -> Result<()> {
    println!("\n{}", "Toggling sub-account...".bright_blue().bold());

    let sub_account = ctx.wallet.as_mut().unwrap().get_sub_account()?;

    let current_role_id = ctx.wallet.as_ref().unwrap().get_current_role_id()?;

    if let Some(sub_account) = sub_account {
        ctx.wallet.as_mut().unwrap().toggle_sub_account(
            sub_account,
            current_role_id,
            sub_account_role_id,
            true,
        )?;
    }

    Ok(())
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
