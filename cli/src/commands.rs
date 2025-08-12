use std::str::FromStr;

use alloy_primitives::{Address, B256};
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use anyhow::{anyhow, Result};
use colored::*;
use hex;
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    nid::Nid,
};
use rand::Rng;
use serde_json::Value;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
};
use solana_secp256r1_program;
use swig_sdk::{
    authority::AuthorityType, client_role::Secp256r1ClientRole, types::UpdateAuthorityData,
    ClientRole, Ed25519ClientRole, Permission, RecurringConfig, Secp256k1ClientRole, SwigError,
    SwigWallet,
};

use crate::{Command, SwigCliContext};

pub fn create_swig_instance(
    ctx: &mut SwigCliContext,
    swig_id: [u8; 32],
    authority_type: AuthorityType,
    authority: String,
    authority_kp: String,
    fee_payer_string: Option<String>,
) -> Result<()> {
    let fee_payer = Keypair::from_base58_string(&fee_payer_string.unwrap_or(authority_kp.clone()));
    let (client_role, fee_payer) = match authority_type {
        AuthorityType::Ed25519 => {
            let authority_kp = Keypair::from_base58_string(&authority_kp);
            let authority = Pubkey::from_str(&authority)?;

            (
                Box::new(Ed25519ClientRole::new(authority)) as Box<dyn ClientRole>,
                authority_kp,
            )
        },
        AuthorityType::Secp256k1 => {
            let wallet = LocalSigner::from_str(&authority_kp)?;
            let eth_pubkey = wallet
                .credential()
                .verifying_key()
                .to_encoded_point(false)
                .to_bytes();

            let eth_address = Address::from_raw_public_key(&eth_pubkey[1..]);

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

            (
                Box::new(Secp256k1ClientRole::new(
                    eth_pubkey[1..].to_vec().into_boxed_slice(),
                    Box::new(sign_fn),
                )) as Box<dyn ClientRole>,
                fee_payer.insecure_clone(),
            )
        },
        AuthorityType::Secp256r1 => {
            // For Secp256r1, the authority_kp should be a hex string of the DER private key
            let clean_authority = authority_kp.trim_start_matches("0x");
            let der_bytes = hex::decode(clean_authority)
                .map_err(|_| anyhow!("Invalid hex string for Secp256r1 private key"))?;

            // Create an EcKey from the DER bytes
            let signing_key = EcKey::private_key_from_der(&der_bytes)
                .map_err(|_| anyhow!("Invalid DER format for Secp256r1 private key"))?;

            // Get the compressed public key
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                .map_err(|_| anyhow!("Failed to create EC group"))?;
            let mut ctx_bn =
                BigNumContext::new().map_err(|_| anyhow!("Failed to create BigNum context"))?;
            let pubkey_bytes = signing_key
                .public_key()
                .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx_bn)
                .map_err(|_| anyhow!("Failed to get public key bytes"))?;

            let compressed_pubkey: [u8; 33] = pubkey_bytes
                .try_into()
                .map_err(|_| anyhow!("Invalid public key length"))?;

            // Create proper signing function using solana_secp256r1_program
            let signing_key_clone = signing_key.clone();
            let sign_fn = move |payload: &[u8]| -> [u8; 64] {
                let signature = solana_secp256r1_program::sign_message(
                    payload,
                    &signing_key_clone.private_key_to_der().unwrap(),
                )
                .unwrap();
                signature
            };

            (
                Box::new(Secp256r1ClientRole::new(
                    compressed_pubkey,
                    Box::new(sign_fn),
                )) as Box<dyn ClientRole>,
                fee_payer.insecure_clone(),
            )
        },
        _ => return Err(anyhow!("Unsupported authority type")),
    };

    // Use Box::leak to create static references (similar to interactive mode)
    let fee_payer_static: &mut Keypair = Box::leak(Box::new(fee_payer));
    let authority_keypair_static: &mut Keypair =
        Box::leak(Box::new(fee_payer_static.insecure_clone()));

    let wallet = SwigWallet::new(
        swig_id,
        client_role,
        fee_payer_static,
        ctx.rpc_url.clone(),
        Some(authority_keypair_static),
    )
    .unwrap();

    ctx.wallet = Some(Box::new(wallet));
    ctx.payer = fee_payer_static.insecure_clone();
    ctx.authority = Some(authority_keypair_static.insecure_clone());

    Ok(())
}

pub fn parse_permission_from_json(permission_json: &Value) -> Result<Permission> {
    match permission_json["type"].as_str() {
        Some("all") => Ok(Permission::All),
        Some("sol") => {
            let amount = permission_json["amount"].as_u64().unwrap_or(1_000_000_000);
            let recurring = if let Some(recurring) = permission_json.get("recurring") {
                let window = recurring["window"].as_u64().unwrap_or(86400);
                Some(swig_sdk::RecurringConfig::new(window))
            } else {
                None
            };
            Ok(Permission::Sol { amount, recurring })
        },
        Some("allButManageAuthority") => Ok(Permission::AllButManageAuthority),
        Some("manageAuthority") => Ok(Permission::ManageAuthority),
        Some("program") => {
            let program_id = permission_json["programId"]
                .as_str()
                .ok_or_else(|| anyhow!("Program ID is required for program permission"))?;
            Ok(Permission::Program {
                program_id: Pubkey::from_str(program_id)?,
            })
        },
        Some("programScope") => {
            let program_id = permission_json["programId"]
                .as_str()
                .ok_or_else(|| anyhow!("Program ID is required for program scope permission"))?;
            let target_account = permission_json["targetAccount"].as_str().ok_or_else(|| {
                anyhow!("Target account is required for program scope permission")
            })?;
            let numeric_type = permission_json["numericType"].as_u64().unwrap_or(0);
            let limit = permission_json["limit"].as_u64();
            let window = permission_json["window"].as_u64();
            let balance_field_start = permission_json["balanceFieldStart"].as_u64();
            let balance_field_end = permission_json["balanceFieldEnd"].as_u64();

            Ok(Permission::ProgramScope {
                program_id: Pubkey::from_str(program_id)?,
                target_account: Pubkey::from_str(target_account)?,
                numeric_type,
                limit,
                window,
                balance_field_start,
                balance_field_end,
            })
        },
        Some("subAccount") => {
            let sub_account = permission_json["subAccount"]
                .as_str()
                .ok_or_else(|| anyhow!("Sub-account is required for sub-account permission"))?;
            Ok(Permission::SubAccount {
                sub_account: sub_account.as_bytes().try_into().unwrap(),
            })
        },
        Some(unknown) => Err(anyhow!("Invalid permission type: {}", unknown)),
        None => Err(anyhow!("Permission type is required")),
    }
}

pub fn run_command_mode(ctx: &mut SwigCliContext, cmd: Command) -> Result<()> {
    match cmd {
        Command::Create {
            authority_type,
            authority,
            authority_kp,
            fee_payer,
            id,
        } => {
            let swig_id = id
                .map(|i| format!("{:0<32}", i))
                .unwrap_or_else(|| {
                    format!(
                        "{:0<32}",
                        bs58::encode(rand::random::<[u8; 32]>()).into_string()
                    )
                })
                .as_bytes()[..32]
                .try_into()
                .unwrap();

            create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
                fee_payer,
            )?;

            Ok(())
        },
        Command::AddAuthority {
            authority_type,
            authority,
            authority_kp,
            fee_payer,
            id,
            new_authority,
            new_authority_type,
            permissions,
        } => {
            let swig_id = format!("{:0<32}", id).as_bytes()[..32].try_into().unwrap();

            // Parse permissions from JSON
            if permissions.is_empty() {
                return Err(anyhow!("Permissions are required"));
            }

            let parsed_permissions = permissions
                .iter()
                .map(|p| {
                    let permission_value: Value = serde_json::from_str(p)
                        .map_err(|e| anyhow!("Invalid permission JSON: {}", e))?;
                    parse_permission_from_json(&permission_value)
                })
                .collect::<Result<Vec<_>>>()?;

            create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
                fee_payer,
            )?;

            let new_authority =
                new_authority.ok_or_else(|| anyhow!("New authority is required"))?;
            let new_authority_type =
                new_authority_type.ok_or_else(|| anyhow!("New authority type is required"))?;

            let new_authority_type = parse_authority_type(new_authority_type)?;
            let authority_bytes = crate::format_authority(&new_authority, &new_authority_type)?;

            ctx.wallet.as_mut().unwrap().add_authority(
                new_authority_type,
                &authority_bytes,
                parsed_permissions,
            )?;

            println!("Authority added successfully!");
            Ok(())
        },
        Command::RemoveAuthority {
            authority_type,
            authority,
            authority_kp,
            fee_payer,
            id,
            remove_authority,
        } => {
            let swig_id = format!("{:0<32}", id).as_bytes()[..32].try_into().unwrap();

            create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
                fee_payer,
            )?;

            let remove_authority =
                remove_authority.ok_or_else(|| anyhow!("Remove authority is required"))?;
            ctx.wallet
                .as_mut()
                .unwrap()
                .remove_authority(remove_authority.as_bytes())?;
            println!("Authority removed successfully!");
            Ok(())
        },
        Command::View {
            authority_type,
            authority,
            authority_kp,
            id,
        } => {
            let swig_id = format!("{:0<32}", id).as_bytes()[..32].try_into().unwrap();

            create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
                None,
            )?;

            ctx.wallet.as_ref().unwrap().display_swig()?;
            Ok(())
        },
        Command::GetRoleId {
            authority_type,
            authority,
            authority_kp,
            id,
            authority_to_fetch,
            authority_type_to_fetch,
        } => {
            let swig_id = format!("{:0<32}", id).as_bytes()[..32].try_into().unwrap();

            let fetch_authority_type = parse_authority_type(authority_type_to_fetch)?;
            let fetch_authority_bytes =
                crate::format_authority(&authority_to_fetch, &fetch_authority_type)?;

            create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
                None,
            )?;

            let role_id = ctx
                .wallet
                .as_ref()
                .unwrap()
                .get_role_id(&fetch_authority_bytes)?;
            println!("Role ID: {}", role_id);
            Ok(())
        },
        Command::Balance {
            authority_type,
            authority,
            authority_kp,
            id,
        } => {
            let swig_id = format!("{:0<32}", id).as_bytes()[..32].try_into().unwrap();

            create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
                None,
            )?;

            let balance = ctx.wallet.as_ref().unwrap().get_balance()?;
            println!("Balance: {} SOL", balance as f64 / 1_000_000_000.0);
            Ok(())
        },
        Command::CreateSubAccount {
            authority_type,
            authority,
            authority_kp,
            id,
        } => {
            let swig_id = format!("{:0<32}", id).as_bytes()[..32].try_into().unwrap();

            create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
                None,
            )?;

            let signature = ctx.wallet.as_mut().unwrap().create_sub_account()?;
            println!("Sub-account created successfully!");
            println!("Signature: {}", signature);
            Ok(())
        },
        Command::TransferFromSubAccount {
            authority_type,
            authority,
            authority_kp,
            id,
            recipient,
            amount,
        } => {
            let swig_id = format!("{:0<32}", id).as_bytes()[..32].try_into().unwrap();

            create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
                None,
            )?;

            let sub_account = ctx.wallet.as_ref().unwrap().get_sub_account()?;
            if let Some(sub_account) = sub_account {
                let recipient = Pubkey::from_str(&recipient)?;
                let transfer_ix = system_instruction::transfer(&sub_account, &recipient, amount);
                let signature = ctx
                    .wallet
                    .as_mut()
                    .unwrap()
                    .sign_with_sub_account(vec![transfer_ix], None)?;
                println!("Transfer successful!");
                println!("Signature: {}", signature);
            } else {
                println!("Sub-account does not exist!");
            }
            Ok(())
        },
        Command::ToggleSubAccount {
            authority_type,
            authority,
            authority_kp,
            id,
            enabled,
        } => {
            let swig_id = format!("{:0<32}", id).as_bytes()[..32].try_into().unwrap();

            create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
                None,
            )?;

            let sub_account = ctx.wallet.as_ref().unwrap().get_sub_account()?;
            if let Some(sub_account) = sub_account {
                ctx.wallet
                    .as_mut()
                    .unwrap()
                    .toggle_sub_account(sub_account, enabled)?;
                println!(
                    "Sub-account {} successfully!",
                    if enabled { "enabled" } else { "disabled" }
                );
            } else {
                println!("Sub-account does not exist!");
            }
            Ok(())
        },
        Command::WithdrawFromSubAccount {
            authority_type,
            authority,
            authority_kp,
            id,
            sub_account,
            amount,
        } => {
            let swig_id = format!("{:0<32}", id).as_bytes()[..32].try_into().unwrap();

            create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
                None,
            )?;

            let sub_account = Pubkey::from_str(&sub_account)?;
            ctx.wallet
                .as_mut()
                .unwrap()
                .withdraw_from_sub_account(sub_account, amount)?;
            println!("Successfully withdrew {} lamports from sub-account", amount);
            Ok(())
        },
        Command::Generate {
            authority_type,
            output_format,
        } => {
            let authority_type = parse_authority_type(authority_type)?;
            let output_format = output_format.unwrap_or_else(|| "json".to_string());

            match authority_type {
                AuthorityType::Ed25519 => {
                    let keypair = Keypair::new();
                    let public_key = keypair.pubkey();
                    let private_key = bs58::encode(keypair.to_bytes()).into_string();

                    match output_format.as_str() {
                        "json" => {
                            println!(
                                "{}",
                                serde_json::json!({
                                    "authority_type": "Ed25519",
                                    "public_key": public_key.to_string(),
                                    "private_key": private_key,
                                    "public_key_bytes": hex::encode(public_key.to_bytes())
                                })
                            );
                        },
                        "text" => {
                            println!("Ed25519 Keypair:");
                            println!("Public Key: {}", public_key);
                            println!("Private Key: {}", private_key);
                            println!("Public Key (hex): {}", hex::encode(public_key.to_bytes()));
                        },
                        _ => return Err(anyhow!("Unsupported output format: {}", output_format)),
                    }
                },
                AuthorityType::Secp256k1 => {
                    // Generate secp256k1 keypair using alloy
                    let wallet = LocalSigner::random();
                    let public_key = wallet.credential().verifying_key().to_encoded_point(false);
                    let private_key_bytes = wallet.credential().to_bytes();
                    let eth_address = wallet.address();

                    // Get uncompressed public key (64 bytes without 0x04 prefix)
                    let uncompressed_pubkey = public_key.to_bytes();

                    match output_format.as_str() {
                        "json" => {
                            println!(
                                "{}",
                                serde_json::json!({
                                    "authority_type": "Secp256k1",
                                    "public_key": hex::encode(&uncompressed_pubkey[1..]),
                                    "private_key": hex::encode(private_key_bytes),
                                    "eth_address": format!("{:?}", eth_address)
                                })
                            );
                        },
                        "text" => {
                            println!("Secp256k1 Keypair:");
                            println!(
                                "Public Key (uncompressed): {}",
                                hex::encode(&uncompressed_pubkey[1..])
                            );
                            println!("Private Key: {}", hex::encode(private_key_bytes));
                            println!("Ethereum Address: {:?}", eth_address);
                        },
                        _ => return Err(anyhow!("Unsupported output format: {}", output_format)),
                    }
                },
                AuthorityType::Secp256r1 => {
                    // Generate secp256r1 keypair using openssl
                    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                        .map_err(|e| anyhow!("Failed to create EC group: {}", e))?;
                    let signing_key = EcKey::generate(&group)
                        .map_err(|e| anyhow!("Failed to generate EC key: {}", e))?;

                    let mut ctx = BigNumContext::new()
                        .map_err(|e| anyhow!("Failed to create BigNum context: {}", e))?;
                    let pubkey_bytes = signing_key
                        .public_key()
                        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
                        .map_err(|e| anyhow!("Failed to serialize public key: {}", e))?;

                    let private_key_der = signing_key
                        .private_key_to_der()
                        .map_err(|e| anyhow!("Failed to serialize private key: {}", e))?;

                    match output_format.as_str() {
                        "json" => {
                            println!(
                                "{}",
                                serde_json::json!({
                                    "authority_type": "Secp256r1",
                                    "public_key": hex::encode(&pubkey_bytes),
                                    "private_key": hex::encode(&private_key_der)
                                })
                            );
                        },
                        "text" => {
                            println!("Secp256r1 Keypair:");
                            println!("Public Key (compressed): {}", hex::encode(&pubkey_bytes));
                            println!("Private Key (DER): {}", hex::encode(&private_key_der));
                        },
                        _ => return Err(anyhow!("Unsupported output format: {}", output_format)),
                    }
                },
                AuthorityType::Ed25519Session => {
                    // Generate Ed25519 keypair for session authority
                    let keypair = Keypair::new();
                    let public_key = keypair.pubkey();
                    let private_key = bs58::encode(keypair.to_bytes()).into_string();

                    match output_format.as_str() {
                        "json" => {
                            println!(
                                "{}",
                                serde_json::json!({
                                    "authority_type": "Ed25519Session",
                                    "public_key": public_key.to_string(),
                                    "private_key": private_key,
                                    "public_key_bytes": hex::encode(public_key.to_bytes()),
                                    "note": "For session authorities, you'll also need a separate fee payer keypair"
                                })
                            );
                        },
                        "text" => {
                            println!("Ed25519Session Keypair:");
                            println!("Public Key: {}", public_key);
                            println!("Private Key: {}", private_key);
                            println!("Public Key (hex): {}", hex::encode(public_key.to_bytes()));
                            println!(
                                "Note: For session authorities, you'll also need a separate fee \
                                 payer keypair"
                            );
                        },
                        _ => return Err(anyhow!("Unsupported output format: {}", output_format)),
                    }
                },
                AuthorityType::Secp256k1Session => {
                    // Generate secp256k1 keypair for session authority
                    let wallet = LocalSigner::random();
                    let public_key = wallet.credential().verifying_key().to_encoded_point(false);
                    let private_key_bytes = wallet.credential().to_bytes();
                    let eth_address = wallet.address();

                    // Get uncompressed public key (64 bytes without 0x04 prefix)
                    let uncompressed_pubkey = public_key.to_bytes();

                    match output_format.as_str() {
                        "json" => {
                            println!(
                                "{}",
                                serde_json::json!({
                                    "authority_type": "Secp256k1Session",
                                    "public_key": hex::encode(&uncompressed_pubkey[1..]),
                                    "private_key": hex::encode(private_key_bytes),
                                    "eth_address": format!("{:?}", eth_address),
                                    "note": "For session authorities, you'll also need a separate fee payer keypair"
                                })
                            );
                        },
                        "text" => {
                            println!("Secp256k1Session Keypair:");
                            println!(
                                "Public Key (uncompressed): {}",
                                hex::encode(&uncompressed_pubkey[1..])
                            );
                            println!("Private Key: {}", hex::encode(private_key_bytes));
                            println!("Ethereum Address: {:?}", eth_address);
                            println!(
                                "Note: For session authorities, you'll also need a separate fee \
                                 payer keypair"
                            );
                        },
                        _ => return Err(anyhow!("Unsupported output format: {}", output_format)),
                    }
                },
                AuthorityType::Secp256r1Session => {
                    // Generate secp256r1 keypair for session authority
                    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                        .map_err(|e| anyhow!("Failed to create EC group: {}", e))?;
                    let signing_key = EcKey::generate(&group)
                        .map_err(|e| anyhow!("Failed to generate EC key: {}", e))?;

                    let mut ctx = BigNumContext::new()
                        .map_err(|e| anyhow!("Failed to create BigNum context: {}", e))?;
                    let pubkey_bytes = signing_key
                        .public_key()
                        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
                        .map_err(|e| anyhow!("Failed to serialize public key: {}", e))?;

                    let prviate_key_pem = signing_key
                        .private_key_to_pem()
                        .map_err(|e| anyhow!("Failed to serialize private key: {}", e))?;

                    match output_format.as_str() {
                        "json" => {
                            println!(
                                "{}",
                                serde_json::json!({
                                    "authority_type": "Secp256r1Session",
                                    "public_key": hex::encode(&pubkey_bytes),
                                    "private_key": hex::encode(&prviate_key_pem),
                                    "note": "For session authorities, you'll also need a separate fee payer keypair"
                                })
                            );
                        },
                        "text" => {
                            println!("Secp256r1Session Keypair:");
                            println!("Public Key (compressed): {}", hex::encode(&pubkey_bytes));
                            println!("Private Key (PEM): {}", hex::encode(&prviate_key_pem));
                            println!(
                                "Note: For session authorities, you'll also need a separate fee \
                                 payer keypair"
                            );
                        },
                        _ => return Err(anyhow!("Unsupported output format: {}", output_format)),
                    }
                },
                _ => {
                    return Err(anyhow!(
                        "Unsupported authority type for generation: {:?}",
                        authority_type
                    ))
                },
            }

            Ok(())
        },
        Command::UpdateAuthority {
            authority_type,
            authority,
            authority_kp,
            fee_payer,
            id,
            authority_to_update_id,
            operation,
            permissions,
            action_types,
            indices,
        } => {
            let swig_id = format!("{:0<32}", id).as_bytes()[..32].try_into().unwrap();

            create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
                fee_payer,
            )?;

            let update_data = match operation.as_str() {
                "ReplaceAll" => {
                    if permissions.is_empty() {
                        return Err(anyhow!("Permissions are required for ReplaceAll operation"));
                    }
                    let parsed_permissions = permissions
                        .iter()
                        .map(|p| {
                            let permission_value: Value = serde_json::from_str(p)
                                .map_err(|e| anyhow!("Invalid permission JSON: {}", e))?;
                            parse_permission_from_json(&permission_value)
                        })
                        .collect::<Result<Vec<_>>>()?;
                    UpdateAuthorityData::ReplaceAll(parsed_permissions)
                },
                "AddActions" => {
                    if permissions.is_empty() {
                        return Err(anyhow!("Permissions are required for AddActions operation"));
                    }
                    let parsed_permissions = permissions
                        .iter()
                        .map(|p| {
                            let permission_value: Value = serde_json::from_str(p)
                                .map_err(|e| anyhow!("Invalid permission JSON: {}", e))?;
                            parse_permission_from_json(&permission_value)
                        })
                        .collect::<Result<Vec<_>>>()?;
                    UpdateAuthorityData::AddActions(parsed_permissions)
                },
                "RemoveActionsByType" => {
                    if action_types.is_empty() {
                        return Err(anyhow!(
                            "Action types are required for RemoveActionsByType operation"
                        ));
                    }
                    let parsed_permissions = action_types
                        .iter()
                        .map(|action_type| match action_type.as_str() {
                            "All" => Ok(Permission::All),
                            "AllButManageAuthority" => Ok(Permission::AllButManageAuthority),
                            "ManageAuthority" => Ok(Permission::ManageAuthority),
                            "Sol" => Ok(Permission::Sol {
                                amount: 0,
                                recurring: None,
                            }),
                            "Token" => Ok(Permission::Token {
                                mint: Pubkey::default(),
                                amount: 0,
                                recurring: None,
                            }),
                            "Program" => Ok(Permission::Program {
                                program_id: Pubkey::default(),
                            }),
                            "ProgramScope" => Ok(Permission::ProgramScope {
                                program_id: Pubkey::default(),
                                target_account: Pubkey::default(),
                                numeric_type: 0,
                                limit: None,
                                window: None,
                                balance_field_start: None,
                                balance_field_end: None,
                            }),
                            "SubAccount" => Ok(Permission::SubAccount {
                                sub_account: [0; 32],
                            }),
                            "Stake" => Ok(Permission::Stake {
                                amount: 0,
                                recurring: None,
                            }),
                            "StakeAll" => Ok(Permission::StakeAll),
                            _ => Err(anyhow!("Invalid action type: {}", action_type)),
                        })
                        .collect::<Result<Vec<_>>>()?;
                    UpdateAuthorityData::RemoveActionsByType(parsed_permissions)
                },
                "RemoveActionsByIndex" => {
                    if indices.is_empty() {
                        return Err(anyhow!(
                            "Indices are required for RemoveActionsByIndex operation"
                        ));
                    }
                    UpdateAuthorityData::RemoveActionsByIndex(indices)
                },
                _ => {
                    return Err(anyhow!(
                        "Invalid operation: {}. Must be one of: ReplaceAll, AddActions, \
                         RemoveActionsByType, RemoveActionsByIndex",
                        operation
                    ))
                },
            };

            ctx.wallet
                .as_mut()
                .unwrap()
                .update_authority(authority_to_update_id, update_data)?;

            println!("Authority updated successfully!");
            Ok(())
        },
    }
}

pub fn parse_authority_type(authority_type: String) -> Result<AuthorityType> {
    match authority_type.as_str() {
        "Ed25519" => Ok(AuthorityType::Ed25519),
        "Secp256k1" => Ok(AuthorityType::Secp256k1),
        "Secp256r1" => Ok(AuthorityType::Secp256r1),
        "Ed25519Session" => Ok(AuthorityType::Ed25519Session),
        "Secp256k1Session" => Ok(AuthorityType::Secp256k1Session),
        "Secp256r1Session" => Ok(AuthorityType::Secp256r1Session),
        _ => Err(anyhow!("Invalid authority type: {}", authority_type)),
    }
}
