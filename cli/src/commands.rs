use std::{collections::HashMap, str::FromStr};

use alloy_primitives::{Address, B256};
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use anyhow::{anyhow, Result};
use colored::*;
use hex;
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    nid::Nid,
};
use rand::Rng;
use serde_json::Value;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
};
use solana_secp256r1_program;
use swig_sdk::{
    authority::{
        ed25519::CreateEd25519SessionAuthority, secp256k1::CreateSecp256k1SessionAuthority,
        secp256r1::CreateSecp256r1SessionAuthority, AuthorityType,
    },
    client_role::{
        Ed25519SessionClientRole, Secp256k1SessionClientRole, Secp256r1ClientRole,
        Secp256r1SessionClientRole,
    },
    swig::SwigWithRoles,
    types::UpdateAuthorityData,
    ClientRole, Ed25519ClientRole, Permission, RecurringConfig, Secp256k1ClientRole, SwigError,
    SwigWallet,
};
use swig_state::IntoBytes;

use crate::{Command, SwigCliContext};

pub fn create_swig_instance(
    ctx: &mut SwigCliContext,
    swig_id: [u8; 32],
    authority_type: AuthorityType,
    authority: String,
    authority_kp: String,
    fee_payer_string: Option<String>,
) -> Result<()> {
    let fee_payer = Keypair::from_base58_string(
        &fee_payer_string.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
    );
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
            // For Secp256r1, the authority_kp should be a hex string of the raw private key (32 bytes)
            let hex_key = authority_kp
                .trim()
                .strip_prefix("0x")
                .unwrap_or(authority_kp.trim());

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
            let private_key_bn = openssl::bn::BigNum::from_slice(&key_bytes)
                .map_err(|_| anyhow!("Failed to create BigNum from private key bytes"))?;

            // Create EC group for secp256r1 (P-256)
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                .map_err(|_| anyhow!("Failed to create EC group"))?;

            // Compute the public key: pub_key = private_key * generator
            let mut ctx =
                BigNumContext::new().map_err(|_| anyhow!("Failed to create BigNum context"))?;
            let mut pub_key =
                EcPoint::new(&group).map_err(|_| anyhow!("Failed to create EC point"))?;
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
        AuthorityType::Ed25519Session => {
            // For Ed25519Session, we need the main authority pubkey and session key
            let authority_kp = Keypair::from_base58_string(&authority_kp);
            let authority = Pubkey::from_str(&authority)?;

            // For session authorities, we need additional parameters
            // For now, we'll use default values, but in a real implementation,
            // these should be passed as parameters
            let session_key = Keypair::new(); // This should be provided as a parameter
            let max_session_length = 100; // This should be provided as a parameter

            (
                Box::new(Ed25519SessionClientRole::new(
                    authority,
                    session_key.pubkey(),
                    max_session_length,
                )) as Box<dyn ClientRole>,
                fee_payer.insecure_clone(),
            )
        },
        AuthorityType::Secp256k1Session => {
            let wallet = LocalSigner::from_str(&authority_kp)?;
            let eth_pubkey = wallet
                .credential()
                .verifying_key()
                .to_encoded_point(false)
                .to_bytes();

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

            // For session authorities, we need additional parameters
            let session_key = Keypair::new(); // This should be provided as a parameter
            let max_session_length = 100; // This should be provided as a parameter

            (
                Box::new(Secp256k1SessionClientRole::new(
                    eth_pubkey[1..].try_into().unwrap(),
                    session_key.pubkey(),
                    max_session_length,
                    Box::new(sign_fn),
                )) as Box<dyn ClientRole>,
                fee_payer.insecure_clone(),
            )
        },
        AuthorityType::Secp256r1Session => {
            // For Secp256r1Session, the authority_kp should be a hex string of the raw private key (32 bytes)
            let hex_key = authority_kp
                .trim()
                .strip_prefix("0x")
                .unwrap_or(authority_kp.trim());

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
            let private_key_bn = openssl::bn::BigNum::from_slice(&key_bytes)
                .map_err(|_| anyhow!("Failed to create BigNum from private key bytes"))?;

            // Create EC group for secp256r1 (P-256)
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                .map_err(|_| anyhow!("Failed to create EC group"))?;

            // Compute the public key: pub_key = private_key * generator
            let mut ctx =
                BigNumContext::new().map_err(|_| anyhow!("Failed to create BigNum context"))?;
            let mut pub_key =
                EcPoint::new(&group).map_err(|_| anyhow!("Failed to create EC point"))?;
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

            // For session authorities, we need additional parameters
            let session_key = Keypair::new(); // This should be provided as a parameter
            let max_session_length = 100; // This should be provided as a parameter

            (
                Box::new(Secp256r1SessionClientRole::new(
                    compressed_pubkey,
                    session_key.pubkey(),
                    max_session_length,
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
        Some("programCurated") => Ok(Permission::ProgramCurated),
        Some("sol") => {
            let amount = if let Some(amount_str) = permission_json["amount"].as_str() {
                amount_str.parse::<u64>().unwrap_or(1_000_000_000)
            } else {
                permission_json["amount"].as_u64().unwrap_or(1_000_000_000)
            };
            let recurring = if let Some(recurring) = permission_json.get("recurring") {
                let window = recurring["window"].as_u64().unwrap_or(86400);
                Some(swig_sdk::RecurringConfig::new(window))
            } else {
                None
            };
            Ok(Permission::Sol { amount, recurring })
        },
        Some("token") => {
            let mint = permission_json["mint"]
                .as_str()
                .ok_or_else(|| anyhow!("Mint is required for token permission"))?;
            let amount = if let Some(amount_str) = permission_json["amount"].as_str() {
                amount_str.parse::<u64>().unwrap_or(1_000_000_000)
            } else {
                permission_json["amount"].as_u64().unwrap_or(1_000_000_000)
            };
            let recurring = if let Some(recurring) = permission_json.get("recurring") {
                let window = recurring["window"].as_u64().unwrap_or(86400);
                Some(swig_sdk::RecurringConfig::new(window))
            } else {
                None
            };
            Ok(Permission::Token {
                mint: Pubkey::from_str(mint)?,
                amount,
                recurring,
            })
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
        Some("programAll") => Ok(Permission::ProgramAll),
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
        Some("solDestination") => {
            let destination = permission_json["destination"]
                .as_str()
                .ok_or_else(|| anyhow!("Destination is required for SOL destination permission"))?;
            let amount = if let Some(amount_str) = permission_json["amount"].as_str() {
                amount_str.parse::<u64>().unwrap_or(1_000_000_000)
            } else {
                permission_json["amount"].as_u64().unwrap_or(1_000_000_000)
            };
            let recurring = if let Some(recurring) = permission_json.get("recurring") {
                let window = recurring["window"].as_u64().unwrap_or(86400);
                Some(swig_sdk::RecurringConfig::new(window))
            } else {
                None
            };
            Ok(Permission::SolDestination {
                destination: Pubkey::from_str(destination)?,
                amount,
                recurring,
            })
        },
        Some("tokenDestination") => {
            let mint = permission_json["mint"]
                .as_str()
                .ok_or_else(|| anyhow!("Mint is required for token destination permission"))?;
            let destination = permission_json["destination"].as_str().ok_or_else(|| {
                anyhow!("Destination is required for token destination permission")
            })?;
            let amount = if let Some(amount_str) = permission_json["amount"].as_str() {
                amount_str.parse::<u64>().unwrap_or(1_000_000_000)
            } else {
                permission_json["amount"].as_u64().unwrap_or(1_000_000_000)
            };
            let recurring = if let Some(recurring) = permission_json.get("recurring") {
                let window = recurring["window"].as_u64().unwrap_or(86400);
                Some(swig_sdk::RecurringConfig::new(window))
            } else {
                None
            };
            Ok(Permission::TokenDestination {
                mint: Pubkey::from_str(mint)?,
                destination: Pubkey::from_str(destination)?,
                amount,
                recurring,
            })
        },
        Some("stake") => {
            let amount = if let Some(amount_str) = permission_json["amount"].as_str() {
                amount_str.parse::<u64>().unwrap_or(1_000_000_000)
            } else {
                permission_json["amount"].as_u64().unwrap_or(1_000_000_000)
            };
            let recurring = if let Some(recurring) = permission_json.get("recurring") {
                let window = recurring["window"].as_u64().unwrap_or(86400);
                Some(swig_sdk::RecurringConfig::new(window))
            } else {
                None
            };
            Ok(Permission::Stake { amount, recurring })
        },
        Some("stakeAll") => Ok(Permission::StakeAll),
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

            println!("{}", "✅ SWIG wallet created successfully!".green().bold());
            ctx.wallet.as_ref().unwrap().display_swig()?;
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
            session_key,
            max_session_length,
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
            let mut authority_bytes = crate::format_authority(&new_authority, &new_authority_type)?;

            match new_authority_type {
                AuthorityType::Secp256r1Session => {
                    let session_key = Pubkey::from_str(&session_key.unwrap())?;
                    let max_session_length = max_session_length.unwrap();
                    let session_data = CreateSecp256r1SessionAuthority::new(
                        authority_bytes.try_into().unwrap(),
                        session_key.to_bytes(),
                        max_session_length,
                    );
                    authority_bytes = session_data.into_bytes().unwrap().to_vec();
                },
                AuthorityType::Secp256k1Session => {
                    let session_key = Pubkey::from_str(&session_key.unwrap())?;
                    let max_session_length = max_session_length.unwrap();
                    let session_data = CreateSecp256k1SessionAuthority::new(
                        authority_bytes.try_into().unwrap(),
                        session_key.to_bytes(),
                        max_session_length,
                    );
                    authority_bytes = session_data.into_bytes().unwrap().to_vec();
                },
                AuthorityType::Ed25519Session => {
                    let session_key = Pubkey::from_str(&session_key.unwrap())?;
                    let max_session_length = max_session_length.unwrap();
                    let session_data = CreateEd25519SessionAuthority::new(
                        authority_bytes.try_into().unwrap(),
                        session_key.to_bytes(),
                        max_session_length,
                    );
                    authority_bytes = session_data.into_bytes().unwrap().to_vec();
                },
                _ => {},
            }
            // Store values for display before moving them
            let authority_type_display = format!("{:?}", new_authority_type);
            let permissions_count = parsed_permissions.len();

            ctx.wallet.as_mut().unwrap().add_authority(
                new_authority_type,
                &authority_bytes,
                parsed_permissions,
            )?;

            println!("{}", "✅ Authority added successfully!".green().bold());
            println!("New Authority: {}", new_authority);
            println!("Authority Type: {}", authority_type_display);
            println!(
                "Permissions: {} permission(s) configured",
                permissions_count
            );

            // Display updated wallet state
            println!("\n{}", "📋 Updated SWIG Wallet:".blue().bold());
            ctx.wallet.as_ref().unwrap().display_swig()?;
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
            println!("{}", "✅ Authority removed successfully!".green().bold());
            println!("Removed Authority: {}", remove_authority);

            // Display updated wallet state
            println!("\n{}", "📋 Updated SWIG Wallet:".blue().bold());
            ctx.wallet.as_ref().unwrap().display_swig()?;
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
            println!("{}", "✅ Wallet loaded successfully!".green().bold());
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
            println!("{}", "✅ Sub-account created successfully!".green().bold());
            println!("Signature: {}", signature);

            // Display updated wallet state
            println!("\n{}", "📋 Updated SWIG Wallet:".blue().bold());
            ctx.wallet.as_ref().unwrap().display_swig()?;
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
                println!("{}", "✅ Transfer successful!".green().bold());
                println!("Signature: {}", signature);
                println!(
                    "Amount: {} lamports ({:.9} SOL)",
                    amount,
                    amount as f64 / 1_000_000_000.0
                );
                println!("From Sub-account: {}", sub_account);
                println!("Recipient: {}", recipient);

                // Display updated wallet state
                println!("\n{}", "📋 Updated SWIG Wallet:".blue().bold());
                ctx.wallet.as_ref().unwrap().display_swig()?;
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
            sub_account_role_id,
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
            let current_role_id = ctx.wallet.as_ref().unwrap().get_current_role_id()?;
            if let Some(sub_account) = sub_account {
                ctx.wallet.as_mut().unwrap().toggle_sub_account(
                    sub_account,
                    current_role_id,
                    sub_account_role_id,
                    enabled,
                )?;
                println!(
                    "Sub-account {} successfully!",
                    if enabled { "enabled" } else { "disabled" }
                );

                // Display updated wallet state
                println!("\n{}", "📋 Updated SWIG Wallet:".blue().bold());
                ctx.wallet.as_ref().unwrap().display_swig()?;
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

            // Display updated wallet state
            println!("\n{}", "📋 Updated SWIG Wallet:".blue().bold());
            ctx.wallet.as_ref().unwrap().display_swig()?;
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
                            "ProgramAll" => Ok(Permission::ProgramAll),
                            "ProgramCurated" => Ok(Permission::ProgramCurated),
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
                            "SolDestination" => Ok(Permission::SolDestination {
                                destination: Pubkey::default(),
                                amount: 0,
                                recurring: None,
                            }),
                            "TokenDestination" => Ok(Permission::TokenDestination {
                                mint: Pubkey::default(),
                                destination: Pubkey::default(),
                                amount: 0,
                                recurring: None,
                            }),
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

            println!("{}", "✅ Authority updated successfully!".green().bold());
            println!("Role ID: {}", authority_to_update_id);
            println!("Operation: {}", operation);

            // Display updated wallet state
            println!("\n{}", "📋 Updated SWIG Wallet:".blue().bold());
            ctx.wallet.as_ref().unwrap().display_swig()?;
            Ok(())
        },
        Command::CreateSession {
            authority_type,
            authority,
            authority_kp,
            id,
            session_key,
            max_session_length,
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

            let session_pubkey = Pubkey::from_str(&session_key)?;
            let max_length = max_session_length.unwrap_or(100);

            let signature = ctx
                .wallet
                .as_mut()
                .unwrap()
                .create_session(session_pubkey, max_length)?;

            println!("{}", "✅ Session created successfully!".green().bold());
            println!("Session key: {}", session_pubkey);
            println!("Max session length: {} slots", max_length);

            // Display updated wallet state
            println!("\n{}", "📋 Updated SWIG Wallet:".blue().bold());
            ctx.wallet.as_ref().unwrap().display_swig()?;
            Ok(())
        },
        Command::TransferSession {
            authority_type,
            authority,
            authority_kp,
            id,
            recipient,
            amount,
            session_keypair,
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

            let session_keypair = Keypair::from_base58_string(&session_keypair);

            let swig_wallet_address = ctx.wallet.as_ref().unwrap().get_swig_wallet_address()?;
            let transfer_instruction = system_instruction::transfer(
                &swig_wallet_address,
                &Pubkey::from_str(&recipient)?,
                amount,
            );

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

            println!("Transfer with session successful!");
            println!("Signature: {}", signature);
            println!("Amount: {} lamports", amount);
            println!("Recipient: {}", recipient);

            // Display updated wallet state
            println!("\n{}", "📋 Updated SWIG Wallet:".blue().bold());
            ctx.wallet.as_ref().unwrap().display_swig()?;
            Ok(())
        },
        Command::SwitchAuthority {
            authority_type,
            authority,
            authority_kp,
            fee_payer,
            id,
            role_id,
            new_authority_type,
            new_authority_kp,
            session_key,
            max_session_length,
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

            let new_authority_type = parse_authority_type(
                new_authority_type
                    .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
            )?;

            let new_authority_kp = new_authority_kp
                .unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone());

            let client_role: Box<dyn ClientRole> = match new_authority_type {
                AuthorityType::Ed25519 => {
                    let authority = Keypair::from_base58_string(&new_authority_kp);
                    let authority_pubkey = authority.pubkey();
                    Box::new(Ed25519ClientRole::new(authority_pubkey))
                },
                AuthorityType::Ed25519Session => {
                    let authority = Keypair::from_base58_string(&new_authority_kp);
                    let authority_pubkey = authority.pubkey();
                    let session_keypair =
                        Keypair::from_base58_string(&session_key.ok_or_else(|| {
                            anyhow!("Session key is required for Ed25519Session")
                        })?);
                    let max_length = max_session_length.unwrap_or(100);
                    Box::new(Ed25519SessionClientRole::new(
                        authority_pubkey,
                        session_keypair.pubkey(),
                        max_length,
                    ))
                },
                AuthorityType::Secp256k1 => {
                    let wallet = LocalSigner::from_str(&new_authority_kp)?;
                    let eth_pubkey = wallet
                        .credential()
                        .verifying_key()
                        .to_encoded_point(false)
                        .to_bytes();

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

                    Box::new(Secp256k1ClientRole::new(
                        eth_pubkey[1..].to_vec().into_boxed_slice(),
                        Box::new(sign_fn),
                    ))
                },
                AuthorityType::Secp256k1Session => {
                    let wallet = LocalSigner::from_str(&new_authority_kp)?;
                    let eth_pubkey = wallet
                        .credential()
                        .verifying_key()
                        .to_encoded_point(false)
                        .to_bytes();

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

                    let session_keypair =
                        Keypair::from_base58_string(&session_key.ok_or_else(|| {
                            anyhow!("Session key is required for Secp256k1Session")
                        })?);
                    let max_length = max_session_length.unwrap_or(100);

                    Box::new(Secp256k1SessionClientRole::new(
                        eth_pubkey[1..].try_into().unwrap(),
                        session_keypair.pubkey(),
                        max_length,
                        Box::new(sign_fn),
                    ))
                },
                AuthorityType::Secp256r1 => {
                    let hex_key = new_authority_kp
                        .trim()
                        .strip_prefix("0x")
                        .unwrap_or(new_authority_kp.trim());

                    // Decode hex string to bytes
                    let mut key_bytes = hex::decode(hex_key)
                        .map_err(|_| anyhow!("Invalid hex format for private key"))?;

                    // Pad to 32 bytes if necessary (left-pad with zeros)
                    if key_bytes.len() < 32 {
                        let mut padded = vec![0u8; 32 - key_bytes.len()];
                        padded.extend_from_slice(&key_bytes);
                        key_bytes = padded;
                    } else if key_bytes.len() > 32 {
                        return Err(anyhow!("Private key too long (expected 32 bytes or less)"));
                    }

                    // Create BigNum from bytes
                    let private_key_bn = openssl::bn::BigNum::from_slice(&key_bytes)
                        .map_err(|_| anyhow!("Failed to create BigNum from private key bytes"))?;

                    // Create EC group for secp256r1 (P-256)
                    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                        .map_err(|_| anyhow!("Failed to create EC group"))?;

                    // Compute the public key: pub_key = private_key * generator
                    let mut ctx = BigNumContext::new()
                        .map_err(|_| anyhow!("Failed to create BigNum context"))?;
                    let mut pub_key =
                        EcPoint::new(&group).map_err(|_| anyhow!("Failed to create EC point"))?;
                    pub_key
                        .mul_generator(&group, &private_key_bn, &ctx)
                        .map_err(|_| anyhow!("Failed to compute public key"))?;

                    // Create EcKey from private key and computed public key
                    let signing_key =
                        EcKey::from_private_components(&group, &private_key_bn, &pub_key)
                            .map_err(|_| anyhow!("Failed to create EcKey from private key"))?;

                    // Verify the key is valid
                    signing_key
                        .check_key()
                        .map_err(|_| anyhow!("Private key validation failed"))?;

                    let mut ctx_bn = BigNumContext::new()
                        .map_err(|_| anyhow!("Failed to create BigNum context"))?;
                    let pubkey_bytes = signing_key
                        .public_key()
                        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx_bn)
                        .map_err(|_| anyhow!("Failed to get public key bytes"))?;

                    let compressed_pubkey: [u8; 33] = pubkey_bytes
                        .try_into()
                        .map_err(|_| anyhow!("Invalid public key length"))?;

                    let signing_key_clone = signing_key.clone();
                    let sign_fn = move |payload: &[u8]| -> [u8; 64] {
                        let signature = solana_secp256r1_program::sign_message(
                            payload,
                            &signing_key_clone.private_key_to_der().unwrap(),
                        )
                        .unwrap();
                        signature
                    };

                    Box::new(Secp256r1ClientRole::new(
                        compressed_pubkey,
                        Box::new(sign_fn),
                    ))
                },
                AuthorityType::Secp256r1Session => {
                    let hex_key = new_authority_kp
                        .trim()
                        .strip_prefix("0x")
                        .unwrap_or(new_authority_kp.trim());

                    // Decode hex string to bytes
                    let mut key_bytes = hex::decode(hex_key)
                        .map_err(|_| anyhow!("Invalid hex format for private key"))?;

                    // Pad to 32 bytes if necessary (left-pad with zeros)
                    if key_bytes.len() < 32 {
                        let mut padded = vec![0u8; 32 - key_bytes.len()];
                        padded.extend_from_slice(&key_bytes);
                        key_bytes = padded;
                    } else if key_bytes.len() > 32 {
                        return Err(anyhow!("Private key too long (expected 32 bytes or less)"));
                    }

                    // Create BigNum from bytes
                    let private_key_bn = openssl::bn::BigNum::from_slice(&key_bytes)
                        .map_err(|_| anyhow!("Failed to create BigNum from private key bytes"))?;

                    // Create EC group for secp256r1 (P-256)
                    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                        .map_err(|_| anyhow!("Failed to create EC group"))?;

                    // Compute the public key: pub_key = private_key * generator
                    let mut ctx = BigNumContext::new()
                        .map_err(|_| anyhow!("Failed to create BigNum context"))?;
                    let mut pub_key =
                        EcPoint::new(&group).map_err(|_| anyhow!("Failed to create EC point"))?;
                    pub_key
                        .mul_generator(&group, &private_key_bn, &ctx)
                        .map_err(|_| anyhow!("Failed to compute public key"))?;

                    // Create EcKey from private key and computed public key
                    let signing_key =
                        EcKey::from_private_components(&group, &private_key_bn, &pub_key)
                            .map_err(|_| anyhow!("Failed to create EcKey from private key"))?;

                    // Verify the key is valid
                    signing_key
                        .check_key()
                        .map_err(|_| anyhow!("Private key validation failed"))?;

                    let mut ctx_bn = BigNumContext::new()
                        .map_err(|_| anyhow!("Failed to create BigNum context"))?;
                    let pubkey_bytes = signing_key
                        .public_key()
                        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx_bn)
                        .map_err(|_| anyhow!("Failed to get public key bytes"))?;

                    let compressed_pubkey: [u8; 33] = pubkey_bytes
                        .try_into()
                        .map_err(|_| anyhow!("Invalid public key length"))?;

                    let signing_key_clone = signing_key.clone();
                    let sign_fn = move |payload: &[u8]| -> [u8; 64] {
                        let signature = solana_secp256r1_program::sign_message(
                            payload,
                            &signing_key_clone.private_key_to_der().unwrap(),
                        )
                        .unwrap();
                        signature
                    };

                    let session_keypair =
                        Keypair::from_base58_string(&session_key.ok_or_else(|| {
                            anyhow!("Session key is required for Secp256r1Session")
                        })?);
                    let max_length = max_session_length.unwrap_or(100);

                    Box::new(Secp256r1SessionClientRole::new(
                        compressed_pubkey,
                        session_keypair.pubkey(),
                        max_length,
                        Box::new(sign_fn),
                    ))
                },
                AuthorityType::None => return Err(anyhow!("Cannot switch to None authority type")),
            };

            ctx.wallet
                .as_mut()
                .unwrap()
                .switch_authority(role_id, client_role, None)?;

            println!(
                "{}",
                "✅ Successfully switched to authority role ID: {}"
                    .green()
                    .bold()
            );
            println!("Role ID: {}", role_id);
            Ok(())
        },
        Command::Transfer {
            authority_type,
            authority,
            authority_kp,
            fee_payer,
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
                fee_payer,
            )?;

            let swig_wallet_address = ctx.wallet.as_ref().unwrap().get_swig_wallet_address()?;
            let transfer_instruction = system_instruction::transfer(
                &swig_wallet_address,
                &Pubkey::from_str(&recipient)?,
                amount,
            );

            // Always use sign_v2 for transfers
            let signature = ctx
                .wallet
                .as_mut()
                .unwrap()
                .sign_v2(vec![transfer_instruction], None)?;

            println!("{}", "✅ Transfer successful!".green().bold());
            println!("Signature: {}", signature);
            println!(
                "Amount: {} lamports ({:.9} SOL)",
                amount,
                amount as f64 / 1_000_000_000.0
            );
            println!("Recipient: {}", recipient);

            // Display updated wallet state
            println!("\n{}", "📋 Updated SWIG Wallet:".blue().bold());
            ctx.wallet.as_ref().unwrap().display_swig()?;
            Ok(())
        },
        Command::CheckSessionStatus {
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
        },
        Command::TransferWithSession {
            authority_type,
            authority,
            authority_kp,
            fee_payer,
            id,
            recipient,
            amount,
            session_keypair,
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

            let session_keypair = Keypair::from_base58_string(&session_keypair);

            let swig_wallet_address = ctx.wallet.as_ref().unwrap().get_swig_wallet_address()?;
            let transfer_instruction = system_instruction::transfer(
                &swig_wallet_address,
                &Pubkey::from_str(&recipient)?,
                amount,
            );

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

            println!("Transfer with session successful!");
            println!("Signature: {}", signature);
            println!("Amount: {} lamports", amount);
            println!("Recipient: {}", recipient);

            // Display updated wallet state
            println!("\n{}", "📋 Updated SWIG Wallet:".blue().bold());
            ctx.wallet.as_ref().unwrap().display_swig()?;
            Ok(())
        },
        Command::LoadWallet {
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

            println!("Wallet loaded successfully!");
            ctx.wallet.as_ref().unwrap().display_swig()?;
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

/// Get all authorities from a SWIG wallet
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
pub fn validate_secp256r1_public_key(public_key: &[u8; 33]) -> Result<(), anyhow::Error> {
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
