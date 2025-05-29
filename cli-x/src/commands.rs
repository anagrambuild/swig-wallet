use alloy_primitives::{Address, B256};
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use anyhow::{anyhow, Result};
use colored::*;
use serde_json::Value;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, system_instruction};
use std::str::FromStr;
use swig_sdk::{
    authority::AuthorityType, AuthorityManager, Permission, RecurringConfig, SwigError, SwigWallet,
};

use crate::{format_authority, Command, SwigCliContext};

pub fn create_swig_instance(
    ctx: &mut SwigCliContext,
    swig_id: [u8; 32],
    authority_type: AuthorityType,
    authority: String,
    authority_kp: String,
) -> Result<Box<SwigWallet<'static>>> {
    let (authority_manager, signing_authority) = match authority_type {
        AuthorityType::Ed25519 => {
            let authority_kp = Keypair::from_base58_string(&authority_kp);
            let authority = Pubkey::from_str(&authority)?;

            (AuthorityManager::Ed25519(authority), Some(authority_kp))
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
                AuthorityManager::Secp256k1(eth_pubkey, Box::new(sign_fn)),
                None,
            )
        },
        _ => return Err(anyhow!("Unsupported authority type")),
    };

    // Create a static reference to avoid lifetime issues
    let payer = Box::new(ctx.payer.insecure_clone());
    let auth_for_wallet = Box::new(signing_authority.unwrap_or_else(|| ctx.payer.insecure_clone()));

    // Convert to static references
    let payer_static = Box::leak(payer);
    let auth_static = Box::leak(auth_for_wallet);

    SwigWallet::new(
        swig_id,
        authority_manager,
        payer_static,
        auth_static,
        ctx.rpc_url.clone(),
    )
    .map(Box::new)
    .map_err(|e| anyhow!("Failed to create SWIG wallet: {}", e))
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

            // Set the fee payer from command args or config
            let fee_payer_str =
                fee_payer.unwrap_or_else(|| ctx.config.default_authority.fee_payer.clone());
            ctx.payer = Keypair::from_base58_string(&fee_payer_str);

            let mut wallet = create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
            )?;

            ctx.wallet = Some(wallet);

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

            // Set the fee payer from command args or config
            let fee_payer_str =
                fee_payer.unwrap_or_else(|| ctx.config.default_authority.fee_payer.clone());
            ctx.payer = Keypair::from_base58_string(&fee_payer_str);

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

            let mut wallet = create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
            )?;

            let new_authority =
                new_authority.ok_or_else(|| anyhow!("New authority is required"))?;
            let new_authority_type =
                new_authority_type.ok_or_else(|| anyhow!("New authority type is required"))?;

            let new_authority_type = parse_authority_type(new_authority_type)?;
            let authority_bytes = format_authority(&new_authority, &new_authority_type)?;

            wallet.add_authority(new_authority_type, &authority_bytes, parsed_permissions)?;

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

            // Set the fee payer from command args or config
            let fee_payer_str =
                fee_payer.unwrap_or_else(|| ctx.config.default_authority.fee_payer.clone());
            ctx.payer = Keypair::from_base58_string(&fee_payer_str);

            let mut wallet = create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
            )?;

            let remove_authority =
                remove_authority.ok_or_else(|| anyhow!("Remove authority is required"))?;
            wallet.remove_authority(remove_authority.as_bytes())?;
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

            let wallet = create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
            )?;

            wallet.display_swig()?;
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
                format_authority(&authority_to_fetch, &fetch_authority_type)?;

            let wallet = create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
            )?;

            let role_id = wallet.get_role_id(&fetch_authority_bytes)?;
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

            let wallet = create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
            )?;

            let balance = wallet.get_balance()?;
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

            let mut wallet = create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
            )?;

            let signature = wallet.create_sub_account()?;
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

            let mut wallet = create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
            )?;

            let sub_account = wallet.get_sub_account()?;
            if let Some(sub_account) = sub_account {
                let recipient = Pubkey::from_str(&recipient)?;
                let transfer_ix = system_instruction::transfer(&sub_account, &recipient, amount);
                let signature = wallet.sign_with_sub_account(vec![transfer_ix], None)?;
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

            let mut wallet = create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
            )?;

            let sub_account = wallet.get_sub_account()?;
            if let Some(sub_account) = sub_account {
                wallet.toggle_sub_account(sub_account, enabled)?;
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

            let mut wallet = create_swig_instance(
                ctx,
                swig_id,
                parse_authority_type(
                    authority_type
                        .unwrap_or_else(|| ctx.config.default_authority.authority_type.clone()),
                )?,
                authority.unwrap_or_else(|| ctx.config.default_authority.authority.clone()),
                authority_kp.unwrap_or_else(|| ctx.config.default_authority.authority_kp.clone()),
            )?;

            let sub_account = Pubkey::from_str(&sub_account)?;
            wallet.withdraw_from_sub_account(sub_account, amount)?;
            println!("Successfully withdrew {} lamports from sub-account", amount);
            Ok(())
        },
    }
}

pub fn parse_authority_type(authority_type: String) -> Result<AuthorityType> {
    match authority_type.as_str() {
        "Ed25519" => Ok(AuthorityType::Ed25519),
        "Secp256k1" => Ok(AuthorityType::Secp256k1),
        _ => Err(anyhow!("Invalid authority type: {}", authority_type)),
    }
}
