use alloy_primitives::{Address, B256};
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use anyhow::{anyhow, Result};
use colored::*;
use solana_sdk::{pubkey::Pubkey, signature::Keypair};
use std::str::FromStr;
use swig_sdk::{authority::AuthorityType, AuthorityManager, Permission, SwigError, SwigWallet};

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

            // Parse permissions
            if permissions.is_empty() {
                return Err(anyhow!("Permissions are required"));
            }
            let parsed_permissions = permissions
                .iter()
                .map(|p| match p.to_lowercase().as_str() {
                    "all" => Ok(Permission::All),
                    "sol" => Ok(Permission::Sol {
                        amount: 1_000_000_000,
                        recurring: None,
                    }),
                    _ => Err(anyhow!("Invalid permission: {}", p)),
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
    }
}

pub fn parse_authority_type(authority_type: String) -> Result<AuthorityType> {
    match authority_type.as_str() {
        "Ed25519" => Ok(AuthorityType::Ed25519),
        "Secp256k1" => Ok(AuthorityType::Secp256k1),
        _ => Err(anyhow!("Invalid authority type: {}", authority_type)),
    }
}
