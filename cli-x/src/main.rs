use alloy_primitives::{Address, B256};
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use console::Term;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password, Select};
use directories::BaseDirs;
use indicatif::{ProgressBar, ProgressStyle};
use secp256k1::{PublicKey as Secp256k1PublicKey, Secp256k1, SecretKey as Secp256k1SecretKey};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signer},
    system_instruction::transfer,
};
use swig_sdk::{
    authority::{ed25519::CreateEd25519SessionAuthority, AuthorityType},
    swig::SwigWithRoles,
    AuthorityManager, Permission, RecurringConfig, SwigError, SwigWallet,
};

mod commands;
mod config;
mod interactive;

use commands::run_command_mode;
use config::SwigConfig;
use interactive::run_interactive_mode;

const LOGO: &str = r#"
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@P!.       :!P@@@@@@@@@@@@@@@@@@B5YYPB@@@@@@@BGGG#@@@@@@@@@@GG#@@@#GGB@@@@@@@BP5JYPG@@@@@@@@@
@@@@@#^   ~YGGPY7:    ~@@@@@@@@@@@@@@?        ?@@@P      Y@@@@@@@B    5@@?  :@@@@P~.        :Y@@@@@@
@@@@7    .@@@@@@@@@B^   Y@@@@@@@@@@@5   P@@B\ 7#@J P@    B@#  !@@7   .@@?   :@@@^   ?G#@#BY: ^G@@@@@
@@@?        ..:7P@@@@P   P@@@@@@@@@@#.   7PB@@@@#  @?  :#@P     G@@G: .@@?  :@@~  .#@@@@@@@@@@@@@@@@
@@@               7@@@~  .@@@@@@@@@@@@5^     ^P@@PB@. ?@@!   7#. @@@@  @@?  :@@.  7@@@@G     :.?@@@@
@@@                 ~~   .@@@@@@@@@@@B@@@#G7   Y@@@Y G@G.  .G@:  G@@@ 5@@?  :@@~  .#@@@#???7   J@@@@
@@@7                     5@@@@@@@@@#:  Y#@@B   ?@@@  P7   7@@^   .YJ J@@@?  :@@@^   ?B#@@#P:  !@@@@@
@@@@!                   J@@@@@@@@@@@B~       .7@@@@7    :B@@@:      G@@@@?  :@@@@5^         ^P@@@@@@
@@@@@G:               ^#@@@@@@@@@@@@@@@G   .:@@@@@@@B  B@@@@@@    #@@@@@@?  :@@@@@@@G.....G#@@@@@@@@
@@@@@@@#J^.       .~5@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
"#;

#[derive(Parser, Debug)]
#[command(
    name = "swig",
    about = "SWIG CLI - A command-line interface for the SWIG wallet",
    version
)]
pub struct SwigCli {
    #[arg(short = 'c', long, help = "Path to Solana config file")]
    pub config: Option<String>,

    #[arg(short = 'k', long, help = "Path to keypair file")]
    pub keypair: Option<String>,

    #[arg(short = 'u', long, help = "RPC URL")]
    pub rpc_url: Option<String>,

    #[arg(short = 'i', long, help = "Use interactive mode")]
    pub interactive: bool,

    #[arg(short = 's', long, help = "Save current authority settings as default")]
    pub save_config: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Create a new SWIG wallet
    Create {
        #[arg(short, long)]
        authority_type: Option<String>,
        #[arg(short, long)]
        authority: Option<String>,
        #[arg(short, long)]
        authority_kp: Option<String>,
        #[arg(short, long)]
        fee_payer: Option<String>,
        #[arg(short, long = "swig-id")]
        id: Option<String>,
    },
    /// Add a new authority to a wallet
    AddAuthority {
        // Signing authority
        #[arg(short, long)]
        authority_type: Option<String>,
        #[arg(short, long)]
        authority: Option<String>,
        #[arg(short, long)]
        authority_kp: Option<String>,
        #[arg(short, long)]
        fee_payer: Option<String>,
        #[arg(short, long = "swig-id")]
        id: String,
        // New authority
        #[arg(short, long)]
        new_authority: Option<String>,
        #[arg(short, long)]
        new_authority_type: Option<String>,
        #[arg(short, long, value_parser, num_args = 1.., value_delimiter = ',')]
        permissions: Vec<String>,
    },
    /// Remove an authority from a wallet
    RemoveAuthority {
        // Signing authority
        #[arg(short, long)]
        authority_type: Option<String>,
        #[arg(short, long)]
        authority: Option<String>,
        #[arg(short, long)]
        authority_kp: Option<String>,
        #[arg(short, long)]
        fee_payer: Option<String>,
        #[arg(short, long = "swig-id")]
        id: String,
        // Remove authority
        #[arg(short, long)]
        remove_authority: Option<String>,
    },
    /// View wallet details
    View {
        // Signing authority
        #[arg(short, long)]
        authority_type: Option<String>,
        #[arg(short, long)]
        authority: Option<String>,
        #[arg(short, long)]
        authority_kp: Option<String>,
        #[arg(short, long = "swig-id")]
        id: String,
    },
    /// Check wallet balance
    Balance {
        // Signing authority
        #[arg(short, long)]
        authority_type: Option<String>,
        #[arg(short, long)]
        authority: Option<String>,
        #[arg(short, long)]
        authority_kp: Option<String>,
        #[arg(short, long = "swig-id")]
        id: String,
    },
    /// Get role id
    GetRoleId {
        // Signing authority
        #[arg(short, long)]
        authority_type: Option<String>,
        #[arg(short, long)]
        authority: Option<String>,
        #[arg(short, long)]
        authority_kp: Option<String>,
        #[arg(short, long = "swig-id")]
        id: String,
        #[arg(short, long)]
        authority_to_fetch: String,
        #[arg(short, long)]
        authority_type_to_fetch: String,
    },
}

pub struct SwigCliContext {
    pub payer: Keypair,
    pub config_dir: PathBuf,
    pub rpc_url: String,
    pub authority: Option<Keypair>,
    pub wallet: Option<Box<SwigWallet<'static>>>,
    pub swig_id: Option<String>,
    pub config: SwigConfig,
}

fn main() -> Result<()> {
    let cli = SwigCli::parse();
    let mut ctx = setup(&cli)?;

    if cli.interactive {
        // Print the logo
        println!("{}", LOGO.bright_cyan());
        run_interactive_mode(&mut ctx)
    } else if let Some(ref cmd) = cli.command {
        run_command_mode(&mut ctx, cmd.clone())
    } else {
        println!("Please specify either --interactive or a command");
        Ok(())
    }
}

fn setup(cli: &SwigCli) -> Result<SwigCliContext> {
    let config_dir = ensure_config_dir()?;

    // Load config
    let mut config = SwigConfig::load(&config_dir)?;

    // Update config from CLI args if provided
    if let Some(ref cmd) = cli.command {
        match cmd {
            Command::Create {
                authority_type,
                authority,
                authority_kp,
                fee_payer,
                ..
            } => {
                config.update_from_cli_args(
                    authority_type.clone(),
                    authority.clone(),
                    authority_kp.clone(),
                    fee_payer.clone(),
                    cli.rpc_url.clone(),
                );
            },
            _ => {},
        }
    }

    // Save config if requested
    if cli.save_config {
        config.save(&config_dir)?;
    }

    // Default values
    let default_rpc_url = "http://localhost:8899".to_string();
    let default_keypair_path = dirs::home_dir()
        .map(|mut p| {
            p.push(".config");
            p.push("solana");
            p.push("id.json");
            p.to_string_lossy().to_string()
        })
        .unwrap_or_else(|| "./.config/solana/id.json".to_string());

    let (rpc_url, keypair_path) = match (&cli.rpc_url, &cli.keypair, &cli.config) {
        (Some(rpc), Some(kp), None) => (rpc.clone(), kp.clone()),
        (Some(rpc), None, None) => (rpc.clone(), default_keypair_path),
        (None, Some(kp), None) => (
            config.rpc_url.clone().unwrap_or(default_rpc_url),
            kp.clone(),
        ),
        (None, None, None) => (
            config.rpc_url.clone().unwrap_or(default_rpc_url),
            default_keypair_path,
        ),
        _ => {
            return Err(anyhow!(
                "Please provide either:\n\
                 1. --rpc-url and/or --keypair\n\
                 2. --config <path-to-solana-config>"
            ));
        },
    };

    let payer = read_keypair_file(&keypair_path)
        .map_err(|e| anyhow!("Failed to read keypair file: {}", e))?;

    Ok(SwigCliContext {
        payer,
        config_dir,
        rpc_url,
        authority: None,
        wallet: None,
        swig_id: None,
        config,
    })
}

fn get_config_path() -> PathBuf {
    if let Some(base_dirs) = BaseDirs::new() {
        base_dirs.data_dir().join("swig-cli")
    } else {
        PathBuf::from(".")
    }
}

fn ensure_config_dir() -> std::io::Result<PathBuf> {
    let config_path = get_config_path();
    std::fs::create_dir_all(&config_path)?;
    Ok(config_path)
}

/// Helper functions for getting inputs from interactive mode
fn get_authority_type() -> Result<AuthorityType> {
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

/// Helper function to get permissions interactively from the user
fn get_permissions_interactive() -> Result<Vec<Permission>> {
    let permission_types = vec![
        "All (Full access to all operations)",
        "Manage Authority (Add/remove authorities)",
        "Token (Token-specific permissions)",
        "SOL (SOL transfer permissions)",
        "Program (Program interaction permissions)",
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
                // Get sub-account address
                let sub_account_str: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter sub-account address")
                    .interact_text()?;
                let sub_account = Pubkey::from_str(&sub_account_str)?;

                Permission::SubAccount { sub_account }
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

fn format_authority(authority: &str, authority_type: &AuthorityType) -> Result<Vec<u8>> {
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

fn get_authorities(ctx: &mut SwigCliContext) -> Result<HashMap<String, Vec<u8>>> {
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
                    // let authority = role.authority.identity().unwrap();
                    // let authority_hex = hex::encode([&[0x4].as_slice(), authority].concat());
                    // //get eth address from public key
                    // let mut hasher = solana_sdk::keccak::Hasher::default();
                    // hasher.hash(authority);
                    // let hash = hasher.result();
                    // let address = format!("0x{}", hex::encode(&hash.0[12..32]));
                    // let authority_pubkey = Secp256k1PublicKey::from_str(&address)?;
                    // authorities.insert(address, authority_pubkey);
                },
                _ => todo!(),
            }
        }
    }

    Ok(authorities)
}
