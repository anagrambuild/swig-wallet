use alloy_primitives::B256;
use alloy_signer_local::LocalSigner;
use std::{
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
};
use swig_sdk::{
    authority::{ed25519::CreateEd25519SessionAuthority, AuthorityType},
    AuthorityManager, Permission, SwigWallet,
};

const LOGO: &str = r#"
   _____ _    _ _____ ______    _____ _      _____ 
  / ____| |  | |_   _|  ____|  / ____| |    |_   _|
 | (___ | |  | | | | | |   __ | |    | |      | |  
  \___ \| |  | | | | |  __ __ | |    | |      | |  
  ____) | |__| |_| |_| |  |   | |____| |____ _| |_ 
 |_____/ \____/|_____|_|_____  \_____|______|_____|
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

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Create a new SWIG wallet
    Create {
        #[arg(short, long)]
        authority_type: String,
        #[arg(short, long)]
        authority: String,
        #[arg(short, long)]
        authority_kp: String,
        #[arg(short, long = "swig-id")]
        id: Option<String>,
    },
    /// Add a new authority to a wallet
    AddAuthority {
        #[arg(short = 't', long)]
        authority_type: String,
        #[arg(short, long)]
        authority: String,
        #[arg(short, long = "swig-id")]
        id: String,
        #[arg(short, long, value_parser, num_args = 1.., value_delimiter = ',')]
        permissions: Vec<String>,
    },
    /// Remove an authority from a wallet
    RemoveAuthority {
        #[arg(short, long = "swig-id")]
        id: String,
        #[arg(short, long)]
        authority: String,
    },
    /// View wallet details
    View {
        #[arg(short, long = "swig-id")]
        id: String,
    },
    /// List all authorities in a wallet
    ListAuthorities {
        #[arg(short, long = "swig-id")]
        id: String,
    },
    /// Check wallet balance
    Balance {
        #[arg(short, long = "swig-id")]
        id: String,
    },
}

pub struct SwigCliContext {
    pub payer: Keypair,
    pub config_dir: PathBuf,
    pub rpc_url: String,
    pub authority: Option<Keypair>,
    pub wallet: Option<Box<SwigWallet<'static>>>,
}

fn main() -> Result<()> {
    // Print the logo
    println!("{}", LOGO.bright_cyan());

    let cli = SwigCli::parse();
    let mut ctx = setup(&cli)?;

    if cli.interactive {
        run_interactive_mode(&mut ctx)
    } else if let Some(ref cmd) = cli.command {
        run_command_mode(&mut ctx, cmd.clone())
    } else {
        println!("Please specify either --interactive or a command");
        Ok(())
    }
}

fn run_interactive_mode(ctx: &mut SwigCliContext) -> Result<()> {
    println!(
        "\n{}",
        "Welcome to SWIG CLI Interactive Mode".bright_blue().bold()
    );

    loop {
        let actions = vec![
            "Create New Wallet",
            "Add Authority",
            "Remove Authority",
            "View Wallet",
            "List Authorities",
            "Check Balance",
            "Exit",
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose an action")
            .items(&actions)
            .default(0)
            .interact()?;

        match selection {
            0 => create_wallet_interactive(ctx)?,
            1 => add_authority_interactive(ctx)?,
            2 => remove_authority_interactive(ctx)?,
            3 => view_wallet_interactive(ctx)?,
            4 => list_authorities_interactive(ctx)?,
            5 => check_balance_interactive(ctx)?,
            6 => break,
            _ => unreachable!(),
        }
    }

    Ok(())
}

fn create_wallet_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Creating new SWIG wallet...".bright_blue().bold());

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

    let authority_keypair = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter authority keypair")
        .interact()?;

    let authority_type = match authority_type_idx {
        0 => AuthorityType::Ed25519,
        1 => AuthorityType::Secp256k1,
        2 => AuthorityType::Ed25519Session,
        3 => AuthorityType::Secp256k1Session,
        _ => unreachable!(),
    };

    let authority = Keypair::from_base58_string(&authority_keypair);
    let authority_pubkey = authority.pubkey();
    println!("Authority public key: {}", authority_pubkey);

    let use_random_id = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Use random SWIG ID?")
        .default(true)
        .interact()?;

    let id = if use_random_id {
        None
    } else {
        Some(
            Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter SWIG ID")
                .interact_text()?,
        )
    };

    execute_create(
        ctx,
        authority_type,
        authority_pubkey.to_string(),
        authority,
        id,
    )?;

    Ok(())
}

fn add_authority_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Adding new authority...".bright_blue().bold());

    let id = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter SWIG ID")
        .interact_text()?;

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

    let authority = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter authority public key")
        .interact_text()?;

    let permissions = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter permissions (comma-separated)")
        .interact_text()?;

    let permissions = permissions
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let authority_type = match authority_type_idx {
        0 => AuthorityType::Ed25519,
        1 => AuthorityType::Secp256k1,
        2 => AuthorityType::Ed25519Session,
        3 => AuthorityType::Secp256k1Session,
        _ => unreachable!(),
    };

    execute_add_authority(ctx, authority_type, authority, id, permissions)
}

fn remove_authority_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Removing authority...".bright_blue().bold());

    let id = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter SWIG ID")
        .interact_text()?;

    let authority = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter authority to remove")
        .interact_text()?;

    execute_remove_authority(ctx, id, authority)
}

fn view_wallet_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Viewing wallet details...".bright_blue().bold());

    if ctx.wallet.is_none() {
        return Err(anyhow!("Wallet not found"));
    }

    ctx.wallet.as_ref().unwrap().display_swig()?;

    Ok(())
}

fn list_authorities_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Listing authorities...".bright_blue().bold());

    let id = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter SWIG ID")
        .interact_text()?;

    execute_list_authorities(ctx, id)
}

fn check_balance_interactive(ctx: &mut SwigCliContext) -> Result<()> {
    println!("\n{}", "Checking balance...".bright_blue().bold());

    let id = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter SWIG ID")
        .interact_text()?;

    execute_balance(ctx, id)
}

fn run_command_mode(ctx: &mut SwigCliContext, cmd: Command) -> Result<()> {
    match cmd {
        Command::Create {
            authority_type,
            authority,
            id,
            authority_kp,
        } => {
            let authority_kp = Keypair::from_base58_string(&authority_kp);
            let wallet = execute_create(
                ctx,
                parse_authority_type(authority_type)?,
                authority,
                authority_kp,
                id,
            )?;

            // Store the wallet in the context
            Ok(())
        },
        Command::AddAuthority {
            authority_type,
            authority,
            id,
            permissions,
        } => execute_add_authority(
            ctx,
            parse_authority_type(authority_type)?,
            authority,
            id,
            permissions,
        ),
        Command::RemoveAuthority { id, authority } => execute_remove_authority(ctx, id, authority),
        Command::View { id } => execute_view(ctx, id),
        Command::ListAuthorities { id } => execute_list_authorities(ctx, id),
        Command::Balance { id } => execute_balance(ctx, id),
    }
}

fn parse_authority_type(authority_type: String) -> Result<AuthorityType> {
    match authority_type.as_str() {
        "Ed25519" => Ok(AuthorityType::Ed25519),
        "Secp256k1" => Ok(AuthorityType::Secp256k1),
        _ => Err(anyhow!("Invalid authority type: {}", authority_type)),
    }
}

fn execute_create(
    ctx: &mut SwigCliContext,
    authority_type: AuthorityType,
    authority: String,
    authority_kp: Keypair,
    id: Option<String>,
) -> Result<()> {
    let spinner = ProgressBar::new_spinner();
    spinner.set_message("Creating SWIG wallet...");
    spinner.enable_steady_tick(Duration::from_millis(100));

    let swig_id = id
        .map(|i| format!("{:0<32}", i).as_bytes()[..32].try_into().unwrap())
        .unwrap_or_else(rand::random);

    let authority_manager = match authority_type {
        AuthorityType::Ed25519 => {
            let pubkey = Pubkey::from_str(&authority)?;
            println!("Authority: {}", authority);
            println!("Authority type: {:?}", authority_type);
            println!("Authority pubkey: {}", pubkey);
            AuthorityManager::Ed25519(pubkey)
        },
        AuthorityType::Ed25519Session => {
            let create_session_authority = CreateEd25519SessionAuthority::new(
                Pubkey::from_str(&authority)?.to_bytes(),
                Pubkey::from_str(&authority)?.to_bytes(),
                100,
            );
            AuthorityManager::Ed25519Session(create_session_authority)
        },
        _ => {
            spinner.finish_with_message("Error: Session-based authorities not supported for root");
            return Err(anyhow!("Session-based authorities not supported for root"));
        },
    };

    // Store the authority keypair in the context
    ctx.authority = Some(authority_kp.insecure_clone());

    // Create a static copy of the authority for the wallet
    let auth_for_wallet = Box::leak(Box::new(authority_kp));

    let wallet = SwigWallet::new(
        swig_id,
        authority_manager,
        auth_for_wallet,
        auth_for_wallet,
        ctx.rpc_url.clone(),
    )?;

    spinner.finish_with_message("SWIG wallet created successfully!");
    wallet.display_swig()?;
    ctx.wallet = Some(Box::new(wallet));
    Ok(())
}

fn execute_add_authority(
    ctx: &mut SwigCliContext,
    authority_type: AuthorityType,
    authority: String,
    id: String,
    permissions: Vec<String>,
) -> Result<()> {
    let spinner = ProgressBar::new_spinner();
    spinner.set_message("Adding authority...");
    spinner.enable_steady_tick(Duration::from_millis(100));

    let swig_id = format!("{:0<32}", id).as_bytes()[..32].try_into().unwrap();
    let authority_manager = match authority_type {
        AuthorityType::Ed25519 => {
            let pubkey = Pubkey::from_str(&authority)?;
            AuthorityManager::Ed25519(pubkey)
        },
        AuthorityType::Ed25519Session => {
            let create_session_authority = CreateEd25519SessionAuthority::new(
                Pubkey::from_str(&authority)?.to_bytes(),
                Pubkey::from_str(&authority)?.to_bytes(),
                100,
            );
            AuthorityManager::Ed25519Session(create_session_authority)
        },
        _ => {
            spinner.finish_with_message("Error: Session-based authorities not implemented yet");
            return Err(anyhow!("Session-based authorities not implemented yet"));
        },
    };

    let mut wallet = SwigWallet::new(
        swig_id,
        authority_manager,
        &ctx.payer,
        &ctx.payer,
        ctx.rpc_url.clone(),
    )?;

    // Convert string permissions to Permission enum
    let parsed_permissions = permissions
        .iter()
        .map(|p| match p.to_lowercase().as_str() {
            "all" => Ok(Permission::All),
            "sol" => Ok(Permission::Sol {
                amount: 1_000_000_000, // 1 SOL default
                recurring: None,
            }),
            _ => Err(anyhow!("Invalid permission: {}", p)),
        })
        .collect::<Result<Vec<_>>>()?;

    wallet.add_authority(
        authority_type.into(),
        authority.as_bytes(),
        parsed_permissions,
    )?;

    spinner.finish_with_message("Authority added successfully!");
    Ok(())
}

fn execute_remove_authority(ctx: &mut SwigCliContext, id: String, authority: String) -> Result<()> {
    let spinner = ProgressBar::new_spinner();
    spinner.set_message("Removing authority...");
    spinner.enable_steady_tick(Duration::from_millis(100));

    let swig_id = format!("{:0<32}", id).as_bytes()[..32].try_into().unwrap();
    let authority_pubkey = Pubkey::from_str(&authority)?;
    let authority_manager = AuthorityManager::Ed25519(authority_pubkey);

    let mut wallet = SwigWallet::new(
        swig_id,
        authority_manager,
        &ctx.payer,
        &ctx.payer,
        ctx.rpc_url.clone(),
    )?;

    wallet.remove_authority(authority.as_bytes())?;

    spinner.finish_with_message("Authority removed successfully!");
    Ok(())
}

fn execute_view(ctx: &mut SwigCliContext, id: String) -> Result<()> {
    let spinner = ProgressBar::new_spinner();
    spinner.set_message("Loading wallet details...");
    spinner.enable_steady_tick(Duration::from_millis(100));

    if ctx.wallet.is_none() {
        return Err(anyhow!("Wallet not found"));
    }

    spinner.finish_and_clear();

    ctx.wallet.as_ref().unwrap().display_swig()?;

    Ok(())
}

fn execute_list_authorities(ctx: &mut SwigCliContext, id: String) -> Result<()> {
    let spinner = ProgressBar::new_spinner();
    spinner.set_message("Loading authorities...");
    spinner.enable_steady_tick(Duration::from_millis(100));

    let swig_id = format!("{:0<32}", id).as_bytes()[..32].try_into().unwrap();
    let authority_manager = AuthorityManager::Ed25519(ctx.payer.pubkey());

    let wallet = SwigWallet::new(
        swig_id,
        authority_manager,
        &ctx.payer,
        &ctx.payer,
        ctx.rpc_url.clone(),
    )?;

    spinner.finish_and_clear();
    wallet.display_swig()?;
    Ok(())
}

fn execute_balance(ctx: &mut SwigCliContext, id: String) -> Result<()> {
    let spinner = ProgressBar::new_spinner();
    spinner.set_message("Fetching balance...");
    spinner.enable_steady_tick(Duration::from_millis(100));

    let swig_id = format!("{:0<32}", id).as_bytes()[..32].try_into().unwrap();
    let authority_manager = AuthorityManager::Ed25519(ctx.payer.pubkey());

    let wallet = SwigWallet::new(
        swig_id,
        authority_manager,
        &ctx.payer,
        &ctx.payer,
        ctx.rpc_url.clone(),
    )?;

    let balance = wallet.get_balance()?;
    spinner.finish_with_message(format!("Balance: {} SOL", balance as f64 / 1_000_000_000.0));
    Ok(())
}

fn setup(cli: &SwigCli) -> Result<SwigCliContext> {
    let config_dir = ensure_config_dir()?;

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
        (None, Some(kp), None) => (default_rpc_url, kp.clone()),
        (None, None, None) => (default_rpc_url, default_keypair_path),
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
        rpc_url,
        config_dir,
        authority: None,
        wallet: None,
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
