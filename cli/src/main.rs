use anyhow::{anyhow, Result};
use borsh::BorshDeserialize;
use clap::{command, Args, Parser, Subcommand, ValueEnum};
use jupiter_swap_api_client::{
    quote::QuoteRequest, swap::SwapRequest, transaction_config::TransactionConfig,
    JupiterSwapApiClient,
};
use serde::{Deserialize, Serialize};

use directories::BaseDirs;
use secp256k1::{PublicKey as Secp256k1PublicKey, Secp256k1, SecretKey as Secp256k1SecretKey};
use solana_account_decoder_client_types::{ParsedAccount, UiAccountData};
use solana_cli_config::{Config, CONFIG_FILE};
use solana_client::{
    rpc_client::RpcClient, rpc_config::RpcSendTransactionConfig, rpc_request::TokenAccountsFilter,
};
use solana_pubkey::pubkey as pubkey_macro;
use solana_sdk::{
    account::ReadableAccount,
    address_lookup_table::{state::AddressLookupTable, AddressLookupTableAccount},
    commitment_config::CommitmentConfig,
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    keccak::hash,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    rent::Rent,
    signature::{read_keypair_file, Keypair, Signature},
    signer::{Signer, SignerError},
    system_instruction,
    sysvar::Sysvar,
    transaction::VersionedTransaction,
};
use spl_associated_token_account::instruction::create_associated_token_account_idempotent;
use spl_token::instruction::TokenInstruction;
use std::path::PathBuf;
use std::{fmt::Display, fs, fs::File, path::Path, str::FromStr};
use swig_interface::{
    program_id,
    swig::{self, actions::sign_v1::SignV1},
    swig_key,
    swig_state::{swig_account_seeds, Action, AuthorityType, SolAction, Swig, TokenAction},
    AddAuthorityInstruction, AuthorityConfig, CreateInstruction, SignInstruction,
};
use tokio::runtime::Runtime;
const TOKEN_PROGRAM_ID: Pubkey = pubkey_macro!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const TOKEN_22_PROGRAM_ID: Pubkey = pubkey_macro!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_key: Vec<u8>,
    pub start_slot: u64,
    pub end_slot: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwigAuthContext {
    pub role_id: u8,
    pub authority_type: CliAuthorityType,
    pub authority_identifier: String,
    pub authority_payload: Vec<u8>,
    pub session: Option<Session>,
}
impl Signer for SwigAuthContext {
    fn pubkey(&self) -> Pubkey {
        self.authority_identifier.parse().unwrap()
    }
    fn try_pubkey(&self) -> Result<Pubkey, SignerError> {
        Ok(self.pubkey())
    }
    fn sign_message(&self, message: &[u8]) -> Signature {
        let sig_bytes = self.sign(message).unwrap();
        Signature::try_from(sig_bytes.as_slice()).unwrap()
    }
    fn is_interactive(&self) -> bool {
        false
    }

    fn try_sign_message(&self, message: &[u8]) -> std::result::Result<Signature, SignerError> {
        Ok(self.sign_message(message))
    }
}
impl SwigAuthContext {
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match self.authority_type {
            CliAuthorityType::Ed25519 => {
                let keypair = Keypair::from_bytes(&self.authority_payload)
                    .map_err(|e| anyhow!("Failed to load keypair: {:?}", e))?;
                let signature = keypair.sign_message(message);
                Ok(signature.as_ref().to_vec())
            }
            CliAuthorityType::Secp256k1 => {
                let secret_key = Secp256k1SecretKey::from_slice(&self.authority_payload)
                    .map_err(|e| anyhow!("Failed to load secret key: {:?}", e))?;
                let secp = Secp256k1::new();
                let hash = hash(message);
                let message = secp256k1::Message::from_digest(hash.0);
                let signature = secp.sign_ecdsa(&message, &secret_key);
                Ok(signature.serialize_compact().to_vec())
            }
        }
    }
}

pub struct SwigCliContext {
    pub payer: Keypair,
    pub rpc_client: RpcClient,
    pub config_dir: PathBuf,
}

#[derive(Debug, ValueEnum, Clone, Copy, Serialize, Deserialize)]
pub enum CliAuthorityType {
    Ed25519,
    Secp256k1,
}

impl Into<AuthorityType> for CliAuthorityType {
    fn into(self) -> AuthorityType {
        match self {
            CliAuthorityType::Ed25519 => AuthorityType::Ed25519,
            CliAuthorityType::Secp256k1 => AuthorityType::Secp256k1,
        }
    }
}

#[derive(Debug, ValueEnum, Clone, Copy, Default)]
pub enum CliAuthorityStrategy {
    #[default]
    Role,
}

#[derive(Parser, Debug)]
#[command(version)]
pub struct SwigCli {
    #[arg(short = 'c', long)]
    pub config: Option<String>,
    #[arg(short = 'k', long)]
    pub keypair: Option<String>,
    #[arg(short = 'u', long)]
    pub rpc_url: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Authenticate {
        #[arg(short, long)]
        id: String,
        #[arg(short, long)]
        authority_identifier: String,
        #[arg(short = 'd', long)]
        authority_data: String,
    },
    AddAuthority {
        #[arg(short = 't', long)]
        new_authority_type: CliAuthorityType,
        #[arg(short, long)]
        new_authority: String,
        #[arg(short, long = "swig-id")]
        id: String,
        #[arg(short, long)]
        start_slot: Option<u64>,
        #[arg(short, long)]
        end_slot: Option<u64>,
        #[arg(short, long, value_parser, num_args = 1.., value_delimiter = ',')]
        permissions: Vec<String>,
    },
    Transfer {
        #[arg(short, long = "swig-id")]
        id: String,
        #[arg(short, long)]
        token: Option<String>,
        #[arg(short, long)]
        amount: u64,
        #[arg(short = 'r', long)]
        recipient: String,
    },
    MakeAta {
        #[arg(short, long)]
        mint: String,
        #[arg(short, long = "swig-id")]
        id: String,
    },
    Create {
        #[arg(short, long)]
        root: CliAuthorityType,
        #[arg(short, long)]
        authority: String,
        #[arg(short, long = "swig-id")]
        id: Option<String>,
    },
    View {
        #[arg(short, long)]
        id: String,
    },
    Swap {
        #[arg(short, long = "swig-id")]
        id: String,
        #[arg(short = 't', long)]
        input_token: String,
        #[arg(short, long)]
        output_token: String,
        #[arg(short, long)]
        amount: u64,
        #[arg(short, long)]
        slippage: Option<u16>,
    },
}

fn main() {
    if let Err(e) = main_fn() {
        println!("Error: {:?}", e);
        std::process::exit(1);
    }
}

fn main_fn() -> Result<()> {
    let cli = SwigCli::parse();
    let ctx = setup(&cli).unwrap();
    match cli.command {
        Command::Authenticate {
            id,
            authority_identifier,
            authority_data,
        } => {
            let swig_id = swig_key(format!("{:0<13}", id));
            let swig_data = ctx.rpc_client.get_account_data(&swig_id)?;
            let swig = Swig::try_from_slice(&swig_data)
                .map_err(|e| anyhow!("Failed to load swig account: {:?}", e))?;
            let auth_key = Pubkey::from_str(&authority_identifier).unwrap();
            let indexed_authority = swig
                .lookup_role(auth_key.as_ref())
                .ok_or(anyhow!("Failed to find authority"))?;
            let auth_data = match indexed_authority.role.authority_type {
                AuthorityType::Ed25519 => {
                    //authority payload is a file path to a keypair
                    let authority_kp = read_keypair_file(Path::new(&authority_data))
                        .map_err(|e| anyhow!("Failed to load authority keypair: {:?}", e))?;
                    let authority = authority_kp.pubkey();
                    if authority != auth_key {
                        anyhow::bail!("Authority Identifier Mismatch");
                    }
                    SwigAuthContext {
                        role_id: indexed_authority.index,
                        authority_payload: authority_kp.to_bytes().to_vec(),
                        authority_identifier: auth_key.to_string(),
                        authority_type: CliAuthorityType::Ed25519,
                        session: None,
                    }
                }
                AuthorityType::Secp256k1 => {
                    //read eth keypair from file
                    let (secret_key, public_key) = read_eth_keypair_from_file(authority_data)
                        .map_err(|e| {
                            anyhow!("Failed to read secp256k1 keypair from file: {:?}", e)
                        })?;
                    SwigAuthContext {
                        role_id: indexed_authority.index,
                        authority_payload: secret_key.secret_bytes().to_vec(),
                        authority_identifier: public_key.to_string(),
                        authority_type: CliAuthorityType::Secp256k1,
                        session: None,
                    }
                } //TODO for session based authorities we will create session keypair and sign the data
            };

            let auth_file_path = Path::new(&ctx.config_dir).join(format!("{:0<13}.auth", id));
            //write authenticated file to disk
            let auth_file = File::create(&auth_file_path)?;
            serde_json::to_writer(auth_file, &auth_data)?;
            println!(
                "Authenticated successfully, wrote session to {:?}",
                auth_file_path
            );
        }
        Command::Transfer {
            id,
            amount,
            token,
            recipient,
        } => {
            let auth_context = load_auth_context(&id)?;
            let swig_id = swig_key(format!("{:0<13}", id));
            let to = Pubkey::from_str(&recipient).unwrap();
            let transfer_ix = match token {
                None => system_instruction::transfer(&swig_id, &to, amount),
                Some(token) => {
                    let token_pubkey = Pubkey::from_str(&token).unwrap();
                    let swig_ata = spl_associated_token_account::get_associated_token_address(
                        &swig_id,
                        &token_pubkey,
                    );
                    let recipient_ata = spl_associated_token_account::get_associated_token_address(
                        &to,
                        &token_pubkey,
                    );
                    Instruction {
                        program_id: spl_token::id(),
                        accounts: vec![
                            AccountMeta::new(swig_ata, false),
                            AccountMeta::new(recipient_ata, false),
                            AccountMeta::new(swig_id, false),
                        ],
                        data: TokenInstruction::Transfer { amount }.pack(),
                    }
                }
            };
            let compute = prio_fees(&ctx, &[swig_id])?;
            match auth_context.authority_type {
                CliAuthorityType::Ed25519 => {
                    let auth_pubkey = Pubkey::from_str(&auth_context.authority_identifier).unwrap();
                    let outerix = SignInstruction::new_ed25519(
                        swig_id,
                        ctx.payer.pubkey(),
                        auth_pubkey,
                        vec![transfer_ix],
                        auth_context.role_id,
                    )?;
                    let me = v0::Message::try_compile(
                        &ctx.payer.pubkey(),
                        &[
                            ComputeBudgetInstruction::set_compute_unit_limit(10000),
                            compute,
                            outerix,
                        ],
                        &[],
                        ctx.rpc_client.get_latest_blockhash()?,
                    )?;
                    let signers: Vec<&dyn Signer> = vec![&ctx.payer, &auth_context];
                    let txn = VersionedTransaction::try_new(
                        VersionedMessage::V0(me),
                        signers.as_slice(),
                    )?;
                    let result = ctx
                        .rpc_client
                        .send_and_confirm_transaction_with_spinner(&txn)?;
                    println!("Transaction result: {:?}", result);
                    diplay_swig(&ctx, swig_id).unwrap();
                }
                _ => todo!(),
            };
        }
        Command::AddAuthority {
            new_authority_type,
            new_authority,
            id,
            start_slot,
            end_slot,
            permissions,
        } => {
            let auth_context = load_auth_context(&id)?;
            let swig_id = swig_key(format!("{:0<13}", id));
            let ix = match auth_context.authority_type {
                CliAuthorityType::Ed25519 => {
                    let authority_credential =
                        Pubkey::from_str(&auth_context.authority_identifier).unwrap();
                    AddAuthorityInstruction::new_with_ed25519_authority(
                        swig_id,
                        ctx.payer.pubkey(),
                        authority_credential,
                        auth_context.role_id,
                        AuthorityConfig {
                            authority_type: new_authority_type.into(),
                            authority: new_authority.as_bytes(),
                        },
                        start_slot.unwrap_or(0),
                        end_slot.unwrap_or(0),
                        permissions_to_actions(permissions),
                    )
                }
                CliAuthorityType::Secp256k1 => {
                    AddAuthorityInstruction::new_with_secp256k1_authority(
                        swig_id,
                        ctx.payer.pubkey(),
                        |data| {
                            let sig = auth_context.sign(data).unwrap();
                            sig[0..64].try_into().unwrap()
                        },
                        auth_context.role_id,
                        AuthorityConfig {
                            authority_type: new_authority_type.into(),
                            authority: new_authority.as_bytes(),
                        },
                        start_slot.unwrap_or(0),
                        end_slot.unwrap_or(0),
                        permissions_to_actions(permissions),
                    )
                }
            }?;

            let compute = prio_fees(&ctx, &[swig_id])?;
            let me = v0::Message::try_compile(
                &ctx.payer.pubkey(),
                &[compute, ix],
                &[],
                ctx.rpc_client.get_latest_blockhash()?,
            )?;
            let signers: Vec<&dyn Signer> = vec![&ctx.payer, &auth_context];
            let txn = VersionedTransaction::try_new(VersionedMessage::V0(me), signers.as_slice())?;
            let result = ctx
                .rpc_client
                .send_and_confirm_transaction_with_spinner(&txn)?;
            println!("Transaction result: {:?}", result);
            diplay_swig(&ctx, swig_id).unwrap();
        }
        Command::MakeAta { mint, id } => {
            let mint_account = ctx
                .rpc_client
                .get_account(&Pubkey::from_str(&mint).unwrap())?;

            let swig_id = swig_key(format!("{:0<13}", id));
            let mint = Pubkey::from_str(&mint).unwrap();

            let ata = create_associated_token_account_idempotent(
                &ctx.payer.pubkey(),
                &swig_id,
                &mint,
                &mint_account.owner,
            );
            let compute = prio_fees(&ctx, &[mint])?;
            let me = v0::Message::try_compile(
                &ctx.payer.pubkey(),
                &[compute, ata],
                &[],
                ctx.rpc_client.get_latest_blockhash()?,
            )?;
            let txn = VersionedTransaction::try_new(
                VersionedMessage::V0(me),
                &[ctx.payer.insecure_clone()],
            )?;

            let result = ctx
                .rpc_client
                .send_and_confirm_transaction_with_spinner(&txn)?;
            println!("Transaction result: {:?}", result);
            diplay_swig(&ctx, swig_id).unwrap();
        }
        Command::View { id } => {
            let swig_id = swig_key(format!("{:0<13}", id));
            diplay_swig(&ctx, swig_id).unwrap();
        }
        Command::Create {
            root,
            authority,
            id,
        } => {
            let authority_type = match root {
                CliAuthorityType::Ed25519 => AuthorityType::Ed25519,
                CliAuthorityType::Secp256k1 => AuthorityType::Secp256k1,
            };
            let id: [u8; 13] = id
                .and_then(|i| format!("{:0<13}", i).as_bytes()[..13].try_into().ok())
                .unwrap_or_else(|| rand::random());
            create(&ctx, authority_type, authority, id).unwrap();
        }
        Command::Swap {
            id,
            input_token,
            output_token,
            amount,
            slippage,
        } => {
            let auth_context = load_auth_context(&id)?;
            let swig_id = swig_key(format!("{:0<13}", id));
            let rt = Runtime::new().unwrap();
            let (budget, fee, ix, alts) = rt.block_on(async {
                let jupiter_swap_api_client =
                    JupiterSwapApiClient::new("https://api.jup.ag/swap/v1/".to_string());

                let quote_request = QuoteRequest {
                    amount: amount,
                    input_mint: Pubkey::from_str(&input_token).unwrap(),
                    output_mint: Pubkey::from_str(&output_token).unwrap(),
                    slippage_bps: slippage.unwrap_or(0),
                    auto_slippage: slippage.map(|_| Some(false)).unwrap_or(Some(true)),
                    ..Default::default()
                };

                let quote_response = jupiter_swap_api_client.quote(&quote_request).await.unwrap();
                let swap_request = SwapRequest {
                    quote_response,
                    user_public_key: swig_id,
                    config: TransactionConfig {
                        use_shared_accounts: Some(false),
                        allow_optimized_wrapped_sol_token_account: true,
                        ..Default::default()
                    },
                };
                let swap_response = jupiter_swap_api_client
                    .swap_instructions(&swap_request)
                    .await
                    .unwrap();
                if swap_response.simulation_error.is_some() {
                    Err(anyhow::anyhow!(
                        "Simulation error: {:?}",
                        swap_response.simulation_error
                    ))
                } else {
                    Ok((
                        swap_response.compute_unit_limit,
                        swap_response.prioritization_fee_lamports,
                        swap_response.swap_instruction,
                        swap_response.address_lookup_table_addresses,
                    ))
                }
            })?;

            match auth_context.authority_type {
                CliAuthorityType::Ed25519 => {
                    let auth_pubkey = Pubkey::from_str(&auth_context.authority_identifier).unwrap();
                    let outerix = SignInstruction::new_ed25519(
                        swig_id,
                        ctx.payer.pubkey(),
                        auth_pubkey,
                        vec![ix],
                        auth_context.role_id,
                    )?;
                    println!("outerix: {:?}", outerix.accounts.len());
                    let mut txn_alts = vec![];
                    for alt in alts {
                        let data = ctx.rpc_client.get_account_data(&alt)?;
                        let alt_obj = AddressLookupTable::deserialize(&data)?;
                        txn_alts.push(AddressLookupTableAccount {
                            key: alt,
                            addresses: alt_obj.addresses.to_vec(),
                        });
                    }
                    let message = v0::Message::try_compile(
                        &ctx.payer.pubkey(),
                        &[
                            ComputeBudgetInstruction::set_compute_unit_limit(budget + 3000),
                            ComputeBudgetInstruction::set_compute_unit_price(fee),
                            outerix,
                        ],
                        txn_alts.as_slice(),
                        ctx.rpc_client.get_latest_blockhash()?,
                    )?;
                    let signers: Vec<&dyn Signer> = vec![&ctx.payer, &auth_context];
                    let txn = VersionedTransaction::try_new(
                        VersionedMessage::V0(message),
                        signers.as_slice(),
                    )?;
                    let result = ctx
                        .rpc_client
                        .send_and_confirm_transaction_with_spinner_and_config(
                            &txn,
                            CommitmentConfig::processed(),
                            RpcSendTransactionConfig {
                                skip_preflight: true,
                                ..Default::default()
                            },
                        )?;

                    println!("Transaction result: {:?}", result);
                    diplay_swig(&ctx, swig_id).unwrap();
                }
                _ => todo!(),
            };
        }
    }
    Ok(())
}

fn get_config_path() -> PathBuf {
    if let Some(base_dirs) = BaseDirs::new() {
        base_dirs.data_dir().join("bonsol-cli")
    } else {
        // Fallback to current directory if we can't get the base dirs
        PathBuf::from(".")
    }
}

fn ensure_config_dir() -> std::io::Result<PathBuf> {
    let config_path = get_config_path();
    std::fs::create_dir_all(&config_path)?;
    Ok(config_path)
}

fn load_auth_context(id: &str) -> Result<SwigAuthContext> {
    let auth_file = Path::new(&get_config_path()).join(format!("{:0<13}.auth", id));
    let auth_file = File::open(auth_file)?;
    let auth_data: SwigAuthContext = serde_json::from_reader(auth_file)?;
    Ok(auth_data)
}

fn prio_fees(ctx: &SwigCliContext, accounts: &[Pubkey]) -> Result<Instruction> {
    let fees = ctx.rpc_client.get_recent_prioritization_fees(accounts)?;
    let median_fee = fees.iter().fold(0, |acc, fee| {
        acc + fee.prioritization_fee / fees.len() as u64
    });
    let compute = ComputeBudgetInstruction::set_compute_unit_price(median_fee / 2);
    return Ok(compute);
}

fn diplay_swig(ctx: &SwigCliContext, swig_id: Pubkey) -> Result<()> {
    let swig_account = ctx.rpc_client.get_account(&swig_id)?;
    let token_accounts = ctx
        .rpc_client
        .get_token_accounts_by_owner(&swig_id, TokenAccountsFilter::ProgramId(TOKEN_PROGRAM_ID))?;
    let token_accounts_22 = ctx.rpc_client.get_token_accounts_by_owner(
        &swig_id,
        TokenAccountsFilter::ProgramId(TOKEN_22_PROGRAM_ID),
    )?;

    let swig = Swig::try_from_slice(&swig_account.data)
        .map_err(|e| anyhow!("Failed to load swig account: {:?}", e))?;
    println!("\tKEY: {}", swig_id.to_string());
    println!("\tID: {}", String::from_utf8(swig.id.to_vec()).unwrap());
    println!(
        "\tLamports: {}",
        swig_account.lamports() - Rent::default().minimum_balance(swig.size())
    );
    for (index, role) in swig.roles.iter().enumerate() {
        println!("\tRole {}", index);
        println!("\t\tAuthority Type: {:?}", role.authority_type);
        println!(
            "\t\tAuthority: {:?}",
            match role.authority_type {
                AuthorityType::Ed25519 =>
                    bs58::encode(role.authority_data.as_slice()).into_string(),
                AuthorityType::Secp256k1 => hex::encode(role.authority_data.as_slice()),
            }
        );
        println!("\t\tStart Slot: {}", role.start_slot);
        println!("\t\tEnd Slot: {}", role.end_slot);
        println!("\t\tPermissions:");
        for (index, action) in role.actions.iter().enumerate() {
            match action {
                Action::ManageAuthority => {
                    println!("\t\t{}: ManageAuthority", index);
                }
                Action::Program { key } => {
                    println!("\t\t{}: Program {:?}", index, key);
                }
                Action::All => {
                    println!("\t\t{}: All", index);
                }
                Action::Sol {
                    action: SolAction::All,
                } => {
                    println!("\t\t{}: Sol All", index);
                }
                Action::Sol {
                    action: SolAction::Manage(amount),
                } => {
                    println!("\t\t{}: Sol Manage {:?}", index, amount);
                }
                Action::Sol {
                    action: SolAction::Temporal(amount, interval, last_action),
                } => {
                    println!(
                        "\t\t{}: Sol Temporal {:?} {:?} {:?}",
                        index, amount, interval, last_action
                    );
                }
                Action::Token {
                    key,
                    action: TokenAction::All,
                } => {
                    println!(
                        "\t\t{}: Token {:?} All",
                        index,
                        bs58::encode(key.as_ref()).into_string()
                    );
                }
                Action::Token {
                    key,
                    action: TokenAction::Manage(amount),
                } => {
                    println!(
                        "\t\t{}: Token {:?} Manage {:?}",
                        index,
                        bs58::encode(key.as_ref()).into_string(),
                        amount
                    );
                }
                Action::Token {
                    key,
                    action: TokenAction::Temporal(amount, interval, last_action),
                } => {
                    println!(
                        "\t\t{}: Token {:?} Temporal {:?} {:?} {:?}",
                        index,
                        bs58::encode(key.as_ref()).into_string(),
                        amount,
                        interval,
                        last_action
                    );
                }
                Action::Tokens {
                    action: TokenAction::All,
                } => {
                    println!("\t\t{}: Tokens All", index);
                }
                Action::Tokens {
                    action: TokenAction::Manage(amount),
                } => {
                    println!("\t\t{}: Tokens Manage {:?}", index, amount);
                }
                Action::Tokens {
                    action: TokenAction::Temporal(amount, interval, last_action),
                } => {
                    println!(
                        "\t\t{}: Tokens Temporal {:?} {:?} {:?}",
                        index, amount, interval, last_action
                    );
                }
            }
        }
    }
    if token_accounts.len() > 0 || token_accounts_22.len() > 0 {
        println!("\tToken Accounts:");
    }
    for (index, token_account) in token_accounts.iter().enumerate() {
        if let UiAccountData::Json(ParsedAccount {
            program, parsed, ..
        }) = &token_account.account.data
        {
            println!("\t\tKey: {}", token_account.pubkey);
            println!("\t\tMint: {}", parsed["info"]["mint"].as_str().unwrap());
            println!("\t\tAmount: {}", parsed["info"]["tokenAmount"]["uiAmount"]);
        }
    }
    for (index, token_account) in token_accounts_22.iter().enumerate() {
        if let UiAccountData::Json(ParsedAccount {
            program, parsed, ..
        }) = &token_account.account.data
        {
            println!("\t\tKey: {}", token_account.pubkey);
            println!("\t\tMint: {}", parsed["info"]["mint"].as_str().unwrap());
            println!("\t\tAmount: {}", parsed["info"]["tokenAmount"]["uiAmount"]);
        }
    }
    Ok(())
}

fn create(
    ctx: &SwigCliContext,
    authority_type: AuthorityType,
    authority: String,
    id: [u8; 13],
) -> Result<()> {
    let program_id = Pubkey::from(swig::ID);
    let swig_account = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id);

    let auth_bytes = match authority_type {
        AuthorityType::Ed25519 => bs58::decode(authority).into_vec()?,
        AuthorityType::Secp256k1 => hex::decode(authority).unwrap(),
    };

    let instruction = CreateInstruction::new(
        swig_account.0,
        swig_account.1,
        ctx.payer.pubkey(),
        AuthorityConfig {
            authority_type,
            authority: &auth_bytes,
        },
        &id,
        0,
        0,
    )?;
    let msg = v0::Message::try_compile(
        &ctx.payer.pubkey(),
        &[instruction],
        &[],
        ctx.rpc_client.get_latest_blockhash()?,
    )
    .unwrap();
    let txn =
        VersionedTransaction::try_new(VersionedMessage::V0(msg), &[ctx.payer.insecure_clone()])?;
    ctx.rpc_client
        .send_and_confirm_transaction_with_spinner(&txn)?;
    diplay_swig(&ctx, swig_account.0)?;
    Ok(())
}

pub fn setup(cli: &SwigCli) -> Result<SwigCliContext> {
    let keypair = cli.keypair.clone();
    let config = cli.config.clone();
    let rpc_url = cli.rpc_url.clone();
    let config_dir = ensure_config_dir()?;
    let (rpc, kpp) = match (rpc_url, keypair, config) {
        (Some(rpc_url), Some(keypair), None) => (rpc_url, keypair),
        (None, None, config) => {
            let config_location = CONFIG_FILE
                .clone()
                .ok_or(anyhow!("Please provide a config file"))?;
            let config = Config::load(&config.unwrap_or(config_location));
            match config {
                Ok(config) => (config.json_rpc_url, config.keypair_path),
                Err(e) => {
                    anyhow::bail!("Error loading config: {:?}", e);
                }
            }
        }
        _ => {
            anyhow::bail!("Please provide a keypair and rpc or a solana config file");
        }
    };

    let keypair = read_keypair_file(Path::new(&kpp));
    if keypair.is_err() {
        anyhow::bail!("Invalid keypair");
    }
    Ok(SwigCliContext {
        payer: keypair.unwrap(),
        rpc_client: RpcClient::new(rpc),
        config_dir,
    })
}

fn read_eth_keypair_from_file(
    path: impl AsRef<Path>,
) -> Result<(Secp256k1SecretKey, Secp256k1PublicKey), Box<dyn std::error::Error>> {
    // Read the private key bytes from file (32 bytes)
    let secret_bytes = fs::read(path)?;

    if secret_bytes.len() != 32 {
        return Err("Invalid key file length".into());
    }

    // Create the secret key
    let secret_key = Secp256k1SecretKey::from_slice(&secret_bytes)?;

    // Initialize the secp256k1 context
    let secp = Secp256k1::new();

    // Derive the public key
    let public_key = Secp256k1PublicKey::from_secret_key(&secp, &secret_key);

    Ok((secret_key, public_key))
}

fn permissions_to_actions(permissions: Vec<String>) -> Vec<Action> {
    let mut actions = Vec::new();
    for permission in permissions {
        let permission = permission.split(':').collect::<Vec<&str>>();
        let len = permission.len();
        match permission[0] {
            "all" => {
                actions.push(Action::All);
            }
            "manage_authority" => {
                actions.push(Action::ManageAuthority);
            }
            "token" => {
                if len == 2 {
                    let token = permission[1].parse::<String>().unwrap();
                    let token = Pubkey::from_str(&token).unwrap();
                    actions.push(Action::Token {
                        key: token.to_bytes(),
                        action: TokenAction::All,
                    });
                    continue;
                }
                if len == 3 {
                    let token = permission[1].parse::<String>().unwrap();
                    let token = Pubkey::from_str(&token).unwrap();
                    let amount = permission[2].parse::<u64>().unwrap();
                    actions.push(Action::Token {
                        key: token.to_bytes(),
                        action: TokenAction::Manage(amount),
                    });
                }
            }
            "tokens" => {
                if len == 1 {
                    actions.push(Action::Tokens {
                        action: TokenAction::All,
                    });
                    continue;
                }
                if len == 3 {
                    let amount = permission[1].parse::<u64>().unwrap();
                    actions.push(Action::Tokens {
                        action: TokenAction::Manage(amount),
                    });
                }
            }
            "sol" => {
                if len == 1 {
                    actions.push(Action::Sol {
                        action: SolAction::All,
                    });
                    continue;
                }
                if len == 2 {
                    let amount = permission[1].parse::<u64>().unwrap();
                    actions.push(Action::Sol {
                        action: SolAction::Manage(amount),
                    });
                }
            }
            _ => {
                println!("Invalid permission: {}", permission[0]);
            }
        }
    }
    return actions;
}
