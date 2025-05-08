use std::{
    fs,
    fs::File,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{anyhow, Result};
use clap::{command, Parser, Subcommand, ValueEnum};
use directories::BaseDirs;
use jupiter_swap_api_client::{
    quote::QuoteRequest, swap::SwapRequest, transaction_config::TransactionConfig,
    JupiterSwapApiClient,
};
use secp256k1::{PublicKey as Secp256k1PublicKey, Secp256k1, SecretKey as Secp256k1SecretKey};
use serde::{Deserialize, Serialize};
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
    transaction::VersionedTransaction,
};
use spl_associated_token_account::instruction::create_associated_token_account_idempotent;
use spl_token::instruction::TokenInstruction;
use swig_interface::{
    swig::{self},
    swig_key, AddAuthorityInstruction, AuthorityConfig, ClientAction, CreateInstruction,
    CreateSessionInstruction, CreateSubAccountInstruction, SignInstruction,
    SubAccountSignInstruction, ToggleSubAccountInstruction, WithdrawFromSubAccountInstruction,
};

use swig_state_x::{
    action::{
        all::All, manage_authority::ManageAuthority, sol_limit::SolLimit, sub_account::SubAccount,
        token_limit::TokenLimit,
    },
    authority::{
        ed25519::{CreateEd25519SessionAuthority, Ed25519SessionAuthority},
        secp256k1::{CreateSecp256k1SessionAuthority, Secp256k1SessionAuthority},
        AuthorityType,
    },
    swig::{sub_account_seeds, swig_account_seeds, SwigSubAccount, SwigWithRoles},
    IntoBytes, Transmutable,
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
    pub swig_key: Pubkey,
    pub swig_id: String,
    pub role_id: u32,
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
    pub fn start_session(&mut self, ctx: &SwigCliContext, max_session_duration: u64) -> Result<()> {
        let session_key = Keypair::new();
        let current_slot = ctx.rpc_client.get_slot()?;
        let session_end_slot = current_slot + max_session_duration;
        let create_session = CreateSessionInstruction::new_with_ed25519_authority(
            self.swig_key,
            ctx.payer.pubkey(),
            self.authority_identifier.parse()?,
            self.role_id,
            session_key.pubkey(),
            max_session_duration,
        )
        .map_err(|e| anyhow!("Failed to create session: {:?}", e))?;
        send_instruction(&ctx, &ctx.payer.pubkey(), &[&ctx.payer], create_session)?;
        let swig_data = ctx.rpc_client.get_account_data(&self.swig_key)?;
        let swig = SwigWithRoles::from_bytes(&swig_data)
            .map_err(|e| anyhow!("Failed to load swig account: {:?}", e))?;
        let role = swig
            .get_role(self.role_id)
            .map_err(|e| anyhow!("Failed to get role: {:?}", e))?
            .ok_or(anyhow!("Failed to get role"))?;
        match role
            .authority_type()
            .map_err(|e| anyhow!("Failed to get authority type: {:?}", e))?
        {
            AuthorityType::Ed25519Session => {
                let auth: &Ed25519SessionAuthority = role
                    .authority
                    .as_any()
                    .downcast_ref::<Ed25519SessionAuthority>()
                    .ok_or(anyhow!("Failed to read authority"))?;
                self.session = Some(Session {
                    session_key: session_key.to_bytes().to_vec(),
                    start_slot: current_slot,
                    end_slot: auth.current_session_expiration,
                });
            },
            AuthorityType::Secp256k1Session => {
                let auth: &Secp256k1SessionAuthority = role
                    .authority
                    .as_any()
                    .downcast_ref::<Secp256k1SessionAuthority>()
                    .ok_or(anyhow!("Failed to read authority"))?;
                self.session = Some(Session {
                    session_key: session_key.to_bytes().to_vec(),
                    start_slot: current_slot,
                    end_slot: auth.current_session_expiration,
                });
            },
            _ => anyhow::bail!("Invalid authority type"),
        }
        Ok(())
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match self.authority_type {
            CliAuthorityType::Ed25519 => {
                let keypair = Keypair::from_bytes(&self.authority_payload)
                    .map_err(|e| anyhow!("Failed to load keypair: {:?}", e))?;
                let signature = keypair.sign_message(message);
                Ok(signature.as_ref().to_vec())
            },
            CliAuthorityType::Secp256k1 => {
                let secret_key = Secp256k1SecretKey::from_slice(&self.authority_payload)
                    .map_err(|e| anyhow!("Failed to load secret key: {:?}", e))?;
                let secp = Secp256k1::new();
                let hash = hash(message);
                let message = secp256k1::Message::from_digest(hash.0);
                let signature = secp.sign_ecdsa(&message, &secret_key);
                Ok(signature.serialize_compact().to_vec())
            },
            CliAuthorityType::Ed25519Session => {
                todo!()
            },
            CliAuthorityType::Secp256k1Session => {
                todo!()
            },
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
    Ed25519Session,
    Secp256k1Session,
}

impl From<CliAuthorityType> for AuthorityType {
    fn from(val: CliAuthorityType) -> Self {
        match val {
            CliAuthorityType::Ed25519 => AuthorityType::Ed25519,
            CliAuthorityType::Secp256k1 => AuthorityType::Secp256k1,
            CliAuthorityType::Ed25519Session => AuthorityType::Ed25519Session,
            CliAuthorityType::Secp256k1Session => AuthorityType::Secp256k1Session,
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
        id: Option<String>,
        #[arg(short, long)]
        key: Option<String>,
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
        id: Option<String>,
        #[arg(short, long)]
        key: Option<String>,
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
    CreateSubAccount {
        #[arg(short, long = "swig-id")]
        id: String,
        #[arg(short, long)]
        role_id: u32,
    },
    WithdrawFromSubAccount {
        #[arg(short, long = "swig-id")]
        id: String,
        #[arg(short, long)]
        role_id: u32,
        #[arg(short, long)]
        sub_account: String,
        #[arg(short, long)]
        amount: u64,
        #[arg(short, long)]
        token: Option<String>,
    },
    SubAccountSign {
        #[arg(short, long = "swig-id")]
        id: String,
        #[arg(short, long)]
        role_id: u32,
        #[arg(short, long)]
        sub_account: String,
        #[arg(short, long)]
        recipient: String,
        #[arg(short, long)]
        amount: u64,
        #[arg(short, long)]
        token: Option<String>,
    },
    ToggleSubAccount {
        #[arg(short, long = "swig-id")]
        id: String,
        #[arg(short, long)]
        role_id: u32,
        #[arg(short, long)]
        sub_account: String,
        #[arg(short, long)]
        enabled: bool,
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
            key,
            authority_identifier,
            authority_data,
        } => {
            if id.is_none() && key.is_none() {
                anyhow::bail!("Either id or key must be provided");
            }

            let swig_key = if let Some(id_val) = id {
                swig_key(format!("{:0<32}", id_val))
            } else {
                // Handle key-based lookup
                Pubkey::from_str(&key.unwrap())?
            };

            let swig_data = ctx.rpc_client.get_account_data(&swig_key)?;
            let swig = SwigWithRoles::from_bytes(&swig_data)
                .map_err(|e| anyhow!("Failed to load swig account: {:?}", e))?;
            let auth_key = Pubkey::from_str(&authority_identifier).unwrap();
            let indexed_authority = swig
                .lookup_role_id(auth_key.as_ref())
                .map_err(|e| anyhow!("Failed to find authority: {:?}", e))?
                .ok_or(anyhow!("Failed to find authority"))?;
            let role = swig
                .get_role(indexed_authority)
                .map_err(|e| anyhow!("Failed to find role: {:?}", e))?
                .ok_or(anyhow!("Failed to find role"))?;
            let auth_data = match role
                .authority_type()
                .map_err(|e| anyhow!("Failed to get authority type: {:?}", e))?
            {
                AuthorityType::Ed25519 => {
                    // authority payload is a file path to a keypair
                    let authority_kp = read_keypair_file(Path::new(&authority_data))
                        .map_err(|e| anyhow!("Failed to load authority keypair: {:?}", e))?;
                    let authority = authority_kp.pubkey();
                    if authority != auth_key {
                        anyhow::bail!("Authority Identifier Mismatch");
                    }
                    SwigAuthContext {
                        swig_key,
                        swig_id: bs58::encode(swig.state.id).into_string(),
                        role_id: indexed_authority,
                        authority_payload: authority_kp.to_bytes().to_vec(),
                        authority_identifier: auth_key.to_string(),
                        authority_type: CliAuthorityType::Ed25519,
                        session: None,
                    }
                },
                AuthorityType::Secp256k1 => {
                    // read eth keypair from file
                    let (secret_key, public_key) = read_eth_keypair_from_file(authority_data)
                        .map_err(|e| {
                            anyhow!("Failed to read secp256k1 keypair from file: {:?}", e)
                        })?;
                    SwigAuthContext {
                        swig_key,
                        swig_id: bs58::encode(swig.state.id).into_string(),
                        role_id: indexed_authority,
                        authority_payload: secret_key.secret_bytes().to_vec(),
                        authority_identifier: public_key.to_string(),
                        authority_type: CliAuthorityType::Secp256k1,
                        session: None,
                    }
                },
                AuthorityType::Ed25519Session => {
                    let auth: &Ed25519SessionAuthority = role
                        .authority
                        .as_any()
                        .downcast_ref::<Ed25519SessionAuthority>()
                        .ok_or(anyhow!("Failed to read authority"))?;
                    let authority_kp = read_keypair_file(Path::new(&authority_data))
                        .map_err(|e| anyhow!("Failed to load authority keypair: {:?}", e))?;
                    let authority = authority_kp.pubkey();
                    if authority != auth_key {
                        anyhow::bail!("Authority Identifier Mismatch");
                    }

                    let mut auth_ctx = SwigAuthContext {
                        swig_key,
                        swig_id: bs58::encode(swig.state.id).into_string(),
                        role_id: indexed_authority,
                        authority_payload: authority_kp.to_bytes().to_vec(),
                        authority_identifier: auth_key.to_string(),
                        authority_type: CliAuthorityType::Ed25519Session,
                        session: None,
                    };
                    auth_ctx.start_session(&ctx, auth.max_session_length)?;
                    auth_ctx
                },
                AuthorityType::Secp256k1Session => {
                    let auth: &Secp256k1SessionAuthority = role
                        .authority
                        .as_any()
                        .downcast_ref::<Secp256k1SessionAuthority>()
                        .ok_or(anyhow!("Failed to read authority"))?;
                    let (secret_key, public_key) = read_eth_keypair_from_file(authority_data)
                        .map_err(|e| {
                            anyhow!("Failed to read secp256k1 keypair from file: {:?}", e)
                        })?;
                    let mut auth_ctx = SwigAuthContext {
                        swig_key,
                        swig_id: bs58::encode(swig.state.id).into_string(),
                        role_id: indexed_authority,
                        authority_payload: secret_key.secret_bytes().to_vec(),
                        authority_identifier: public_key.to_string(),
                        authority_type: CliAuthorityType::Secp256k1Session,
                        session: None,
                    };
                    auth_ctx.start_session(&ctx, auth.max_session_age)?;
                    auth_ctx
                },
                _ => anyhow::bail!("Invalid authority type"),
            };

            let auth_file_path =
                Path::new(&ctx.config_dir).join(format!("{:0<32}.auth", swig_key.to_string()));
            // write authenticated file to disk
            let auth_file = File::create(&auth_file_path)?;
            serde_json::to_writer(auth_file, &auth_data)?;
            println!(
                "Authenticated successfully, wrote session to {:?}",
                auth_file_path
            );
        },
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
                },
            };
            let compute = prio_fees(&ctx, &[swig_id])?;
            let ix = match auth_context.authority_type {
                CliAuthorityType::Ed25519 => {
                    let auth_pubkey = Pubkey::from_str(&auth_context.authority_identifier).unwrap();
                    SignInstruction::new_ed25519(
                        swig_id,
                        ctx.payer.pubkey(),
                        auth_pubkey,
                        transfer_ix,
                        auth_context.role_id,
                    )?
                },
                CliAuthorityType::Secp256k1 => {
                    let current_slot = ctx.rpc_client.get_slot()?;
                    SignInstruction::new_secp256k1(
                        swig_id,
                        ctx.payer.pubkey(),
                        |data| {
                            let sig = auth_context.sign(data).unwrap();
                            sig[0..65].try_into().unwrap()
                        },
                        current_slot,
                        transfer_ix,
                        auth_context.role_id,
                    )?
                },

                _ => todo!(),
            };
            let me = v0::Message::try_compile(
                &ctx.payer.pubkey(),
                &[ix],
                &[],
                ctx.rpc_client.get_latest_blockhash()?,
            )?;
            let txn = VersionedTransaction::try_new(VersionedMessage::V0(me), &[&ctx.payer])?;
            let result = ctx
                .rpc_client
                .send_and_confirm_transaction_with_spinner(&txn)?;
            println!("Transaction result: {:?}", result);
            diplay_swig(&ctx, swig_id).unwrap();
        },
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
                        permissions_to_actions(permissions),
                    )
                },
                CliAuthorityType::Secp256k1 => {
                    let current_slot = ctx.rpc_client.get_slot()?;
                    AddAuthorityInstruction::new_with_secp256k1_authority(
                        swig_id,
                        ctx.payer.pubkey(),
                        |data| {
                            let sig = auth_context.sign(data).unwrap();
                            sig.try_into().unwrap()
                        },
                        current_slot,
                        auth_context.role_id,
                        AuthorityConfig {
                            authority_type: new_authority_type.into(),
                            authority: new_authority.as_bytes(),
                        },
                        permissions_to_actions(permissions),
                    )
                },
                CliAuthorityType::Ed25519Session => {
                    todo!()
                },
                CliAuthorityType::Secp256k1Session => {
                    todo!()
                },
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
        },
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
        },
        Command::View { id, key } => {
            if id.is_none() && key.is_none() {
                anyhow::bail!("Either id or key must be provided");
            }

            let swig_id = if let Some(id_val) = id {
                swig_key(format!("{:0<32}", id_val))
            } else {
                // Handle key-based lookup
                Pubkey::from_str(&key.unwrap())?
            };
            diplay_swig(&ctx, swig_id).unwrap();
        },
        Command::Create {
            root,
            authority,
            id,
        } => {
            let authority_type = root.into();
            let id: [u8; 32] = id
                .and_then(|i| format!("{:0<32}", i).as_bytes()[..32].try_into().ok())
                .unwrap_or_else(rand::random);
            create(&ctx, authority_type, authority, id).unwrap();
        },
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
                    amount,
                    input_mint: Pubkey::from_str(&input_token).unwrap(),
                    output_mint: Pubkey::from_str(&output_token).unwrap(),
                    slippage_bps: slippage.unwrap_or(0),
                    max_accounts: Some(62),
                    auto_slippage: slippage.map(|_| Some(false)).unwrap_or(Some(true)),
                    ..Default::default()
                };

                let quote_response = jupiter_swap_api_client.quote(&quote_request).await.unwrap();
                let swap_request = SwapRequest {
                    quote_response,
                    user_public_key: swig_id,
                    config: TransactionConfig {
                        use_shared_accounts: Some(true),
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
                        ix,
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
                },
                _ => todo!(),
            };
        },
        Command::CreateSubAccount { id, role_id } => {
            let auth_context = load_auth_context(&id)?;
            let swig_id = swig_key(format!("{:0<13}", id));

            // Derive the sub-account address
            let role_id_bytes = role_id.to_le_bytes();
            let swig_id_bytes = auth_context.swig_id.as_bytes();
            let (sub_account, sub_account_bump) = Pubkey::find_program_address(
                &sub_account_seeds(swig_id_bytes, &role_id_bytes),
                &swig_interface::program_id(),
            );

            println!("Creating sub-account at address: {}", sub_account);

            // Create the instruction
            let ix = match auth_context.authority_type {
                CliAuthorityType::Ed25519 => {
                    let auth_pubkey = Pubkey::from_str(&auth_context.authority_identifier).unwrap();
                    CreateSubAccountInstruction::new_with_ed25519_authority(
                        swig_id,
                        auth_pubkey,
                        ctx.payer.pubkey(),
                        sub_account,
                        role_id,
                        sub_account_bump,
                    )
                },
                CliAuthorityType::Secp256k1 => {
                    let current_slot = ctx.rpc_client.get_slot()?;
                    CreateSubAccountInstruction::new_with_secp256k1_authority(
                        swig_id,
                        ctx.payer.pubkey(),
                        |data| {
                            let sig = auth_context.sign(data).unwrap();
                            sig[0..65].try_into().unwrap()
                        },
                        current_slot,
                        sub_account,
                        role_id,
                        sub_account_bump,
                    )
                },
                CliAuthorityType::Ed25519Session => {
                    // For Ed25519Session, similar to Ed25519 but with session handling
                    anyhow::bail!("Ed25519Session is not yet implemented for CreateSubAccount");
                },
                CliAuthorityType::Secp256k1Session => {
                    // For Secp256k1Session, similar to Secp256k1 but with session handling
                    anyhow::bail!("Secp256k1Session is not yet implemented for CreateSubAccount");
                },
            }?;

            // Send the transaction
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
            println!("Sub-account created successfully: {}", result);

            // Display the sub-account details
            if let Ok(sub_account_data) = ctx.rpc_client.get_account_data(&sub_account) {
                if let Ok(sub_account_state) =
                    unsafe { SwigSubAccount::load_unchecked(&sub_account_data) }
                {
                    println!("Sub-account details:");
                    println!(
                        "  Swig ID: {}",
                        bs58::encode(sub_account_state.swig_id).into_string()
                    );
                    println!("  Role ID: {}", sub_account_state.role_id);
                    println!("  Enabled: {}", sub_account_state.enabled);
                    println!("  Bump: {}", sub_account_state.bump);
                }
            }
        },
        Command::WithdrawFromSubAccount {
            id,
            role_id,
            sub_account,
            amount,
            token,
        } => {
            let auth_context = load_auth_context(&id)?;
            let swig_id = swig_key(format!("{:0<13}", id));
            let sub_account_pubkey = Pubkey::from_str(&sub_account)?;

            println!(
                "Withdrawing {} from sub-account {}",
                amount, sub_account_pubkey
            );

            // Create the instruction
            let ix = match auth_context.authority_type {
                CliAuthorityType::Ed25519 => {
                    let auth_pubkey = Pubkey::from_str(&auth_context.authority_identifier).unwrap();
                    WithdrawFromSubAccountInstruction::new_with_ed25519_authority(
                        swig_id,
                        auth_pubkey,
                        ctx.payer.pubkey(),
                        sub_account_pubkey,
                        role_id,
                        amount,
                    )
                },
                CliAuthorityType::Secp256k1 => {
                    let current_slot = ctx.rpc_client.get_slot()?;
                    WithdrawFromSubAccountInstruction::new_with_secp256k1_authority(
                        swig_id,
                        ctx.payer.pubkey(),
                        |data| {
                            let sig = auth_context.sign(data).unwrap();
                            sig[0..65].try_into().unwrap()
                        },
                        current_slot,
                        sub_account_pubkey,
                        role_id,
                        amount,
                    )
                },
                CliAuthorityType::Ed25519Session => {
                    anyhow::bail!(
                        "Ed25519Session is not yet implemented for WithdrawFromSubAccount"
                    );
                },
                CliAuthorityType::Secp256k1Session => {
                    anyhow::bail!(
                        "Secp256k1Session is not yet implemented for WithdrawFromSubAccount"
                    );
                },
            }?;

            // Send the transaction
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
            println!("Funds withdrawn successfully: {}", result);

            // Show current balances
            if token.is_none() {
                if let Ok(recipient_account) = ctx.rpc_client.get_account(&sub_account_pubkey) {
                    println!(
                        "Sub-account balance: {} lamports",
                        recipient_account.lamports
                    );
                }
            } else {
                println!("Token transfer completed. Check token balances separately.");
            }
        },
        Command::SubAccountSign {
            id,
            role_id,
            sub_account,
            recipient,
            amount,
            token,
        } => {
            let auth_context = load_auth_context(&id)?;
            let swig_id = swig_key(format!("{:0<13}", id));
            let sub_account_pubkey = Pubkey::from_str(&sub_account)?;
            let recipient_pubkey = Pubkey::from_str(&recipient)?;

            println!(
                "Creating a transaction from sub-account {} to {}",
                sub_account_pubkey, recipient_pubkey
            );

            // Create the instruction to be executed by the sub-account
            let transfer_ix = match &token {
                Some(token_mint) => {
                    // Token transfer
                    let token_mint_pubkey = Pubkey::from_str(token_mint)?;
                    let sub_account_ata =
                        spl_associated_token_account::get_associated_token_address(
                            &sub_account_pubkey,
                            &token_mint_pubkey,
                        );
                    let recipient_ata = spl_associated_token_account::get_associated_token_address(
                        &recipient_pubkey,
                        &token_mint_pubkey,
                    );

                    Instruction {
                        program_id: spl_token::id(),
                        accounts: vec![
                            AccountMeta::new(sub_account_ata, false),
                            AccountMeta::new(recipient_ata, false),
                            AccountMeta::new(sub_account_pubkey, false),
                        ],
                        data: spl_token::instruction::TokenInstruction::Transfer { amount }.pack(),
                    }
                },
                None => {
                    // SOL transfer
                    system_instruction::transfer(&sub_account_pubkey, &recipient_pubkey, amount)
                },
            };

            // Create the sub-account sign instruction
            let ix = match auth_context.authority_type {
                CliAuthorityType::Ed25519 => {
                    let auth_pubkey = Pubkey::from_str(&auth_context.authority_identifier).unwrap();
                    SubAccountSignInstruction::new_with_ed25519_authority(
                        sub_account_pubkey,
                        swig_id,
                        auth_pubkey,
                        ctx.payer.pubkey(),
                        role_id,
                        vec![transfer_ix],
                    )
                },
                CliAuthorityType::Secp256k1 => {
                    let current_slot = ctx.rpc_client.get_slot()?;
                    SubAccountSignInstruction::new_with_secp256k1_authority(
                        sub_account_pubkey,
                        swig_id,
                        ctx.payer.pubkey(),
                        |data| {
                            let sig = auth_context.sign(data).unwrap();
                            sig[0..65].try_into().unwrap()
                        },
                        current_slot,
                        role_id,
                        vec![transfer_ix],
                    )
                },
                CliAuthorityType::Ed25519Session => {
                    anyhow::bail!("Ed25519Session is not yet implemented for SubAccountSign");
                },
                CliAuthorityType::Secp256k1Session => {
                    anyhow::bail!("Secp256k1Session is not yet implemented for SubAccountSign");
                },
            }?;

            // Send the transaction
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
            println!("Transaction executed successfully: {}", result);

            // Show current balances
            if token.is_none() {
                if let Ok(recipient_account) = ctx.rpc_client.get_account(&recipient_pubkey) {
                    println!("Recipient balance: {} lamports", recipient_account.lamports);
                }

                if let Ok(sub_account_info) = ctx.rpc_client.get_account(&sub_account_pubkey) {
                    println!(
                        "Sub-account balance: {} lamports",
                        sub_account_info.lamports
                    );
                }
            } else {
                println!("Token transfer completed. Check token balances separately.");
            }
        },
        Command::ToggleSubAccount {
            id,
            role_id,
            sub_account,
            enabled,
        } => {
            let auth_context = load_auth_context(&id)?;
            let swig_id = swig_key(format!("{:0<13}", id));
            let sub_account_pubkey = Pubkey::from_str(&sub_account)?;

            println!(
                "Toggling sub-account {} to enabled={}",
                sub_account_pubkey, enabled
            );

            // Create the instruction
            let ix = match auth_context.authority_type {
                CliAuthorityType::Ed25519 => {
                    let auth_pubkey = Pubkey::from_str(&auth_context.authority_identifier).unwrap();
                    ToggleSubAccountInstruction::new_with_ed25519_authority(
                        swig_id,
                        auth_pubkey,
                        ctx.payer.pubkey(),
                        sub_account_pubkey,
                        role_id,
                        enabled,
                    )
                },
                CliAuthorityType::Secp256k1 => {
                    let current_slot = ctx.rpc_client.get_slot()?;
                    ToggleSubAccountInstruction::new_with_secp256k1_authority(
                        swig_id,
                        ctx.payer.pubkey(),
                        |data| {
                            let sig = auth_context.sign(data).unwrap();
                            sig[0..65].try_into().unwrap()
                        },
                        current_slot,
                        sub_account_pubkey,
                        role_id,
                        enabled,
                    )
                },
                CliAuthorityType::Ed25519Session => {
                    anyhow::bail!("Ed25519Session is not yet implemented for ToggleSubAccount");
                },
                CliAuthorityType::Secp256k1Session => {
                    anyhow::bail!("Secp256k1Session is not yet implemented for ToggleSubAccount");
                },
            }?;

            // Send the transaction
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
            println!("Sub-account state toggled successfully: {}", result);

            // Display the sub-account details
            if let Ok(sub_account_data) = ctx.rpc_client.get_account_data(&sub_account_pubkey) {
                if let Ok(sub_account_state) =
                    unsafe { SwigSubAccount::load_unchecked(&sub_account_data) }
                {
                    println!("Sub-account details:");
                    println!(
                        "  Swig ID: {}",
                        bs58::encode(sub_account_state.swig_id).into_string()
                    );
                    println!("  Role ID: {}", sub_account_state.role_id);
                    println!("  Enabled: {}", sub_account_state.enabled);
                    println!("  Bump: {}", sub_account_state.bump);
                }
            }
        },
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
    let auth_file = Path::new(&get_config_path()).join(format!("{:0<32}.auth", id));
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
    Ok(compute)
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

    let swig = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow!("Failed to load swig account: {:?}", e))?;
    println!("\tKEY: {}", swig_id);
    println!(
        "\tID Bytes(bs58): {:?}",
        bs58::encode(swig.state.id.to_vec()).into_string()
    );
    println!(
        "\tLamports: {}",
        swig_account.lamports() - swig.state.reserved_lamports
    );

    for index in 0..swig.state.roles {
        let role = swig
            .get_role(index as u32)
            .map_err(|e| anyhow!("Failed to get role: {:?}", e))?
            .ok_or(anyhow!("Failed to get role"))?;
        println!("\tRole {}", index);
        let authority_type = role
            .authority_type()
            .map_err(|e| anyhow!("Failed to get authority type: {:?}", e))?;
        println!("\t\tAuthority Type: {:?}", authority_type);
        match authority_type {
            AuthorityType::Ed25519 | AuthorityType::Ed25519Session => {
                let authority = role
                    .authority
                    .identity()
                    .map_err(|e| anyhow!("Failed to get authority identity: {:?}", e))?;
                let authority = bs58::encode(authority).into_string();
                println!("\t\tAuthority: {}", authority);
            },
            AuthorityType::Secp256k1 | AuthorityType::Secp256k1Session => {
                let authority = role
                    .authority
                    .identity()
                    .map_err(|e| anyhow!("Failed to get authority identity: {:?}", e))?;
                let authority_hex = hex::encode([&[0x4].as_slice(), authority].concat());
                //get eth address from public key
                let mut hasher = solana_sdk::keccak::Hasher::default();
                hasher.hash(authority);
                let hash = hasher.result();
                let address = format!("0x{}", hex::encode(&hash.0[12..32]));
                println!(
                    "\t\tAuthority Public Key: 0x{} address {}",
                    authority_hex, address
                );
            },
            _ => {
                println!(
                    "\t\tAuthority: {:?}",
                    role.authority
                        .identity()
                        .map_err(|e| anyhow!("Failed to get authority identity: {:?}", e))?
                );
            },
        };
        println!("\t\tPermissions");
        println!("{}", "/".repeat(80));
        let actions = role
            .get_all_actions()
            .map_err(|e| anyhow!("Failed to get actions: {:?}", e))?;
        for action in actions {
            print!(
                "\t\t\t{:?}",
                action
                    .permission()
                    .map_err(|e| anyhow!("Failed to get permission type: {:?}", e))?
            );
        }
        println!("\n{}", "\\".repeat(80));
    }
    if !token_accounts.is_empty() || !token_accounts_22.is_empty() {
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

fn parse_session_authority(authority_type: &AuthorityType, authority: String) -> Result<Vec<u8>> {
    let split = authority.split(':').collect::<Vec<&str>>();
    return match authority_type {
        AuthorityType::Ed25519Session => {
            let key = bs58::decode(split[0])
                .into_vec()
                .map_err(|e| anyhow!("Failed to decode key: {:?}", e))?;
            if key.len() != 32 {
                anyhow::bail!("Invalid key length");
            }
            let key = key.try_into().unwrap();
            let max_session_duration = split[1].parse::<u64>().unwrap();
            let create_session_authority =
                CreateEd25519SessionAuthority::new(key, [0; 32], max_session_duration);

            create_session_authority
                .into_bytes()
                .map(|b| b.to_vec())
                .map_err(|e| anyhow!("Failed to create session authority: {:?}", e))
        },
        AuthorityType::Secp256k1Session => {
            let key =
                hex::decode(split[0]).map_err(|e| anyhow!("Failed to decode key: {:?}", e))?;
            if key.len() != 65 || key[0] != 4 {
                anyhow::bail!("Invalid key length");
            }
            let key: [u8; 64] = key[1..].try_into().unwrap();
            let max_session_duration = split[1].parse::<u64>()?;
            let create_session_authority =
                CreateSecp256k1SessionAuthority::new(key, [0; 32], max_session_duration);

            create_session_authority
                .into_bytes()
                .map(|b| b.to_vec())
                .map_err(|e| anyhow!("Failed to create session authority: {:?}", e))
        },
        _ => anyhow::bail!("Invalid authority type"),
    };
}

fn send_instruction(
    ctx: &SwigCliContext,
    payer: &Pubkey,
    signers: &[&dyn Signer],
    instruction: Instruction,
) -> Result<()> {
    let msg = v0::Message::try_compile(
        &payer,
        &[instruction],
        &[],
        ctx.rpc_client.get_latest_blockhash()?,
    )
    .unwrap();
    let txn = VersionedTransaction::try_new(VersionedMessage::V0(msg), signers)?;
    ctx.rpc_client
        .send_and_confirm_transaction_with_spinner(&txn)?;
    Ok(())
}

fn create(
    ctx: &SwigCliContext,
    authority_type: AuthorityType,
    authority: String,
    id: [u8; 32],
) -> Result<()> {
    let program_id = Pubkey::from(swig::ID);
    let swig_account = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id);

    let auth_bytes = match authority_type {
        AuthorityType::Ed25519 => bs58::decode(authority).into_vec()?,
        AuthorityType::Secp256k1 => hex::decode(authority).unwrap(),
        AuthorityType::Ed25519Session => parse_session_authority(&authority_type, authority)?,
        AuthorityType::Secp256k1Session => parse_session_authority(&authority_type, authority)?,
        _ => anyhow::bail!("Invalid authority type"),
    };

    let instruction = CreateInstruction::new(
        swig_account.0,
        swig_account.1,
        ctx.payer.pubkey(),
        AuthorityConfig {
            authority_type,
            authority: &auth_bytes,
        },
        vec![ClientAction::All(All {})],
        id,
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
    diplay_swig(ctx, swig_account.0)?;
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
                },
            }
        },
        _ => {
            anyhow::bail!("Please provide a keypair and rpc or a solana config file");
        },
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

fn permissions_to_actions(permissions: Vec<String>) -> Vec<ClientAction> {
    let mut actions = Vec::new();
    for permission in permissions {
        let permission = permission.split(':').collect::<Vec<&str>>();
        let len = permission.len();
        match permission[0] {
            "all" => {
                actions.push(ClientAction::All(All {}));
            },
            "manage_authority" => {
                actions.push(ClientAction::ManageAuthority(ManageAuthority {}));
            },
            "token" => {
                if len == 2 {
                    let token = permission[1].parse::<String>().unwrap();
                    let token = Pubkey::from_str(&token).unwrap();
                    actions.push(ClientAction::TokenLimit(TokenLimit {
                        token_mint: token.to_bytes(),
                        current_amount: u64::MAX,
                    }));
                    continue;
                }
                if len == 3 {
                    let token = permission[1].parse::<String>().unwrap();
                    let token = Pubkey::from_str(&token).unwrap();
                    let amount = permission[2].parse::<u64>().unwrap();
                    actions.push(ClientAction::TokenLimit(TokenLimit {
                        token_mint: token.to_bytes(),
                        current_amount: amount,
                    }));
                }
            },
            "sol" => {
                if len == 1 {
                    actions.push(ClientAction::SolLimit(SolLimit { amount: u64::MAX }));
                    continue;
                }
                if len == 2 {
                    let amount = permission[1].parse::<u64>().unwrap();
                    actions.push(ClientAction::SolLimit(SolLimit { amount }));
                }
            },
            _ => {
                println!("Invalid permission: {}", permission[0]);
            },
        }
    }
    actions
}
