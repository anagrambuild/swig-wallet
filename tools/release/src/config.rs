use std::{env, str::FromStr};

use anyhow::{anyhow, ensure, Result};
use solana_sdk::{pubkey::Pubkey, signature::Keypair};
use zeroize::Zeroizing;

// Deliberately no Debug: the RPC URL can contain credentials.
pub struct ReleaseConfig {
    pub rpc_url: String,
    pub squads_program: Pubkey,
    pub multisig: Pubkey,
    pub vault_index: u8,
    pub program: Pubkey,
}

impl ReleaseConfig {
    pub fn from_env() -> Result<Self> {
        let rpc_url =
            env::var("SOLANA_RPC_URL").map_err(|_| anyhow!("SOLANA_RPC_URL is required"))?;
        let parsed = url::Url::parse(&rpc_url)
            .map_err(|_| anyhow!("SOLANA_RPC_URL must be an HTTP(S) URL"))?;
        ensure!(
            matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some(),
            "SOLANA_RPC_URL must be an HTTP(S) URL"
        );
        let squads_program =
            env::var("SQUADS_PROGRAM_ID").map_err(|_| anyhow!("SQUADS_PROGRAM_ID is required"))?;
        let multisig = env::var("SQUADS_MULTISIG_ADDRESS")
            .map_err(|_| anyhow!("SQUADS_MULTISIG_ADDRESS is required"))?;
        let vault_index = env::var("SQUADS_VAULT_INDEX")
            .map_err(|_| anyhow!("SQUADS_VAULT_INDEX is required"))?;
        let program =
            env::var("SWIG_PROGRAM_ID").map_err(|_| anyhow!("SWIG_PROGRAM_ID is required"))?;
        Ok(Self {
            rpc_url,
            squads_program: Pubkey::from_str(&squads_program)
                .map_err(|_| anyhow!("SQUADS_PROGRAM_ID must be a public key"))?,
            multisig: Pubkey::from_str(&multisig)
                .map_err(|_| anyhow!("SQUADS_MULTISIG_ADDRESS must be a public key"))?,
            vault_index: vault_index
                .parse()
                .map_err(|_| anyhow!("SQUADS_VAULT_INDEX must be an integer from 0 to 255"))?,
            program: Pubkey::from_str(&program)
                .map_err(|_| anyhow!("SWIG_PROGRAM_ID must be a public key"))?,
        })
    }
}

pub fn load_proposer() -> Result<Keypair> {
    let secret = Zeroizing::new(
        env::var("PROPOSER_KEYPAIR").map_err(|_| anyhow!("PROPOSER_KEYPAIR is required"))?,
    );
    parse_proposer(&secret)
}

pub fn parse_proposer(secret: &str) -> Result<Keypair> {
    let bytes = Zeroizing::new(
        serde_json::from_str::<Vec<u8>>(secret)
            .map_err(|_| anyhow!("PROPOSER_KEYPAIR must be a Solana keypair JSON array"))?,
    );
    Keypair::try_from(bytes.as_slice())
        .map_err(|_| anyhow!("PROPOSER_KEYPAIR must contain a valid 64-byte Solana keypair"))
}
