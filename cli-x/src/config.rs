use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SigningAuthority {
    pub authority_type: String,
    pub authority: String,
    pub authority_kp: String,
    pub fee_payer: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SwigConfig {
    pub default_authority: SigningAuthority,
    pub rpc_url: Option<String>,
}

impl Default for SwigConfig {
    fn default() -> Self {
        Self {
            default_authority: SigningAuthority {
                authority_type: "Ed25519".to_string(),
                authority: String::new(),
                authority_kp: String::new(),
                fee_payer: String::new(),
            },
            rpc_url: Some("http://localhost:8899".to_string()),
        }
    }
}

impl SwigConfig {
    pub fn load(config_dir: &PathBuf) -> Result<Self> {
        let config_path = config_dir.join("config.json");
        if !config_path.exists() {
            return Ok(Self::default());
        }

        let config_str = fs::read_to_string(config_path)?;
        serde_json::from_str(&config_str).map_err(|e| anyhow!("Failed to parse config: {}", e))
    }

    pub fn save(&self, config_dir: &PathBuf) -> Result<()> {
        let config_path = config_dir.join("config.json");
        let config_str = serde_json::to_string_pretty(self)?;
        fs::write(config_path, config_str)?;
        Ok(())
    }

    pub fn update_from_cli_args(
        &mut self,
        authority_type: Option<String>,
        authority: Option<String>,
        authority_kp: Option<String>,
        fee_payer: Option<String>,
        rpc_url: Option<String>,
    ) {
        if let Some(authority_type) = authority_type {
            self.default_authority.authority_type = authority_type;
        }
        if let Some(authority) = authority {
            self.default_authority.authority = authority;
        }
        if let Some(authority_kp) = authority_kp {
            self.default_authority.authority_kp = authority_kp;
        }
        if let Some(fee_payer) = fee_payer {
            self.default_authority.fee_payer = fee_payer;
        }
        if let Some(rpc_url) = rpc_url {
            self.rpc_url = Some(rpc_url);
        }
    }
}
