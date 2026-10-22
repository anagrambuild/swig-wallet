pub use developer_account_registry;
use developer_account_registry::actions::create_or_update_developer_account::CreateOrUpdateDeveloperAccountArgs;
pub use developer_account_registry_state::{
    self, developer_account_seeds, DeveloperAccount, DeveloperTier,
};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
use swig_state::IntoBytes;

pub fn program_id() -> Pubkey {
    developer_account_registry::ID.into()
}

pub fn registry_admin() -> Pubkey {
    developer_account_registry::REGISTRY_ADMIN.into()
}

pub fn developer_account_address(developer_account_id: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &developer_account_seeds(developer_account_id),
        &program_id(),
    )
}

pub struct CreateOrUpdateDeveloperAccountInstruction;

impl CreateOrUpdateDeveloperAccountInstruction {
    pub fn new(
        developer_account: Pubkey,
        registry_admin: Pubkey,
        payer: Pubkey,
        developer_account_id: [u8; 32],
        tier: DeveloperTier,
        valid_until: i64,
    ) -> anyhow::Result<Instruction> {
        let accounts = vec![
            AccountMeta::new(developer_account, false),
            AccountMeta::new_readonly(registry_admin, true),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];
        let args = CreateOrUpdateDeveloperAccountArgs::new(developer_account_id, tier, valid_until);
        let args_bytes = args
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize args {:?}", e))?;
        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: args_bytes.to_vec(),
        })
    }
}
