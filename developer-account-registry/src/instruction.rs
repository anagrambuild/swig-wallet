use num_enum::{IntoPrimitive, TryFromPrimitive};
use pinocchio::{account_info::AccountInfo, program_error::ProgramError};
use shank::ShankContext;

#[derive(Clone, Copy, Debug, ShankContext, TryFromPrimitive, IntoPrimitive)]
#[rustfmt::skip]
#[repr(u16)]
pub enum DeveloperAccountRegistryInstruction {
    #[account(0, writable, name="developer_account", desc="the developer account PDA")]
    #[account(1, signer, name="registry_admin", desc="the embedded registry admin")]
    #[account(2, writable, signer, name="payer", desc="the rent payer")]
    #[account(3, name="system_program", desc="the system program")]
    CreateOrUpdateDeveloperAccount = 0,

    #[account(0, writable, name="developer_account", desc="the developer account PDA")]
    #[account(1, signer, name="registry_admin", desc="the embedded registry admin")]
    UpdateDeveloperSigner = 1,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_values_are_stable() {
        assert_eq!(
            u16::from(DeveloperAccountRegistryInstruction::CreateOrUpdateDeveloperAccount),
            0
        );
        assert_eq!(
            u16::from(DeveloperAccountRegistryInstruction::UpdateDeveloperSigner),
            1
        );
        assert!(DeveloperAccountRegistryInstruction::try_from(2u16).is_err());
    }
}
