use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
use solana_system_interface::program as system_program;

pub const CONFIGURE_RECOVERY_V1_DISCRIMINATOR: [u8; 8] = *b"cfgrecV1";
pub const SET_OPERATOR_V1_DISCRIMINATOR: [u8; 8] = *b"setoprV1";
pub const START_RECOVERY_V1_DISCRIMINATOR: [u8; 8] = *b"strrecV1";
pub const CANCEL_RECOVERY_V1_DISCRIMINATOR: [u8; 8] = *b"canrecV1";
pub const EXECUTE_RECOVERY_V1_DISCRIMINATOR: [u8; 8] = *b"execreV1";

pub const OPERATOR_CONFIG_SEED: &[u8] = b"operator-config";
pub const RECOVERY_CONFIG_SEED: &[u8] = b"recovery-config";
pub const PENDING_RECOVERY_SEED: &[u8] = b"pending-recovery";
pub const MAX_RECOVERY_AUTHORITY_LEN: usize = 64;

pub fn find_operator_config_address(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[OPERATOR_CONFIG_SEED], program_id)
}

pub fn find_recovery_config_address(program_id: &Pubkey, swig_wallet: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[RECOVERY_CONFIG_SEED, swig_wallet.as_ref()], program_id)
}

pub fn find_pending_recovery_address(
    program_id: &Pubkey,
    swig_wallet: &Pubkey,
    target_role_id: u32,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            PENDING_RECOVERY_SEED,
            swig_wallet.as_ref(),
            &target_role_id.to_le_bytes(),
        ],
        program_id,
    )
}

pub fn configure_recovery_v1_instruction(
    program_id: Pubkey,
    payer: Pubkey,
    operator: Pubkey,
    org_config: Pubkey,
    swig_wallet: Pubkey,
    target_role_id: u32,
    guardian: Pubkey,
    delay_slots: u64,
) -> Instruction {
    let (config, _) = find_recovery_config_address(&program_id, &swig_wallet);
    let (operator_config, _) = find_operator_config_address(&program_id);
    let mut data = Vec::with_capacity(8 + 32 + 4 + 32 + 8);
    data.extend_from_slice(&CONFIGURE_RECOVERY_V1_DISCRIMINATOR);
    data.extend_from_slice(org_config.as_ref());
    data.extend_from_slice(&target_role_id.to_le_bytes());
    data.extend_from_slice(guardian.as_ref());
    data.extend_from_slice(&delay_slots.to_le_bytes());

    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(config, false),
            AccountMeta::new_readonly(operator_config, false),
            AccountMeta::new_readonly(operator, true),
            AccountMeta::new_readonly(swig_wallet, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

pub fn set_operator_v1_instruction(
    program_id: Pubkey,
    payer: Pubkey,
    admin: Pubkey,
    program_data: Pubkey,
    operator: Pubkey,
) -> Instruction {
    let (operator_config, _) = find_operator_config_address(&program_id);
    let mut data = Vec::with_capacity(8 + 32);
    data.extend_from_slice(&SET_OPERATOR_V1_DISCRIMINATOR);
    data.extend_from_slice(operator.as_ref());

    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(operator_config, false),
            AccountMeta::new_readonly(admin, true),
            AccountMeta::new_readonly(program_data, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

pub fn start_recovery_v1_instruction(
    program_id: Pubkey,
    payer: Pubkey,
    guardian: Pubkey,
    swig_wallet: Pubkey,
    target_role_id: u32,
    authority_type: u16,
    old_authority: &[u8],
    new_authority: &[u8],
) -> Instruction {
    let (config, _) = find_recovery_config_address(&program_id, &swig_wallet);
    let (pending, _) = find_pending_recovery_address(&program_id, &swig_wallet, target_role_id);
    assert!(!old_authority.is_empty() && old_authority.len() <= MAX_RECOVERY_AUTHORITY_LEN);
    assert!(!new_authority.is_empty() && new_authority.len() <= MAX_RECOVERY_AUTHORITY_LEN);
    let mut data = Vec::with_capacity(8 + 2 + 2 + 2 + old_authority.len() + new_authority.len());
    data.extend_from_slice(&START_RECOVERY_V1_DISCRIMINATOR);
    data.extend_from_slice(&authority_type.to_le_bytes());
    data.extend_from_slice(&(old_authority.len() as u16).to_le_bytes());
    data.extend_from_slice(&(new_authority.len() as u16).to_le_bytes());
    data.extend_from_slice(old_authority);
    data.extend_from_slice(new_authority);

    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(guardian, true),
            AccountMeta::new_readonly(config, false),
            AccountMeta::new(pending, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

pub fn cancel_recovery_v1_instruction(
    program_id: Pubkey,
    swig_wallet: Pubkey,
    target_role_id: u32,
) -> Instruction {
    let (pending, _) = find_pending_recovery_address(&program_id, &swig_wallet, target_role_id);

    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(swig_wallet, true),
            AccountMeta::new(pending, false),
        ],
        data: CANCEL_RECOVERY_V1_DISCRIMINATOR.to_vec(),
    }
}

pub fn execute_recovery_v1_instruction(
    program_id: Pubkey,
    swig_config: Pubkey,
    swig_wallet: Pubkey,
    target_role_id: u32,
    authority_type: u16,
    old_authority: &[u8],
    new_authority: &[u8],
) -> Instruction {
    let (pending, _) = find_pending_recovery_address(&program_id, &swig_wallet, target_role_id);
    assert!(!old_authority.is_empty() && old_authority.len() <= MAX_RECOVERY_AUTHORITY_LEN);
    assert!(!new_authority.is_empty() && new_authority.len() <= MAX_RECOVERY_AUTHORITY_LEN);
    let mut data = Vec::with_capacity(8 + 2 + 2 + 2 + old_authority.len() + new_authority.len());
    data.extend_from_slice(&EXECUTE_RECOVERY_V1_DISCRIMINATOR);
    data.extend_from_slice(&authority_type.to_le_bytes());
    data.extend_from_slice(&(old_authority.len() as u16).to_le_bytes());
    data.extend_from_slice(&(new_authority.len() as u16).to_le_bytes());
    data.extend_from_slice(old_authority);
    data.extend_from_slice(new_authority);

    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(swig_config, false),
            AccountMeta::new_readonly(swig_wallet, false),
            AccountMeta::new(pending, false),
        ],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminators_are_stable() {
        assert_eq!(CONFIGURE_RECOVERY_V1_DISCRIMINATOR, *b"cfgrecV1");
        assert_eq!(SET_OPERATOR_V1_DISCRIMINATOR, *b"setoprV1");
        assert_eq!(START_RECOVERY_V1_DISCRIMINATOR, *b"strrecV1");
        assert_eq!(CANCEL_RECOVERY_V1_DISCRIMINATOR, *b"canrecV1");
        assert_eq!(EXECUTE_RECOVERY_V1_DISCRIMINATOR, *b"execreV1");
    }

    #[test]
    fn pending_address_includes_target_role() {
        let program_id = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();
        let (role_zero, _) = find_pending_recovery_address(&program_id, &wallet, 0);
        let (role_one, _) = find_pending_recovery_address(&program_id, &wallet, 1);

        assert_ne!(role_zero, role_one);
    }
}
