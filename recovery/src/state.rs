use solana_program::{hash::hashv, program_error::ProgramError, pubkey::Pubkey};

use crate::error::RecoveryError;

pub const RECOVERY_CONFIG_V1_DISCRIMINATOR: [u8; 8] = *b"rcfgstV1";
pub const PENDING_RECOVERY_V1_DISCRIMINATOR: [u8; 8] = *b"rpendV01";
pub const OPERATOR_CONFIG_V1_DISCRIMINATOR: [u8; 8] = *b"opcfgV01";

pub const RECOVERY_CONFIG_V1_LEN: usize = 8 + 32 + 32 + 4 + 32 + 8 + 1;
pub const PENDING_RECOVERY_V1_LEN: usize =
    8 + 32 + 32 + 4 + 32 + 32 + 32 + 8 + 8 + 1 + 1 + 2 + 2 + 2;
pub const OPERATOR_CONFIG_V1_LEN: usize = 8 + 32 + 1;

pub const PENDING_RECOVERY_STATUS_PENDING: u8 = 0;
pub const PENDING_RECOVERY_STATUS_CANCELLED: u8 = 1;
pub const PENDING_RECOVERY_STATUS_EXECUTED: u8 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryConfigV1 {
    pub org_config: Pubkey,
    pub swig_wallet: Pubkey,
    pub target_role_id: u32,
    pub guardian: Pubkey,
    pub delay_slots: u64,
    pub bump: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorConfigV1 {
    pub operator: Pubkey,
    pub bump: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingRecoveryV1 {
    pub org_config: Pubkey,
    pub swig_wallet: Pubkey,
    pub target_role_id: u32,
    pub guardian: Pubkey,
    pub old_authority_hash: [u8; 32],
    pub new_authority_hash: [u8; 32],
    pub start_slot: u64,
    pub executable_after_slot: u64,
    pub status: u8,
    pub bump: u8,
    pub authority_type: u16,
    pub old_authority_len: u16,
    pub new_authority_len: u16,
}

pub fn hash_authority(authority: &[u8]) -> [u8; 32] {
    hashv(&[authority]).to_bytes()
}

impl OperatorConfigV1 {
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < OPERATOR_CONFIG_V1_LEN || data[0..8] != OPERATOR_CONFIG_V1_DISCRIMINATOR {
            return Err(RecoveryError::InvalidState.into());
        }

        Ok(Self {
            operator: read_pubkey(data, 8)?,
            bump: read_u8(data, 40)?,
        })
    }

    pub fn pack(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < OPERATOR_CONFIG_V1_LEN {
            return Err(RecoveryError::InvalidState.into());
        }

        data[..OPERATOR_CONFIG_V1_LEN].fill(0);
        data[0..8].copy_from_slice(&OPERATOR_CONFIG_V1_DISCRIMINATOR);
        write_pubkey(data, 8, &self.operator)?;
        write_u8(data, 40, self.bump)?;
        Ok(())
    }
}

impl RecoveryConfigV1 {
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < RECOVERY_CONFIG_V1_LEN || data[0..8] != RECOVERY_CONFIG_V1_DISCRIMINATOR {
            return Err(RecoveryError::InvalidState.into());
        }

        Ok(Self {
            org_config: read_pubkey(data, 8)?,
            swig_wallet: read_pubkey(data, 40)?,
            target_role_id: read_u32(data, 72)?,
            guardian: read_pubkey(data, 76)?,
            delay_slots: read_u64(data, 108)?,
            bump: read_u8(data, 116)?,
        })
    }

    pub fn pack(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < RECOVERY_CONFIG_V1_LEN {
            return Err(RecoveryError::InvalidState.into());
        }

        data[..RECOVERY_CONFIG_V1_LEN].fill(0);
        data[0..8].copy_from_slice(&RECOVERY_CONFIG_V1_DISCRIMINATOR);
        write_pubkey(data, 8, &self.org_config)?;
        write_pubkey(data, 40, &self.swig_wallet)?;
        write_u32(data, 72, self.target_role_id)?;
        write_pubkey(data, 76, &self.guardian)?;
        write_u64(data, 108, self.delay_slots)?;
        write_u8(data, 116, self.bump)?;
        Ok(())
    }
}

impl PendingRecoveryV1 {
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < PENDING_RECOVERY_V1_LEN || data[0..8] != PENDING_RECOVERY_V1_DISCRIMINATOR {
            return Err(RecoveryError::InvalidState.into());
        }

        Ok(Self {
            org_config: read_pubkey(data, 8)?,
            swig_wallet: read_pubkey(data, 40)?,
            target_role_id: read_u32(data, 72)?,
            guardian: read_pubkey(data, 76)?,
            old_authority_hash: read_hash(data, 108)?,
            new_authority_hash: read_hash(data, 140)?,
            start_slot: read_u64(data, 172)?,
            executable_after_slot: read_u64(data, 180)?,
            status: read_u8(data, 188)?,
            bump: read_u8(data, 189)?,
            authority_type: read_u16(data, 190)?,
            old_authority_len: read_u16(data, 192)?,
            new_authority_len: read_u16(data, 194)?,
        })
    }

    pub fn pack(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < PENDING_RECOVERY_V1_LEN {
            return Err(RecoveryError::InvalidState.into());
        }

        data[..PENDING_RECOVERY_V1_LEN].fill(0);
        data[0..8].copy_from_slice(&PENDING_RECOVERY_V1_DISCRIMINATOR);
        write_pubkey(data, 8, &self.org_config)?;
        write_pubkey(data, 40, &self.swig_wallet)?;
        write_u32(data, 72, self.target_role_id)?;
        write_pubkey(data, 76, &self.guardian)?;
        write_hash(data, 108, &self.old_authority_hash)?;
        write_hash(data, 140, &self.new_authority_hash)?;
        write_u64(data, 172, self.start_slot)?;
        write_u64(data, 180, self.executable_after_slot)?;
        write_u8(data, 188, self.status)?;
        write_u8(data, 189, self.bump)?;
        write_u16(data, 190, self.authority_type)?;
        write_u16(data, 192, self.old_authority_len)?;
        write_u16(data, 194, self.new_authority_len)?;
        Ok(())
    }
}

fn read_u8(data: &[u8], offset: usize) -> Result<u8, ProgramError> {
    data.get(offset)
        .copied()
        .ok_or_else(|| RecoveryError::InvalidState.into())
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, ProgramError> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or(RecoveryError::InvalidState)?
        .try_into()
        .map_err(|_| RecoveryError::InvalidState)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, ProgramError> {
    let bytes: [u8; 2] = data
        .get(offset..offset + 2)
        .ok_or(RecoveryError::InvalidState)?
        .try_into()
        .map_err(|_| RecoveryError::InvalidState)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, ProgramError> {
    let bytes: [u8; 8] = data
        .get(offset..offset + 8)
        .ok_or(RecoveryError::InvalidState)?
        .try_into()
        .map_err(|_| RecoveryError::InvalidState)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_hash(data: &[u8], offset: usize) -> Result<[u8; 32], ProgramError> {
    data.get(offset..offset + 32)
        .ok_or(RecoveryError::InvalidState)?
        .try_into()
        .map_err(|_| RecoveryError::InvalidState.into())
}

fn read_pubkey(data: &[u8], offset: usize) -> Result<Pubkey, ProgramError> {
    let bytes: [u8; 32] = read_hash(data, offset)?;
    Ok(Pubkey::new_from_array(bytes))
}

fn write_u8(data: &mut [u8], offset: usize, value: u8) -> Result<(), ProgramError> {
    let slot = data.get_mut(offset).ok_or(RecoveryError::InvalidState)?;
    *slot = value;
    Ok(())
}

fn write_u16(data: &mut [u8], offset: usize, value: u16) -> Result<(), ProgramError> {
    let target = data
        .get_mut(offset..offset + 2)
        .ok_or(RecoveryError::InvalidState)?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) -> Result<(), ProgramError> {
    let target = data
        .get_mut(offset..offset + 4)
        .ok_or(RecoveryError::InvalidState)?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(data: &mut [u8], offset: usize, value: u64) -> Result<(), ProgramError> {
    let target = data
        .get_mut(offset..offset + 8)
        .ok_or(RecoveryError::InvalidState)?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_hash(data: &mut [u8], offset: usize, value: &[u8; 32]) -> Result<(), ProgramError> {
    let target = data
        .get_mut(offset..offset + 32)
        .ok_or(RecoveryError::InvalidState)?;
    target.copy_from_slice(value);
    Ok(())
}

fn write_pubkey(data: &mut [u8], offset: usize, value: &Pubkey) -> Result<(), ProgramError> {
    let bytes = value.to_bytes();
    write_hash(data, offset, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_config_round_trip() {
        let config = RecoveryConfigV1 {
            org_config: Pubkey::new_unique(),
            swig_wallet: Pubkey::new_unique(),
            target_role_id: 7,
            guardian: Pubkey::new_unique(),
            delay_slots: 42,
            bump: 255,
        };
        let mut data = vec![0; RECOVERY_CONFIG_V1_LEN];

        config.pack(&mut data).unwrap();

        assert_eq!(RecoveryConfigV1::unpack(&data).unwrap(), config);
    }

    #[test]
    fn packs_pending_round_trip() {
        let pending = PendingRecoveryV1 {
            org_config: Pubkey::new_unique(),
            swig_wallet: Pubkey::new_unique(),
            target_role_id: 7,
            guardian: Pubkey::new_unique(),
            old_authority_hash: [1; 32],
            new_authority_hash: [2; 32],
            start_slot: 42,
            executable_after_slot: 100,
            status: PENDING_RECOVERY_STATUS_PENDING,
            bump: 254,
            authority_type: 5,
            old_authority_len: 33,
            new_authority_len: 33,
        };
        let mut data = vec![0; PENDING_RECOVERY_V1_LEN];

        pending.pack(&mut data).unwrap();

        assert_eq!(PendingRecoveryV1::unpack(&data).unwrap(), pending);
    }

    #[test]
    fn packs_operator_config_round_trip() {
        let config = OperatorConfigV1 {
            operator: Pubkey::new_unique(),
            bump: 253,
        };
        let mut data = vec![0; OPERATOR_CONFIG_V1_LEN];

        config.pack(&mut data).unwrap();

        assert_eq!(OperatorConfigV1::unpack(&data).unwrap(), config);
    }
}
