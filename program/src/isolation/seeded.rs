//! Select accounts used by direct native instructions with a signed base key.

use pinocchio::ProgramResult;

use super::IsolationGuard;
use crate::error::SwigError;

impl IsolationGuard<'_> {
    /// Scan the complete compact batch before snapshots or CPI. The native
    /// program validates the seed derivation; a successful with-seed operation
    /// using a protected base signer must preserve the target's existing assets.
    /// Nested CPI instruction data is not visible here.
    #[inline(always)]
    pub fn capture_seeded_accounts(&mut self, payload: &[u8]) -> ProgramResult {
        if self.signers.as_slice().is_empty()
            || !self.accounts.iter().any(|account| {
                account.is_writable()
                    && (account.is_owned_by(&crate::STAKING_ID)
                        || account.is_owned_by(&crate::VOTE_PROGRAM_ID)
                        || (account.is_owned_by(&crate::SYSTEM_PROGRAM_ID)
                            && account.data_len() == 0
                            && account.lamports() != 0))
            })
        {
            return Ok(());
        }

        // Read only borrowed compact fields. The execution iterator allocates
        // CPI metas, which are unnecessary for this preflight pass.
        let (count, mut remaining) = payload
            .split_first()
            .ok_or(SwigError::InstructionExecutionError)?;
        for _ in 0..*count {
            let (header, rest) = remaining
                .split_at_checked(2)
                .ok_or(SwigError::InstructionExecutionError)?;
            let program = self
                .accounts
                .get(header[0] as usize)
                .ok_or(SwigError::InstructionExecutionError)?;
            let (indexes, rest) = rest
                .split_at_checked(header[1] as usize)
                .ok_or(SwigError::InstructionExecutionError)?;
            let (length, rest) = rest
                .split_at_checked(2)
                .ok_or(SwigError::InstructionExecutionError)?;
            let (data, rest) = rest
                .split_at_checked(u16::from_le_bytes([length[0], length[1]]) as usize)
                .ok_or(SwigError::InstructionExecutionError)?;
            remaining = rest;

            let (target_position, base_position) = match (program.key(), data.get(..4)) {
                // Stake AuthorizeWithSeed / AuthorizeCheckedWithSeed.
                (&crate::STAKING_ID, Some([8, 0, 0, 0] | [11, 0, 0, 0])) => (0, Some(1)),
                // Vote AuthorizeWithSeed / AuthorizeCheckedWithSeed put clock first.
                (&crate::VOTE_PROGRAM_ID, Some([10, 0, 0, 0] | [11, 0, 0, 0])) => (0, Some(2)),
                // System TransferWithSeed also uses account 1 as the base.
                (&crate::SYSTEM_PROGRAM_ID, Some([11, 0, 0, 0])) => (0, Some(1)),
                // AllocateWithSeed / AssignWithSeed encode the base in data.
                // The runtime accepts that signer anywhere in the account list.
                (&crate::SYSTEM_PROGRAM_ID, Some([9, 0, 0, 0] | [10, 0, 0, 0])) => (0, None),
                // CreateAccountWithSeed encodes the base in the same data field.
                (&crate::SYSTEM_PROGRAM_ID, Some([3, 0, 0, 0])) => (1, None),
                _ => continue,
            };
            let target_index = indexes
                .get(target_position)
                .ok_or(SwigError::InstructionExecutionError)?;
            let target = self
                .accounts
                .get(*target_index as usize)
                .ok_or(SwigError::InstructionExecutionError)?;
            let base = if let Some(position) = base_position {
                let index = indexes
                    .get(position)
                    .ok_or(SwigError::InstructionExecutionError)?;
                self.accounts
                    .get(*index as usize)
                    .ok_or(SwigError::InstructionExecutionError)?
                    .key()
                    .as_slice()
            } else {
                data.get(4..36)
                    .ok_or(SwigError::InstructionExecutionError)?
            };
            if target.is_writable()
                && target.is_owned_by(program.key())
                && (program.key() == &crate::STAKING_ID
                    || program.key() == &crate::VOTE_PROGRAM_ID
                    || (target.data_len() == 0 && target.lamports() != 0))
                && self
                    .signers
                    .as_slice()
                    .iter()
                    .any(|signer| self.accounts[signer.index as usize].key().as_slice() == base)
            {
                self.seeded[*target_index as usize / 8] |= 1 << (*target_index as usize % 8);
            }
        }
        Ok(())
    }
}
