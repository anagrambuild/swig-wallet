//! Select accounts used by direct native instructions with a signed base key.

use pinocchio::ProgramResult;

use super::IsolationGuard;
use crate::error::SwigError;

impl IsolationGuard<'_> {
    /// Scan the complete compact batch before snapshots or CPI. The native
    /// program validates the seed derivation; a successful with-seed operation
    /// using a protected base signer must preserve the target's existing assets.
    /// Nested CPI instruction data is not visible here.
    #[inline(never)]
    pub fn capture_seeded_accounts(&mut self, payload: &[u8]) -> ProgramResult {
        if self.signers.as_slice().is_empty()
            || !self
                .accounts
                .iter()
                .any(|account| account.is_writable() && account.is_owned_by(&crate::STAKING_ID))
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

            // Stake AuthorizeWithSeed / AuthorizeCheckedWithSeed. Both use
            // account 0 as the target and account 1 as the signed authority base.
            if program.key() != &crate::STAKING_ID
                || !matches!(data.get(..4), Some([8, 0, 0, 0] | [11, 0, 0, 0]))
            {
                continue;
            }
            let [target_index, base_index, ..] = indexes else {
                return Err(SwigError::InstructionExecutionError.into());
            };
            let target = self
                .accounts
                .get(*target_index as usize)
                .ok_or(SwigError::InstructionExecutionError)?;
            let base = self
                .accounts
                .get(*base_index as usize)
                .ok_or(SwigError::InstructionExecutionError)?;
            if target.is_writable()
                && target.is_owned_by(&crate::STAKING_ID)
                && self
                    .signers
                    .as_slice()
                    .iter()
                    .any(|signer| self.accounts[signer.index as usize].key() == base.key())
            {
                self.seeded[*target_index as usize / 8] |= 1 << (*target_index as usize % 8);
            }
        }
        Ok(())
    }
}
