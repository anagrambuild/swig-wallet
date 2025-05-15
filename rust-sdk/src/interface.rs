// Look for the existing instruction implementations and add the ToggleSubAccountInstruction

// Sub-account instruction structures
pub struct ToggleSubAccountInstruction;

impl ToggleSubAccountInstruction {
    pub fn new(
        swig_account: Pubkey,
        authority: Pubkey,
        payer: Pubkey,
        sub_account: Pubkey,
        role_id: u32,
        enabled: bool,
    ) -> Result<Instruction, SwigError> {
        let accounts = vec![
            AccountMeta::new(swig_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(sub_account, false),
        ];

        let mut buffer = vec![];
        buffer.extend_from_slice(&(10u16).to_le_bytes()); // ToggleSubAccountV1 = 10
        buffer.extend_from_slice(&[0]); // padding
        buffer.push(if enabled { 1 } else { 0 });
        buffer.extend_from_slice(&role_id.to_le_bytes());

        Ok(Instruction {
            program_id: program_id(),
            accounts,
            data: buffer,
        })
    }
}
