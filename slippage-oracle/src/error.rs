use pinocchio::program_error::ProgramError;

#[derive(Debug)]
pub enum OracleError {
    SlippageExceeded = 0,
    InvalidInstruction = 1,
    InvalidAccountCount = 2,
    InvalidSwigAccount = 3,
    ArithmeticOverflow = 4,
}

impl From<OracleError> for ProgramError {
    fn from(e: OracleError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
