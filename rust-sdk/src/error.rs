use thiserror::Error;

/// Errors that can occur when using the Swig wallet SDK
#[derive(Error, Debug)]
pub enum SwigError {
    /// Indicates that an invalid authority type was provided
    #[error("Invalid authority type provided")]
    InvalidAuthorityType,

    /// Error occurred during base58 decoding
    #[error("Base58 decode error: {0}")]
    Base58DecodeError(#[from] bs58::decode::Error),

    /// Solana program error
    #[error("Program error: {0}")]
    ProgramError(#[from] solana_program::program_error::ProgramError),

    /// General interface error with description
    #[error("Interface error: {0}")]
    InterfaceError(String),

    /// RPC client error
    #[error("RPC client error: {0}")]
    ClientError(#[from] solana_client::client_error::ClientError),

    /// Invalid swig data
    #[error("Invalid swig data")]
    InvalidSwigData,

    /// Authority not found
    #[error("Authority not found")]
    AuthorityNotFound,

    /// Invalid swig account discriminator
    #[error("Invalid swig account discriminator")]
    InvalidSwigAccountDiscriminator,

    /// Error occurred during message compilation
    #[error("Message compilation error: {0}")]
    MessageCompilationError(String),

    /// Invalid secp256k1 signature
    #[error("Invalid secp256k1 signature")]
    InvalidSecp256k1,

    /// Transaction error
    #[error("Transaction error")]
    TransactionError,
}

impl From<anyhow::Error> for SwigError {
    fn from(error: anyhow::Error) -> Self {
        SwigError::InterfaceError(error.to_string())
    }
}

impl From<solana_sdk::message::CompileError> for SwigError {
    fn from(error: solana_sdk::message::CompileError) -> Self {
        SwigError::MessageCompilationError(error.to_string())
    }
}
