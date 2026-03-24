use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModelLedgerError {
    #[error("Missing required field: {0}")]
    MissingField(&'static str),

    #[error("Serialisation error: {0}")]
    SerdeError(#[from] serde_json::Error),

    #[error("Canonical JSON error: {0}")]
    CanonError(String),

    #[error("Signature verification failed")]
    InvalidSignature,

    #[error("Invalid key encoding: {0}")]
    KeyError(String),
}
