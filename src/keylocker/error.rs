use std::env::VarError;

use base64::DecodeError;

#[derive(thiserror::Error, Debug)]
pub enum ServerKeyError {
    #[error("VarError: {0}")]
    Var(#[from] VarError),

    #[error("Decode: {0}")]
    Decode(#[from] DecodeError),

    #[error("KeyLength: Server Key size is invalid. Must be 32 bytes")]
    KeyLength,
}

#[derive(thiserror::Error, Debug)]
pub enum KdfError {
    #[error("UserKey: Failed to derive user key: {0}")]
    User(argon2::Error),

    #[error("OutputKey: Failed to derive output key: {0}")]
    OutputKey(#[from] hkdf::InvalidLength),
}

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("ServerKeyError: {0}")]
    ServerKey(#[from] ServerKeyError),

    #[error("KdfError: {0}")]
    Kdf(#[from] KdfError),

    #[error("ChaCha20Poly1305Error: {0}")]
    ChaCha20Poly1305(chacha20poly1305::Error),
}
