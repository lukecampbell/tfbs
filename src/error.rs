use actix_web::{App, HttpResponse, ResponseError, http::StatusCode};

use crate::keylocker::{KdfError, ServerKeyError};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("PasswordHash: {0}")]
    PasswordHash(String),

    #[error("Database")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Redis")]
    RedisError(#[from] redis::RedisError),

    #[error("ServerKey")]
    ServerKey(#[from] ServerKeyError),

    #[error("UserSalt: The salt length is invalid for encryption/decryption")]
    UserSalt,

    #[error("KdfError: Failed to derive key: {0}")]
    KdfError(#[from] KdfError),

    #[error("EncryptionError: {0}")]
    EncryptionError(chacha20poly1305::Error),

    #[error("DecryptionError: {0}")]
    DecryptionError(chacha20poly1305::Error),

    #[error("SerializationError: Failed to serialize an object: {0}")]
    SerializationError(serde_json::Error)
}

impl AppError {
    fn safe_display(&self) -> String {
        match self {
            AppError::PasswordHash(_) => "Failed to hash password".to_string(),
            AppError::DatabaseError(_) => "Unexpected error. See logs".to_string(),
            AppError::RedisError(_) => {
                "Unable to create websocket due to server error. See logs.".to_string()
            },
            AppError::ServerKey(_) => {
                "Server-side cryptography not enabled".to_string()
            }
            AppError::UserSalt => {
                "Server-side cryptography not enabled".to_string()
            }
            AppError::KdfError(_) => {
                "Server-side cryptography not enabled".to_string()
            },
            AppError::EncryptionError(_) => {
                "Server-side cryptography not enabled".to_string()
            },
            AppError::DecryptionError(_) => {
                "Server-side cryptography not enabled".to_string()
            },
            AppError::SerializationError(error) => {
                "Failed to serialize an object into JSON".to_string()
            }
        }
    }
}

impl ResponseError for AppError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            AppError::PasswordHash(_) => StatusCode::BAD_REQUEST,
            AppError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::RedisError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::ServerKey(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::UserSalt => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::KdfError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::EncryptionError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::DecryptionError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::SerializationError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        tracing::error!("{}", self.to_string());
        HttpResponse::build(self.status_code())
            .json(serde_json::json!({"error": self.safe_display()}))
    }
}
