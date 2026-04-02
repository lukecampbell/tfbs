use actix_web::{HttpResponse, ResponseError, http::StatusCode};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("PasswordHash: {0}")]
    PasswordHash(String),

    #[error("Database")]
    DatabaseError(#[from] sqlx::Error)
}

impl AppError {
    fn safe_display(&self) -> String {
        match self {
            AppError::PasswordHash(_) => "Failed to hash password".to_string(),
            AppError::DatabaseError(_) => "Unexpected error. See logs".to_string(),
        }
    }
}

impl ResponseError for AppError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            AppError::PasswordHash(_) => StatusCode::BAD_REQUEST,
            AppError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        tracing::error!("{}", self.to_string());
        HttpResponse::build(self.status_code())
            .json(serde_json::json!({"error": self.safe_display()}))
    }
}