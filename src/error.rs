use thiserror::Error;
use std::error::Error as StdError;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Invalid input: {0}")]
    ValidationError(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<Box<dyn StdError>> for ApiError {
    fn from(err: Box<dyn StdError>) -> Self {
        ApiError::InternalError(err.to_string())
    }
}

impl actix_web::ResponseError for ApiError {
    fn error_response(&self) -> actix_web::HttpResponse {
        match self {
            ApiError::NotFound(_) => {
                actix_web::HttpResponse::NotFound().json(format!("{}", self))
            }
            ApiError::ValidationError(_) => {
                actix_web::HttpResponse::BadRequest().json(format!("{}", self))
            }
            _ => actix_web::HttpResponse::InternalServerError().json(format!("{}", self)),
        }
    }
} 