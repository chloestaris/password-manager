use crate::error::ApiError;
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::env;
use time::{Duration, OffsetDateTime};

/// User registration information
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct User {
    /// User ID (auto-generated)
    #[schema(nullable = true)]
    pub id: Option<i64>,
    /// User's email address
    pub email: String,
    /// User's password (will be hashed before storage)
    pub password: String,
}

/// Login credentials
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LoginCredentials {
    /// User's email address
    pub email: String,
    /// User's password
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: i64,
    exp: i64,
}

pub async fn create_user(pool: &SqlitePool, user: &User) -> Result<i64, ApiError> {
    let password_hash = hash_password(&user.password)?;

    let result = sqlx::query!(
        r#"
        INSERT INTO users (email, password_hash)
        VALUES (?, ?)
        "#,
        user.email,
        password_hash
    )
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

pub async fn login(pool: &SqlitePool, creds: &LoginCredentials) -> Result<String, ApiError> {
    let user = sqlx::query!(
        r#"
        SELECT id, password_hash
        FROM users
        WHERE email = ?
        "#,
        creds.email
    )
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::ValidationError("Invalid credentials".to_string()))?;

    if !verify_password(&creds.password, &user.password_hash)? {
        return Err(ApiError::ValidationError("Invalid credentials".to_string()));
    }

    create_token(user.id.expect("User ID should be present"))
}

fn hash_password(password: &str) -> Result<String, ApiError> {
    hash(password.as_bytes(), DEFAULT_COST)
        .map_err(|e| ApiError::EncryptionError(e.to_string()))
}

fn verify_password(password: &str, hash: &str) -> Result<bool, ApiError> {
    verify(password.as_bytes(), hash)
        .map_err(|e| ApiError::EncryptionError(e.to_string()))
}

fn create_token(user_id: i64) -> Result<String, ApiError> {
    let expiration = OffsetDateTime::now_utc() + Duration::hours(24);
    
    let claims = Claims {
        sub: user_id,
        exp: expiration.unix_timestamp(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(get_jwt_secret().as_bytes()),
    )
    .map_err(|e| ApiError::EncryptionError(e.to_string()))
}

pub fn verify_token(token: &str) -> Result<i64, ApiError> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(get_jwt_secret().as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| ApiError::ValidationError(e.to_string()))?;

    Ok(token_data.claims.sub)
}

fn get_jwt_secret() -> String {
    std::env::var("JWT_SECRET").unwrap_or_else(|_| "your_jwt_secret_key_here".to_string())
} 