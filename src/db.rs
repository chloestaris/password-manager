use crate::Credential;
use sqlx::SqlitePool;
use std::error::Error;

pub async fn create_credential(
    pool: &SqlitePool,
    website: &str,
    username: &str,
    encrypted_password: &str,
    user_id: i64,
) -> Result<i64, Box<dyn Error>> {
    let result = sqlx::query!(
        r#"
        INSERT INTO credentials (website, username, encrypted_password, user_id)
        VALUES (?, ?, ?, ?)
        RETURNING id
        "#,
        website,
        username,
        encrypted_password,
        user_id
    )
    .fetch_one(pool)
    .await?;

    Ok(result.id)
}

pub async fn get_credentials(pool: &SqlitePool, user_id: i64) -> Result<Vec<Credential>, Box<dyn Error>> {
    let credentials = sqlx::query_as!(
        Credential,
        r#"
        SELECT id as "id?", website, username, encrypted_password as password
        FROM credentials
        WHERE user_id = ?
        "#,
        user_id
    )
    .fetch_all(pool)
    .await?;

    Ok(credentials)
}

pub async fn get_credential_by_id(
    pool: &SqlitePool,
    credential_id: i64,
    user_id: i64,
) -> Result<Option<Credential>, Box<dyn Error>> {
    let credential = sqlx::query_as!(
        Credential,
        r#"
        SELECT id as "id?", website, username, encrypted_password as password
        FROM credentials
        WHERE id = ? AND user_id = ?
        "#,
        credential_id,
        user_id
    )
    .fetch_optional(pool)
    .await?;

    Ok(credential)
} 