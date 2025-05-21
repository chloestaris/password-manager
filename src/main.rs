use actix_cors::Cors;
use actix_web::{middleware, web, App, HttpRequest, HttpResponse, HttpServer};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use std::env;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

mod auth;
mod crypto;
mod db;
mod error;
mod api_docs;

use auth::{LoginCredentials, User, verify_token};
use error::ApiError;
use api_docs::ApiDoc;

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
struct Credential {
    id: Option<i64>,
    website: String,
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
struct CredentialResponse {
    id: i64,
    website: String,
    username: String,
}

/// Register a new user
#[utoipa::path(
    post,
    path = "/auth/register",
    tag = "auth",
    request_body = User,
    responses(
        (status = 201, description = "User created successfully", body = inline(serde_json::Value)),
        (status = 400, description = "Invalid input"),
        (status = 500, description = "Internal server error")
    )
)]
async fn register(pool: web::Data<SqlitePool>, user: web::Json<User>) -> Result<HttpResponse, ApiError> {
    let user_id = auth::create_user(&pool, &user).await?;
    Ok(HttpResponse::Created().json(serde_json::json!({ "id": user_id })))
}

/// Login with username and password
#[utoipa::path(
    post,
    path = "/auth/login",
    tag = "auth",
    request_body = LoginCredentials,
    responses(
        (status = 200, description = "Login successful", body = inline(serde_json::Value)),
        (status = 401, description = "Invalid credentials"),
        (status = 500, description = "Internal server error")
    )
)]
async fn login(pool: web::Data<SqlitePool>, creds: web::Json<LoginCredentials>) -> Result<HttpResponse, ApiError> {
    let token = auth::login(&pool, &creds).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "token": token })))
}

fn get_user_id(req: &HttpRequest) -> Result<i64, ApiError> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ApiError::ValidationError("Missing authorization header".to_string()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::ValidationError("Invalid authorization header".to_string()))?;

    verify_token(token)
}

/// Create a new credential
#[utoipa::path(
    post,
    path = "/credentials",
    tag = "credentials",
    request_body = Credential,
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 201, description = "Credential created successfully", body = inline(serde_json::Value)),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid input"),
        (status = 500, description = "Internal server error")
    )
)]
async fn create_credential(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    cred: web::Json<Credential>,
) -> Result<HttpResponse, ApiError> {
    let user_id = get_user_id(&req)?;
    
    let crypto = crypto::Crypto::new(&get_encryption_key()?);
    let encrypted_password = crypto.encrypt(&cred.password)?;
    
    let id = db::create_credential(
        &pool,
        &cred.website,
        &cred.username,
        &encrypted_password,
        user_id,
    ).await?;
    
    Ok(HttpResponse::Created().json(serde_json::json!({ "id": id })))
}

/// Get all credentials for the authenticated user
#[utoipa::path(
    get,
    path = "/credentials",
    tag = "credentials",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "List of credentials", body = Vec<CredentialResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    )
)]
async fn get_credentials(req: HttpRequest, pool: web::Data<SqlitePool>) -> Result<HttpResponse, ApiError> {
    let user_id = get_user_id(&req)?;
    let credentials = db::get_credentials(&pool, user_id).await?;
    
    let responses: Vec<CredentialResponse> = credentials
        .into_iter()
        .map(|c| CredentialResponse {
            id: c.id.unwrap(),
            website: c.website,
            username: c.username,
        })
        .collect();
    
    Ok(HttpResponse::Ok().json(responses))
}

/// Get a specific credential by ID
#[utoipa::path(
    get,
    path = "/credentials/{id}",
    tag = "credentials",
    params(
        ("id" = i64, Path, description = "Credential ID")
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Credential found", body = CredentialResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Credential not found"),
        (status = 500, description = "Internal server error")
    )
)]
async fn get_credential_by_id(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    id: web::Path<i64>,
) -> Result<HttpResponse, ApiError> {
    let user_id = get_user_id(&req)?;
    let credential = db::get_credential_by_id(&pool, *id, user_id).await?
        .ok_or_else(|| ApiError::NotFound("Credential not found".to_string()))?;
    
    Ok(HttpResponse::Ok().json(CredentialResponse {
        id: credential.id.unwrap(),
        website: credential.website,
        username: credential.username,
    }))
}

fn get_encryption_key() -> Result<[u8; 32], ApiError> {
    let key = env::var("ENCRYPTION_KEY")
        .map_err(|_| ApiError::ValidationError("Missing encryption key".to_string()))?;
    
    let mut bytes = [0u8; 32];
    if key.len() != 32 {
        return Err(ApiError::ValidationError("Invalid encryption key length".to_string()));
    }
    bytes.copy_from_slice(key.as_bytes());
    Ok(bytes)
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    dotenv::dotenv().ok();

    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:password_manager.db".to_string());

    let pool = SqlitePool::connect(&database_url)
        .await
        .expect("Failed to create pool");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to migrate the database");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(pool.clone()))
            // Swagger UI
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}")
                    .url("/api-docs/openapi.json", ApiDoc::openapi()),
            )
            // Public routes
            .route("/auth/register", web::post().to(register))
            .route("/auth/login", web::post().to(login))
            // Protected routes
            .route("/credentials", web::post().to(create_credential))
            .route("/credentials", web::get().to(get_credentials))
            .route("/credentials/{id}", web::get().to(get_credential_by_id))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
} 