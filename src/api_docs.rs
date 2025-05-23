use utoipa::OpenApi;
use crate::{auth::{LoginCredentials, User}, Credential, CredentialResponse};

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::register,
        crate::login,
        crate::create_credential,
        crate::get_credentials,
        crate::get_credential_by_id,
    ),
    components(
        schemas(User, LoginCredentials, Credential, CredentialResponse)
    ),
    tags(
        (name = "auth", description = "Authentication endpoints"),
        (name = "credentials", description = "Password credentials management endpoints")
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_auth",
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::HttpBuilder::new()
                    .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
} 