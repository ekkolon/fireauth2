use crate::Result;
use crate::client::GoogleOAuthClient;
use actix_firebase_auth::FirebaseUser;
use actix_web::{HttpResponse, Responder, post, web};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TokenTypeHint {
    AccessToken,
    #[default]
    IdToken,
}

#[derive(Debug, Deserialize)]
struct TokenIntrospectionFormData {
    token: String,
    #[allow(unused)]
    #[serde(default)]
    token_type_hint: TokenTypeHint,
}

/// OAuth introspection endpoint
#[post("/introspect")]
pub async fn introspect(
    oauth2: GoogleOAuthClient,
    form: web::Form<TokenIntrospectionFormData>,
    _firebase_user: FirebaseUser,
) -> Result<impl Responder> {
    let TokenIntrospectionFormData {
        token,
        token_type_hint,
    } = form.into_inner();

    match token_type_hint {
        TokenTypeHint::AccessToken => {
            // // let token_payload = oauth2.validate_access_token(&token).await?;
            // // return Ok(HttpResponse::Ok().json(token_payload));
            return Ok(HttpResponse::UnprocessableEntity().json(json!({
                "error": "access_token introspection not allowed"
            })));
        }
        TokenTypeHint::IdToken => {
            let token_payload = oauth2.validate_id_token(&token).await?;
            return Ok(HttpResponse::Ok().json(token_payload));
        }
    };
}
