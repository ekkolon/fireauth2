use crate::Result;
use crate::web::extractors::FireAuth2;
use actix_firebase_auth::FirebaseUser;
use actix_web::{HttpResponse, Responder, post, web};
use fireauth2::{TokenIntrospectionPayload, TokenIntrospectionTypeHint};
use serde_json::json;

/// OAuth introspection endpoint
#[post("/introspect")]
pub async fn introspect(
    fireauth2: FireAuth2,
    form: web::Form<TokenIntrospectionPayload>,
    _firebase_user: FirebaseUser,
) -> Result<impl Responder> {
    let payload = form.into_inner();

    match payload.token_type_hint() {
        TokenIntrospectionTypeHint::AccessToken => {
            // // let token_payload = oauth2.validate_access_token(&token).await?;
            // // return Ok(HttpResponse::Ok().json(token_payload));
            Ok(HttpResponse::UnprocessableEntity().json(json!({
                "error": "access_token introspection not allowed"
            })))
        }
        TokenIntrospectionTypeHint::IdToken => {
            let token_payload =
                fireauth2.validate_id_token(payload.token()).await?;
            Ok(HttpResponse::Ok().json(token_payload))
        }
    }
}
