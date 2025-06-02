use crate::Result;
use crate::client::GoogleOAuthClient;
use actix_web::{Either, HttpRequest, HttpResponse, Responder, get, web};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthSuccessRedirectQuery {
    access_token: String,
    expires_in: i64,
    issued_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthErrorRedirectQuery {
    error: String,
}

// NOTE: This type exists for reference only. URL fragments (the part after `#`) are never sent to the server,
// so they cannot be read or parsed server-side.
#[allow(unused)]
type AuthQuery = Either<web::Query<AuthSuccessRedirectQuery>, web::Query<AuthErrorRedirectQuery>>;

/// NOTE: This endpoint is intended for testing only and will be removed once the project becomes stable.
#[get("/")]
pub async fn index(
    _req: HttpRequest,
    _oauth2: web::Data<GoogleOAuthClient>,
) -> Result<impl Responder> {
    Ok(HttpResponse::Ok().json("successfully"))
}
