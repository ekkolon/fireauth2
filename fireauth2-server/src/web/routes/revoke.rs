use crate::Result;
use crate::web::extractors::FireAuth2;
use actix_firebase_auth::{FirebaseUser, GoogleUserId};
use actix_web::{HttpResponse, post, web};
use fireauth2::{TokenRevocationConfig, TokenRevocationPayload};

/// POST `/revoke`
///
/// Revokes an OAuth2 **access token** or **refresh token** issued by Google.
///
/// This endpoint accepts a **JSON payload**, and depending on the shape of the payload,
/// it revokes either:
/// - An `accessToken` (access token)
/// - A `refreshToken` (refresh token)
///
/// ### Use Cases
/// - Invalidate an access token after logout.
/// - Invalidate a refresh token to prevent any further access or token refreshes.
/// - Clean up long-lived tokens stored on the client side.
///
/// ### Request Body (JSON)
///
/// You must provide **either** an `accessToken` or a `refreshToken`.
///
/// #### Revoke Access Token
/// ```json
/// {
///   "accessToken": "ya29.a0AfH6SMBx..."
/// }
/// ```
///
/// #### Revoke Refresh Token
/// ```json
/// {
///   "refreshToken": "1//06bV01..."
/// }
/// ```
///
/// ### Response
/// - `200 OK`: Token successfully revoked (empty response body).
/// - `400 Bad Request`: Invalid input.
/// - `500 Internal Server Error`: If the request to Google's revocation endpoint fails.
///
/// ---
#[post("/revoke")]
pub async fn revoke_token(
    fireauth2: FireAuth2,
    firebase_user: FirebaseUser,
    payload: web::Json<TokenRevocationPayload>,
) -> Result<HttpResponse> {
    let payload = payload.into_inner();
    let google_user_id = GoogleUserId::try_from(&firebase_user)?;

    let config = TokenRevocationConfig::new(payload, &*google_user_id);
    fireauth2.revoke_token(config).await?;

    Ok(HttpResponse::Ok().body(()))
}
