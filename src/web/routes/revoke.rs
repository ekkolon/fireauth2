use crate::Result;
use crate::client::GoogleOAuthClient;
use actix_web::{Either, HttpResponse, post, web};
use oauth2::{AccessToken, RefreshToken, StandardRevocableToken};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeAccessTokenBody {
    access_token: AccessToken,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeRefreshTokenBody {
    refresh_token: RefreshToken,
}

// Accepts either an access token or refresh token in JSON form.
type RevokeTokenBody = Either<web::Json<RevokeAccessTokenBody>, web::Json<RevokeRefreshTokenBody>>;

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
    oauth2: GoogleOAuthClient,
    payload: RevokeTokenBody,
) -> Result<HttpResponse> {
    let revocable_token = match payload {
        Either::Left(ref json) => StandardRevocableToken::AccessToken(json.access_token.clone()),
        Either::Right(ref json) => StandardRevocableToken::RefreshToken(json.refresh_token.clone()),
    };

    oauth2.revoke_token(revocable_token).await?;

    Ok(HttpResponse::Ok().body(()))
}
