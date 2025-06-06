use crate::client::GoogleOAuthClient;
use crate::web::repositories::GoogleUserRepository;
use crate::{Result, models::user::GoogleUserId};
use actix_firebase_auth::FirebaseUser;
use actix_web::{HttpResponse, post, web};
use oauth2::{AccessToken, RefreshToken, StandardRevocableToken};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeTokenBody {
    access_token: AccessToken,
    #[serde(default)]
    revoke_refresh_token: bool,
}

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
    payload: web::Json<RevokeTokenBody>,
    firebase_user: FirebaseUser,
    google_user_repo: GoogleUserRepository,
) -> Result<HttpResponse> {
    let RevokeTokenBody {
        access_token,
        revoke_refresh_token,
    } = payload.into_inner();

    let revocable_token = StandardRevocableToken::AccessToken(access_token);
    oauth2.revoke_token(revocable_token).await?;

    if revoke_refresh_token {
        let google_user_id = GoogleUserId::try_from(&firebase_user)?;
        let google_user = google_user_repo.get(&*google_user_id).await?;

        let refresh_token = google_user
            .and_then(|user| user.refresh_token)
            .map(RefreshToken::new)
            .map(StandardRevocableToken::RefreshToken);

        if let Some(token) = refresh_token {
            oauth2.revoke_token(token).await?;
        }
    }
    Ok(HttpResponse::Ok().body(()))
}
