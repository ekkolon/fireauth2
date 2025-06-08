use crate::Result;
use crate::web::extractors::FireAuth2;
use actix_firebase_auth::{FirebaseUser, GoogleUserId};
use actix_web::{HttpResponse, post};

/// POST `/token`
///
/// Exchanges a Google OAuth2 **refresh token** for a new access token.
///
/// ### Request Body
/// Accepts a JSON payload of type [`ExchangeRefreshTokenRequest`] which contains the `refresh_token`
/// previously issued by Google. This token is stored in Firebase Firestore and should be retrieved
/// via an authenticated Firebase Client or via a trusted backend before calling this endpoint.
///
/// ### Example Payload:
/// ```json
/// {
///   "refreshToken": "1//0gL2EXAMPLE...gOo"
/// }
/// ```
///
/// ### Source of Refresh Token
/// In production environments, the refresh token should typically be retrieved from a secure location,
/// such as **Firebase Firestore**, where it's associated with a user document AND secured via Firebase
/// security rules. For example:
///
/// ```ts
/// const usersCollection = firestore.collection("users");
/// const userRef = usersCollection.doc(user_id);
/// const userData = await userRef.get().then(snap => snap.data());   
/// const refreshToken = userData['refreshToken'];
/// ```
///
/// ### Response
/// On success, returns a JSON object of type [`ExchangeRefreshTokenResponse`] containing the new access token,
/// its expiry time, the time the token was issued, and optionally an ID token.
///
/// ### Example Response:
/// ```json
/// {
///   "accessToken": "ya29.a0AfH6SMDs...",
///   "expiresIn": 3599,
///   "issuedAt": 1759485825,
/// }
/// ```
///
/// ### Errors
/// Returns appropriate HTTP error codes (e.g., 400 or 500) in case of:
/// - Invalid or expired refresh tokens
/// - Network issues
/// - Google OAuth errors
///
/// ### TODO
/// - Enforce that a valid Firebase `idToken` is included in the `Authorization` header.
/// - Re-evaluate the current implementation. Ideally, the client should never have direct access to the
///   refresh token — even if the user is authenticated in Firebase and technically able to retrieve it.
/// - Consider accepting only the user's `idToken` in the request and validating it server-side.
///   Once validated, use Firebase Admin SDK to securely fetch and revoke associated refresh tokens.
#[post("/token")]
pub async fn exchange_refresh_token(
    fireauth2: FireAuth2,
    firebase_user: FirebaseUser,
) -> Result<HttpResponse> {
    let google_user_id = GoogleUserId::try_from(&firebase_user)?;
    let response = fireauth2.exchange_refresh_token(&*google_user_id).await?;
    Ok(HttpResponse::Ok().json(response))
}
