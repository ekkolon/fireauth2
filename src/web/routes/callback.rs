use crate::Result;
use crate::client::{
    AuthRedirectErrorResponse, AuthRedirectSuccessResponse, ExchangeAuthorizationCodeRequest,
    GoogleOAuthClient,
};
use crate::models::user::GoogleUser;
use crate::web::AppState;
use crate::web::repositories::GoogleUserRepository;
use crate::web::session::Session;

use actix_web::http::header;
use actix_web::{HttpRequest, HttpResponse, get, web};
use oauth2::{
    AuthorizationCode, PkceCodeVerifier, RefreshToken, StandardRevocableToken, TokenResponse,
};
use serde::Deserialize;
use url::Url;

// Represents the `code` and `state` query parameters received
// from the OAuth2 authorization server after redirect.
#[derive(Debug, Clone, Deserialize)]
struct CallbackQueryParams {
    code: String,
    state: String,
}

/// GET `/callback`
///
/// Finalizes the Google OAuth 2.0 login flow by exchanging the authorization code
/// for access and (optionally) refresh tokens. This endpoint is invoked after the user
/// authorizes the application via Google’s OAuth 2.0 consent screen.
///
/// This server-side redirect handler exists to protect sensitive OAuth metadata from
/// being exposed to client-side scripts, browser extensions, or analytics tools.
/// To mitigate these risks, sensitive tokens are transmitted via the URL fragment
/// rather than query parameters.
///
/// ### Query Parameters (from Google):
/// - `code`: The authorization code used to exchange for tokens.
/// - `state`: The original CSRF token, used to validate the session integrity.
///
/// ### Flow:
/// 1. Validates the CSRF token against the session.
/// 2. Exchanges the authorization `code` and `pkce_verifier` for tokens.
/// 3. Verifies the ID token to ensure it was issued by Google.
/// 4. If a `refresh_token` is included:
///    - Stores the user and `refresh_token` in Firestore under `users/{sub}`.
///    - Avoids overwriting existing entries if no `refresh_token` is returned (e.g., due to `access_type=online`).
/// 5. Redirects the user to the original post-authentication URL, encoding tokens in the URL fragment.
///
/// ### Important Notes:
/// - A `refresh_token` is only returned when `access_type=offline` **and** `prompt=consent`
///   are specified, and only if the user hasn’t recently granted access.
/// - To prevent accidental loss of refresh tokens, storage is conditional: user data is only
///   persisted if a `refresh_token` is present.
///
/// ### Response:
/// - `302 Found` Redirect to the original application URL (success or failure).
///
/// ---
#[get("/callback")]
pub async fn exchange_authorization_code(
    req: HttpRequest,
    query: web::Query<CallbackQueryParams>,
    oauth: GoogleOAuthClient,
    google_user_repo: GoogleUserRepository,
    state: AppState,
) -> Result<HttpResponse> {
    let session = Session::from_request(&req)?;

    // Validate CSRF token from query against session.
    if session.csrf_token != query.state {
        return respond_with_error(session.redirect_to, "CSRF token mismatch");
    }

    // Prepare the token exchange request.
    let request = ExchangeAuthorizationCodeRequest {
        code: AuthorizationCode::new(query.code.clone()),
        pkce_verifier: PkceCodeVerifier::new(session.pkce_verifier),
    };

    // Exchange authorization code for tokens.
    let auth_result = oauth
        .exchange_authorization_code(request, &session.extra_params)
        .await;

    let response = match auth_result {
        Err(err) => return respond_with_error(session.redirect_to, err.to_string()),
        Ok(res) => res,
    };

    // Verify the ID token to confirm issuer and audience.
    let id_token = response.extra_fields().id_token();
    let id_token_payload = match oauth.validate_id_token(id_token).await {
        Err(err) => return respond_with_error(session.redirect_to, err.to_string()),
        Ok(token) => token,
    };

    if let Some(token) = response.refresh_token() {
        // Persist authentication metadata to Firestore ONLY if a `refresh_token` is present.
        //
        // When the original authentication request uses `access_type=online`, Google will NOT
        // return a new `refresh_token`. The refresh token is critical for session continuity
        // and may have already been stored during a previous successful authentication.
        //
        // Overwriting an existing user record without a new `refresh_token` would result in
        // unintentionally nullifying the stored token.

        let google_user_id = id_token_payload.sub.clone();

        if state.enable_existing_token_revocation() {
            // Revoke existing refresh token, if any
            let existing_google_user_result = google_user_repo.get(&google_user_id).await;
            match existing_google_user_result {
                Err(err) => {
                    log::debug!("Token revocation attempt failed: {}", &err.to_string());
                    return respond_with_error(session.redirect_to, err.to_string());
                }
                Ok(None) => {
                    // No User record
                    log::debug!("Skipping token revocation. No record found for Google User ID");
                }
                Ok(Some(user)) => {
                    if user.refresh_token.is_none() {
                        log::debug!(
                            "Skipping token revocation. User record is missing refresh token"
                        );
                    }

                    if let Some(token) = user.refresh_token {
                        // Revoke refresh token
                        let refresh_token = RefreshToken::new(token);
                        let revocable_token = StandardRevocableToken::RefreshToken(refresh_token);

                        log::debug!("Preparing for token revocation");
                        match oauth.revoke_token(revocable_token).await {
                            Err(err) => {
                                log::debug!("Token revocation failed: {}", &err.to_string());
                            }
                            Ok(_) => log::debug!("Token successfully revoked"),
                        }
                    }
                }
            }
        }

        let refresh_token = token.to_owned().into_secret();
        let scope = response
            .scopes()
            .map(|scopes| scopes.iter().map(|scope| scope.to_string()).collect())
            .unwrap_or_default();

        let google_user = GoogleUser {
            id: google_user_id, // Note: this field is not saved to Firestore
            refresh_token: Some(refresh_token),
            email: id_token_payload.email,
            scope,
        };

        if let Err(err) = google_user_repo.update(&google_user).await {
            return respond_with_error(session.redirect_to, err.to_string());
        }
    };

    // Redirect to success handler with tokens in URL fragment
    let redirect_url = AuthRedirectSuccessResponse::new(session.redirect_to, response);
    let response = HttpResponse::Found()
        .append_header((header::LOCATION, redirect_url.to_string()))
        .finish();

    Ok(response)
}

/// Redirects back to the client with an error encoded in the URL fragment.
fn respond_with_error(redirect_url: Url, error: impl AsRef<str>) -> Result<HttpResponse> {
    let redirect_url = AuthRedirectErrorResponse::new(redirect_url, error);
    let response = HttpResponse::Found()
        .append_header((header::LOCATION, redirect_url.to_string()))
        .finish();
    Ok(response)
}
