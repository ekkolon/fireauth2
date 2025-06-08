use crate::Result;
use crate::web::AppState;
use crate::web::extractors::FireAuth2;
use crate::web::session::Session;
use fireauth2::{
    ExchangeAuthorizationCodeConfigBuilder,
    ExchangeAuthorizationCodeQueryParams,
};

use actix_web::http::header;
use actix_web::{HttpRequest, HttpResponse, get, web};

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
    fireauth2: FireAuth2,
    state: AppState,
    query: web::Query<ExchangeAuthorizationCodeQueryParams>,
) -> Result<HttpResponse> {
    let session = Session::from_request(&req)?;

    // Prepare the token exchange request.
    let config = ExchangeAuthorizationCodeConfigBuilder::new()
        .csrf_token(session.csrf_token)
        .state(query.state.clone())
        .code(query.code.clone())
        .pkce_verifier(session.pkce_verifier)
        .params(session.extra_params)
        .redirect_to(session.redirect_to)
        .revoke_existing_tokens(state.enable_existing_token_revocation())
        .build()?;

    // Exchange authorization code for tokens.
    let token_response = fireauth2.exchange_authorization_code(config).await?;

    let response = HttpResponse::Found()
        .append_header((header::LOCATION, token_response.to_string()))
        .finish();

    Ok(response)
}
