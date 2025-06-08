use crate::Result;
use crate::web::extractors::FireAuth2;
use crate::web::session::Session;
use crate::web::utils::get_referer_url;
use fireauth2::RequestAccessTokenPayload;

use actix_web::http::header;
use actix_web::{HttpRequest, HttpResponse, get, web};
use url::Url;

/// GET `/authorize`
///
/// Initiates the Google OAuth 2.0 authorization flow by redirecting the user to Google’s consent screen.
/// This endpoint generates and stores secure PKCE and CSRF values in a session cookie to protect against
/// replay and forgery attacks.
///
/// ### Query Parameters
/// - `redirect_uri` _(optional)_: The URI to redirect the user to after successful authentication.  
///   Falls back to the `Referer` header if omitted.  
///   Must be a valid, absolute URL and must match a URI configured in your Google OAuth client settings.
///
/// - Additional OAuth parameters (defined by [`RequestAccessTokenExtraParams`]) are supported:
///   - `prompt=consent` — forces the consent screen to appear, even if the user has already authorized the app.
///   - `access_type=offline` — requests a `refresh_token` in addition to the `access_token`.
///   - `scope=email%20profile` — custom scopes to request specific permissions.
///
/// ### Example Request
/// ```http
/// GET /authorize?redirect_uri=https%3A%2F%2Fexample.com%2Fdashboard&prompt=consent&access_type=offline
/// ```
///
/// ### Flow
/// 1. Constructs the Google authorization URL with PKCE and CSRF parameters.
/// 2. Stores a session cookie containing:
///    - The original `redirect_uri`
///    - A generated `pkce_verifier`
///    - A CSRF `state` token
/// 3. Issues a `302` redirect to Google’s OAuth 2.0 authorization endpoint.
///
/// ### Redirect Flow
/// After the user grants permission on Google’s consent screen, they are redirected to your configured callback
/// (e.g., `/callback`). There, the session cookie must be validated and the token exchange completed.
///
/// ### Example Redirect Response
/// ```http
/// HTTP/1.1 302 Found
/// Location: https://accounts.google.com/o/oauth2/v2/auth?client_id=...
/// Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax
/// ```
///
/// ### Errors
/// - `400 Bad Request` — if no valid `redirect_uri` can be resolved.
/// - `500 Internal Server Error` — if session creation or URL construction fails.
///
/// ---
#[get("/authorize")]
pub async fn authorize(
    req: HttpRequest,
    fireauth2: FireAuth2,
    query: web::Query<RequestAccessTokenPayload>,
) -> Result<HttpResponse> {
    let response = fireauth2.request_access_token(&query.extra_params);

    let redirect_to = query
        .redirect_uri
        .clone()
        .or_else(|| get_referer_url(&req))
        .ok_or(crate::Error::MissingRedirectUrl)?;

    let redirect_uri_decoded = urlencoding::decode(&redirect_to)?;

    // (todo) Verify that it's an http/s scheme
    let redirect_uri = Url::parse(&redirect_uri_decoded)?;

    let session = Session::new(
        response.pkce_verifier(),
        response.csrf_token(),
        redirect_uri,
        query.extra_params.clone(),
    )?;

    let redirect_response = HttpResponse::Found()
        .append_header((header::LOCATION, response.url().to_string()))
        .cookie(session.into_cookie()?)
        .finish();

    Ok(redirect_response)
}
