use crate::client::RequestAccessTokenExtraParams;
use crate::error::Result;

use actix_web::{
    HttpRequest,
    cookie::{Cookie, SameSite, time::Duration},
};
use oauth2::PkceCodeVerifier;
use serde::{Deserialize, Serialize};
use url::Url;

/// Payload stored in the user's auth cookie, used to persist state between
/// the initial authorization request and the redirect-based OAuth2 callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// OAuth 2.0 PKCE verifier associated with this session.
    pub(crate) pkce_verifier: String,

    /// Anti-CSRF token generated during the auth request.
    pub(crate) csrf_token: String,

    /// URL to redirect the user to after successful login.
    ///
    /// ## Note
    ///
    /// This is **NOT** the redirect uri of the OAuth 2.0 flow.
    pub(crate) redirect_to: Url,

    /// Arbitrary user-defined extra OAuth2 parameters (e.g., prompt, login_hint).
    pub(crate) extra_params: RequestAccessTokenExtraParams,
}

impl Session {
    /// Canonical name for the authentication cookie.
    pub const COOKIE_NAME: &'static str = "fireauth2";

    /// Constructs a new payload to be persisted into the auth cookie.
    ///
    /// This typically occurs at the beginning of the OAuth2 flow.
    pub fn new(
        verifier: &PkceCodeVerifier,
        csrf_token: &oauth2::CsrfToken,
        redirect_to: Url,
        extra_params: RequestAccessTokenExtraParams,
    ) -> Result<Self> {
        Ok(Self {
            pkce_verifier: verifier.secret().to_string(),
            csrf_token: csrf_token.secret().to_string(),
            redirect_to,
            extra_params,
        })
    }

    /// Serializes the payload into a secure, short-lived HTTP cookie.
    ///
    /// - `http_only`: Prevents client-side JS access (defense against XSS).
    /// - `secure`: Ensures cookie is only sent over HTTPS.
    /// - `same_site=Lax`: Restricts cross-site transmission except top-level GET.
    /// - `max_age=300s`: Limits lifetime to 5 minutes to minimize attack surface.
    pub fn into_cookie<'c>(self) -> Result<Cookie<'c>> {
        let value = serde_json::to_string(&self)?;
        Ok(Cookie::build(Self::COOKIE_NAME, value)
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Lax)
            .max_age(Duration::new(300, 0))
            .finish())
    }

    /// Attempts to extract and deserialize the `AuthCookiePayload` from the request.
    ///
    /// Fails if the cookie is missing or contains invalid JSON.
    pub fn from_request(req: &HttpRequest) -> Result<Self> {
        let raw = req
            .cookie(Self::COOKIE_NAME)
            .ok_or_else(|| crate::error::Error::FailedToExtractAuthCookie {
                because: "missing cookie".into(),
            })?
            .value()
            .to_string();

        Ok(serde_json::from_str(&raw)?)
    }
}
