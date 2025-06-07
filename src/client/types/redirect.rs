use std::{fmt, ops::Deref};

use oauth2::TokenResponse;
use url::Url;

use crate::client::GoogleOAuthTokenResponse;

/// Wraps a successful OAuth2 token exchange and provides a redirect URL
/// to send the user to after login.
#[derive(Debug, Clone)]
pub struct AuthRedirectSuccessResponse {
    pub redirect_url: Url,
    pub token: GoogleOAuthTokenResponse,
}

impl AuthRedirectSuccessResponse {
    pub fn new(redirect_url: Url, token: GoogleOAuthTokenResponse) -> Self {
        Self {
            redirect_url,
            token,
        }
    }
}

impl Deref for AuthRedirectSuccessResponse {
    type Target = GoogleOAuthTokenResponse;
    fn deref(&self) -> &Self::Target {
        &self.token
    }
}

impl fmt::Display for AuthRedirectSuccessResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let issued_at = chrono::Utc::now().timestamp();
        let expires_in = self.token.expires_in().map(|d| d.as_secs()).unwrap_or(0);
        write!(
            f,
            "{}#access_token={}&id_token={}&expires_in={}&issued_at={}",
            self.redirect_url,
            self.token.access_token().secret(),
            self.token.extra_fields().id_token(),
            expires_in,
            issued_at
        )
    }
}

/// Wraps an error OAuth2 token exchange and provides a redirect URL to send the user to.
#[derive(Debug, Clone)]
pub struct AuthRedirectErrorResponse {
    pub redirect_url: Url,
    pub error: String,
}

impl AuthRedirectErrorResponse {
    pub fn new(redirect_url: Url, error: impl AsRef<str>) -> Self {
        Self {
            redirect_url,
            error: error.as_ref().to_string(),
        }
    }
}

impl fmt::Display for AuthRedirectErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}#error={}",
            self.redirect_url,
            urlencoding::encode(&self.error)
        )
    }
}
