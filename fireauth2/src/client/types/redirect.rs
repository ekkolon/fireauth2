use std::fmt;

use oauth2::TokenResponse;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::client::GoogleOAuthTokenResponse;

/// Represents the result of an `OAuth2` authorization redirect.
///
/// This enum captures whether the redirect resulted in a success with a token
/// or an error with an error message, along with the redirect URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthRedirectResponse {
    /// Represents an authorization failure redirect.
    Error {
        /// The URL to redirect to after this response.
        url: Url,
        /// The error message explaining why authorization failed.
        error: String,
    },
    /// Represents a successful authorization redirect.
    Success {
        /// The URL to redirect to after this response.
        url: Url,
        /// The OAuth token response received upon successful authorization.
        token: GoogleOAuthTokenResponse,
    },
}

impl AuthRedirectResponse {
    /// Creates a new error variant with the given URL and error message.
    pub fn new_error(url: Url, error: impl AsRef<str>) -> Self {
        AuthRedirectResponse::Error {
            url,
            error: error.as_ref().to_owned(),
        }
    }

    /// Creates a new success variant with the given URL and OAuth token response.
    pub fn new_success(url: Url, token: GoogleOAuthTokenResponse) -> Self {
        AuthRedirectResponse::Success { url, token }
    }
}

impl fmt::Display for AuthRedirectResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthRedirectResponse::Error { url, error } => {
                write!(f, "{}#error={}", url, urlencoding::encode(error))
            }
            AuthRedirectResponse::Success { url, token } => {
                let issued_at = chrono::Utc::now().timestamp();
                let expires_in =
                    token.expires_in().map(|d| d.as_secs()).unwrap_or(0);
                write!(
                    f,
                    "{}#access_token={}&id_token={}&expires_in={}&issued_at={}",
                    url,
                    token.access_token().secret(),
                    token.extra_fields().id_token(),
                    expires_in,
                    issued_at
                )
            }
        }
    }
}
