use oauth2::{AuthorizationCode, PkceCodeVerifier, RefreshToken, TokenResponse};
use serde::{Deserialize, Serialize};

use crate::client::GoogleOAuthTokenResponse;

#[derive(Debug)]
pub struct ExchangeAuthorizationCodeRequest {
    pub(crate) code: AuthorizationCode,
    pub(crate) pkce_verifier: PkceCodeVerifier,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeRefreshTokenRequest {
    pub(crate) refresh_token: RefreshToken,
}

impl ExchangeRefreshTokenRequest {
    pub fn new(refresh_token: impl AsRef<str>) -> Self {
        Self {
            refresh_token: RefreshToken::new(refresh_token.as_ref().to_owned()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeRefreshTokenResponse {
    pub(crate) access_token: String,
    pub(crate) id_token: String,
    pub(crate) issued_at: i64,
    pub(crate) expires_in: u64,
}

impl From<GoogleOAuthTokenResponse> for ExchangeRefreshTokenResponse {
    fn from(value: GoogleOAuthTokenResponse) -> Self {
        let issued_at = chrono::Utc::now().timestamp();
        let expires_in = value.expires_in().map(|d| d.as_secs()).unwrap_or(0);
        let access_token = value.access_token().clone();
        Self {
            access_token: access_token.into_secret(),
            id_token: value.extra_fields().id_token().to_owned(),
            issued_at,
            expires_in,
        }
    }
}
