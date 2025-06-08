use oauth2::{AuthorizationCode, PkceCodeVerifier, TokenResponse};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{RequestAccessTokenExtraParams, client::GoogleOAuthTokenResponse};

/// Query parameters received after `OAuth2` authorization redirect.
///
/// These represent the `code` and `state` parameters returned by the
/// authorization server, which are required to exchange for an access token.
#[derive(Debug, Clone, Deserialize)]
pub struct ExchangeAuthorizationCodeQueryParams {
    /// The authorization code to exchange for an access token.
    pub code: String,
    /// The state parameter for CSRF protection and request validation.
    pub state: String,
}

/// Configuration for exchanging an authorization code for tokens.
///
/// Includes the authorization code, PKCE verifier, extra request params,
/// and metadata such as redirect URL, CSRF token, and whether to revoke
/// existing tokens.
#[derive(Debug)]
pub struct ExchangeAuthorizationCodeConfig {
    pub(crate) code: AuthorizationCode,
    pub(crate) pkce_verifier: PkceCodeVerifier,
    pub(crate) params: RequestAccessTokenExtraParams,
    pub(crate) revoke_existing_tokens: bool,
    pub(crate) redirect_to: Url,
    pub(crate) csrf_token: String,
    pub(crate) state: String,
}

/// Builder type for [`ExchangeAuthorizationCodeConfig`] to aid ergonomic construction.
#[derive(Debug, Default)]
pub struct ExchangeAuthorizationCodeConfigBuilder {
    code: Option<AuthorizationCode>,
    pkce_verifier: Option<PkceCodeVerifier>,
    params: Option<RequestAccessTokenExtraParams>,
    redirect_to: Option<Url>,
    csrf_token: Option<String>,
    state: Option<String>,
    revoke_existing_tokens: bool,
}

impl ExchangeAuthorizationCodeConfigBuilder {
    /// Creates a new builder instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the authorization code to exchange.
    #[must_use]
    pub fn code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(AuthorizationCode::new(code.into()));
        self
    }

    /// Sets the PKCE code verifier associated with the authorization request.
    #[must_use]
    pub fn pkce_verifier(mut self, verifier: impl Into<String>) -> Self {
        self.pkce_verifier = Some(PkceCodeVerifier::new(verifier.into()));
        self
    }

    /// Sets extra parameters to include in the access token request.
    #[must_use]
    pub fn params(mut self, params: RequestAccessTokenExtraParams) -> Self {
        self.params = Some(params);
        self
    }

    /// Sets whether to revoke existing tokens upon exchanging the code.
    #[must_use]
    pub fn revoke_existing_tokens(mut self, yes: bool) -> Self {
        self.revoke_existing_tokens = yes;
        self
    }

    /// Sets the redirect URL to send the user after the exchange completes.
    #[must_use]
    pub fn redirect_to(mut self, url: Url) -> Self {
        self.redirect_to = Some(url);
        self
    }

    /// Sets the CSRF token associated with the authorization request.
    #[must_use]
    pub fn csrf_token(mut self, csrf_token: impl Into<String>) -> Self {
        self.csrf_token = Some(csrf_token.into());
        self
    }

    /// Sets the state string used to validate the authorization response.
    #[must_use]
    pub fn state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    /// Finalizes the builder, returning an error if any required field is missing.
    pub fn build(self) -> crate::Result<ExchangeAuthorizationCodeConfig> {
        Ok(ExchangeAuthorizationCodeConfig {
            code: self.code.ok_or(crate::Error::MissingConfigField("code"))?,
            pkce_verifier: self
                .pkce_verifier
                .ok_or(crate::Error::MissingConfigField("pkce_verifier"))?,
            params: self
                .params
                .ok_or(crate::Error::MissingConfigField("params"))?,
            redirect_to: self
                .redirect_to
                .ok_or(crate::Error::MissingConfigField("redirect_to"))?,

            csrf_token: self
                .csrf_token
                .ok_or(crate::Error::MissingConfigField("csrf_token"))?,
            state: self
                .state
                .ok_or(crate::Error::MissingConfigField("state"))?,
            revoke_existing_tokens: self.revoke_existing_tokens,
        })
    }
}

/// Response returned when exchanging a refresh token for a new access token.
///
/// Contains the new access token, ID token, and timing metadata.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeRefreshTokenResponse {
    /// The new access token string.
    pub(crate) access_token: String,
    /// The `OpenID` Connect ID token string.
    pub(crate) id_token: String,
    /// The UNIX timestamp when the token was issued.
    pub(crate) issued_at: i64,
    /// Token lifetime in seconds.
    pub(crate) expires_in: u64,
}

impl From<GoogleOAuthTokenResponse> for ExchangeRefreshTokenResponse {
    fn from(value: GoogleOAuthTokenResponse) -> Self {
        let issued_at = chrono::Utc::now().timestamp();
        let expires_in = value.expires_in().map_or(0, |d| d.as_secs());
        let access_token = value.access_token().clone();
        Self {
            access_token: access_token.into_secret(),
            id_token: value.extra_fields().id_token().to_owned(),
            issued_at,
            expires_in,
        }
    }
}
