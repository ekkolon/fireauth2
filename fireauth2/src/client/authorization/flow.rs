use super::extra_params::{
    AccessType, ExtraParam, IncludeGrantedScopes, IntoExtraParam, PromptList,
    ToExtraParams,
};
use super::scope::{Scope, ScopeList};
use crate::GoogleOAuthTokenResponse;

use std::borrow::Cow;
use std::fmt;

use oauth2::{AuthorizationCode, CsrfToken, PkceCodeVerifier, TokenResponse};
use serde::{Deserialize, Serialize};
use url::Url;

/// Represents optional parameters sent during the `OAuth2` authorization request.
/// These affect the server behavior for consent, prompt, and token refreshability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestAccessTokenExtraParams {
    /// If this parameter is provided with the value true, and the authorization request
    /// is granted, the authorization will include any previous authorizations granted
    /// to this user/application combination for other scopes; see Incremental authorization.
    /// Note that you cannot do incremental authorization with the Installed App flow.
    #[serde(default)]
    pub(crate) include_granted_scopes: IncludeGrantedScopes,

    /// If your application knows which user is trying to authenticate, it can use
    /// this parameter to provide a hint to the Google Authentication Server.
    ///
    /// The server uses the hint to simplify the login flow either by prefilling
    /// the email field in the sign-in form or by selecting the appropriate multi-login session.
    ///
    /// Set the parameter value to an email address or sub identifier,
    /// which is equivalent to the user's Google ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) login_hint: Option<String>,

    #[serde(default)]
    pub(crate) access_type: AccessType,

    #[serde(default)]
    pub(crate) prompt: PromptList,
}

impl<'a> ToExtraParams<'a> for RequestAccessTokenExtraParams {
    fn to_extra_params(&self) -> Vec<(ExtraParam, Cow<'a, str>)> {
        let mut params = vec![];

        // access_type
        params.push(self.access_type.clone().into_extra_param());

        // include_granted_scopes
        if *self.include_granted_scopes {
            params.push((
                ExtraParam::INCLUDE_GRANTED_SCOPES,
                Cow::Owned(self.include_granted_scopes.to_string()),
            ));
        }

        // login_hint
        if let Some(hint) = self.login_hint.clone() {
            params.push((ExtraParam::LOGIN_HINT, Cow::Owned(hint)));
        }

        // prompt
        params.push(self.prompt.clone().into_extra_param());

        params
    }
}

/// Represents optional parameters sent during the `OAuth2` authorization request.
///
/// These parameters influence the authorization server's behavior for consent prompts,
/// login hints, token refreshability, and redirect handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestAccessTokenPayload {
    /// Optional URI to which the authorization server will redirect after authorization.
    pub redirect_uri: Option<String>,

    /// User defined scopes to authorize
    #[serde(rename = "scope")]
    pub scopes: ScopeList,

    /// Additional parameters sent along with the authorization request,
    /// flattened into the top-level JSON object for convenience.
    #[serde(flatten)]
    pub extra_params: RequestAccessTokenExtraParams,
}

/// Represents configuration for an authorization request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestAccessTokenConfig {
    scopes: Vec<Scope>,

    extra_params: RequestAccessTokenExtraParams,
}

impl RequestAccessTokenConfig {
    /// User defined scopes to authorize
    pub fn scopes(&self) -> &[Scope] {
        self.scopes.as_slice()
    }

    /// Additional parameters sent along with the authorization request.
    pub fn extra_params(&self) -> &RequestAccessTokenExtraParams {
        &self.extra_params
    }
}

impl From<&RequestAccessTokenPayload> for RequestAccessTokenConfig {
    fn from(payload: &RequestAccessTokenPayload) -> Self {
        RequestAccessTokenConfig {
            scopes: payload.scopes.to_vec(),
            extra_params: payload.extra_params.clone(),
        }
    }
}

/// Represents the response details after constructing an `OAuth2` authorization request URL.
///
/// Contains the PKCE code verifier, CSRF token, and the constructed authorization URL
/// to which the user should be redirected.
pub struct RequestAccessTokenResponse {
    pkce_verifier: PkceCodeVerifier,
    csrf_token: CsrfToken,
    url: Url,
}

impl RequestAccessTokenResponse {
    /// Constructs a new `RequestAccessTokenResponse`.
    ///
    /// # Parameters
    /// - `pkce_verifier`: The PKCE code verifier to be used in the token exchange.
    /// - `csrf_token`: The CSRF token used for request validation.
    /// - `url`: The full authorization URL where the user should be redirected.
    pub fn new(
        pkce_verifier: PkceCodeVerifier,
        csrf_token: CsrfToken,
        url: Url,
    ) -> Self {
        RequestAccessTokenResponse {
            pkce_verifier,
            csrf_token,
            url,
        }
    }

    /// Returns a reference to the PKCE code verifier.
    pub fn pkce_verifier(&self) -> &PkceCodeVerifier {
        &self.pkce_verifier
    }

    /// Returns a reference to the CSRF token.
    pub fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }

    /// Returns a reference to the authorization URL.
    pub fn url(&self) -> &Url {
        &self.url
    }
}

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

/// Represents the result of an `OAuth2` authorization redirect.
///
/// This enum captures whether the redirect resulted in a success with a token
/// or an error with an error message, along with the redirect URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthorizationResponse {
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

impl AuthorizationResponse {
    /// Creates a new error variant with the given URL and error message.
    pub fn new_error(url: Url, error: impl AsRef<str>) -> Self {
        AuthorizationResponse::Error {
            url,
            error: error.as_ref().to_owned(),
        }
    }

    /// Creates a new success variant with the given URL and OAuth token response.
    pub fn new_success(url: Url, token: GoogleOAuthTokenResponse) -> Self {
        AuthorizationResponse::Success { url, token }
    }
}

impl fmt::Display for AuthorizationResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorizationResponse::Error { url, error } => {
                write!(f, "{}#error={}", url, urlencoding::encode(error))
            }
            AuthorizationResponse::Success { url, token } => {
                let issued_at = chrono::Utc::now().timestamp();
                let expires_in = token.expires_in().map_or(0, |d| d.as_secs());
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
