use super::config::GoogleOAuthClientConfig;
use super::types::{
    ExchangeAuthorizationCodeRequest, RequestAccessTokenExtraParams, RequestAccessTokenResponse,
    ToExtraParams,
};
use super::{ExchangeRefreshTokenRequest, GoogleOAuthExtraTokenFields};

use google_oauth::{GoogleAccessTokenPayload, GooglePayload};
use oauth2::{
    basic::{BasicErrorResponseType, BasicTokenType},
    *,
};

/// Type alias for Google's token response which includes `id_token` as an extra field.
pub type GoogleOAuthTokenResponse =
    StandardTokenResponse<GoogleOAuthExtraTokenFields, BasicTokenType>;

/// Standardized OAuth client implementation using generic types from `oauth2` crate.
type StandardClient = Client<
    StandardErrorResponse<BasicErrorResponseType>,
    StandardTokenResponse<GoogleOAuthExtraTokenFields, BasicTokenType>,
    StandardTokenIntrospectionResponse<GoogleOAuthExtraTokenFields, BasicTokenType>,
    StandardRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
    EndpointSet,
>;

/// A high-level OAuth2 client tailored for Google, with support for ID token verification
/// and Firebase compatibility.
#[derive(Clone)]
pub struct GoogleOAuthClient {
    client: StandardClient,
    config: GoogleOAuthClientConfig,
    http_client: reqwest::Client,
    token_verifier: google_oauth::AsyncClient,
}

impl GoogleOAuthClient {
    /// Initializes a new GoogleOAuthClient using environment-provided configuration.
    /// Verifies configuration presence and sets up the internal OAuth client and verifier.
    pub fn new() -> crate::Result<Self> {
        let config = GoogleOAuthClientConfig::from_env()?;
        let client_id = config.client_id()?;

        let token_verifier = google_oauth::AsyncClient::new(client_id.as_str());

        let client = Client::new(config.client_id()?)
            .set_auth_type(AuthType::BasicAuth)
            .set_token_uri(config.token_uri()?)
            .set_auth_uri(config.auth_uri()?)
            .set_client_secret(config.client_secret()?)
            .set_redirect_uri(config.redirect_uri()?)
            .set_revocation_url(config.revocation_url()?);

        let http_client = reqwest::ClientBuilder::new()
            // Explicitly disable redirects to avoid SSRF attack surface.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to build HTTP client");

        Ok(Self {
            client,
            config,
            http_client,
            token_verifier,
        })
    }

    pub fn project_id(&self) -> &str {
        self.config.project_id()
    }

    pub fn allowed_origins(&self) -> &Vec<url::Url> {
        self.config.allowed_origins()
    }

    /// Exchanges a Google-issued refresh token for an access token.
    pub async fn exchange_refresh_token(
        &self,
        request: ExchangeRefreshTokenRequest,
    ) -> crate::Result<GoogleOAuthTokenResponse> {
        let token_result = self
            .client
            .exchange_refresh_token(&request.refresh_token)
            .request_async(&self.http_client)
            .await
            .map_err(|err| crate::Error::TokenExchangeFailed(err.to_string()))?;
        Ok(token_result)
    }

    /// Exchanges an authorization code for an access token.
    /// This method also applies the PKCE verifier and any additional parameters.
    pub async fn exchange_authorization_code(
        &self,
        request: ExchangeAuthorizationCodeRequest,
        extra_params: &RequestAccessTokenExtraParams,
    ) -> crate::Result<GoogleOAuthTokenResponse> {
        let mut client = self
            .client
            .exchange_code(request.code)
            .set_pkce_verifier(request.pkce_verifier);

        for (name, value) in extra_params.to_extra_params() {
            client = client.add_extra_param(name.into_cow(), value);
        }

        let token_result = client
            .request_async(&self.http_client)
            .await
            .map_err(|err| crate::Error::TokenExchangeFailed(err.to_string()))?;

        Ok(token_result)
    }

    /// Generates an authorization URL with a PKCE challenge and CSRF token.
    /// Returns the verifier, URL to redirect the user to, and the CSRF token to validate later.
    pub fn request_access_token(
        &self,
        extra_params: &RequestAccessTokenExtraParams,
    ) -> RequestAccessTokenResponse {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut client = self
            .client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge)
            .add_scopes(self.config.scopes());

        for (name, value) in extra_params.to_extra_params() {
            client = client.add_extra_param(name.into_cow(), value);
        }

        let (auth_url, csrf_token) = client.url();

        RequestAccessTokenResponse::new(pkce_verifier, csrf_token, auth_url)
    }

    /// Revokes a Google-issued `access_token` or `refresh_token`.
    pub async fn revoke_token(&self, token: StandardRevocableToken) -> crate::Result<()> {
        self.client
            .revoke_token(token)?
            .request_async(&self.http_client)
            .await
            .map_err(|err| crate::Error::TokenRevocationFailed {
                because: err.to_string(),
            })?;

        Ok(())
    }

    /// Validates a Google-issued `id_token` using Google's public keys.
    /// Returns the parsed payload if successful.
    pub async fn validate_id_token<T: AsRef<str>>(
        &self,
        id_token: T,
    ) -> crate::Result<GooglePayload> {
        let payload = self.token_verifier.validate_id_token(id_token).await?;
        Ok(payload)
    }

    /// Validates a Google-issued `access_token` using Google's public keys.
    /// Returns the parsed payload if successful.
    pub async fn validate_access_token<T: AsRef<str>>(
        &self,
        access_token: T,
    ) -> crate::Result<GoogleAccessTokenPayload> {
        let payload = self
            .token_verifier
            .validate_access_token(access_token)
            .await?;
        Ok(payload)
    }

    pub(crate) fn with_redirect_uri(mut self, uri: url::Url) -> Self {
        let redirect_uri = RedirectUrl::from_url(uri);
        self.client = self.client.set_redirect_uri(redirect_uri);
        self
    }
}
