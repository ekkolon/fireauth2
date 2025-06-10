use crate::client::authorization::{
    AuthorizationResponse, ExchangeAuthorizationCodeConfig,
    ExchangeRefreshTokenResponse, RequestAccessTokenConfig,
    RequestAccessTokenResponse, ToExtraParams,
};
use crate::client::config::GoogleOAuthClientConfig;
use crate::client::revocation::TokenRevocationConfig;
use crate::models::GoogleUser;
use crate::repositories::GoogleUserRepository;

use firestore::FirestoreDb;
use google_oauth::{GoogleAccessTokenPayload, GooglePayload};
use oauth2::{
    AuthType, Client, CsrfToken, PkceCodeChallenge, RedirectUrl, RefreshToken,
    StandardRevocableToken, TokenResponse, reqwest,
};

type FireAuthClientInner = crate::client::google::GoogleOAuthClient;

/// Type alias for Google's token response which includes `id_token` as an extra field.
pub type FireAuthTokenResponse =
    crate::client::google::GoogleOAuthTokenResponse;

/// A high-level `OAuth2` client tailored for Google, with support for ID token verification
/// and Firebase compatibility.
#[derive(Clone)]
pub struct FireAuthClient {
    client: FireAuthClientInner,
    config: GoogleOAuthClientConfig,
    http_client: reqwest::Client,
    repository: GoogleUserRepository,
    token_verifier: google_oauth::AsyncClient,
}

impl FireAuthClient {
    /// Initializes a new `GoogleOAuthClient` using environment-provided configuration.
    /// Verifies configuration presence and sets up the internal OAuth client and verifier.
    pub async fn new() -> crate::Result<Self> {
        let config = GoogleOAuthClientConfig::from_env()?;
        let client_id = config.client_id();

        let token_verifier = google_oauth::AsyncClient::new(client_id.as_str());

        let client = Client::new(client_id)
            .set_auth_type(AuthType::BasicAuth)
            .set_token_uri(config.token_uri()?)
            .set_auth_uri(config.auth_uri()?)
            .set_client_secret(config.client_secret())
            .set_revocation_url(GoogleOAuthClientConfig::revocation_url()?);

        // Explicitly disable redirects to avoid SSRF attack surface.
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let firestore = FirestoreDb::new(config.project_id()).await?;
        let repository = GoogleUserRepository::new(firestore, "googleUsers");

        Ok(Self {
            client,
            config,
            http_client,
            repository,
            token_verifier,
        })
    }

    /// Returns a string slice of the configured Google Cloud project ID.
    ///
    /// This ID is used to identify the Firebase or Firestore project in use.
    pub fn project_id(&self) -> &str {
        self.config.project_id()
    }

    /// Returns the list of allowed javascript origins, as configured
    /// in the Google OAuth Client config.
    pub fn allowed_origins(&self) -> &Vec<url::Url> {
        self.config.allowed_origins()
    }

    /// Exchanges a Google-issued refresh token for an access token.
    pub async fn exchange_refresh_token(
        &self,
        google_user_id: impl AsRef<str>,
    ) -> crate::Result<ExchangeRefreshTokenResponse> {
        let google_user = self
            .repository
            .get(google_user_id)
            .await?
            .ok_or(crate::Error::UserNotFound)?;

        let refresh_token = google_user
            .refresh_token
            .ok_or(crate::Error::TokenExchangeFailed {
                because: "No refresh token found for user".into(),
            })
            .map(RefreshToken::new)?;

        let token_result = self
            .client
            .exchange_refresh_token(&refresh_token)
            .request_async(&self.http_client)
            .await
            .map_err(|err| crate::Error::TokenExchangeFailed {
                because: err.to_string(),
            })?;

        let response = ExchangeRefreshTokenResponse::from(token_result);
        Ok(response)
    }

    /// Exchanges an authorization code for an access token.
    /// This method also applies the PKCE verifier and any additional parameters.
    pub async fn exchange_authorization_code(
        &self,
        config: ExchangeAuthorizationCodeConfig,
    ) -> crate::Result<AuthorizationResponse> {
        // Validate CSRF token from query against session.
        if config.csrf_token != config.state {
            let response = AuthorizationResponse::new_error(
                config.redirect_to,
                "CSRF token mismatch",
            );
            return Ok(response);
        }

        let mut client = self
            .client
            .exchange_code(config.code)
            .set_pkce_verifier(config.pkce_verifier);

        for (name, value) in config.params.to_extra_params() {
            client = client.add_extra_param(name.into_cow(), value);
        }

        let token_result = client
            .request_async(&self.http_client)
            .await
            .map_err(|err| crate::Error::TokenExchangeFailed {
                because: err.to_string(),
            });

        let response = match token_result {
            Ok(token) => token,
            Err(err) => {
                let response = AuthorizationResponse::new_error(
                    config.redirect_to,
                    err.to_string(),
                );
                return Ok(response);
            }
        };

        // Verify the ID token to confirm issuer and audience.
        let id_token = response.extra_fields().id_token();
        let id_token_payload = match self.validate_id_token(id_token).await {
            Ok(token) => token,
            Err(err) => {
                let response = AuthorizationResponse::new_error(
                    config.redirect_to,
                    err.to_string(),
                );
                return Ok(response);
            }
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

            if config.revoke_existing_tokens {
                self.revoke_existing_tokens(&google_user_id).await;
            }

            let refresh_token = token.to_owned().into_secret();
            let scope =
                response.scopes().map(Vec::to_owned).unwrap_or_default();

            let google_user = GoogleUser {
                id: google_user_id, // Note: this field is not saved to Firestore
                refresh_token: Some(refresh_token),
                email: id_token_payload.email,
                scope,
            };

            if let Err(err) = self.repository.update(&google_user).await {
                // TODO: Maybe return an error
                log::debug!(
                    "Failed to update Google user: {}",
                    &err.to_string()
                );
                // let response = AuthRedirectResponse::new_error(config.redirect_to, err.to_string());
                // return Ok(response);
            }
        }

        let redirect_response =
            AuthorizationResponse::new_success(config.redirect_to, response);

        Ok(redirect_response)
    }

    /// Generates an authorization URL with a PKCE challenge and CSRF token.
    /// Returns the verifier, URL to redirect the user to, and the CSRF token to validate later.
    pub fn request_access_token(
        &self,
        config: &RequestAccessTokenConfig,
    ) -> RequestAccessTokenResponse {
        let (pkce_challenge, pkce_verifier) =
            PkceCodeChallenge::new_random_sha256();

        let scopes = config.scopes();
        let extra_params = config.extra_params().to_extra_params();

        let mut client = self
            .client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge)
            .add_scopes(scopes.to_vec());

        for (name, value) in extra_params {
            client = client.add_extra_param(name.into_cow(), value);
        }

        let (auth_url, csrf_token) = client.url();

        RequestAccessTokenResponse::new(pkce_verifier, csrf_token, auth_url)
    }

    /// Revokes a Google-issued `access_token` or `refresh_token`.
    pub async fn revoke_token(
        &self,
        config: TokenRevocationConfig,
    ) -> crate::Result<()> {
        let token = StandardRevocableToken::AccessToken(
            config.access_token().to_owned(),
        );
        self.revoke_revocable_token(token).await?;

        if config.revoke_refresh_token() {
            let google_user = self.repository.get(config.user_id()).await?;

            let refresh_token = google_user
                .and_then(|user| user.refresh_token)
                .map(RefreshToken::new)
                .map(StandardRevocableToken::RefreshToken);

            if let Some(token) = refresh_token {
                self.revoke_revocable_token(token).await?;
            }
        }

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

    /// Sets the redirect URI for the `OAuth2` client.
    ///
    /// # Parameters
    /// - `uri`: The URL to be used as the redirect URI in the `OAuth2` flow.
    ///
    /// # Returns
    /// The updated builder instance with the redirect URI set.
    #[must_use]
    pub fn with_redirect_uri(mut self, uri: url::Url) -> Self {
        let redirect_uri = RedirectUrl::from_url(uri);
        self.client = self.client.set_redirect_uri(redirect_uri);
        self
    }

    async fn revoke_existing_tokens(&self, user_id: &str) {
        // Revoke existing refresh token, if any
        let existing_google_user_result = self.repository.get(user_id).await;
        match existing_google_user_result {
            Err(err) => {
                // TODO: Maybe return an error
                // return Err(err);
                log::debug!(
                    "Failed to update Google user: {}",
                    &err.to_string()
                );
            }
            Ok(None) => {
                // No User record
                log::debug!(
                    "Skipping token revocation. No record found for Google User ID"
                );
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
                    let revocable_token =
                        StandardRevocableToken::RefreshToken(refresh_token);

                    log::debug!("Preparing for token revocation");
                    match self.revoke_revocable_token(revocable_token).await {
                        Err(err) => {
                            // TODO: Maybe return an error
                            log::debug!(
                                "Token revocation failed: {}",
                                &err.to_string()
                            );
                        }
                        Ok(()) => {
                            log::debug!("Token successfully revoked");
                        }
                    }
                }
            }
        }
    }

    async fn revoke_revocable_token(
        &self,
        token: StandardRevocableToken,
    ) -> crate::Result<()> {
        self.client
            .revoke_token(token)?
            .request_async(&self.http_client)
            .await
            .map_err(|err| crate::Error::TokenRevocationFailed {
                because: err.to_string(),
            })
    }
}
