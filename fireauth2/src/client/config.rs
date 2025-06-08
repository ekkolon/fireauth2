use base64::Engine;
use oauth2::{
    AuthUrl, ClientId, ClientSecret, RedirectUrl, RevocationUrl, Scope,
    TokenUrl,
};
use serde::Deserialize;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GoogleOAuthWebClientConfig {
    client_id: String,
    project_id: String,
    auth_uri: url::Url,
    token_uri: url::Url,
    #[allow(unused)]
    auth_provider_x509_cert_url: String,
    client_secret: String,
    #[allow(unused)]
    redirect_uris: Vec<url::Url>,
    javascript_origins: Vec<url::Url>,
}

#[derive(Clone, Deserialize)]
pub struct GoogleOAuthClientConfig {
    web: GoogleOAuthWebClientConfig,
}

impl GoogleOAuthClientConfig {
    const CLIENT_CONFIG_VAR: &'static str = "GOOGLE_OAUTH_CLIENT_CONFIG";
    const REVOCATION_URL: &'static str = "https://oauth2.googleapis.com/revoke";

    const SCOPES: &'static [&str] = &[
        "email",
        "openid",
        "profile",
        "https://www.googleapis.com/auth/datastore",
    ];

    pub fn scopes(&self) -> Vec<Scope> {
        Self::SCOPES
            .iter()
            .map(|s| Scope::new(s.to_string()))
            .collect()
    }

    pub fn token_uri(&self) -> crate::Result<TokenUrl> {
        let url = TokenUrl::new(self.web.token_uri.to_string())?;
        Ok(url)
    }

    pub fn auth_uri(&self) -> crate::Result<AuthUrl> {
        let url = AuthUrl::new(self.web.auth_uri.to_string())?;
        Ok(url)
    }

    pub fn revocation_url(&self) -> crate::Result<RevocationUrl> {
        let url = RevocationUrl::new(Self::REVOCATION_URL.to_string())?;
        Ok(url)
    }

    pub fn project_id(&self) -> &str {
        &self.web.project_id
    }

    pub fn allowed_origins(&self) -> &Vec<url::Url> {
        self.web.javascript_origins.as_ref()
    }

    pub fn redirect_uri(&self) -> crate::Result<RedirectUrl> {
        let redirect_url = "http://localhost:8080/callback";
        let redirect_url = RedirectUrl::new(redirect_url.to_owned())?;
        Ok(redirect_url)
    }

    pub fn client_id(&self) -> crate::Result<ClientId> {
        Ok(ClientId::new(self.web.client_id.clone()))
    }

    // (todo): Redact the secret to prevent accidentally exposing it
    pub(crate) fn client_secret(&self) -> crate::Result<ClientSecret> {
        let secret = ClientSecret::new(self.web.client_secret.clone());
        Ok(secret)
    }

    /// Parses Google OAuth 2.0 JSON from an base64-encoded string
    pub fn from_env() -> crate::Result<Self> {
        let encoded = std::env::var(Self::CLIENT_CONFIG_VAR)?;
        let decoded =
            base64::engine::general_purpose::STANDARD.decode(encoded)?;
        let data: GoogleOAuthClientConfig = serde_json::from_slice(&decoded)?;
        Ok(data)
    }
}
