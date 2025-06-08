use oauth2::AccessToken;
use serde::Deserialize;

/// Payload for token revocation requests.
///
/// Contains the access token to revoke and an optional flag
/// indicating whether the refresh token should also be revoked.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenRevocationPayload {
    access_token: AccessToken,
    #[serde(default)]
    revoke_refresh_token: bool,
}

impl TokenRevocationPayload {
    /// Returns a reference to the access token to revoke.
    pub fn access_token(&self) -> &AccessToken {
        &self.access_token
    }

    /// Returns whether the refresh token should also be revoked.
    pub fn revoke_refresh_token(&self) -> bool {
        self.revoke_refresh_token
    }
}

/// Configuration for a token revocation operation.
///
/// Includes the revocation payload and the ID of the user associated with the tokens.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenRevocationConfig {
    payload: TokenRevocationPayload,
    user_id: String,
}

impl TokenRevocationConfig {
    /// Creates a new token revocation configuration with the given payload and user ID.
    pub fn new(
        payload: TokenRevocationPayload,
        user_id: impl AsRef<str>,
    ) -> TokenRevocationConfig {
        Self {
            payload,
            user_id: user_id.as_ref().to_owned(),
        }
    }

    /// Returns the user ID associated with the tokens.
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Returns a reference to the access token to revoke.
    pub fn access_token(&self) -> &AccessToken {
        &self.payload.access_token
    }

    /// Returns whether the refresh token should also be revoked.
    pub fn revoke_refresh_token(&self) -> bool {
        self.payload.revoke_refresh_token
    }
}
