use serde::{Deserialize, Serialize};

/// Specifies the type hint for token introspection, guiding how the token should be interpreted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TokenIntrospectionTypeHint {
    /// Indicates the token is an access token.
    AccessToken,
    /// Indicates the token is an ID token. This is the default value.
    #[default]
    IdToken,
}

/// Payload structure for token introspection requests.
#[derive(Debug, Deserialize)]
pub struct TokenIntrospectionPayload {
    /// The token string to be introspected.
    token: String,

    /// Optional hint about the type of the token.
    #[serde(default)]
    token_type_hint: TokenIntrospectionTypeHint,
}

impl TokenIntrospectionPayload {
    /// Returns a reference to the token string.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Returns a reference to the token type hint.
    pub fn token_type_hint(&self) -> &TokenIntrospectionTypeHint {
        &self.token_type_hint
    }
}
