use oauth2::Scope;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Represents a Google user authenticated via `OAuth2`.
///
/// Contains user identification, email, refresh token, and scopes.
/// Sensitive fields like `email` and `refresh_token` are redacted in debug output for security.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleUser {
    /// Internal Firestore ID (not serialized).
    #[serde(alias = "_firestore_id", skip_serializing)]
    pub(crate) id: String,

    /// User's email address, if available.
    pub(crate) email: Option<String>,

    /// `OAuth2` refresh token, if present.
    pub(crate) refresh_token: Option<String>,

    /// `OAuth2` scopes granted to the user.
    pub(crate) scope: Vec<Scope>,
}

// Custom `Debug` implementation to avoid exposing sensitive information.
impl fmt::Debug for GoogleUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoogleUser")
            .field("id", &self.id)
            .field("email", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("scope", &self.scope)
            .finish()
    }
}
