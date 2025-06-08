use oauth2::ExtraTokenFields;
use serde::{Deserialize, Serialize};

/// Represents additional fields returned in Google's OAuth2 token response.
///
/// Specifically, this struct captures the `id_token` field, which contains
/// a JWT used to validate and extract user identity information.
///
/// Implements `ExtraTokenFields` to integrate with the `oauth2` crate's token
/// response deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleOAuthExtraTokenFields {
    /// The OpenID Connect ID token returned by Google.
    id_token: String,
}

impl ExtraTokenFields for GoogleOAuthExtraTokenFields {}

impl GoogleOAuthExtraTokenFields {
    /// Returns a reference to the ID token string.
    pub fn id_token(&self) -> &str {
        &self.id_token
    }
}
