use oauth2::ExtraTokenFields;
use serde::{Deserialize, Serialize};

/// Extra fields returned in Google's token response. We expect the `id_token`
/// to be present so we can validate and extract user identity from it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleOAuthExtraTokenFields {
    id_token: String,
}

impl ExtraTokenFields for GoogleOAuthExtraTokenFields {}

impl GoogleOAuthExtraTokenFields {
    pub fn id_token(&self) -> &str {
        &self.id_token
    }
}
