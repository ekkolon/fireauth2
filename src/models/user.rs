use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleUser {
    #[allow(unused)]
    #[serde(alias = "_firestore_id", skip_serializing)]
    pub(crate) id: String,
    pub(crate) email: Option<String>,
    pub(crate) refresh_token: Option<String>,
    pub(crate) scope: Vec<String>,
}

// Manually implement Debug to redact sensitive information
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
