use serde::{Deserialize, Serialize};
use std::{fmt, ops::Deref};

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

pub const FIREBASE_GOOGLE_IDENTITY: &str = "google.com";

#[derive(Clone, Serialize, Deserialize)]
pub struct GoogleUserId(String);

impl TryFrom<&actix_firebase_auth::FirebaseUser> for GoogleUserId {
    type Error = crate::Error;

    fn try_from(firebase_user: &actix_firebase_auth::FirebaseUser) -> Result<Self, Self::Error> {
        // Look for "google.com" identity
        let google_id = firebase_user
            .firebase
            .identities
            .get(FIREBASE_GOOGLE_IDENTITY)
            .and_then(|value| value.as_array())
            .and_then(|value| value.first())
            .and_then(|id| id.as_str())
            .ok_or(crate::Error::FirebaseUserMissingGoogleIdentity)?;

        Ok(GoogleUserId(google_id.to_owned()))
    }
}

impl Deref for GoogleUserId {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
