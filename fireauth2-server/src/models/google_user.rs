use serde::{Deserialize, Serialize};
use std::ops::Deref;

const FIREBASE_GOOGLE_IDENTITY: &str = "google.com";

#[derive(Clone, Serialize, Deserialize)]
pub struct GoogleUserId(String);

impl TryFrom<&actix_firebase_auth::FirebaseUser> for GoogleUserId {
    type Error = crate::Error;

    fn try_from(
        firebase_user: &actix_firebase_auth::FirebaseUser,
    ) -> Result<Self, Self::Error> {
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
