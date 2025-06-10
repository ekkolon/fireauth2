use std::{borrow::Cow, fmt};

use serde::{Deserialize, Serialize};

use super::extra_param::{ExtraParam, IntoExtraParam};

/// Indicates whether your application can refresh access tokens
/// when the user is not present at the browser.
///
/// Valid values are:
/// - `online` (default): The application can only use access tokens
///   while the user is actively using the application.
/// - `offline`: The application can refresh access tokens without
///   the user being present in the browser.
///
/// Setting this to [`AccessType::Offline`] requests that the Google authorization server
/// return a refresh token along with the access token the first time
/// your application exchanges an authorization code for tokens.
///
/// This enables your application to maintain long-lived access without
/// requiring the user to reauthenticate frequently.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AccessType {
    /// The default mode where the application only obtains access tokens
    /// usable while the user is actively interacting with the app.
    /// No refresh token is issued in this mode.
    #[default]
    Online,

    /// Requests that the authorization server issues a refresh token
    /// along with the access token. This allows the application to refresh
    /// access tokens even when the user is not actively using the app.
    Offline,
}

impl fmt::Display for AccessType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Offline => write!(f, "offline"),
            Self::Online => write!(f, "online"),
        }
    }
}

impl<'a> IntoExtraParam<'a> for AccessType {
    fn into_extra_param(self) -> (ExtraParam, Cow<'a, str>) {
        (ExtraParam::ACCESS_TYPE, Cow::Owned(self.to_string()))
    }
}
