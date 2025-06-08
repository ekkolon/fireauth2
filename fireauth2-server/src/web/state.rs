#![expect(unused)]

use crate::impl_actix_from_request;

const DEFAULT_FIREAUTH2_REDIRECT_URI_PATH: &str = "/callback";
const DEFAULT_FIREAUTH2_SESSION_COOKIE_NAME: &str = "FIREAUTH2_SESSION";
const DEFAULT_FIREAUTH2_SESSION_COOKIE_MAX_AGE: u16 = 180; // in seconds
const DEFAULT_FIREAUTH2_FIRESTORE_COLLECTION: &str = "googleUsers";
const DEFAULT_FIREAUTH2_ENABLE_EXISTING_TOKEN_REVOCATION: bool = false;

#[derive(Debug, Clone)]
pub struct AppState {
    cookie_name: String,
    cookie_max_age: u16,
    enable_existing_token_revocation: bool,
    firestore_collection_name: String,
    /// The internal (server-side) redirect URI for the OAuth 2.0 authentication flow.
    /// This implementation uses a server-side approach to handle authorization
    /// token exchange.
    ///
    /// Note, that the URI provided here must also be set in the the OAuth 2.0 Client config
    /// json in the Google Cloud Platform console.
    redirect_uri_path: String,
}

impl AppState {
    pub fn from_env() -> crate::Result<Self> {
        let redirect_uri_path = option_env!("FIREAUTH2_REDIRECT_URI_PATH")
            .map(std::borrow::ToOwned::to_owned)
            .unwrap_or_else(|| DEFAULT_FIREAUTH2_REDIRECT_URI_PATH.to_string());

        let cookie_name = option_env!("FIREAUTH2_SESSION_COOKIE_NAME")
            .map(std::borrow::ToOwned::to_owned)
            .unwrap_or_else(|| {
                DEFAULT_FIREAUTH2_SESSION_COOKIE_NAME.to_string()
            });

        let cookie_max_age = option_env!("FIREAUTH2_SESSION_COOKIE_MAX_AGE")
            .map(std::borrow::ToOwned::to_owned)
            .unwrap_or_else(|| {
                DEFAULT_FIREAUTH2_SESSION_COOKIE_MAX_AGE.to_string()
            })
            .parse::<u16>()?;

        let firestore_collection_name =
            option_env!("FIREAUTH2_FIRESTORE_COLLECTION")
                .map(std::borrow::ToOwned::to_owned)
                .unwrap_or_else(|| {
                    DEFAULT_FIREAUTH2_FIRESTORE_COLLECTION.to_string()
                });

        let enable_existing_token_revocation =
            option_env!("FIREAUTH2_ENABLE_EXISTING_TOKEN_REVOCATION")
                .map(std::borrow::ToOwned::to_owned)
                .unwrap_or_else(|| {
                    DEFAULT_FIREAUTH2_ENABLE_EXISTING_TOKEN_REVOCATION
                        .to_string()
                })
                .parse::<bool>()?;

        Ok(Self {
            cookie_name,
            cookie_max_age,
            enable_existing_token_revocation,
            firestore_collection_name,
            redirect_uri_path,
        })
    }

    pub fn redirect_uri_path(&self) -> &str {
        &self.redirect_uri_path
    }

    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    pub fn cookie_max_age(&self) -> u16 {
        self.cookie_max_age
    }

    pub fn firestore_collection_name(&self) -> &str {
        &self.firestore_collection_name
    }

    pub fn enable_existing_token_revocation(&self) -> bool {
        self.enable_existing_token_revocation
    }
}

impl_actix_from_request!(for AppState);
