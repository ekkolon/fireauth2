use actix_web::HttpRequest;

use crate::impl_actix_from_request;

const DEFAULT_FIREAUTH2_REDIRECT_URI_PATH: &str = "/callback";
const DEFAULT_FIREAUTH2_SESSION_COOKIE_NAME: &str = "FIREAUTH2_SESSION";
const DEFAULT_FIREAUTH2_SESSION_COOKIE_MAX_AGE: u16 = 180; // in seconds
const DEFAULT_FIREAUTH2_FIRESTORE_COLLECTION: &str = "users";
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
            .map(|v| v.to_owned())
            .unwrap_or_else(|| DEFAULT_FIREAUTH2_REDIRECT_URI_PATH.to_string());

        let cookie_name = option_env!("FIREAUTH2_SESSION_COOKIE_NAME")
            .map(|v| v.to_owned())
            .unwrap_or_else(|| DEFAULT_FIREAUTH2_SESSION_COOKIE_NAME.to_string());

        let cookie_max_age = option_env!("FIREAUTH2_SESSION_COOKIE_MAX_AGE")
            .map(|v| v.to_owned())
            .unwrap_or_else(|| DEFAULT_FIREAUTH2_SESSION_COOKIE_MAX_AGE.to_string())
            .parse::<u16>()?;

        let firestore_collection_name = option_env!("FIREAUTH2_FIRESTORE_COLLECTION")
            .map(|v| v.to_owned())
            .unwrap_or_else(|| DEFAULT_FIREAUTH2_FIRESTORE_COLLECTION.to_string());

        let enable_existing_token_revocation =
            option_env!("FIREAUTH2_ENABLE_EXISTING_TOKEN_REVOCATION")
                .map(|v| v.to_owned())
                .unwrap_or_else(|| DEFAULT_FIREAUTH2_ENABLE_EXISTING_TOKEN_REVOCATION.to_string())
                .parse::<bool>()?;

        Ok(Self {
            cookie_max_age,
            cookie_name,
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

    pub fn get_redirect_uri_from_request(&self, req: &HttpRequest) -> crate::Result<url::Url> {
        let info = req.connection_info();
        let scheme = info.scheme();
        let host = info.host();
        let origin = format!("{}://{}", scheme, host);
        let mut origin_url = url::Url::parse(&origin)?;
        origin_url.set_path(&self.redirect_uri_path);
        Ok(origin_url)
    }
}

impl_actix_from_request!(for AppState);
