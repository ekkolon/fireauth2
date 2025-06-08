/// Common result type used throughout the crate,
/// with the custom `Error` enum as the error variant.
pub type Result<T> = core::result::Result<T, Error>;

/// Represents all possible errors returned by this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // --- IO and Parsing Errors ---
    /// Error parsing JSON data.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Error reading environment variables.
    #[error(transparent)]
    Env(#[from] std::env::VarError),

    /// Error decoding Base64 strings.
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),

    // --- Web / Actix / HTTP Errors ---
    /// Error parsing URLs.
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    /// HTTP request error from the `OAuth2` HTTP client.
    #[error(transparent)]
    Http(#[from] oauth2::reqwest::Error),

    // --- OAuth-specific Errors ---
    /// Token verification error from Google OAuth.
    #[error(transparent)]
    TokenVerification(#[from] google_oauth::Error),

    /// `OAuth2` configuration error.
    #[error(transparent)]
    OAuthConfig(#[from] oauth2::ConfigurationError),

    // --- Firebase Errors ---
    /// Firestore database operation error.
    #[error(transparent)]
    Firestore(#[from] firestore::errors::FirestoreError),

    /// No Google user found in the expected context.
    #[error("No Google user found")]
    UserNotFound,

    // --- Domain-specific Errors ---
    /// Provided prompt value is invalid.
    #[error("Invalid prompt value: {0}")]
    InvalidPromptValue(String),

    /// Token exchange process failed, with reason.
    #[error("Failed to exchange token: {because}")]
    TokenExchangeFailed {
        /// The reason for why the token exchange failed.
        because: String,
    },

    /// Token revocation process failed, with reason.
    #[error("Failed to revoke token: {because}")]
    TokenRevocationFailed {
        /// The reason for why the token revocation failed.
        because: String,
    },

    /// Required configuration field is missing.
    #[error("Missing required config field `{0}`")]
    MissingConfigField(&'static str),
}
