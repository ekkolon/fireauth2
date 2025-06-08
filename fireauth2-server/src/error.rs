use actix_web::{HttpResponse, ResponseError, http::StatusCode};

/// A convenient alias for results returned by this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Represents all possible errors that can occur in the application.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // IO and Parsing Errors
    /// I/O operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// JSON parsing or serialization failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Failed to read or parse an environment variable.
    #[error(transparent)]
    Env(#[from] std::env::VarError),

    /// Failed to load or parse `.env` file.
    #[error(transparent)]
    DotEnv(#[from] dotenvy::Error),

    /// Failed to parse a network address.
    #[error(transparent)]
    Net(#[from] std::net::AddrParseError),

    /// Failed to parse a `String`.
    #[error(transparent)]
    ParseString(#[from] std::string::ParseError),

    /// Failed to parse an integer.
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),

    /// Failed to parse a boolean value.
    #[error(transparent)]
    ParseBool(#[from] std::str::ParseBoolError),

    // Web / Actix Errors
    /// Actix-web related error.
    #[error(transparent)]
    Actix(#[from] actix_web::Error),

    /// Failed to parse a URL.
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    /// Error from the `fireauth2` crate.
    #[error(transparent)]
    FireAuth2(#[from] fireauth2::Error),

    // Firebase Errors
    /// Error from the `actix-firebase-auth` crate.
    #[error(transparent)]
    FirebaseAuth(#[from] actix_firebase_auth::Error),

    /// Firebase ID token is missing required Google identity claims.
    #[error("Firebase ID token is missing Google identity claims")]
    FirebaseUserMissingGoogleIdentity,

    // Domain errors
    /// The redirect URL contains invalid UTF-8.
    #[error(transparent)]
    InvalidRedirectUrl(#[from] std::string::FromUtf8Error),

    /// Failed to extract auth cookie due to a specific reason.
    #[error("Failed to extract auth info: {because}")]
    FailedToExtractAuthCookie {
        /// The reason for why the auth cookie could not be extracted.
        because: String,
    },

    /// No valid `redirect_to` query parameter or Referer header found.
    #[error(
        "Request is missing a valid redirect_to query param or Referer header"
    )]
    MissingRedirectUrl,
}

// TODO: Map specific errors to appropriate HTTP codes
impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        let body = serde_json::json!({
            "error": self.to_string(),
        });

        HttpResponse::build(self.status_code()).json(body)
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Error::Actix(err) => err.as_response_error().status_code(),
            Error::FirebaseAuth(err) => err.error_response().status(),

            Error::FailedToExtractAuthCookie { .. }
            | Error::FirebaseUserMissingGoogleIdentity
            | Error::InvalidRedirectUrl(_)
            | Error::MissingRedirectUrl
            | Error::UrlParse(_) => StatusCode::BAD_REQUEST,

            Error::Env(_)
            | Error::DotEnv(_)
            | Error::Net(_)
            | Error::Json(_)
            | Error::Io(_)
            | Error::ParseString(_)
            | Error::ParseBool(_)
            | Error::ParseInt(_) => StatusCode::INTERNAL_SERVER_ERROR,

            // FireAuth2 errors
            Error::FireAuth2(err) => match err {
                fireauth2::Error::Firestore(_)
                | fireauth2::Error::Http(_)
                | fireauth2::Error::TokenRevocationFailed { .. } => {
                    StatusCode::BAD_GATEWAY
                }

                fireauth2::Error::InvalidPromptValue(_)
                | fireauth2::Error::MissingConfigField(_)
                | fireauth2::Error::UserNotFound
                | fireauth2::Error::UrlParse(_)
                | fireauth2::Error::TokenVerification(_) => {
                    StatusCode::BAD_REQUEST
                }

                fireauth2::Error::Env(_)
                | fireauth2::Error::Base64(_)
                | fireauth2::Error::Json(_)
                | fireauth2::Error::TokenExchangeFailed { .. }
                | fireauth2::Error::OAuthConfig(_) => {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            },
        }
    }
}
