use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use oauth2::reqwest;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    // IO and Parsing Errors
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Env(#[from] std::env::VarError),

    #[error(transparent)]
    DotEnv(#[from] dotenvy::Error),

    #[error(transparent)]
    Net(#[from] std::net::AddrParseError),

    #[error(transparent)]
    ParseString(#[from] std::string::ParseError),

    #[error(transparent)]
    Base64(#[from] base64::DecodeError),

    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),

    #[error(transparent)]
    ParseBool(#[from] std::str::ParseBoolError),

    // Web / Actix Errors
    #[error(transparent)]
    Actix(#[from] actix_web::Error),

    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    #[error(transparent)]
    Http(#[from] reqwest::Error),

    // OAuth-specific errors
    #[error(transparent)]
    TokenVerification(#[from] google_oauth::Error),

    #[error(transparent)]
    OAuthConfig(#[from] oauth2::ConfigurationError),

    // Firestore Errors
    #[error(transparent)]
    Firestore(#[from] firestore::errors::FirestoreError),

    // Domain errors
    #[error(transparent)]
    InvalidRedirectUrl(#[from] std::string::FromUtf8Error),

    #[error("Invalid prompt value: {0}")]
    InvalidPromptValue(String),

    #[error("{0}")]
    TokenExchangeFailed(String),

    #[error("Failed to revoke token: {because}")]
    TokenRevocationFailed { because: String },

    #[error("Failed to extract auth info: {because}")]
    FailedToExtractAuthCookie { because: String },

    #[error("Request is missing a valid redirect_to query param or Referer header")]
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

            Error::Firestore(_) | Error::Http(_) | Error::TokenRevocationFailed { .. } => {
                StatusCode::BAD_GATEWAY
            }

            Error::FailedToExtractAuthCookie { .. }
            | Error::InvalidRedirectUrl(_)
            | Error::InvalidPromptValue(_)
            | Error::MissingRedirectUrl
            | Error::UrlParse(_)
            | Error::TokenVerification(_) => StatusCode::BAD_REQUEST,

            Error::Env(_)
            | Error::DotEnv(_)
            | Error::Net(_)
            | Error::Base64(_)
            | Error::Json(_)
            | Error::TokenExchangeFailed(_)
            | Error::Io(_)
            | Error::OAuthConfig(_)
            | Error::ParseString(_)
            | Error::ParseBool(_)
            | Error::ParseInt(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
