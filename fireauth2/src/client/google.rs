use oauth2::basic::{BasicErrorResponseType, BasicTokenType};
use oauth2::{
    Client, EndpointNotSet, EndpointSet, ExtraTokenFields,
    RevocationErrorResponseType, StandardErrorResponse, StandardRevocableToken,
    StandardTokenIntrospectionResponse, StandardTokenResponse,
};
use serde::{Deserialize, Serialize};

/// Represents additional fields returned in Google's `OAuth2` token response.
///
/// Specifically, this struct captures the `id_token` field, which contains
/// a JWT used to validate and extract user identity information.
///
/// Implements `ExtraTokenFields` to integrate with the `oauth2` crate's token
/// response deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleOAuthExtraTokenFields {
    /// The `OpenID` Connect ID token returned by Google.
    id_token: String,
}

impl ExtraTokenFields for GoogleOAuthExtraTokenFields {}

impl GoogleOAuthExtraTokenFields {
    /// Returns a reference to the ID token string.
    pub fn id_token(&self) -> &str {
        &self.id_token
    }
}

/// Type alias for Google's token response which includes `id_token` as an extra field.
pub(crate) type GoogleOAuthTokenResponse =
    StandardTokenResponse<GoogleOAuthExtraTokenFields, BasicTokenType>;

/// Standardized OAuth client implementation using generic types from `oauth2` crate.
pub(crate) type GoogleOAuthClient = Client<
    StandardErrorResponse<BasicErrorResponseType>,
    StandardTokenResponse<GoogleOAuthExtraTokenFields, BasicTokenType>,
    StandardTokenIntrospectionResponse<
        GoogleOAuthExtraTokenFields,
        BasicTokenType,
    >,
    StandardRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
    EndpointSet,
>;
