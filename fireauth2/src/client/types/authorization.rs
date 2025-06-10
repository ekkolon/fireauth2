use std::{borrow::Cow, fmt, str::FromStr};

use oauth2::{CsrfToken, PkceCodeVerifier, Scope};
use serde::{Deserialize, Serialize, de};
use url::Url;

use super::extra_params::{ExtraParam, IntoExtraParam, ToExtraParams};

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

/// A space-delimited list of string values that specifies whether the
/// authorization server prompts the user for reauthentication and consent.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Prompt {
    /// The authorization server does not display any authentication or user consent screens;
    /// it will return an error if the user is not already authenticated and has not
    /// pre-configured consent for the requested scopes. You can use `none` to check for
    /// existing authentication and/or consent.
    None,

    /// The authorization server prompts the user for consent before returning
    /// information to the client.
    #[default]
    Consent,

    /// The authorization server prompts the user to select a user account.
    /// This allows a user who has multiple accounts at the authorization
    /// server to select amongst the multiple accounts that they may have
    /// current sessions for.
    SelectAccount,
}

impl FromStr for Prompt {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Prompt::None),
            "consent" => Ok(Prompt::Consent),
            "select_account" => Ok(Prompt::SelectAccount),
            other => Err(crate::Error::InvalidPromptValue(other.to_string())),
        }
    }
}

impl fmt::Display for Prompt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Consent => write!(f, "consent"),
            Self::SelectAccount => write!(f, "select_account"),
        }
    }
}

impl<'a> IntoExtraParam<'a> for Vec<Prompt> {
    fn into_extra_param(self) -> (ExtraParam, Cow<'a, str>) {
        let joined = self
            .into_iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(" ");

        (ExtraParam::PROMPT, Cow::Owned(joined))
    }
}

/// Represents optional parameters sent during the `OAuth2` authorization request.
/// These affect the server behavior for consent, prompt, and token refreshability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestAccessTokenExtraParams {
    /// If this parameter is provided with the value true, and the authorization request
    /// is granted, the authorization will include any previous authorizations granted
    /// to this user/application combination for other scopes; see Incremental authorization.
    /// Note that you cannot do incremental authorization with the Installed App flow.
    #[serde(
        default = "include_granted_scopes",
        deserialize_with = "deserialize_bool"
    )]
    pub(crate) include_granted_scopes: bool,

    /// If your application knows which user is trying to authenticate, it can use
    /// this parameter to provide a hint to the Google Authentication Server.
    ///
    /// The server uses the hint to simplify the login flow either by prefilling
    /// the email field in the sign-in form or by selecting the appropriate multi-login session.
    ///
    /// Set the parameter value to an email address or sub identifier,
    /// which is equivalent to the user's Google ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) login_hint: Option<String>,

    #[serde(default)]
    pub(crate) access_type: AccessType,

    #[serde(default = "prompt", deserialize_with = "deserialize_prompt_vec")]
    pub(crate) prompt: Vec<Prompt>,
}

fn include_granted_scopes() -> bool {
    true
}

fn prompt() -> Vec<Prompt> {
    vec![Prompt::None]
}

impl<'a> ToExtraParams<'a> for RequestAccessTokenExtraParams {
    fn to_extra_params(&self) -> Vec<(ExtraParam, Cow<'a, str>)> {
        let mut params = vec![];

        // access_type
        params.push(self.access_type.clone().into_extra_param());

        // include_granted_scopes
        if self.include_granted_scopes {
            params.push((
                ExtraParam::INCLUDE_GRANTED_SCOPES,
                Cow::Owned(self.include_granted_scopes.to_string()),
            ));
        }

        // login_hint
        if let Some(hint) = self.login_hint.clone() {
            params.push((ExtraParam::LOGIN_HINT, Cow::Owned(hint)));
        }

        // prompt
        params.push(self.prompt.clone().into_extra_param());

        params
    }
}

fn deserialize_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct StringOrBoolVisitor;

    impl de::Visitor<'_> for StringOrBoolVisitor {
        type Value = bool;

        fn expecting(
            &self,
            formatter: &mut std::fmt::Formatter,
        ) -> std::fmt::Result {
            formatter.write_str(r#""true", "false", true, or false"#)
        }

        fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
            Ok(v)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            match v {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(de::Error::unknown_variant(v, &["true", "false"])),
            }
        }
    }

    deserializer.deserialize_any(StringOrBoolVisitor)
}

fn deserialize_prompt_vec<'de, D>(
    deserializer: D,
) -> Result<Vec<Prompt>, D::Error>
where
    D: de::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum PromptInput {
        List(Vec<Prompt>),
        String(Prompt),
    }

    let input = PromptInput::deserialize(deserializer)?;

    match input {
        PromptInput::List(list) => Ok(list),
        PromptInput::String(s) => s
            .to_string()
            .split(',')
            .filter(|part| !part.trim().is_empty())
            .map(|part| {
                Prompt::from_str(part.trim()).map_err(|_| {
                    serde::de::Error::custom(format!(
                        "Invalid prompt value: '{}'",
                        part.trim()
                    ))
                })
            })
            .collect(),
    }
}

// Deserializes either:
// - a space-delimited string of scopes: "read write admin"
// - an array of strings: ["read", "write", "admin"]
//
// It is an error if the resulting list is empty.
fn deserialize_scopes<'de, D>(deserializer: D) -> Result<Vec<Scope>, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct ScopesVisitor;

    impl<'de> de::Visitor<'de> for ScopesVisitor {
        type Value = Vec<Scope>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a non-empty space-separated string or a non-empty list of scopes")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let scopes: Vec<Scope> = v
                .split_whitespace()
                .map(|s| Scope::new(s.to_owned()))
                .collect();

            if scopes.is_empty() {
                return Err(E::custom(
                    "scopes string must contain at least one scope",
                ));
            }

            Ok(scopes)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut scopes = Vec::with_capacity(seq.size_hint().unwrap_or(0));

            while let Some(item) = seq.next_element::<String>()? {
                scopes.push(Scope::new(item));
            }

            if scopes.is_empty() {
                return Err(de::Error::custom(
                    "scopes array must contain at least one scope",
                ));
            }

            Ok(scopes)
        }
    }

    deserializer.deserialize_any(ScopesVisitor)
}

/// Represents optional parameters sent during the `OAuth2` authorization request.
///
/// These parameters influence the authorization server's behavior for consent prompts,
/// login hints, token refreshability, and redirect handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestAccessTokenPayload {
    /// Optional URI to which the authorization server will redirect after authorization.
    pub redirect_uri: Option<String>,

    /// User defined scopes to authorize
    #[serde(rename = "scope", deserialize_with = "deserialize_scopes")]
    pub scopes: Vec<Scope>,

    /// Additional parameters sent along with the authorization request,
    /// flattened into the top-level JSON object for convenience.
    #[serde(flatten)]
    pub extra_params: RequestAccessTokenExtraParams,
}

/// Represents configuration for an authorization request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestAccessTokenConfig {
    scopes: Vec<Scope>,

    extra_params: RequestAccessTokenExtraParams,
}

impl RequestAccessTokenConfig {
    /// User defined scopes to authorize
    pub fn scopes(&self) -> &[Scope] {
        self.scopes.as_slice()
    }

    /// Additional parameters sent along with the authorization request.
    pub fn extra_params(&self) -> &RequestAccessTokenExtraParams {
        &self.extra_params
    }
}

impl From<&RequestAccessTokenPayload> for RequestAccessTokenConfig {
    fn from(payload: &RequestAccessTokenPayload) -> Self {
        RequestAccessTokenConfig {
            scopes: payload.scopes.clone(),
            extra_params: payload.extra_params.clone(),
        }
    }
}

/// Represents the response details after constructing an `OAuth2` authorization request URL.
///
/// Contains the PKCE code verifier, CSRF token, and the constructed authorization URL
/// to which the user should be redirected.
pub struct RequestAccessTokenResponse {
    pkce_verifier: PkceCodeVerifier,
    csrf_token: CsrfToken,
    url: Url,
}

impl RequestAccessTokenResponse {
    /// Constructs a new `RequestAccessTokenResponse`.
    ///
    /// # Parameters
    /// - `pkce_verifier`: The PKCE code verifier to be used in the token exchange.
    /// - `csrf_token`: The CSRF token used for request validation.
    /// - `url`: The full authorization URL where the user should be redirected.
    pub fn new(
        pkce_verifier: PkceCodeVerifier,
        csrf_token: CsrfToken,
        url: Url,
    ) -> Self {
        RequestAccessTokenResponse {
            pkce_verifier,
            csrf_token,
            url,
        }
    }

    /// Returns a reference to the PKCE code verifier.
    pub fn pkce_verifier(&self) -> &PkceCodeVerifier {
        &self.pkce_verifier
    }

    /// Returns a reference to the CSRF token.
    pub fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }

    /// Returns a reference to the authorization URL.
    pub fn url(&self) -> &Url {
        &self.url
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Debug, Deserialize)]
    struct TokenResponse {
        #[serde(deserialize_with = "deserialize_scopes")]
        scopes: Vec<Scope>,
    }

    #[test]
    fn test_valid_string() {
        let json = json!({ "scopes": "read write" });
        let parsed: TokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(
            parsed.scopes,
            vec![Scope::new("read".into()), Scope::new("write".into())]
        );
    }

    #[test]
    fn test_valid_array() {
        let json = json!({ "scopes": ["read", "write"] });
        let parsed: TokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(
            parsed.scopes,
            vec![Scope::new("read".into()), Scope::new("write".into())]
        );
    }

    #[test]
    fn test_empty_string_should_fail() {
        let json = json!({ "scopes": "" });
        let result: Result<TokenResponse, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("at least one scope")
        );
    }

    #[test]
    fn test_empty_array_should_fail() {
        let json = json!({ "scopes": [] });
        let result: Result<TokenResponse, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("at least one scope")
        );
    }
}
