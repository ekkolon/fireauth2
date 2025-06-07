use std::{borrow::Cow, fmt, str::FromStr};

use oauth2::{CsrfToken, PkceCodeVerifier};
use serde::{Deserialize, Serialize, de};
use url::Url;

use super::extra_params::{ExtraParam, IntoExtraParam, ToExtraParams};

/// Indicates whether your application can refresh access tokens
/// when the user is not present at the browser.
///
/// Valid parameter values are `online`, which is the default value, and `offline`.
///
/// Set the value to [GoogleOAuthAccessType::Offline] if your application needs
/// to refresh access tokens when the user is not present at the browser.
/// This is the method of refreshing access tokens described later in this document.
/// This value instructs the Google authorization server to return a refresh token
/// and an access token the first time  that your application exchanges an authorization
/// code for tokens.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AccessType {
    #[default]
    Online,
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

/// Represents optional parameters sent during the OAuth2 authorization request.
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

    impl<'de> de::Visitor<'de> for StringOrBoolVisitor {
        type Value = bool;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
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

pub(in crate::client) fn deserialize_prompt_vec<'de, D>(
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
                    serde::de::Error::custom(format!("Invalid prompt value: '{}'", part.trim()))
                })
            })
            .collect(),
    }
}

pub struct RequestAccessTokenResponse {
    pkce_verifier: PkceCodeVerifier,
    csrf_token: CsrfToken,
    url: Url,
}

impl RequestAccessTokenResponse {
    pub fn new(pkce_verifier: PkceCodeVerifier, csrf_token: CsrfToken, url: Url) -> Self {
        RequestAccessTokenResponse {
            pkce_verifier,
            csrf_token,
            url,
        }
    }

    pub fn pkce_verifier(&self) -> &PkceCodeVerifier {
        &self.pkce_verifier
    }

    pub fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }

    pub fn url(&self) -> &Url {
        &self.url
    }
}
