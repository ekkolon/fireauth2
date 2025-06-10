use std::{borrow::Cow, fmt, str::FromStr};

use serde::{Deserialize, Serialize, de};

use super::extra_param::{ExtraParam, IntoExtraParam};

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

impl<'a> IntoExtraParam<'a> for PromptList {
    // Changed to PromptList
    fn into_extra_param(self) -> (ExtraParam, Cow<'a, str>) {
        let joined = self
            .0 // Access the inner Vec
            .into_iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(" ");

        (ExtraParam::PROMPT, Cow::Owned(joined))
    }
}

/// A newtype struct for the `prompt` extra param that wraps a list of [Prompts][Prompt].
#[derive(Debug, Clone)]
pub struct PromptList(pub Vec<Prompt>);

impl Default for PromptList {
    fn default() -> Self {
        PromptList(vec![Prompt::None])
    }
}

impl<'de> Deserialize<'de> for PromptList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum PromptInput {
            List(Vec<Prompt>),
            String(String),
        }

        let input = PromptInput::deserialize(deserializer)?;

        match input {
            PromptInput::List(list) => Ok(PromptList(list)), // Wrap in newtype
            PromptInput::String(s) => {
                let prompts = s
                    .split(',')
                    .filter(|part| !part.trim().is_empty())
                    .map(|part| {
                        Prompt::from_str(part.trim()).map_err(|_| {
                            de::Error::custom(format!(
                                "Invalid prompt value: '{}'",
                                part.trim()
                            ))
                        })
                    })
                    .collect::<Result<Vec<Prompt>, _>>()?;

                Ok(PromptList(prompts))
            }
        }
    }
}

impl Serialize for PromptList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as a space-separated string or a list, depending on your needs.
        // For simplicity, let's serialize as a space-separated string if there's more than one,
        // otherwise as a single string.
        if self.0.len() > 1 {
            let joined = self
                .0
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            serializer.serialize_str(&joined)
        } else if let Some(prompt) = self.0.first() {
            serializer.serialize_str(&prompt.to_string())
        } else {
            serializer.serialize_str("")
        }
    }
}
