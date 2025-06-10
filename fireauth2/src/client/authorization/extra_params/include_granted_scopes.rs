use std::borrow::Cow;
use std::ops::Deref;

use serde::de::{Deserializer, Visitor};
use serde::{Deserialize, Serialize};

use super::extra_param::{ExtraParam, IntoExtraParam};

/// A newtype struct for the `include_granted_scope` extra param.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IncludeGrantedScopes(bool);

impl Deref for IncludeGrantedScopes {
    type Target = bool;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for IncludeGrantedScopes {
    fn default() -> Self {
        IncludeGrantedScopes(true)
    }
}

impl<'de> Deserialize<'de> for IncludeGrantedScopes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringOrBoolVisitor;

        impl Visitor<'_> for StringOrBoolVisitor {
            type Value = IncludeGrantedScopes;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str(r#""true", "false", true, or false"#)
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
                Ok(IncludeGrantedScopes(v))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match v {
                    "true" => Ok(IncludeGrantedScopes(true)),
                    "false" => Ok(IncludeGrantedScopes(false)),
                    _ => Err(serde::de::Error::unknown_variant(
                        v,
                        &["true", "false"],
                    )),
                }
            }
        }

        deserializer.deserialize_any(StringOrBoolVisitor)
    }
}

impl<'a> IntoExtraParam<'a> for IncludeGrantedScopes {
    fn into_extra_param(self) -> (ExtraParam, Cow<'a, str>) {
        (
            ExtraParam::INCLUDE_GRANTED_SCOPES,
            Cow::Owned(self.0.to_string()),
        )
    }
}
