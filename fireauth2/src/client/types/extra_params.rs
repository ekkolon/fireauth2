use serde::{Deserialize, Serialize};
use std::{borrow::Cow, ops::Deref};

/// Wrapper type for extra `OAuth2` authorization request parameters.
///
/// Provides a strongly typed representation of common extra parameters
/// as well as utilities for conversion to query parameter formats.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ExtraParam(&'static str);

impl Deref for ExtraParam {
    type Target = str;

    /// Dereferences to the underlying string slice.
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl ExtraParam {
    /// Include scopes previously granted by the user.
    pub const INCLUDE_GRANTED_SCOPES: ExtraParam =
        ExtraParam("include_granted_scopes");

    /// Hint to the authorization server about the user to authenticate.
    pub const LOGIN_HINT: ExtraParam = ExtraParam("login_hint");

    /// Type of access requested (e.g., "offline" or "online").
    pub const ACCESS_TYPE: ExtraParam = ExtraParam("access_type");

    /// Specifies whether the user should be prompted for consent.
    pub const PROMPT: ExtraParam = ExtraParam("prompt");

    /// Converts the parameter name into a borrowed `Cow<str>`.
    pub fn into_cow<'a>(&self) -> Cow<'a, str> {
        Cow::Borrowed(self.0)
    }
}

/// Trait to convert a value into a single extra authorization parameter key-value pair.
pub trait IntoExtraParam<'a> {
    /// Converts **self** into an `(ExtraParam, Cow<str>)` tuple.
    fn into_extra_param(self) -> (ExtraParam, Cow<'a, str>);
}

/// Trait for types that can be converted into multiple extra authorization parameters.
pub trait ToExtraParams<'a> {
    /// Converts **self** into a vector of `(ExtraParam, Cow<str>)` pairs
    /// suitable for use as authorization query parameters.
    fn to_extra_params(&self) -> Vec<(ExtraParam, Cow<'a, str>)>;
}
