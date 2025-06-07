use std::{borrow::Cow, ops::Deref};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ExtraParam(&'static str);

impl Deref for ExtraParam {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl ExtraParam {
    pub const INCLUDE_GRANTED_SCOPES: ExtraParam = ExtraParam("include_granted_scopes");
    pub const LOGIN_HINT: ExtraParam = ExtraParam("login_hint");
    pub const ACCESS_TYPE: ExtraParam = ExtraParam("access_type");
    pub const PROMPT: ExtraParam = ExtraParam("prompt");

    pub fn into_cow<'a>(&self) -> Cow<'a, str> {
        Cow::Borrowed(self.0)
    }
}

pub trait IntoExtraParam<'a> {
    fn into_extra_param(self) -> (ExtraParam, Cow<'a, str>);
}

pub trait ToExtraParams<'a> {
    /// Converts **self** into a list of query parameters for the authorization request.
    fn to_extra_params(&self) -> Vec<(ExtraParam, Cow<'a, str>)>;
}
