use std::{fmt, ops::Deref};

pub use oauth2::Scope;
use serde::{Deserialize, Serialize, de};

/// A newtype struct for the `scope` param that wraps a list of [Scopes][Scope].
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ScopeList(pub Vec<Scope>);

impl ScopeList {
    /// Creates a new `ScopeList` from a vector of `Scope` values.
    pub fn new(scopes: Vec<Scope>) -> ScopeList {
        ScopeList(scopes)
    }
}

impl Deref for ScopeList {
    type Target = Vec<Scope>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ScopeList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct ScopesVisitor;

        impl<'de> de::Visitor<'de> for ScopesVisitor {
            type Value = ScopeList; // Now returns ScopeList

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

                Ok(ScopeList(scopes)) // Wrap in ScopeList
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut scopes =
                    Vec::with_capacity(seq.size_hint().unwrap_or(0));

                while let Some(item) = seq.next_element::<String>()? {
                    scopes.push(Scope::new(item));
                }

                if scopes.is_empty() {
                    return Err(de::Error::custom(
                        "scopes array must contain at least one scope",
                    ));
                }

                Ok(ScopeList(scopes)) // Wrap in ScopeList
            }
        }

        deserializer.deserialize_any(ScopesVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Debug, Deserialize)]
    struct TokenResponse {
        scopes: ScopeList,
    }

    #[test]
    fn test_deserialize_scopes_valid_string() {
        let json = json!({ "scopes": "read write" });
        let parsed: TokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(
            parsed.scopes,
            ScopeList::new(vec![
                Scope::new("read".into()),
                Scope::new("write".into())
            ])
        );
    }

    #[test]
    fn test_deserialize_scopes_valid_array() {
        let json = json!({ "scopes": ["read", "write"] });
        let parsed: TokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(
            parsed.scopes,
            ScopeList::new(vec![
                Scope::new("read".into()),
                Scope::new("write".into())
            ])
        );
    }

    #[test]
    fn test_deserialize_scopes_empty_string_should_fail() {
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
    fn test_deserialize_scopes_empty_array_should_fail() {
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
