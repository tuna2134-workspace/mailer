#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

const MAX_KEYWORD_BYTES: usize = 255;
const MAX_KEYWORDS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum SystemFlag {
    Answered,
    Deleted,
    Draft,
    Flagged,
    Seen,
}

impl SystemFlag {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Answered => "\\Answered",
            Self::Deleted => "\\Deleted",
            Self::Draft => "\\Draft",
            Self::Flagged => "\\Flagged",
            Self::Seen => "\\Seen",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum FlagError {
    #[error("invalid keyword")]
    InvalidKeyword,
    #[error("too many keywords")]
    TooManyKeywords,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FlagSet {
    pub system: BTreeSet<SystemFlag>,
    pub keywords: BTreeSet<String>,
}

impl FlagSet {
    pub fn new(
        system: impl IntoIterator<Item = SystemFlag>,
        keywords: impl IntoIterator<Item = String>,
    ) -> Result<Self, FlagError> {
        let keywords: BTreeSet<_> = keywords.into_iter().collect();
        if keywords.len() > MAX_KEYWORDS {
            return Err(FlagError::TooManyKeywords);
        }
        if keywords.iter().any(|keyword| !valid_keyword(keyword)) {
            return Err(FlagError::InvalidKeyword);
        }
        Ok(Self {
            system: system.into_iter().collect(),
            keywords,
        })
    }

    #[must_use]
    pub fn system_names(&self) -> Vec<String> {
        self.system
            .iter()
            .map(|flag| flag.as_str().into())
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreMode {
    Replace,
    Add,
    Remove,
}

#[must_use]
pub fn valid_keyword(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_KEYWORD_BYTES
        && value.bytes().all(|byte| {
            (0x21..=0x7e).contains(&byte)
                && !matches!(
                    byte,
                    b'(' | b')' | b'{' | b' ' | b'%' | b'*' | b'"' | b'\\' | b']'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_are_canonical_and_keywords_are_bounded() -> Result<(), FlagError> {
        let flags = FlagSet::new(
            [SystemFlag::Seen, SystemFlag::Answered],
            ["project-x".to_owned(), "project-x".to_owned()],
        )?;
        assert_eq!(flags.system_names(), ["\\Answered", "\\Seen"]);
        assert_eq!(flags.keywords.len(), 1);
        assert!(!valid_keyword("bad keyword"));
        assert!(!valid_keyword("\\Seen"));
        Ok(())
    }
}
