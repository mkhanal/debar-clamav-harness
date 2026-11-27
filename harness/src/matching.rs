pub const MATCHING_VARIABLE: &str = "HARNESS_MATCHING";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Matching {
    #[default]
    EveryMatch,
    FirstMatch,
}

impl Matching {
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        match word {
            "every" => Some(Self::EveryMatch),
            "first" => Some(Self::FirstMatch),
            _ => None,
        }
    }

    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::EveryMatch => "every",
            Self::FirstMatch => "first",
        }
    }
}
