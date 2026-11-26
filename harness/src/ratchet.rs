use std::collections::BTreeSet;
use std::fmt;
use std::io::BufRead;

use harness_report::Sha256;

use crate::difference::Difference;

#[derive(Debug, Default)]
pub struct KnownDifferences {
    entries: Vec<Difference>,
}

#[derive(Debug, Default)]
pub struct Judgement {
    pub new: Vec<Difference>,
    pub known: Vec<Difference>,
    pub no_longer_occurring: Vec<Difference>,
}

#[derive(Debug)]
pub enum KnownDifferencesError {
    Io(std::io::Error),
    Malformed { line: usize, reason: String },
}

impl KnownDifferences {
    pub fn read(input: impl BufRead) -> Result<Self, KnownDifferencesError> {
        let mut entries = Vec::new();
        for (line, text) in (1..).zip(input.lines()) {
            let text = text.map_err(KnownDifferencesError::Io)?;
            if text.trim().is_empty() {
                continue;
            }
            let entry =
                serde_json::from_str(&text).map_err(|error| KnownDifferencesError::Malformed {
                    line,
                    reason: error.to_string(),
                })?;
            entries.push(entry);
        }
        Ok(Self { entries })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn judge(
        &self,
        inputs_compared: &BTreeSet<Sha256>,
        differences: Vec<Difference>,
    ) -> Judgement {
        let mut unused: Vec<Option<&Difference>> = self
            .entries
            .iter()
            .filter(|entry| inputs_compared.contains(&entry.input))
            .map(Some)
            .collect();
        let mut judgement = Judgement::default();
        for difference in differences {
            let entry = unused
                .iter_mut()
                .find(|entry| entry.is_some_and(|known| known == &difference));
            match entry {
                Some(used) => {
                    *used = None;
                    judgement.known.push(difference);
                }
                None => judgement.new.push(difference),
            }
        }
        judgement.no_longer_occurring = unused.into_iter().flatten().cloned().collect();
        judgement
    }
}

impl Judgement {
    #[must_use]
    pub fn fails(&self) -> bool {
        !self.new.is_empty()
    }
}

impl fmt::Display for KnownDifferencesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "cannot read the known differences: {error}"),
            Self::Malformed { line, reason } => write!(
                formatter,
                "line {line} of the known differences is not a difference: {reason}"
            ),
        }
    }
}

impl std::error::Error for KnownDifferencesError {}
