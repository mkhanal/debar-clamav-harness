use std::collections::BTreeSet;
use std::fmt;
use std::io::BufRead;

use harness_report::Sha256;
use serde_json::{Map, Value};

use crate::difference::Difference;

const INPUT_FIELD: &str = "input";
const GAP_FIELD: &str = "gap";

#[derive(Debug, Default)]
pub struct KnownDifferences {
    entries: Vec<Difference>,
    rules: Vec<KnownRule>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownRule {
    fields: Map<String, Value>,
}

impl KnownRule {
    fn covers(&self, difference: &Difference) -> bool {
        let Ok(Value::Object(fields)) = serde_json::to_value(difference) else {
            return false;
        };
        self.fields
            .iter()
            .all(|(name, value)| fields.get(name) == Some(value))
    }
}

impl fmt::Display for KnownRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", Value::Object(self.fields.clone()))
    }
}

#[derive(Debug, Default)]
pub struct Judgement {
    pub new: Vec<Difference>,
    pub known: Vec<Difference>,
    pub no_longer_occurring: Vec<Difference>,
    pub rules_not_used: Vec<KnownRule>,
}

#[derive(Debug)]
pub enum KnownDifferencesError {
    Io(std::io::Error),
    Malformed { line: usize, reason: String },
}

impl KnownDifferences {
    pub fn read(input: impl BufRead) -> Result<Self, KnownDifferencesError> {
        let mut entries = Vec::new();
        let mut rules = Vec::new();
        for (line, text) in (1..).zip(input.lines()) {
            let text = text.map_err(KnownDifferencesError::Io)?;
            if text.trim().is_empty() {
                continue;
            }
            let malformed = |reason: String| KnownDifferencesError::Malformed { line, reason };
            let mut fields: Map<String, Value> =
                serde_json::from_str(&text).map_err(|error| malformed(error.to_string()))?;
            match fields.remove(GAP_FIELD) {
                None | Some(Value::String(_)) => {}
                Some(_) => {
                    return Err(malformed(
                        "the gap a line names is a sentence of text".to_owned(),
                    ));
                }
            }
            if fields.contains_key(INPUT_FIELD) {
                let entry = serde_json::from_value(Value::Object(fields))
                    .map_err(|error| malformed(error.to_string()))?;
                entries.push(entry);
            } else if fields.contains_key("kind") {
                rules.push(KnownRule { fields });
            } else {
                return Err(malformed(
                    "a line without an input is a rule, and names at least the kind".to_owned(),
                ));
            }
        }
        Ok(Self { entries, rules })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len().saturating_add(self.rules.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.rules.is_empty()
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
        let mut rule_used = vec![false; self.rules.len()];
        let mut judgement = Judgement::default();
        for difference in differences {
            let entry = unused
                .iter_mut()
                .find(|entry| entry.is_some_and(|known| known == &difference));
            if let Some(used) = entry {
                *used = None;
                judgement.known.push(difference);
                continue;
            }
            let rule = self.rules.iter().position(|rule| rule.covers(&difference));
            match rule.and_then(|index| rule_used.get_mut(index)) {
                Some(used) => {
                    *used = true;
                    judgement.known.push(difference);
                }
                None => judgement.new.push(difference),
            }
        }
        judgement.no_longer_occurring = unused.into_iter().flatten().cloned().collect();
        judgement.rules_not_used = self
            .rules
            .iter()
            .zip(rule_used)
            .filter(|(_, used)| !used)
            .map(|(rule, _)| rule.clone())
            .collect();
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
