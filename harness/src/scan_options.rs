use std::fmt;

pub const SCAN_OPTIONS_VARIABLE: &str = "HARNESS_SCAN_OPTIONS";

const OPTIONS_WITH_A_NUMBER: [&str; 4] = [
    "--max-files",
    "--max-scan-size",
    "--max-file-size",
    "--max-recursion",
];
const RAW_ONLY: &str = "--raw-only";
const ALERT_EXCEEDS_MAX: &str = "--alert-exceeds-max";
const OPTIONS_ALONE: [&str; 2] = [RAW_ONLY, ALERT_EXCEEDS_MAX];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanOptions {
    words: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ScanOptionsError {
    Unknown { option: String },
    NeedsANumber { option: String },
    RawOnlyRaisesNoAlerts,
}

impl ScanOptions {
    pub fn parse(text: &str) -> Result<Self, ScanOptionsError> {
        let mut words = Vec::new();
        let mut remaining = text.split_whitespace();
        while let Some(option) = remaining.next() {
            if OPTIONS_ALONE.contains(&option) {
                words.push(option.to_owned());
            } else if OPTIONS_WITH_A_NUMBER.contains(&option) {
                let number = remaining
                    .next()
                    .filter(|value| value.parse::<u64>().is_ok())
                    .ok_or_else(|| ScanOptionsError::NeedsANumber {
                        option: option.to_owned(),
                    })?;
                words.push(option.to_owned());
                words.push(number.to_owned());
            } else {
                return Err(ScanOptionsError::Unknown {
                    option: option.to_owned(),
                });
            }
        }
        if words.iter().any(|word| word == RAW_ONLY)
            && words.iter().any(|word| word == ALERT_EXCEEDS_MAX)
        {
            return Err(ScanOptionsError::RawOnlyRaisesNoAlerts);
        }
        Ok(Self { words })
    }

    #[must_use]
    pub fn words(&self) -> &[String] {
        &self.words
    }

    #[must_use]
    pub fn as_text(&self) -> String {
        self.words.join(" ")
    }
}

impl fmt::Display for ScanOptionsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown { option } => write!(
                formatter,
                "unknown scan option {option}: the scan options are {} with a number, and {}",
                OPTIONS_WITH_A_NUMBER.join(", "),
                OPTIONS_ALONE.join(", ")
            ),
            Self::NeedsANumber { option } => {
                write!(formatter, "the scan option {option} needs a number")
            }
            Self::RawOnlyRaisesNoAlerts => write!(
                formatter,
                "{RAW_ONLY} cannot be given with {ALERT_EXCEEDS_MAX}: a raw-only scan raises no heuristic alert"
            ),
        }
    }
}

impl std::error::Error for ScanOptionsError {}
