use std::fmt;

use crate::ObjectId;

#[derive(Debug)]
pub enum ReportError {
    Io(std::io::Error),
    Malformed { line: usize, reason: String },
    UnsupportedSchema { line: usize, schema: u64 },
    NoTopLevelObject,
    FirstRecordIsNotTopLevel,
    TopLevelNotAtDepthZero,
    TopLevelWithoutVerdict,
    SecondTopLevelObject { line: usize },
    VerdictOnChild { line: usize },
    UnknownParent { line: usize, parent: ObjectId },
    DuplicateId { line: usize, id: ObjectId },
    NotDeeperThanParent { line: usize },
}

impl fmt::Display for ReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "cannot read or write the report: {error}"),
            Self::Malformed { line, reason } => {
                write!(formatter, "line {line} is not a valid record: {reason}")
            }
            Self::UnsupportedSchema { line, schema } => write!(
                formatter,
                "line {line} follows schema {schema}; this reader knows schema {}",
                crate::SCHEMA_VERSION
            ),
            Self::NoTopLevelObject => formatter.write_str("the report holds no record"),
            Self::FirstRecordIsNotTopLevel => formatter
                .write_str("the first record has a parent; it must be the top-level object"),
            Self::TopLevelNotAtDepthZero => {
                formatter.write_str("the top-level object is not at depth 0")
            }
            Self::TopLevelWithoutVerdict => {
                formatter.write_str("the top-level object has no verdict or no scanner")
            }
            Self::SecondTopLevelObject { line } => {
                write!(
                    formatter,
                    "line {line} has no parent, but only the first record may be top-level"
                )
            }
            Self::VerdictOnChild { line } => write!(
                formatter,
                "line {line} carries a verdict or scanner, which only the top-level object may"
            ),
            Self::UnknownParent { line, parent } => write!(
                formatter,
                "line {line} names parent {}, which no earlier record has as its id",
                parent.0
            ),
            Self::DuplicateId { line, id } => {
                write!(formatter, "line {line} repeats the id {}", id.0)
            }
            Self::NotDeeperThanParent { line } => {
                write!(formatter, "line {line} is not deeper than its parent")
            }
        }
    }
}

impl std::error::Error for ReportError {}

impl From<std::io::Error> for ReportError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
