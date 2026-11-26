mod error;
mod record;
mod sha256;

use std::collections::BTreeMap;
use std::fmt;
use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};

pub use error::ReportError;
pub use sha256::{NotLowercaseHexSha256, Sha256};

pub const SCHEMA_VERSION: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    NothingFound,
    Trusted,
    StrongIndicator,
    PotentiallyUnwanted,
}

impl fmt::Display for Verdict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NothingFound => "nothing_found",
            Self::Trusted => "trusted",
            Self::StrongIndicator => "strong_indicator",
            Self::PotentiallyUnwanted => "potentially_unwanted",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scanner {
    pub name: String,
    pub version: String,
    pub databases: Vec<DatabaseVersion>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseVersion {
    pub name: String,
    pub version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    pub id: ObjectId,
    pub parent: Option<ObjectId>,
    pub depth: u32,
    pub file_type: Option<String>,
    pub size: u64,
    pub sha256: Sha256,
    pub detections: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    scanner: Scanner,
    verdict: Verdict,
    top_level: Object,
    descendants: Vec<Object>,
}

impl Report {
    pub fn from_parts(
        scanner: Scanner,
        verdict: Verdict,
        objects: Vec<Object>,
    ) -> Result<Self, ReportError> {
        let mut objects = objects.into_iter();
        let top_level = objects.next().ok_or(ReportError::NoTopLevelObject)?;
        let descendants: Vec<Object> = objects.collect();
        check_object_tree(&top_level, &descendants)?;
        Ok(Self {
            scanner,
            verdict,
            top_level,
            descendants,
        })
    }

    pub fn read(input: impl BufRead) -> Result<Self, ReportError> {
        let records = record::read_lines(input)?;
        let (scanner, verdict) = record::top_level_facts(&records)?;
        Self::from_parts(
            scanner,
            verdict,
            records
                .into_iter()
                .map(record::Record::into_object)
                .collect(),
        )
    }

    pub fn write(&self, output: impl Write) -> Result<(), ReportError> {
        record::write_lines(output, &self.scanner, self.verdict, self.objects())
    }

    #[must_use]
    pub fn scanner(&self) -> &Scanner {
        &self.scanner
    }

    #[must_use]
    pub fn verdict(&self) -> Verdict {
        self.verdict
    }

    #[must_use]
    pub fn top_level(&self) -> &Object {
        &self.top_level
    }

    pub fn objects(&self) -> impl Iterator<Item = &Object> {
        std::iter::once(&self.top_level).chain(&self.descendants)
    }

    #[must_use]
    pub fn children_of(&self, parent: ObjectId) -> Vec<&Object> {
        self.descendants
            .iter()
            .filter(|object| object.parent == Some(parent))
            .collect()
    }
}

fn check_object_tree(top_level: &Object, descendants: &[Object]) -> Result<(), ReportError> {
    if top_level.parent.is_some() {
        return Err(ReportError::FirstRecordIsNotTopLevel);
    }
    if top_level.depth != 0 {
        return Err(ReportError::TopLevelNotAtDepthZero);
    }
    let mut depth_by_id = BTreeMap::from([(top_level.id, top_level.depth)]);
    for (line, child) in (2..).zip(descendants) {
        let Some(parent) = child.parent else {
            return Err(ReportError::SecondTopLevelObject { line });
        };
        let Some(&parent_depth) = depth_by_id.get(&parent) else {
            return Err(ReportError::UnknownParent { line, parent });
        };
        if child.depth <= parent_depth {
            return Err(ReportError::NotDeeperThanParent { line });
        }
        if depth_by_id.insert(child.id, child.depth).is_some() {
            return Err(ReportError::DuplicateId { line, id: child.id });
        }
    }
    Ok(())
}
