use std::fmt;

use harness_report::{DatabaseVersion, Sha256, Verdict};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Difference {
    pub input: Sha256,
    #[serde(flatten)]
    pub kind: DifferenceKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectPath(pub Vec<Sha256>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DifferenceKind {
    DatabasesDiffer {
        reference: Vec<DatabaseVersion>,
        debar: Vec<DatabaseVersion>,
    },
    VerdictDiffers {
        reference: Verdict,
        debar: Verdict,
    },
    ObjectOnlyInReference {
        path: ObjectPath,
        #[serde(rename = "type")]
        file_type: Option<String>,
        detections: Vec<String>,
    },
    ObjectOnlyInDebar {
        path: ObjectPath,
        #[serde(rename = "type")]
        file_type: Option<String>,
        detections: Vec<String>,
    },
    TypeDiffers {
        path: ObjectPath,
        reference: Option<String>,
        debar: Option<String>,
    },
    DepthDiffers {
        path: ObjectPath,
        reference: u32,
        debar: u32,
    },
    SizeDiffers {
        path: ObjectPath,
        reference: u64,
        debar: u64,
    },
    HashDiffers {
        path: ObjectPath,
        reference: Sha256,
        debar: Sha256,
    },
    DetectionOnlyInReference {
        path: ObjectPath,
        signature: String,
    },
    DetectionOnlyInDebar {
        path: ObjectPath,
        signature: String,
    },
    DetectionCountDiffers {
        path: ObjectPath,
        signature: String,
        reference: u32,
        debar: u32,
    },
}

impl ObjectPath {
    #[must_use]
    pub fn child(&self, content: Sha256) -> Self {
        let mut steps = self.0.clone();
        steps.push(content);
        Self(steps)
    }
}

impl fmt::Display for ObjectPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return formatter.write_str("top level");
        }
        let steps: Vec<String> = self.0.iter().map(short_hash).collect();
        formatter.write_str(&steps.join(" > "))
    }
}

const SHORT_HASH_DIGITS: usize = 12;

#[must_use]
pub fn short_hash(content: &Sha256) -> String {
    content
        .to_string()
        .chars()
        .take(SHORT_HASH_DIGITS)
        .collect()
}

fn type_name(file_type: Option<&str>) -> &str {
    file_type.unwrap_or("untyped")
}

impl fmt::Display for DifferenceKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatabasesDiffer { reference, debar } => write!(
                formatter,
                "databases differ: reference {}, Debar {}",
                database_list(reference),
                database_list(debar)
            ),
            Self::VerdictDiffers { reference, debar } => write!(
                formatter,
                "verdict differs: reference {reference}, Debar {debar}"
            ),
            Self::ObjectOnlyInReference {
                path,
                file_type,
                detections,
            } => write!(
                formatter,
                "object only in reference at {path}: {} {detections:?}",
                type_name(file_type.as_deref())
            ),
            Self::ObjectOnlyInDebar {
                path,
                file_type,
                detections,
            } => write!(
                formatter,
                "object only in Debar at {path}: {} {detections:?}",
                type_name(file_type.as_deref())
            ),
            Self::TypeDiffers {
                path,
                reference,
                debar,
            } => write!(
                formatter,
                "type differs at {path}: reference {}, Debar {}",
                type_name(reference.as_deref()),
                type_name(debar.as_deref())
            ),
            Self::DepthDiffers {
                path,
                reference,
                debar,
            } => write!(
                formatter,
                "depth differs at {path}: reference {reference}, Debar {debar}"
            ),
            Self::SizeDiffers {
                path,
                reference,
                debar,
            } => write!(
                formatter,
                "size differs at {path}: reference {reference}, Debar {debar}"
            ),
            Self::HashDiffers {
                path,
                reference,
                debar,
            } => write!(
                formatter,
                "content differs at {path}: reference {}, Debar {}",
                short_hash(reference),
                short_hash(debar)
            ),
            Self::DetectionOnlyInReference { path, signature } => write!(
                formatter,
                "detection only in reference at {path}: {signature}"
            ),
            Self::DetectionOnlyInDebar { path, signature } => {
                write!(formatter, "detection only in Debar at {path}: {signature}")
            }
            Self::DetectionCountDiffers {
                path,
                signature,
                reference,
                debar,
            } => write!(
                formatter,
                "detection reported {reference} times by the reference and {debar} by Debar at {path}: {signature}"
            ),
        }
    }
}

fn database_list(databases: &[DatabaseVersion]) -> String {
    let names: Vec<String> = databases
        .iter()
        .map(|database| format!("{} {}", database.name, database.version))
        .collect();
    names.join(", ")
}
