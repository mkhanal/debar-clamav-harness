use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use crate::pattern_signature::{PatternSignature, SignatureError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DatabaseKind {
    Extended,
    Logical,
    Hash,
    ContainerMetadata,
    IgnoreList,
    NotADetectionSignature,
}

impl DatabaseKind {
    #[must_use]
    pub fn of(path: &Path) -> Self {
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default();
        match extension {
            "ndb" | "ndu" => Self::Extended,
            "ldb" | "ldu" => Self::Logical,
            "hdb" | "hsb" | "hdu" | "hsu" | "mdb" | "msb" | "mdu" | "msu" => Self::Hash,
            "cdb" => Self::ContainerMetadata,
            "ign" | "ign2" => Self::IgnoreList,
            _ => Self::NotADetectionSignature,
        }
    }

    #[must_use]
    pub fn is_potentially_unwanted(path: &Path) -> bool {
        path.extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.ends_with('u'))
    }

    #[must_use]
    pub fn parse(self, line: &str) -> Option<Result<PatternSignature, SignatureError>> {
        match self {
            Self::Extended => Some(PatternSignature::parse_extended(line)),
            Self::Logical => Some(PatternSignature::parse_logical(line)),
            Self::Hash
            | Self::ContainerMetadata
            | Self::IgnoreList
            | Self::NotADetectionSignature => None,
        }
    }
}

pub fn database_files(directory: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

pub fn signature_lines(path: &Path) -> io::Result<Vec<String>> {
    let bytes = std::fs::read(path)?;
    Ok(String::from_utf8_lossy(&bytes)
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect())
}

pub fn ignored_names(files: &[PathBuf]) -> io::Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for path in files {
        if DatabaseKind::of(path) == DatabaseKind::IgnoreList {
            names.extend(signature_lines(path)?.iter().map(|line| ignored_name(line)));
        }
    }
    Ok(names)
}

fn ignored_name(line: &str) -> String {
    let fields: Vec<&str> = line.split(':').collect();
    match fields.as_slice() {
        [_, _, name] | [name, ..] => (*name).to_owned(),
        [] => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_kind_follows_the_extension() {
        assert_eq!(
            DatabaseKind::of(Path::new("a/main.ndb")),
            DatabaseKind::Extended
        );
        assert_eq!(
            DatabaseKind::of(Path::new("daily.ldu")),
            DatabaseKind::Logical
        );
        assert_eq!(DatabaseKind::of(Path::new("main.mdb")), DatabaseKind::Hash);
        assert_eq!(
            DatabaseKind::of(Path::new("daily.ign2")),
            DatabaseKind::IgnoreList
        );
        assert_eq!(
            DatabaseKind::of(Path::new("daily.ftm")),
            DatabaseKind::NotADetectionSignature
        );
        assert!(DatabaseKind::is_potentially_unwanted(Path::new(
            "daily.ndu"
        )));
        assert!(!DatabaseKind::is_potentially_unwanted(Path::new(
            "daily.ndb"
        )));
    }

    #[test]
    fn an_ignore_line_names_its_signature_in_any_of_its_forms() {
        assert_eq!(ignored_name("Win.Test-1"), "Win.Test-1");
        assert_eq!(ignored_name("Win.Test-1:0123abcd"), "Win.Test-1");
        assert_eq!(ignored_name("db:12:Win.Test-1"), "Win.Test-1");
    }
}
