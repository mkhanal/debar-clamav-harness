use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io;
use std::path::Path;

use crate::database_files::{DatabaseKind, database_files, ignored_names, signature_lines};
use crate::input_construction::build_input;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SurveyOutcome {
    Built,
    NotBuilt(String),
    IgnoredByList,
    HashCheckedByLookup,
    ContainerMetadataNeedsArchive,
    Unreadable,
}

impl SurveyOutcome {
    fn label(&self) -> String {
        match self {
            Self::Built => "built".to_owned(),
            Self::NotBuilt(reason) => format!("not built: {reason}"),
            Self::IgnoredByList => "not built: ignored by .ign/.ign2".to_owned(),
            Self::HashCheckedByLookup => "not built: hash, checked by lookup".to_owned(),
            Self::ContainerMetadataNeedsArchive => {
                "not built: container metadata, needs archive container".to_owned()
            }
            Self::Unreadable => "not built: unreadable signature".to_owned(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Survey {
    pub per_database: BTreeMap<String, BTreeMap<SurveyOutcome, u64>>,
    pub not_built_signatures: Vec<NotBuiltSignature>,
}

#[derive(Debug)]
pub struct NotBuiltSignature {
    pub database: String,
    pub line: String,
    pub outcome: SurveyOutcome,
}

pub fn survey_directory(directory: &Path) -> io::Result<Survey> {
    let files = database_files(directory)?;
    let ignored = ignored_names(&files)?;
    let mut survey = Survey::default();
    for path in &files {
        let kind = DatabaseKind::of(path);
        if matches!(
            kind,
            DatabaseKind::IgnoreList | DatabaseKind::NotADetectionSignature
        ) {
            continue;
        }
        let label = path
            .strip_prefix(directory)
            .unwrap_or(path)
            .display()
            .to_string();
        let outcomes = survey.per_database.entry(label.clone()).or_default();
        for line in signature_lines(path)? {
            let outcome = survey_line(kind, &line, &ignored);
            let count = outcomes.entry(outcome.clone()).or_insert(0);
            *count = count.saturating_add(1);
            if matches!(
                outcome,
                SurveyOutcome::NotBuilt(_)
                    | SurveyOutcome::Unreadable
                    | SurveyOutcome::IgnoredByList
            ) {
                survey.not_built_signatures.push(NotBuiltSignature {
                    database: label.clone(),
                    line,
                    outcome,
                });
            }
        }
    }
    Ok(survey)
}

fn survey_line(kind: DatabaseKind, line: &str, ignored: &BTreeSet<String>) -> SurveyOutcome {
    match kind {
        DatabaseKind::Hash => return SurveyOutcome::HashCheckedByLookup,
        DatabaseKind::ContainerMetadata => return SurveyOutcome::ContainerMetadataNeedsArchive,
        DatabaseKind::Extended
        | DatabaseKind::Logical
        | DatabaseKind::IgnoreList
        | DatabaseKind::NotADetectionSignature => {}
    }
    if line
        .split([':', ';'])
        .next()
        .is_some_and(|name| ignored.contains(name))
    {
        return SurveyOutcome::IgnoredByList;
    }
    let Some(Ok(signature)) = kind.parse(line) else {
        return SurveyOutcome::Unreadable;
    };
    match build_input(&signature) {
        Ok(_) => SurveyOutcome::Built,
        Err(reason) => SurveyOutcome::NotBuilt(reason.to_string()),
    }
}

impl Survey {
    #[must_use]
    pub fn report(&self) -> String {
        let mut report = String::new();
        let mut totals: BTreeMap<String, u64> = BTreeMap::new();
        let mut built: u64 = 0;
        let mut all: u64 = 0;
        for (database, outcomes) in &self.per_database {
            for (outcome, count) in outcomes {
                let label = outcome.label();
                let _ = writeln!(report, "{database}\t{label}\t{count}");
                let total = totals.entry(label).or_insert(0);
                *total = total.saturating_add(*count);
                all = all.saturating_add(*count);
                if *outcome == SurveyOutcome::Built {
                    built = built.saturating_add(*count);
                }
            }
        }
        let mut ordered: Vec<(&String, &u64)> = totals.iter().collect();
        ordered.sort_by(|left, right| right.1.cmp(left.1).then(left.0.cmp(right.0)));
        for (label, count) in ordered {
            let _ = writeln!(report, "TOTAL\t{label}\t{count}");
        }
        let _ = writeln!(report, "TOTAL\tbuilt of all signatures\t{built} of {all}");
        report
    }

    #[must_use]
    pub fn not_built_details(&self) -> String {
        let mut details = String::new();
        for signature in &self.not_built_signatures {
            let _ = writeln!(
                details,
                "{}\t{}\t{}",
                signature.database,
                signature.outcome.label(),
                signature.line
            );
        }
        details
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_line_gets_one_outcome() {
        let ignored = BTreeSet::from(["Ignored-1".to_owned()]);
        assert_eq!(
            survey_line(DatabaseKind::Extended, "A:0:*:41424344", &ignored),
            SurveyOutcome::Built
        );
        assert_eq!(
            survey_line(DatabaseKind::Extended, "Ignored-1:0:*:41424344", &ignored),
            SurveyOutcome::IgnoredByList
        );
        assert_eq!(
            survey_line(DatabaseKind::Extended, "A:1:*:41424344", &ignored),
            SurveyOutcome::NotBuilt("needs PE container".to_owned())
        );
        assert_eq!(
            survey_line(DatabaseKind::Hash, "00:1:x", &ignored),
            SurveyOutcome::HashCheckedByLookup
        );
        assert_eq!(
            survey_line(DatabaseKind::Logical, "broken", &ignored),
            SurveyOutcome::Unreadable
        );
    }
}
