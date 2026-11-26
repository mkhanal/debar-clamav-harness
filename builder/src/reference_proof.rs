use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io;
use std::path::Path;

use crate::body_pattern::PatternElement;
use crate::database_files::{DatabaseKind, database_files, ignored_names, signature_lines};
use crate::input_construction::build_input;
use crate::pattern_offset::PatternOffset;
use crate::pattern_signature::{CharacterWidth, PatternSignature, SignatureForm, Subsignature};

pub const MANIFEST_FILE_NAME: &str = "manifest.tsv";
pub const INPUTS_DIRECTORY_NAME: &str = "inputs";

pub struct SampleRequest<'request> {
    pub database_directory: &'request Path,
    pub output_directory: &'request Path,
    pub extended_count: usize,
    pub logical_count: usize,
    pub seed: u64,
}

struct Candidate {
    database: String,
    line: String,
    form: SignatureForm,
    bytes: Vec<u8>,
}

pub fn write_sample(request: &SampleRequest<'_>) -> io::Result<usize> {
    let files = database_files(request.database_directory)?;
    let ignored = ignored_names(&files)?;
    let mut extended = Vec::new();
    let mut logical = Vec::new();
    for path in &files {
        let kind = DatabaseKind::of(path);
        if DatabaseKind::is_potentially_unwanted(path)
            || !matches!(kind, DatabaseKind::Extended | DatabaseKind::Logical)
        {
            continue;
        }
        let database = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        for line in signature_lines(path)? {
            let Some(Ok(signature)) = kind.parse(&line) else {
                continue;
            };
            if ignored.contains(&signature.name) {
                continue;
            }
            if let Ok(bytes) = build_input(&signature) {
                let candidate = Candidate {
                    database: database.clone(),
                    line,
                    form: signature.form,
                    bytes,
                };
                match signature.form {
                    SignatureForm::Extended => extended.push(candidate),
                    SignatureForm::Logical => logical.push(candidate),
                }
            }
        }
    }
    let mut shuffle = SeededShuffle::new(request.seed);
    shuffle.shuffle(&mut extended);
    shuffle.shuffle(&mut logical);
    extended.truncate(request.extended_count);
    logical.truncate(request.logical_count);
    let inputs = request.output_directory.join(INPUTS_DIRECTORY_NAME);
    std::fs::create_dir_all(&inputs)?;
    let mut manifest = String::new();
    for (index, candidate) in extended.iter().chain(logical.iter()).enumerate() {
        let file_name = format!(
            "{}{index:05}.bin",
            match candidate.form {
                SignatureForm::Extended => "e",
                SignatureForm::Logical => "l",
            }
        );
        std::fs::write(inputs.join(&file_name), &candidate.bytes)?;
        let _ = writeln!(
            manifest,
            "{file_name}\t{}\t{}",
            candidate.database, candidate.line
        );
    }
    std::fs::write(request.output_directory.join(MANIFEST_FILE_NAME), manifest)?;
    Ok(extended.len().saturating_add(logical.len()))
}

struct SeededShuffle {
    state: u64,
}

impl SeededShuffle {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut mixed = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        mixed ^ (mixed >> 31)
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for upper in (1..items.len()).rev() {
            let bound = u64::try_from(upper).unwrap_or(u64::MAX).saturating_add(1);
            let chosen = usize::try_from(self.next().checked_rem(bound).unwrap_or(0)).unwrap_or(0);
            items.swap(upper, chosen);
        }
    }
}

pub struct ProofResult {
    pub report: String,
    pub failures: String,
}

pub fn check_scan(manifest: &str, scan_output: &str) -> ProofResult {
    let reported = reported_detections(scan_output);
    let mut matched: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut failure_categories: BTreeMap<String, u64> = BTreeMap::new();
    let mut failures = String::new();
    let mut total: u64 = 0;
    let mut detected: u64 = 0;
    for row in manifest.lines() {
        let mut fields = row.splitn(3, '\t');
        let (Some(file_name), Some(database), Some(line)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let kind = DatabaseKind::of(Path::new(database));
        let Some(Ok(signature)) = kind.parse(line) else {
            continue;
        };
        let names = reported.get(file_name);
        let found = names.is_some_and(|names| names.contains(&signature.name));
        let group = format!(
            "{}\ttarget {}",
            form_label(signature.form),
            signature.target_code
        );
        let entry = matched.entry(group).or_insert((0, 0));
        entry.1 = entry.1.saturating_add(1);
        total = total.saturating_add(1);
        if found {
            entry.0 = entry.0.saturating_add(1);
            detected = detected.saturating_add(1);
            continue;
        }
        let others = names.map_or(0, BTreeSet::len);
        let category = format!(
            "{}\ttarget {}\t{}\t{}",
            form_label(signature.form),
            signature.target_code,
            features(&signature),
            if others > 0 {
                "other detections"
            } else {
                "nothing reported"
            }
        );
        let count = failure_categories.entry(category).or_insert(0);
        *count = count.saturating_add(1);
        let other_names = names.map_or_else(String::new, |names| {
            names.iter().cloned().collect::<Vec<_>>().join(",")
        });
        let _ = writeln!(failures, "{file_name}\t{database}\t{other_names}\t{line}");
    }
    let mut report = String::new();
    let _ = writeln!(report, "matched\t{detected} of {total}");
    for (group, (found, of)) in &matched {
        let _ = writeln!(report, "group\t{group}\t{found} of {of}");
    }
    for (category, count) in &failure_categories {
        let _ = writeln!(report, "failure\t{category}\t{count}");
    }
    ProofResult { report, failures }
}

fn reported_detections(scan_output: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut reported: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in scan_output.lines() {
        let Some(found) = line.strip_suffix(" FOUND") else {
            continue;
        };
        let Some((path, name)) = found.rsplit_once(": ") else {
            continue;
        };
        let file_name = Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(path)
            .to_owned();
        reported
            .entry(file_name)
            .or_default()
            .insert(name.to_owned());
    }
    reported
}

fn form_label(form: SignatureForm) -> &'static str {
    match form {
        SignatureForm::Extended => "extended",
        SignatureForm::Logical => "logical",
    }
}

fn features(signature: &PatternSignature) -> String {
    let mut features = BTreeSet::new();
    for subsignature in &signature.subsignatures {
        let Subsignature::Body(body) = subsignature else {
            continue;
        };
        features.insert(match body.offset {
            PatternOffset::Anywhere => "anywhere",
            PatternOffset::FromStart { .. } => "from-start",
            PatternOffset::BeforeEnd { .. } => "before-end",
            PatternOffset::ExecutableAnchor(_) | PatternOffset::VersionInfo => "executable",
        });
        for element in &body.pattern.elements {
            features.insert(match element {
                PatternElement::Literal(_) => continue,
                PatternElement::PartialByte(_) => "half-byte",
                PatternElement::AnyByte => "any-byte",
                PatternElement::Gap(_) => "gap",
                PatternElement::Alternatives(alternatives) if alternatives.negated => "negated",
                PatternElement::Alternatives(_) => "alternatives",
                PatternElement::CharacterClass(_) => "class",
            });
        }
        let modifiers = body.modifiers;
        for (present, name) in [
            (modifiers.ignores_case(), "nocase"),
            (modifiers.width == CharacterWidth::Wide, "wide"),
            (
                modifiers.width == CharacterWidth::NarrowOrWide,
                "narrow-or-wide",
            ),
            (modifiers.matches_whole_words(), "fullword"),
        ] {
            if present {
                features.insert(name);
            }
        }
    }
    if signature.conditions.file_size.is_some() {
        features.insert("file-size");
    }
    features.into_iter().collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_gives_the_same_order() {
        let mut first: Vec<u32> = (0..50).collect();
        let mut second = first.clone();
        SeededShuffle::new(7).shuffle(&mut first);
        SeededShuffle::new(7).shuffle(&mut second);
        assert_eq!(first, second);
        assert_ne!(first, (0..50).collect::<Vec<u32>>());
    }

    #[test]
    fn a_scan_report_is_checked_for_the_intended_signature() {
        let manifest = "e00000.bin\tmain.ndb\tWanted-1:0:*:41424344\ne00001.bin\tmain.ndb\tMissed-1:0:*:45464748\n";
        let scan = "/inputs/e00000.bin: Wanted-1 FOUND\n/inputs/e00000.bin: Other-2 FOUND\n/inputs/e00001.bin: Other-3 FOUND\n";
        let result = check_scan(manifest, scan);
        assert!(result.report.starts_with("matched\t1 of 2\n"));
        assert!(
            result
                .failures
                .contains("e00001.bin\tmain.ndb\tOther-3\tMissed-1")
        );
        assert!(result.report.contains("other detections"));
    }
}
