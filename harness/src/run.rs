use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};

use harness_report::{Report, ReportError, Sha256};

use crate::comparison::{DifferentInputs, compare, compare_first_match, every_detection};
use crate::debar_command::{DebarCommand, DebarCommandError};
use crate::difference::Difference;
use crate::inputs::{Inputs, InputsError};
use crate::matching::Matching;
use crate::observer::{Observer, ObserverError};
use crate::ratchet::{Judgement, KnownDifferences};
use crate::scan_options::ScanOptions;

pub struct RunSettings {
    pub input: PathBuf,
    pub debar_command: DebarCommand,
    pub observer: Observer,
    pub matching: Matching,
    pub scan_options: ScanOptions,
    pub known_differences: KnownDifferences,
    pub work_directory: PathBuf,
    pub manifest: Option<PathBuf>,
}

pub struct ComparedInput {
    pub name: String,
    pub input: Sha256,
    pub differences: Vec<Difference>,
    pub reference_detections: BTreeSet<String>,
    pub debar_detections: BTreeSet<String>,
}

pub struct Outcome {
    pub compared: Vec<ComparedInput>,
    pub judgement: Judgement,
    pub built_inputs: Option<BuiltInputs>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct BuiltInputs {
    pub inputs: usize,
    pub detected_by_reference: usize,
    pub detected_by_both: usize,
    pub detected_by_debar_only: usize,
}

#[derive(Debug)]
pub enum RunError {
    Inputs(InputsError),
    WorkDirectory {
        path: PathBuf,
        error: io::Error,
    },
    Observer(ObserverError),
    DebarCommand(DebarCommandError),
    Report {
        path: PathBuf,
        error: ReportError,
    },
    Manifest {
        path: PathBuf,
        error: io::Error,
    },
    DifferentInputs {
        name: String,
        error: DifferentInputs,
    },
}

struct WorkDirectory {
    databases: PathBuf,
    reference: PathBuf,
    reference_every_match: PathBuf,
    debar: PathBuf,
}

pub fn run(settings: &RunSettings) -> Result<Outcome, RunError> {
    let built_for = match &settings.manifest {
        Some(path) => Some(read_manifest(path)?),
        None => None,
    };
    let inputs = Inputs::find(&settings.input).map_err(RunError::Inputs)?;
    let work = WorkDirectory::prepare(&settings.work_directory)?;
    settings
        .observer
        .copy_databases(&work.databases)
        .map_err(RunError::Observer)?;
    let reference_reports = settings
        .observer
        .observe(
            &inputs,
            &work.reference,
            settings.matching,
            &settings.scan_options,
        )
        .map_err(RunError::Observer)?;
    let reference_every_match_reports = match settings.matching {
        Matching::EveryMatch => None,
        Matching::FirstMatch => Some(
            settings
                .observer
                .observe(
                    &inputs,
                    &work.reference_every_match,
                    Matching::EveryMatch,
                    &settings.scan_options,
                )
                .map_err(RunError::Observer)?,
        ),
    };
    let mut compared = Vec::new();
    for ((index, relative), reference_report) in inputs
        .relative_paths()
        .iter()
        .enumerate()
        .zip(&reference_reports)
    {
        let reference_every_match = reference_every_match_reports
            .as_ref()
            .and_then(|reports| reports.get(index));
        let debar_report = work.debar.join(format!("{index}.jsonl"));
        settings
            .debar_command
            .run(
                &inputs.root().join(relative),
                &work.databases,
                &debar_report,
                settings.matching,
                &settings.scan_options,
            )
            .map_err(RunError::DebarCommand)?;
        compared.push(compare_reports(
            relative.display().to_string(),
            reference_report,
            reference_every_match.map(PathBuf::as_path),
            &debar_report,
        )?);
    }
    let mut outcome = judge(&settings.known_differences, compared);
    outcome.built_inputs =
        built_for.map(|built_for| summarise_built_inputs(&built_for, &outcome.compared));
    Ok(outcome)
}

pub fn read_manifest(path: &Path) -> Result<BTreeMap<String, String>, RunError> {
    let text = fs::read_to_string(path).map_err(|error| RunError::Manifest {
        path: path.to_owned(),
        error,
    })?;
    Ok(built_for_signatures(&text))
}

#[must_use]
pub fn built_for_signatures(manifest: &str) -> BTreeMap<String, String> {
    manifest
        .lines()
        .filter_map(|row| {
            let mut fields = row.splitn(3, '\t');
            let file_name = fields.next()?;
            let line = fields.nth(1)?;
            let signature = line.split([':', ';']).next()?;
            Some((file_name.to_owned(), signature.to_owned()))
        })
        .collect()
}

#[must_use]
pub fn summarise_built_inputs(
    built_for: &BTreeMap<String, String>,
    compared: &[ComparedInput],
) -> BuiltInputs {
    let mut summary = BuiltInputs::default();
    for input in compared {
        let file_name = Path::new(&input.name)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&input.name);
        let Some(signature) = built_for.get(file_name) else {
            continue;
        };
        summary.inputs = summary.inputs.saturating_add(1);
        let by_reference = input.reference_detections.contains(signature);
        let by_debar = input.debar_detections.contains(signature);
        if by_reference {
            summary.detected_by_reference = summary.detected_by_reference.saturating_add(1);
        }
        match (by_reference, by_debar) {
            (true, true) => summary.detected_by_both = summary.detected_by_both.saturating_add(1),
            (false, true) => {
                summary.detected_by_debar_only = summary.detected_by_debar_only.saturating_add(1);
            }
            _ => {}
        }
    }
    summary
}

pub fn compare_reports(
    name: String,
    reference: &Path,
    reference_every_match: Option<&Path>,
    debar: &Path,
) -> Result<ComparedInput, RunError> {
    let reference = read_report(reference)?;
    let debar = read_report(debar)?;
    let compared = match reference_every_match {
        None => compare(&reference, &debar),
        Some(path) => compare_first_match(&reference, &read_report(path)?, &debar),
    };
    let differences = compared.map_err(|error| RunError::DifferentInputs {
        name: name.clone(),
        error,
    })?;
    Ok(ComparedInput {
        name,
        input: reference.top_level().sha256,
        differences,
        reference_detections: every_detection(&reference),
        debar_detections: every_detection(&debar),
    })
}

#[must_use]
pub fn judge(known: &KnownDifferences, compared: Vec<ComparedInput>) -> Outcome {
    let inputs_compared: BTreeSet<Sha256> = compared.iter().map(|input| input.input).collect();
    let differences = compared
        .iter()
        .flat_map(|input| input.differences.iter().cloned())
        .collect();
    Outcome {
        judgement: known.judge(&inputs_compared, differences),
        compared,
        built_inputs: None,
    }
}

fn read_report(path: &Path) -> Result<Report, RunError> {
    let failed = |error| RunError::Report {
        path: path.to_owned(),
        error,
    };
    let file = File::open(path).map_err(|error| failed(ReportError::Io(error)))?;
    Report::read(BufReader::new(file)).map_err(failed)
}

impl WorkDirectory {
    fn prepare(root: &Path) -> Result<Self, RunError> {
        let work = Self {
            databases: root.join("databases"),
            reference: root.join("reference"),
            reference_every_match: root.join("reference-every-match"),
            debar: root.join("debar"),
        };
        for directory in [
            &work.databases,
            &work.reference,
            &work.reference_every_match,
            &work.debar,
        ] {
            let unusable = |error| RunError::WorkDirectory {
                path: directory.clone(),
                error,
            };
            if directory.exists() {
                fs::remove_dir_all(directory).map_err(unusable)?;
            }
            fs::create_dir_all(directory).map_err(unusable)?;
        }
        Ok(work)
    }
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inputs(error) => error.fmt(formatter),
            Self::WorkDirectory { path, error } => {
                write!(formatter, "cannot prepare {}: {error}", path.display())
            }
            Self::Observer(error) => error.fmt(formatter),
            Self::DebarCommand(error) => error.fmt(formatter),
            Self::Report { path, error } => write!(formatter, "{}: {error}", path.display()),
            Self::Manifest { path, error } => {
                write!(
                    formatter,
                    "cannot read the manifest {}: {error}",
                    path.display()
                )
            }
            Self::DifferentInputs { name, error } => write!(formatter, "{name}: {error}"),
        }
    }
}

impl std::error::Error for RunError {}
