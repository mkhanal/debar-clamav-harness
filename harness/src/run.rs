use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};

use harness_report::{Report, ReportError, Sha256};

use crate::comparison::{DifferentInputs, compare};
use crate::debar_command::{DebarCommand, DebarCommandError};
use crate::difference::Difference;
use crate::inputs::{Inputs, InputsError};
use crate::observer::{Observer, ObserverError};
use crate::ratchet::{Judgement, KnownDifferences};

pub struct RunSettings {
    pub input: PathBuf,
    pub debar_command: DebarCommand,
    pub observer: Observer,
    pub known_differences: KnownDifferences,
    pub work_directory: PathBuf,
}

pub struct ComparedInput {
    pub name: String,
    pub input: Sha256,
    pub differences: Vec<Difference>,
}

pub struct Outcome {
    pub compared: Vec<ComparedInput>,
    pub judgement: Judgement,
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
    DifferentInputs {
        name: String,
        error: DifferentInputs,
    },
}

struct WorkDirectory {
    databases: PathBuf,
    reference: PathBuf,
    debar: PathBuf,
}

pub fn run(settings: &RunSettings) -> Result<Outcome, RunError> {
    let inputs = Inputs::find(&settings.input).map_err(RunError::Inputs)?;
    let work = WorkDirectory::prepare(&settings.work_directory)?;
    settings
        .observer
        .copy_databases(&work.databases)
        .map_err(RunError::Observer)?;
    let reference_reports = settings
        .observer
        .observe(&inputs, &work.reference)
        .map_err(RunError::Observer)?;
    let mut compared = Vec::new();
    for ((index, relative), reference_report) in inputs
        .relative_paths()
        .iter()
        .enumerate()
        .zip(&reference_reports)
    {
        let debar_report = work.debar.join(format!("{index}.jsonl"));
        settings
            .debar_command
            .run(
                &inputs.root().join(relative),
                &work.databases,
                &debar_report,
            )
            .map_err(RunError::DebarCommand)?;
        compared.push(compare_reports(
            relative.display().to_string(),
            reference_report,
            &debar_report,
        )?);
    }
    Ok(judge(&settings.known_differences, compared))
}

pub fn compare_reports(
    name: String,
    reference: &Path,
    debar: &Path,
) -> Result<ComparedInput, RunError> {
    let reference = read_report(reference)?;
    let debar = read_report(debar)?;
    let differences = compare(&reference, &debar).map_err(|error| RunError::DifferentInputs {
        name: name.clone(),
        error,
    })?;
    Ok(ComparedInput {
        name,
        input: reference.top_level().sha256,
        differences,
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
            debar: root.join("debar"),
        };
        for directory in [&work.databases, &work.reference, &work.debar] {
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
            Self::DifferentInputs { name, error } => write!(formatter, "{name}: {error}"),
        }
    }
}

impl std::error::Error for RunError {}
