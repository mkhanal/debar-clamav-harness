use std::fmt;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::inputs::Inputs;

pub const PINNED_IMAGE: &str = include_str!("../../observer-image");
const DATABASE_DIRECTORY_IN_IMAGE: &str = "/var/lib/clamav/.";
const INPUT_MOUNT: &str = "/input";
const REPORT_MOUNT: &str = "/reports";
const INPUTS_PER_CONTAINER: usize = 200;

#[derive(Debug)]
pub struct Observer {
    image: String,
}

#[derive(Debug)]
pub enum ObserverError {
    DockerNotStarted {
        step: &'static str,
        error: io::Error,
    },
    DockerFailed {
        step: &'static str,
        output: Output,
    },
    WorkDirectory {
        path: PathBuf,
        error: io::Error,
    },
}

impl Observer {
    #[must_use]
    pub fn new(image: &str) -> Self {
        Self {
            image: image.trim().to_owned(),
        }
    }

    #[must_use]
    pub fn pinned() -> Self {
        Self::new(PINNED_IMAGE)
    }

    pub fn copy_databases(&self, destination: &Path) -> Result<(), ObserverError> {
        let created = docker(
            "create a container to copy the databases from",
            &["create", "--network", "none", &self.image],
        )?;
        let container = String::from_utf8_lossy(&created.stdout).trim().to_owned();
        let source = format!("{container}:{DATABASE_DIRECTORY_IN_IMAGE}");
        let copied = docker(
            "copy the databases out of the observer image",
            &["cp", &source, &destination.to_string_lossy()],
        );
        let removed = docker("remove the database container", &["rm", &container]);
        copied.and(removed).map(|_| ())
    }

    pub fn observe(&self, inputs: &Inputs, reports: &Path) -> Result<Vec<PathBuf>, ObserverError> {
        let owner = owner_of(reports)?;
        let input_volume = format!("{}:{INPUT_MOUNT}:ro", inputs.root().display());
        let report_volume = format!("{}:{REPORT_MOUNT}", reports.display());
        let report_names: Vec<String> = (0..inputs.relative_paths().len())
            .map(|index| format!("{index}.jsonl"))
            .collect();
        let pairs: Vec<(String, &String)> = inputs
            .relative_paths()
            .iter()
            .map(|relative| format!("{INPUT_MOUNT}/{}", relative.display()))
            .zip(&report_names)
            .collect();
        for batch in pairs.chunks(INPUTS_PER_CONTAINER) {
            let mut arguments: Vec<String> = [
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                &owner,
                "--volume",
                &input_volume,
                "--volume",
                &report_volume,
                &self.image,
            ]
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect();
            for (input, report) in batch {
                arguments.push(input.clone());
                arguments.push(format!("{REPORT_MOUNT}/{report}"));
            }
            let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
            docker("run the reference observer", &borrowed)?;
        }
        Ok(report_names.iter().map(|name| reports.join(name)).collect())
    }
}

fn owner_of(directory: &Path) -> Result<String, ObserverError> {
    let metadata = directory
        .metadata()
        .map_err(|error| ObserverError::WorkDirectory {
            path: directory.to_owned(),
            error,
        })?;
    Ok(format!("{}:{}", metadata.uid(), metadata.gid()))
}

fn docker(step: &'static str, arguments: &[&str]) -> Result<Output, ObserverError> {
    let output = Command::new("docker")
        .args(arguments)
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .map_err(|error| ObserverError::DockerNotStarted { step, error })?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(ObserverError::DockerFailed { step, output })
    }
}

impl fmt::Display for ObserverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DockerNotStarted { step, error } => {
                write!(formatter, "cannot start docker to {step}: {error}")
            }
            Self::DockerFailed { step, output } => write!(
                formatter,
                "docker failed to {step} ({}):\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ),
            Self::WorkDirectory { path, error } => {
                write!(
                    formatter,
                    "cannot use the work directory {}: {error}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for ObserverError {}
