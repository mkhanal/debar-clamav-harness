use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use crate::matching::{MATCHING_VARIABLE, Matching};
use crate::scan_options::{SCAN_OPTIONS_VARIABLE, ScanOptions};

pub const INPUT_VARIABLE: &str = "HARNESS_INPUT";
pub const REPORT_VARIABLE: &str = "HARNESS_REPORT";
pub const DATABASES_VARIABLE: &str = "HARNESS_DATABASES";

#[derive(Debug)]
pub struct DebarCommand {
    shell_command: String,
}

#[derive(Debug)]
pub enum DebarCommandError {
    NotStarted { error: io::Error },
    Failed { input: PathBuf, status: ExitStatus },
}

impl DebarCommand {
    #[must_use]
    pub fn new(shell_command: String) -> Self {
        Self { shell_command }
    }

    pub fn run(
        &self,
        input: &Path,
        databases: &Path,
        report: &Path,
        matching: Matching,
        scan_options: &ScanOptions,
    ) -> Result<(), DebarCommandError> {
        let status = Command::new("sh")
            .arg("-c")
            .arg(&self.shell_command)
            .env(INPUT_VARIABLE, input)
            .env(DATABASES_VARIABLE, databases)
            .env(REPORT_VARIABLE, report)
            .env(MATCHING_VARIABLE, matching.word())
            .env(SCAN_OPTIONS_VARIABLE, scan_options.as_text())
            .status()
            .map_err(|error| DebarCommandError::NotStarted { error })?;
        if status.success() {
            Ok(())
        } else {
            Err(DebarCommandError::Failed {
                input: input.to_owned(),
                status,
            })
        }
    }
}

impl fmt::Display for DebarCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotStarted { error } => {
                write!(formatter, "cannot start the Debar command: {error}")
            }
            Self::Failed { input, status } => write!(
                formatter,
                "the Debar command failed on {} with {status}",
                input.display()
            ),
        }
    }
}

impl std::error::Error for DebarCommandError {}
