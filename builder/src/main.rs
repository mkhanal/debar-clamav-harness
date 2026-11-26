use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clamav_input_builder::database_files::{DatabaseKind, signature_lines};
use clamav_input_builder::database_survey::survey_directory;
use clamav_input_builder::input_construction::build_input;
use clamav_input_builder::reference_proof::{SampleRequest, check_scan, write_sample};

const USAGE: &str = "usage:
  builder build --database <file> --signature <name> --out <file>
  builder survey --database-dir <dir> [--details <file>]
  builder sample --database-dir <dir> --out-dir <dir> [--extended <n>] [--logical <n>] [--seed <n>]
  builder check --manifest <file> --scan-output <file> [--failures <file>]";

const DEFAULT_EXTENDED_SAMPLE: usize = 2000;
const DEFAULT_LOGICAL_SAMPLE: usize = 500;
const DEFAULT_SEED: u64 = 1;

#[derive(Debug)]
enum CommandError {
    Usage(String),
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
    SignatureNotFound(String),
    Unreadable {
        name: String,
        reason: String,
    },
    NotBuilt {
        name: String,
        reason: String,
    },
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(problem) => write!(formatter, "{problem}\n{USAGE}"),
            Self::Io { path, error } => write!(formatter, "{}: {error}", path.display()),
            Self::SignatureNotFound(name) => write!(formatter, "no signature named {name:?}"),
            Self::Unreadable { name, reason } => write!(formatter, "{name}: unreadable: {reason}"),
            Self::NotBuilt { name, reason } => write!(formatter, "{name}: not built: {reason}"),
        }
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("builder: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: &[String]) -> Result<(), CommandError> {
    let (command, options) = arguments
        .split_first()
        .ok_or_else(|| CommandError::Usage("no command given".to_owned()))?;
    let options = Options::parse(options)?;
    match command.as_str() {
        "build" => build(&options),
        "survey" => survey(&options),
        "sample" => sample(&options),
        "check" => check(&options),
        other => Err(CommandError::Usage(format!("unknown command {other:?}"))),
    }
}

struct Options {
    values: BTreeMap<String, String>,
}

impl Options {
    fn parse(arguments: &[String]) -> Result<Self, CommandError> {
        let mut values = BTreeMap::new();
        let mut remaining = arguments.iter();
        while let Some(flag) = remaining.next() {
            let name = flag
                .strip_prefix("--")
                .ok_or_else(|| CommandError::Usage(format!("unexpected argument {flag:?}")))?;
            let value = remaining
                .next()
                .ok_or_else(|| CommandError::Usage(format!("{flag} needs a value")))?;
            values.insert(name.to_owned(), value.clone());
        }
        Ok(Self { values })
    }

    fn required(&self, name: &str) -> Result<&str, CommandError> {
        self.values
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| CommandError::Usage(format!("--{name} is required")))
    }

    fn number<T: std::str::FromStr>(&self, name: &str, default: T) -> Result<T, CommandError> {
        match self.values.get(name) {
            None => Ok(default),
            Some(text) => text
                .parse()
                .map_err(|_| CommandError::Usage(format!("--{name} needs a number"))),
        }
    }
}

fn io_error(path: &Path) -> impl FnOnce(std::io::Error) -> CommandError + '_ {
    move |error| CommandError::Io {
        path: path.to_path_buf(),
        error,
    }
}

fn build(options: &Options) -> Result<(), CommandError> {
    let database = Path::new(options.required("database")?);
    let wanted = options.required("signature")?;
    let out = Path::new(options.required("out")?);
    let kind = DatabaseKind::of(database);
    for line in signature_lines(database).map_err(io_error(database))? {
        let Some(parsed) = kind.parse(&line) else {
            break;
        };
        let name_matches = line
            .split([':', ';'])
            .next()
            .is_some_and(|name| name == wanted);
        if !name_matches {
            continue;
        }
        let signature = parsed.map_err(|error| CommandError::Unreadable {
            name: wanted.to_owned(),
            reason: error.to_string(),
        })?;
        let bytes = build_input(&signature).map_err(|reason| CommandError::NotBuilt {
            name: wanted.to_owned(),
            reason: reason.to_string(),
        })?;
        return std::fs::write(out, bytes).map_err(io_error(out));
    }
    Err(CommandError::SignatureNotFound(wanted.to_owned()))
}

fn survey(options: &Options) -> Result<(), CommandError> {
    let directory = Path::new(options.required("database-dir")?);
    let survey = survey_directory(directory).map_err(io_error(directory))?;
    print!("{}", survey.report());
    if let Some(details_path) = options.values.get("details") {
        let details_path = Path::new(details_path);
        std::fs::write(details_path, survey.not_built_details()).map_err(io_error(details_path))?;
    }
    Ok(())
}

fn sample(options: &Options) -> Result<(), CommandError> {
    let database_directory = Path::new(options.required("database-dir")?);
    let output_directory = Path::new(options.required("out-dir")?);
    let written = write_sample(&SampleRequest {
        database_directory,
        output_directory,
        extended_count: options.number("extended", DEFAULT_EXTENDED_SAMPLE)?,
        logical_count: options.number("logical", DEFAULT_LOGICAL_SAMPLE)?,
        seed: options.number("seed", DEFAULT_SEED)?,
    })
    .map_err(io_error(output_directory))?;
    println!("wrote {written} inputs to {}", output_directory.display());
    Ok(())
}

fn check(options: &Options) -> Result<(), CommandError> {
    let manifest_path = Path::new(options.required("manifest")?);
    let scan_path = Path::new(options.required("scan-output")?);
    let manifest = std::fs::read_to_string(manifest_path).map_err(io_error(manifest_path))?;
    let scan_output = std::fs::read_to_string(scan_path).map_err(io_error(scan_path))?;
    let result = check_scan(&manifest, &scan_output);
    print!("{}", result.report);
    if let Some(failures_path) = options.values.get("failures") {
        let failures_path = Path::new(failures_path);
        std::fs::write(failures_path, result.failures).map_err(io_error(failures_path))?;
    }
    Ok(())
}
