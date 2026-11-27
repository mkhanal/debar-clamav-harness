use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use harness::console::print_outcome;
use harness::debar_command::DebarCommand;
use harness::matching::Matching;
use harness::observer::Observer;
use harness::ratchet::KnownDifferences;
use harness::run::{RunSettings, compare_reports, judge, run};
use harness::scan_options::ScanOptions;

const USAGE: &str = "usage:
  harness compare --reference REPORT --debar REPORT [--known-differences FILE]
                  [--reference-every-match REPORT]
  harness run --input FILE_OR_DIRECTORY --debar-command COMMAND
              [--known-differences FILE] [--observer-image IMAGE] [--work-directory DIRECTORY]
              [--manifest FILE] [--matching every|first] [--scan-options OPTIONS]

harness run scans every file of the input with the reference observer and with COMMAND,
which runs under sh -c with HARNESS_INPUT, HARNESS_REPORT, HARNESS_DATABASES and
HARNESS_MATCHING set, and must write the report of HARNESS_INPUT to HARNESS_REPORT.
With --matching first the reference scans without all-match, so each scan stops at its
first strong detection, and scans again with it: Debar's detection must be one the
reference reports for the input with all-match, of a class the reference reported without
it. The default, every, scans with all-match only, and compares each object's detections as
a set. harness compare judges a report made without all-match that way when
--reference-every-match names the reference's report of the same input with all-match. With --manifest, the builder's
manifest of the inputs, it also counts how many inputs each scanner detected under the
signature the input was built for. --scan-options gives both scanners the same settings, as
one argument of space-separated words: --max-files N, --max-scan-size N, --max-file-size N
and --max-recursion N set a limit (0 switches any but the last off), --alert-exceeds-max
reports a limit reached as a detection, and --raw-only scans raw-only: every parser and heuristic off, each
object typed and then matched once against the signatures for any type. The observer takes
them as they are, and COMMAND finds them in HARNESS_SCAN_OPTIONS.

Exit status: 0 when every difference is a known one, 1 when a new difference was found,
2 when the comparison could not be made.";

const EXIT_NEW_DIFFERENCES: u8 = 1;
const EXIT_NOT_COMPARED: u8 = 2;
const DEFAULT_WORK_DIRECTORY_NAME: &str = "debar-clamav-harness";

enum Task {
    Compare {
        reference: PathBuf,
        reference_every_match: Option<PathBuf>,
        debar: PathBuf,
        known_differences: Option<PathBuf>,
    },
    Run {
        input: PathBuf,
        debar_command: String,
        known_differences: Option<PathBuf>,
        observer_image: Option<String>,
        work_directory: Option<PathBuf>,
        manifest: Option<PathBuf>,
        matching: Matching,
        scan_options: ScanOptions,
    },
}

fn main() -> ExitCode {
    match parse_task(std::env::args_os().skip(1).collect()).and_then(perform) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(EXIT_NEW_DIFFERENCES),
        Err(reason) => {
            eprintln!("harness: {reason}");
            ExitCode::from(EXIT_NOT_COMPARED)
        }
    }
}

fn perform(task: Task) -> Result<bool, String> {
    let outcome = match task {
        Task::Compare {
            reference,
            reference_every_match,
            debar,
            known_differences,
        } => {
            let known = read_known_differences(known_differences.as_deref())?;
            let compared = compare_reports(
                debar.display().to_string(),
                &reference,
                reference_every_match.as_deref(),
                &debar,
            )
            .map_err(|error| error.to_string())?;
            judge(&known, vec![compared])
        }
        Task::Run {
            input,
            debar_command,
            known_differences,
            observer_image,
            work_directory,
            manifest,
            matching,
            scan_options,
        } => {
            let settings = RunSettings {
                input,
                debar_command: DebarCommand::new(debar_command),
                observer: observer_image
                    .map_or_else(Observer::pinned, |image| Observer::new(&image)),
                matching,
                scan_options,
                known_differences: read_known_differences(known_differences.as_deref())?,
                work_directory: work_directory
                    .unwrap_or_else(|| std::env::temp_dir().join(DEFAULT_WORK_DIRECTORY_NAME)),
                manifest,
            };
            run(&settings).map_err(|error| error.to_string())?
        }
    };
    print_outcome(&outcome, &mut io::stdout().lock()).map_err(|error| error.to_string())?;
    Ok(!outcome.judgement.fails())
}

fn read_known_differences(path: Option<&Path>) -> Result<KnownDifferences, String> {
    let Some(path) = path else {
        return Ok(KnownDifferences::default());
    };
    let file =
        File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    KnownDifferences::read(BufReader::new(file))
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn parse_task(arguments: Vec<OsString>) -> Result<Task, String> {
    let mut arguments = arguments.into_iter();
    let task = arguments.next();
    let mut options = Options::default();
    while let Some(flag) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("{} needs a value\n{USAGE}", flag.display()))?;
        options.set(&flag, value)?;
    }
    match task.as_ref().and_then(|task| task.to_str()) {
        Some("compare") => Ok(Task::Compare {
            reference: required("--reference", options.reference.clone())?.into(),
            reference_every_match: options.reference_every_match.map(PathBuf::from),
            debar: required("--debar", options.debar.clone())?.into(),
            known_differences: options.known_differences.map(PathBuf::from),
        }),
        Some("run") => Ok(Task::Run {
            input: required("--input", options.input.clone())?.into(),
            debar_command: required("--debar-command", options.debar_command.clone())?
                .into_string()
                .map_err(|_| "--debar-command must be valid UTF-8".to_owned())?,
            known_differences: options.known_differences.map(PathBuf::from),
            observer_image: options
                .observer_image
                .map(OsString::into_string)
                .transpose()
                .map_err(|_| "--observer-image must be valid UTF-8".to_owned())?,
            work_directory: options.work_directory.map(PathBuf::from),
            manifest: options.manifest.map(PathBuf::from),
            matching: options
                .matching
                .map_or(Some(Matching::EveryMatch), |word| {
                    word.to_str().and_then(Matching::from_word)
                })
                .ok_or_else(|| format!("--matching must be every or first\n{USAGE}"))?,
            scan_options: options
                .scan_settings
                .map(OsString::into_string)
                .transpose()
                .map_err(|_| "--scan-options must be valid UTF-8".to_owned())?
                .map_or_else(
                    || Ok(ScanOptions::default()),
                    |text| ScanOptions::parse(&text),
                )
                .map_err(|error| format!("{error}\n{USAGE}"))?,
        }),
        _ => Err(USAGE.to_owned()),
    }
}

#[derive(Default)]
struct Options {
    reference: Option<OsString>,
    reference_every_match: Option<OsString>,
    debar: Option<OsString>,
    input: Option<OsString>,
    debar_command: Option<OsString>,
    known_differences: Option<OsString>,
    observer_image: Option<OsString>,
    work_directory: Option<OsString>,
    manifest: Option<OsString>,
    matching: Option<OsString>,
    scan_settings: Option<OsString>,
}

impl Options {
    fn set(&mut self, flag: &OsString, value: OsString) -> Result<(), String> {
        let slot = match flag.to_str() {
            Some("--reference") => &mut self.reference,
            Some("--reference-every-match") => &mut self.reference_every_match,
            Some("--debar") => &mut self.debar,
            Some("--input") => &mut self.input,
            Some("--debar-command") => &mut self.debar_command,
            Some("--known-differences") => &mut self.known_differences,
            Some("--observer-image") => &mut self.observer_image,
            Some("--work-directory") => &mut self.work_directory,
            Some("--manifest") => &mut self.manifest,
            Some("--matching") => &mut self.matching,
            Some("--scan-options") => &mut self.scan_settings,
            _ => return Err(format!("unknown option {}\n{USAGE}", flag.display())),
        };
        *slot = Some(value);
        Ok(())
    }
}

fn required(flag: &str, value: Option<OsString>) -> Result<OsString, String> {
    value.ok_or_else(|| format!("{flag} is required\n{USAGE}"))
}
