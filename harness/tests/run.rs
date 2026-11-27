#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

use harness::debar_command::{DebarCommand, DebarCommandError};
use harness::inputs::Inputs;
use harness::matching::Matching;
use harness::scan_options::{ScanOptions, ScanOptionsError};

struct Scratch(PathBuf);

impl Scratch {
    fn new(test: &str) -> Self {
        let directory =
            std::env::temp_dir().join(format!("harness-run-test-{}-{test}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        Self(directory.canonicalize().unwrap())
    }

    fn file(&self, relative: &str, content: &[u8]) -> PathBuf {
        let path = self.0.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn relative_names(inputs: &Inputs) -> Vec<String> {
    inputs
        .relative_paths()
        .iter()
        .map(|path| path.display().to_string())
        .collect()
}

#[test]
fn every_file_under_an_input_directory_is_an_input_in_name_order() {
    let scratch = Scratch::new("directory");
    scratch.file("b.txt", b"b");
    scratch.file("a/z.bin", b"z");
    scratch.file("a/c.txt", b"c");

    let inputs = Inputs::find(&scratch.0).unwrap();

    assert_eq!(inputs.root(), scratch.0.as_path());
    assert_eq!(relative_names(&inputs), ["a/c.txt", "a/z.bin", "b.txt"]);
}

#[test]
fn a_single_input_file_is_found_beside_its_directory() {
    let scratch = Scratch::new("single");
    let file = scratch.file("only.txt", b"only");

    let inputs = Inputs::find(&file).unwrap();

    assert_eq!(inputs.root(), scratch.0.as_path());
    assert_eq!(relative_names(&inputs), ["only.txt"]);
}

#[test]
fn a_directory_without_files_is_refused() {
    let scratch = Scratch::new("empty");
    fs::create_dir_all(scratch.0.join("nothing")).unwrap();

    assert!(Inputs::find(&scratch.0.join("nothing")).is_err());
}

#[test]
fn the_debar_command_is_told_its_input_report_and_databases_through_the_environment() {
    let scratch = Scratch::new("environment");
    let input = scratch.file("input.txt", b"input");
    let databases = scratch.0.join("databases");
    let report = scratch.0.join("report.jsonl");
    let command = DebarCommand::new(
        r#"printf '%s|%s|%s' "$HARNESS_INPUT" "$HARNESS_DATABASES" "$HARNESS_REPORT" > "$HARNESS_REPORT""#
            .to_owned(),
    );

    command
        .run(
            &input,
            &databases,
            &report,
            Matching::EveryMatch,
            &ScanOptions::default(),
        )
        .unwrap();

    assert_eq!(
        fs::read_to_string(&report).unwrap(),
        format!(
            "{}|{}|{}",
            input.display(),
            databases.display(),
            report.display()
        )
    );
}

#[test]
fn a_failing_debar_command_stops_the_run() {
    let scratch = Scratch::new("failing");
    let input = scratch.file("input.txt", b"input");
    let command = DebarCommand::new("exit 3".to_owned());

    let outcome = command.run(
        &input,
        Path::new("/databases"),
        &scratch.0.join("report"),
        Matching::EveryMatch,
        &ScanOptions::default(),
    );

    assert!(matches!(outcome, Err(DebarCommandError::Failed { .. })));
}

#[test]
fn the_debar_command_is_told_whether_the_reference_stopped_at_its_first_match() {
    let scratch = Scratch::new("matching");
    let input = scratch.file("input.txt", b"input");
    let report = scratch.0.join("report.txt");
    let command =
        DebarCommand::new(r#"printf '%s' "$HARNESS_MATCHING" > "$HARNESS_REPORT""#.to_owned());

    command
        .run(
            &input,
            Path::new("/databases"),
            &report,
            Matching::FirstMatch,
            &ScanOptions::default(),
        )
        .unwrap();

    assert_eq!(fs::read_to_string(&report).unwrap(), "first");
}

#[test]
fn the_debar_command_is_told_the_scan_options_both_scanners_run_with() {
    let scratch = Scratch::new("scan-options");
    let input = scratch.file("input.txt", b"input");
    let report = scratch.0.join("report.txt");
    let command =
        DebarCommand::new(r#"printf '%s' "$HARNESS_SCAN_OPTIONS" > "$HARNESS_REPORT""#.to_owned());
    let scan_options = ScanOptions::parse("--raw-only  --max-recursion 2 --max-files 3").unwrap();

    command
        .run(
            &input,
            Path::new("/databases"),
            &report,
            Matching::EveryMatch,
            &scan_options,
        )
        .unwrap();

    assert_eq!(
        fs::read_to_string(&report).unwrap(),
        "--raw-only --max-recursion 2 --max-files 3"
    );
}

#[test]
fn a_scan_option_the_observer_does_not_take_is_refused() {
    assert_eq!(
        ScanOptions::parse("--max-files 3 --max-scantime 10"),
        Err(ScanOptionsError::Unknown {
            option: "--max-scantime".to_owned()
        })
    );
}

#[test]
fn a_limit_without_a_number_is_refused() {
    assert_eq!(
        ScanOptions::parse("--max-files many"),
        Err(ScanOptionsError::NeedsANumber {
            option: "--max-files".to_owned()
        })
    );
}

#[test]
fn a_raw_only_scan_cannot_be_asked_to_alert_on_limits() {
    assert_eq!(
        ScanOptions::parse("--alert-exceeds-max --raw-only"),
        Err(ScanOptionsError::RawOnlyRaisesNoAlerts)
    );
}
