mod databases;

use std::fs::File;
use std::io::{self, BufWriter};
use std::path::PathBuf;
use std::process::ExitCode;

use harness_report::{Object, ObjectId, Report, Scanner, Sha256, Verdict};
use sha2::{Digest, Sha256 as Sha256Hasher};

const USAGE: &str = "usage: debar-stand-in --databases DIRECTORY INPUT REPORT";
const SCANNER_NAME: &str = "debar-stand-in";

struct Arguments {
    databases: PathBuf,
    input: PathBuf,
    report: PathBuf,
}

fn main() -> ExitCode {
    match parse_arguments(std::env::args_os().skip(1).collect())
        .and_then(|arguments| write_report(&arguments))
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("debar-stand-in: {reason}");
            ExitCode::FAILURE
        }
    }
}

fn parse_arguments(arguments: Vec<std::ffi::OsString>) -> Result<Arguments, String> {
    match <[std::ffi::OsString; 4]>::try_from(arguments) {
        Ok([flag, databases, input, report]) if flag == "--databases" => Ok(Arguments {
            databases: databases.into(),
            input: input.into(),
            report: report.into(),
        }),
        _ => Err(USAGE.to_owned()),
    }
}

fn write_report(arguments: &Arguments) -> Result<(), String> {
    let databases = databases::versions_in(&arguments.databases)?;
    let (size, sha256) = measure(&arguments.input)
        .map_err(|error| format!("cannot read {}: {error}", arguments.input.display()))?;
    let top_level = Object {
        id: ObjectId(0),
        parent: None,
        depth: 0,
        file_type: None,
        size,
        sha256,
        detections: Vec::new(),
    };
    let scanner = Scanner {
        name: SCANNER_NAME.to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        databases,
    };
    let report = Report::from_parts(scanner, Verdict::NothingFound, vec![top_level])
        .map_err(|error| error.to_string())?;
    let output = File::create(&arguments.report)
        .map_err(|error| format!("cannot create {}: {error}", arguments.report.display()))?;
    report
        .write(BufWriter::new(output))
        .map_err(|error| format!("cannot write {}: {error}", arguments.report.display()))
}

fn measure(input: &PathBuf) -> io::Result<(u64, Sha256)> {
    let mut hasher = Sha256Hasher::new();
    let size = io::copy(&mut File::open(input)?, &mut hasher)?;
    Ok((size, Sha256::from_digest(hasher.finalize().into())))
}
