#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use harness_report::{DatabaseVersion, Report, Verdict};

const HELLO_SHA256: &str = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";

struct Scratch(PathBuf);

impl Scratch {
    fn new(test: &str) -> Self {
        let directory =
            std::env::temp_dir().join(format!("debar-stand-in-test-{}-{test}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(directory.join("databases")).unwrap();
        Self(directory)
    }

    fn database(&self, file_name: &str, header: &str) {
        let mut bytes = header.as_bytes().to_vec();
        bytes.resize(512, b' ');
        bytes.extend_from_slice(b"body");
        fs::write(self.0.join("databases").join(file_name), bytes).unwrap();
    }

    fn run(&self, input: &[u8]) -> std::process::Output {
        fs::write(self.0.join("input"), input).unwrap();
        Command::new(env!("CARGO_BIN_EXE_debar-stand-in"))
            .arg("--databases")
            .arg(self.0.join("databases"))
            .arg(self.0.join("input"))
            .arg(self.0.join("report.jsonl"))
            .output()
            .unwrap()
    }

    fn report(&self) -> Report {
        Report::read(fs::read(self.0.join("report.jsonl")).unwrap().as_slice()).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn writes_a_valid_report_of_the_top_level_object_alone_with_nothing_found() {
    let scratch = Scratch::new("top-level");
    scratch.database(
        "main.cvd",
        "ClamAV-VDB:16 Dec 2025 23-18 +0000:63:3287027:90:x:y:z:1",
    );

    let outcome = scratch.run(b"hello\n");
    assert!(outcome.status.success(), "{outcome:?}");

    let report = scratch.report();
    assert_eq!(report.verdict(), Verdict::NothingFound);
    assert_eq!(report.objects().count(), 1);
    let top_level = report.top_level();
    assert_eq!(top_level.size, 6);
    assert_eq!(top_level.sha256.to_string(), HELLO_SHA256);
    assert_eq!(top_level.file_type, None);
    assert_eq!(top_level.detections, Vec::<String>::new());
}

#[test]
fn reports_the_version_in_each_database_header_sorted_by_name() {
    let scratch = Scratch::new("databases");
    scratch.database(
        "main.cvd",
        "ClamAV-VDB:16 Dec 2025 23-18 +0000:63:3287027:90:x:y:z:1",
    );
    scratch.database(
        "daily.cld",
        "ClamAV-VDB:26 Oct 2026 06-27 +0000:28165:355788:90:x:y:z:1",
    );
    scratch.database("main-63.cvd.sign", "not a database");

    assert!(scratch.run(b"hello\n").status.success());

    assert_eq!(
        scratch.report().scanner().databases,
        [
            DatabaseVersion {
                name: "daily".to_owned(),
                version: 28165
            },
            DatabaseVersion {
                name: "main".to_owned(),
                version: 63
            },
        ]
    );
}

#[test]
fn fails_loudly_on_a_database_whose_header_it_cannot_read() {
    let scratch = Scratch::new("bad-header");
    scratch.database("main.cvd", "not a header");

    let outcome = scratch.run(b"hello\n");

    assert!(!outcome.status.success());
    assert!(String::from_utf8_lossy(&outcome.stderr).contains("main.cvd"));
}
