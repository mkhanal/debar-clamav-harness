use harness_report::{ObjectId, Report, ReportError, Verdict};

const TOP_LEVEL_ZIP: &str = r#"{"schema":1,"id":0,"parent":null,"depth":0,"type":"CL_TYPE_ZIP","size":487,"sha256":"380e61e6ebec633a6e12702dc78eabe3d4635d97f8fb07b8d861077956ca65e2","detections":[],"verdict":"strong_indicator","scanner":{"name":"ClamAV","version":"1.5.4","databases":[{"name":"bytecode","version":339},{"name":"daily","version":28165},{"name":"main","version":63}]}}"#;
const EICAR_ENTRY: &str = r#"{"schema":1,"id":1,"parent":0,"depth":1,"type":"CL_TYPE_TEXT_ASCII","size":68,"sha256":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f","detections":["Eicar-Test-Signature","Eicar-Signature"]}"#;
const CLEAN_ENTRY: &str = r#"{"schema":1,"id":3,"parent":0,"depth":1,"type":"CL_TYPE_TEXT_ASCII","size":30,"sha256":"d54b1fa434bc0cb711a533e2a426647a951150f4e2aac1edb801bcf701f7d14c","detections":[]}"#;

fn lines(records: &[&str]) -> String {
    records.iter().flat_map(|record| [record, "\n"]).collect()
}

fn read(records: &[&str]) -> Result<Report, ReportError> {
    Report::read(lines(records).as_bytes())
}

#[test]
fn reads_an_archive_and_its_entries_with_their_detections() {
    let report = read(&[TOP_LEVEL_ZIP, EICAR_ENTRY, CLEAN_ENTRY]).unwrap();

    assert_eq!(report.verdict(), Verdict::StrongIndicator);
    assert_eq!(report.scanner().name, "ClamAV");
    assert_eq!(report.scanner().databases.len(), 3);
    assert_eq!(report.top_level().file_type.as_deref(), Some("CL_TYPE_ZIP"));
    let children = report.children_of(report.top_level().id);
    assert_eq!(children.len(), 2);
    assert_eq!(
        children[0].detections,
        ["Eicar-Test-Signature", "Eicar-Signature"]
    );
    assert_eq!(children[1].parent, Some(ObjectId(0)));
}

#[test]
fn writing_a_report_and_reading_it_back_gives_the_same_report() {
    let report = read(&[TOP_LEVEL_ZIP, EICAR_ENTRY, CLEAN_ENTRY]).unwrap();
    let mut written = Vec::new();
    report.write(&mut written).unwrap();

    assert_eq!(Report::read(written.as_slice()).unwrap(), report);
}

#[test]
fn writes_one_record_per_line_in_the_order_the_objects_were_reached() {
    let report = read(&[TOP_LEVEL_ZIP, EICAR_ENTRY, CLEAN_ENTRY]).unwrap();
    let mut written = Vec::new();
    report.write(&mut written).unwrap();
    let text = String::from_utf8(written).unwrap();

    let ids: Vec<u64> = text
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap()["id"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(ids, [0, 1, 3]);
}

#[test]
fn an_empty_report_is_rejected() {
    assert!(matches!(read(&[]), Err(ReportError::NoTopLevelObject)));
}

#[test]
fn a_report_must_start_with_its_top_level_object() {
    assert!(matches!(
        read(&[EICAR_ENTRY, TOP_LEVEL_ZIP]),
        Err(ReportError::FirstRecordIsNotTopLevel)
    ));
}

#[test]
fn only_the_top_level_object_carries_the_verdict() {
    let second_top_level = TOP_LEVEL_ZIP.replace(r#""id":0"#, r#""id":9"#);
    assert!(matches!(
        read(&[TOP_LEVEL_ZIP, &second_top_level]),
        Err(ReportError::SecondTopLevelObject { line: 2 })
    ));
}

#[test]
fn a_child_record_without_a_parent_is_rejected_even_without_a_verdict() {
    let orphan = EICAR_ENTRY.replace(r#""parent":0"#, r#""parent":null"#);
    assert!(matches!(
        read(&[TOP_LEVEL_ZIP, &orphan]),
        Err(ReportError::SecondTopLevelObject { line: 2 })
    ));
}

#[test]
fn a_child_carrying_a_verdict_is_rejected() {
    let child_with_verdict = EICAR_ENTRY.replace(
        r#""detections""#,
        r#""verdict":"nothing_found","detections""#,
    );
    assert!(matches!(
        read(&[TOP_LEVEL_ZIP, &child_with_verdict]),
        Err(ReportError::VerdictOnChild { line: 2 })
    ));
}

#[test]
fn a_parent_must_be_recorded_before_its_children() {
    let early_child = CLEAN_ENTRY.replace(r#""parent":0"#, r#""parent":1"#);
    assert!(matches!(
        read(&[TOP_LEVEL_ZIP, &early_child, EICAR_ENTRY]),
        Err(ReportError::UnknownParent {
            line: 2,
            parent: ObjectId(1)
        })
    ));
}

#[test]
fn object_ids_are_unique() {
    assert!(matches!(
        read(&[TOP_LEVEL_ZIP, EICAR_ENTRY, EICAR_ENTRY]),
        Err(ReportError::DuplicateId {
            line: 3,
            id: ObjectId(1)
        })
    ));
}

#[test]
fn a_child_is_deeper_than_its_parent() {
    let shallow_child = EICAR_ENTRY.replace(r#""depth":1"#, r#""depth":0"#);
    assert!(matches!(
        read(&[TOP_LEVEL_ZIP, &shallow_child]),
        Err(ReportError::NotDeeperThanParent { line: 2 })
    ));
}

#[test]
fn the_top_level_object_is_at_depth_zero() {
    let deep_top_level = TOP_LEVEL_ZIP.replace(r#""depth":0"#, r#""depth":2"#);
    assert!(matches!(
        read(&[&deep_top_level]),
        Err(ReportError::TopLevelNotAtDepthZero)
    ));
}

#[test]
fn a_record_of_another_schema_version_is_rejected() {
    let future = TOP_LEVEL_ZIP.replace(r#""schema":1"#, r#""schema":2"#);
    assert!(matches!(
        read(&[&future]),
        Err(ReportError::UnsupportedSchema { line: 1, schema: 2 })
    ));
}

#[test]
fn a_sha256_that_is_not_64_lowercase_hex_digits_is_rejected() {
    let uppercase = EICAR_ENTRY.replace("275a021b", "275A021B");
    let short = EICAR_ENTRY.replace("275a021b", "275a");
    assert!(matches!(
        read(&[TOP_LEVEL_ZIP, &uppercase]),
        Err(ReportError::Malformed { line: 2, .. })
    ));
    assert!(matches!(
        read(&[TOP_LEVEL_ZIP, &short]),
        Err(ReportError::Malformed { line: 2, .. })
    ));
}

#[test]
fn an_unknown_field_is_rejected() {
    let extra = EICAR_ENTRY.replace(r#""size""#, r#""colour":"blue","size""#);
    assert!(matches!(
        read(&[TOP_LEVEL_ZIP, &extra]),
        Err(ReportError::Malformed { line: 2, .. })
    ));
}

#[test]
fn an_untyped_object_has_no_type() {
    let untyped = TOP_LEVEL_ZIP.replace(r#""type":"CL_TYPE_ZIP""#, r#""type":null"#);
    let report = read(&[&untyped]).unwrap();
    assert_eq!(report.top_level().file_type, None);
}

#[test]
fn the_json_schema_requires_every_field_the_writer_emits() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../report.schema.json")).unwrap();
    let report = read(&[TOP_LEVEL_ZIP, EICAR_ENTRY]).unwrap();
    let mut written = Vec::new();
    report.write(&mut written).unwrap();
    let text = String::from_utf8(written).unwrap();
    let mut lines = text.lines();
    let top_level: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    let child: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();

    let field_names = |record: &serde_json::Value| -> Vec<String> {
        let mut names: Vec<String> = record.as_object().unwrap().keys().cloned().collect();
        names.sort();
        names
    };
    let schema_names = |pointer: &str| -> Vec<String> {
        let mut names: Vec<String> = schema
            .pointer(pointer)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap().to_owned())
            .collect();
        names.sort();
        names
    };
    assert_eq!(field_names(&child), schema_names("/$defs/object/required"));
    assert_eq!(
        field_names(&top_level),
        schema_names("/$defs/topLevelObject/required")
    );
}

#[test]
fn a_verdict_is_shown_by_the_name_the_schema_gives_it() {
    for verdict in [
        Verdict::NothingFound,
        Verdict::Trusted,
        Verdict::StrongIndicator,
        Verdict::PotentiallyUnwanted,
    ] {
        assert_eq!(
            serde_json::to_string(&verdict).unwrap(),
            format!("\"{verdict}\"")
        );
    }
}
