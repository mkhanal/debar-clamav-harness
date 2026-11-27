#![allow(clippy::unwrap_used)]

use harness::comparison::{DifferentInputs, compare, compare_first_match};
use harness::difference::{Difference, DifferenceKind, ObjectPath};
use harness_report::{DatabaseVersion, Object, ObjectId, Report, Scanner, Sha256, Verdict};

fn sha(fill: u8) -> Sha256 {
    Sha256::from_digest([fill; 32])
}

fn object(id: u64, parent: Option<u64>, depth: u32, file_type: &str, content: u8) -> Object {
    Object {
        id: ObjectId(id),
        parent: parent.map(ObjectId),
        depth,
        file_type: Some(file_type.to_owned()),
        size: u64::from(content).saturating_mul(10),
        sha256: sha(content),
        detections: Vec::new(),
    }
}

fn detected(mut object: Object, names: &[&str]) -> Object {
    object.detections = names.iter().map(|name| (*name).to_owned()).collect();
    object
}

fn scanner(daily: u32) -> Scanner {
    Scanner {
        name: "test".to_owned(),
        version: "0".to_owned(),
        databases: vec![DatabaseVersion {
            name: "daily".to_owned(),
            version: daily,
        }],
    }
}

fn report(verdict: Verdict, objects: Vec<Object>) -> Report {
    Report::from_parts(scanner(1), verdict, objects).unwrap()
}

fn zip_with(children: Vec<Object>) -> Report {
    let mut objects = vec![object(0, None, 0, "CL_TYPE_ZIP", 1)];
    objects.extend(children);
    report(Verdict::NothingFound, objects)
}

fn kinds(reference: &Report, debar: &Report) -> Vec<DifferenceKind> {
    compare(reference, debar)
        .unwrap()
        .into_iter()
        .map(|difference| {
            assert_eq!(difference.input, sha(1));
            difference.kind
        })
        .collect()
}

fn path(contents: &[u8]) -> ObjectPath {
    ObjectPath(contents.iter().map(|content| sha(*content)).collect())
}

#[test]
fn identical_reports_have_no_differences() {
    let both = zip_with(vec![object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 2)]);
    assert_eq!(kinds(&both, &both), []);
}

#[test]
fn children_are_matched_by_content_whatever_order_each_side_reached_them_in() {
    let reference = zip_with(vec![
        object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 2),
        object(2, Some(0), 1, "CL_TYPE_TEXT_ASCII", 3),
    ]);
    let debar = zip_with(vec![
        object(7, Some(0), 1, "CL_TYPE_TEXT_ASCII", 3),
        object(9, Some(0), 1, "CL_TYPE_TEXT_ASCII", 2),
    ]);
    assert_eq!(kinds(&reference, &debar), []);
}

#[test]
fn an_object_only_the_reference_reached_is_reported_with_everything_under_it() {
    let reference = zip_with(vec![
        object(1, Some(0), 1, "CL_TYPE_ZIP", 2),
        detected(object(2, Some(1), 2, "CL_TYPE_TEXT_ASCII", 3), &["Eicar"]),
    ]);
    let debar = zip_with(vec![]);
    assert_eq!(
        kinds(&reference, &debar),
        [
            DifferenceKind::ObjectOnlyInReference {
                path: path(&[2]),
                file_type: Some("CL_TYPE_ZIP".to_owned()),
                detections: vec![],
            },
            DifferenceKind::ObjectOnlyInReference {
                path: path(&[2, 3]),
                file_type: Some("CL_TYPE_TEXT_ASCII".to_owned()),
                detections: vec!["Eicar".to_owned()],
            },
        ]
    );
}

#[test]
fn an_object_only_debar_reached_is_reported() {
    let reference = zip_with(vec![]);
    let debar = zip_with(vec![object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 2)]);
    assert_eq!(
        kinds(&reference, &debar),
        [DifferenceKind::ObjectOnlyInDebar {
            path: path(&[2]),
            file_type: Some("CL_TYPE_TEXT_ASCII".to_owned()),
            detections: vec![],
        }]
    );
}

#[test]
fn identical_siblings_are_paired_one_for_one() {
    let reference = zip_with(vec![
        object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 2),
        object(2, Some(0), 1, "CL_TYPE_TEXT_ASCII", 2),
    ]);
    let debar = zip_with(vec![object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 2)]);
    assert_eq!(
        kinds(&reference, &debar),
        [DifferenceKind::ObjectOnlyInReference {
            path: path(&[2]),
            file_type: Some("CL_TYPE_TEXT_ASCII".to_owned()),
            detections: vec![],
        }]
    );
}

#[test]
fn the_same_content_typed_differently_is_a_type_difference() {
    let reference = zip_with(vec![object(1, Some(0), 1, "CL_TYPE_HTML", 2)]);
    let debar = zip_with(vec![object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 2)]);
    assert_eq!(
        kinds(&reference, &debar),
        [DifferenceKind::TypeDiffers {
            path: path(&[2]),
            reference: Some("CL_TYPE_HTML".to_owned()),
            debar: Some("CL_TYPE_TEXT_ASCII".to_owned()),
        }]
    );
}

#[test]
fn the_same_content_at_another_depth_is_a_depth_difference() {
    let reference = zip_with(vec![object(1, Some(0), 2, "CL_TYPE_TEXT_ASCII", 2)]);
    let debar = zip_with(vec![object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 2)]);
    assert_eq!(
        kinds(&reference, &debar),
        [DifferenceKind::DepthDiffers {
            path: path(&[2]),
            reference: 2,
            debar: 1,
        }]
    );
}

#[test]
fn unmatched_content_of_the_same_type_is_paired_as_a_size_difference() {
    let reference = zip_with(vec![object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 2)]);
    let debar = zip_with(vec![object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 3)]);
    assert_eq!(
        kinds(&reference, &debar),
        [DifferenceKind::SizeDiffers {
            path: path(&[2]),
            reference: 20,
            debar: 30,
        }]
    );
}

#[test]
fn unmatched_content_of_the_same_type_and_size_is_a_hash_difference() {
    let reference = zip_with(vec![object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 2)]);
    let mut changed = object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 3);
    changed.size = 20;
    let debar = zip_with(vec![changed]);
    assert_eq!(
        kinds(&reference, &debar),
        [DifferenceKind::HashDiffers {
            path: path(&[2]),
            reference: sha(2),
            debar: sha(3),
        }]
    );
}

#[test]
fn children_of_objects_whose_content_differs_are_still_compared_under_the_reference_path() {
    let reference = zip_with(vec![
        object(1, Some(0), 1, "CL_TYPE_GZ", 2),
        object(2, Some(1), 2, "CL_TYPE_TEXT_ASCII", 4),
    ]);
    let debar = zip_with(vec![
        object(1, Some(0), 1, "CL_TYPE_GZ", 3),
        object(2, Some(1), 2, "CL_TYPE_TEXT_ASCII", 5),
        object(3, Some(1), 2, "CL_TYPE_TEXT_ASCII", 6),
    ]);
    assert_eq!(
        kinds(&reference, &debar),
        [
            DifferenceKind::SizeDiffers {
                path: path(&[2]),
                reference: 20,
                debar: 30,
            },
            DifferenceKind::SizeDiffers {
                path: path(&[2, 4]),
                reference: 40,
                debar: 50,
            },
            DifferenceKind::ObjectOnlyInDebar {
                path: path(&[2, 6]),
                file_type: Some("CL_TYPE_TEXT_ASCII".to_owned()),
                detections: vec![],
            },
        ]
    );
}

#[test]
fn unmatched_content_of_another_type_is_reported_on_each_side() {
    let reference = zip_with(vec![object(1, Some(0), 1, "CL_TYPE_PDF", 2)]);
    let debar = zip_with(vec![object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 3)]);
    assert_eq!(
        kinds(&reference, &debar),
        [
            DifferenceKind::ObjectOnlyInReference {
                path: path(&[2]),
                file_type: Some("CL_TYPE_PDF".to_owned()),
                detections: vec![],
            },
            DifferenceKind::ObjectOnlyInDebar {
                path: path(&[3]),
                file_type: Some("CL_TYPE_TEXT_ASCII".to_owned()),
                detections: vec![],
            },
        ]
    );
}

#[test]
fn detections_are_compared_as_sets_whatever_their_order_and_repeats() {
    let reference = zip_with(vec![detected(
        object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 2),
        &[
            "Eicar-Test-Signature",
            "Eicar-Test-Signature",
            "Eicar-Signature",
        ],
    )]);
    let debar = zip_with(vec![detected(
        object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 2),
        &["Eicar-Signature", "Eicar-Test-Signature", "Debar.Only"],
    )]);
    assert_eq!(
        kinds(&reference, &debar),
        [DifferenceKind::DetectionOnlyInDebar {
            path: path(&[2]),
            signature: "Debar.Only".to_owned(),
        }]
    );
}

#[test]
fn a_detection_one_side_never_reported_is_one_difference_however_often_the_other_reported_it() {
    let reference = zip_with(vec![detected(
        object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 2),
        &["Eicar-Test-Signature", "Eicar-Test-Signature"],
    )]);
    let debar = zip_with(vec![object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 2)]);
    assert_eq!(
        kinds(&reference, &debar),
        [DifferenceKind::DetectionOnlyInReference {
            path: path(&[2]),
            signature: "Eicar-Test-Signature".to_owned(),
        }]
    );
}

fn first_match_kinds(
    reference: &Report,
    reference_every_match: &Report,
    debar: &Report,
) -> Vec<DifferenceKind> {
    compare_first_match(reference, reference_every_match, debar)
        .unwrap()
        .into_iter()
        .map(|difference| difference.kind)
        .collect()
}

fn top_level_detecting(verdict: Verdict, names: &[&str]) -> Report {
    report(
        verdict,
        vec![detected(object(0, None, 0, "CL_TYPE_ZIP", 1), names)],
    )
}

#[test]
fn without_every_match_any_name_the_reference_reports_with_every_match_is_the_same_result() {
    let reference = top_level_detecting(Verdict::StrongIndicator, &["Win.Trojan.Mini-50"]);
    let reference_every_match = top_level_detecting(
        Verdict::StrongIndicator,
        &["Win.Trojan.Mini-50", "Win.Trojan.Trivial-471"],
    );
    let debar = top_level_detecting(Verdict::StrongIndicator, &["Win.Trojan.Trivial-471"]);
    assert_eq!(
        first_match_kinds(&reference, &reference_every_match, &debar),
        []
    );
}

#[test]
fn without_every_match_the_name_may_come_from_another_object_than_the_reference_names() {
    let reference = zip_with(vec![detected(
        object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 2),
        &["Inner"],
    )]);
    let reference_every_match = report(
        Verdict::NothingFound,
        vec![
            detected(object(0, None, 0, "CL_TYPE_ZIP", 1), &["Outer"]),
            detected(object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 2), &["Inner"]),
        ],
    );
    let debar = report(
        Verdict::NothingFound,
        vec![
            detected(object(0, None, 0, "CL_TYPE_ZIP", 1), &["Outer"]),
            object(1, Some(0), 1, "CL_TYPE_TEXT_ASCII", 2),
        ],
    );
    assert_eq!(
        first_match_kinds(&reference, &reference_every_match, &debar),
        []
    );
}

#[test]
fn without_every_match_a_name_the_reference_never_reports_for_the_input_is_a_difference() {
    let reference = top_level_detecting(Verdict::StrongIndicator, &["Win.Trojan.Mini-50"]);
    let debar = top_level_detecting(Verdict::StrongIndicator, &["Win.Trojan.Other-1"]);
    assert_eq!(
        first_match_kinds(&reference, &reference, &debar),
        [DifferenceKind::DetectionNotReportedByReference {
            signature: "Win.Trojan.Other-1".to_owned(),
        }]
    );
}

#[test]
fn without_every_match_a_name_of_another_class_than_the_reference_reports_is_a_difference() {
    let reference = top_level_detecting(Verdict::StrongIndicator, &["Win.Trojan.Mini-50"]);
    let reference_every_match = top_level_detecting(
        Verdict::StrongIndicator,
        &["Win.Trojan.Mini-50", "PUA.Win.Tool.Packed-1"],
    );
    let debar = top_level_detecting(Verdict::StrongIndicator, &["PUA.Win.Tool.Packed-1"]);
    assert_eq!(
        first_match_kinds(&reference, &reference_every_match, &debar),
        [DifferenceKind::DetectionOfAnotherClass {
            signature: "PUA.Win.Tool.Packed-1".to_owned(),
        }]
    );
}

#[test]
fn without_every_match_a_different_verdict_is_still_a_difference() {
    let reference = top_level_detecting(Verdict::StrongIndicator, &["Win.Trojan.Mini-50"]);
    let debar = report(
        Verdict::NothingFound,
        vec![object(0, None, 0, "CL_TYPE_ZIP", 1)],
    );
    assert_eq!(
        first_match_kinds(&reference, &reference, &debar),
        [DifferenceKind::VerdictDiffers {
            reference: Verdict::StrongIndicator,
            debar: Verdict::NothingFound,
        }]
    );
}

#[test]
fn without_every_match_reports_of_another_input_cannot_be_the_allowed_names() {
    let reference = zip_with(vec![]);
    let other = report(
        Verdict::NothingFound,
        vec![object(0, None, 0, "CL_TYPE_ZIP", 9)],
    );
    assert_eq!(
        compare_first_match(&reference, &other, &reference),
        Err(DifferentInputs {
            reference: sha(1),
            debar: sha(9),
        })
    );
}

#[test]
fn detections_on_the_top_level_object_have_an_empty_path() {
    let reference = report(
        Verdict::StrongIndicator,
        vec![detected(object(0, None, 0, "CL_TYPE_ZIP", 1), &["Eicar"])],
    );
    let debar = report(
        Verdict::StrongIndicator,
        vec![object(0, None, 0, "CL_TYPE_ZIP", 1)],
    );
    assert_eq!(
        kinds(&reference, &debar),
        [DifferenceKind::DetectionOnlyInReference {
            path: ObjectPath(vec![]),
            signature: "Eicar".to_owned(),
        }]
    );
}

#[test]
fn a_different_verdict_is_a_difference() {
    let reference = report(
        Verdict::StrongIndicator,
        vec![object(0, None, 0, "CL_TYPE_ZIP", 1)],
    );
    let debar = report(
        Verdict::NothingFound,
        vec![object(0, None, 0, "CL_TYPE_ZIP", 1)],
    );
    assert_eq!(
        kinds(&reference, &debar),
        [DifferenceKind::VerdictDiffers {
            reference: Verdict::StrongIndicator,
            debar: Verdict::NothingFound,
        }]
    );
}

#[test]
fn different_database_versions_are_a_difference() {
    let reference = zip_with(vec![]);
    let debar = Report::from_parts(
        scanner(2),
        Verdict::NothingFound,
        vec![object(0, None, 0, "CL_TYPE_ZIP", 1)],
    )
    .unwrap();
    assert_eq!(
        kinds(&reference, &debar),
        [DifferenceKind::DatabasesDiffer {
            reference: scanner(1).databases,
            debar: scanner(2).databases,
        }]
    );
}

#[test]
fn reports_of_different_inputs_cannot_be_compared() {
    let reference = zip_with(vec![]);
    let debar = report(
        Verdict::NothingFound,
        vec![object(0, None, 0, "CL_TYPE_ZIP", 9)],
    );
    assert_eq!(
        compare(&reference, &debar),
        Err(DifferentInputs {
            reference: sha(1),
            debar: sha(9),
        })
    );
}

#[test]
fn a_difference_is_written_as_one_json_object_naming_its_kind() {
    let difference = Difference {
        input: sha(1),
        kind: DifferenceKind::DetectionOnlyInReference {
            path: path(&[2]),
            signature: "Eicar".to_owned(),
        },
    };
    let json = serde_json::to_string(&difference).unwrap();
    assert_eq!(
        json,
        format!(
            r#"{{"input":"{}","kind":"detection_only_in_reference","path":["{}"],"signature":"Eicar"}}"#,
            sha(1),
            sha(2)
        )
    );
    assert_eq!(
        serde_json::from_str::<Difference>(&json).unwrap(),
        difference
    );
}
