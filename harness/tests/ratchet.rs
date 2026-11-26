#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;

use harness::difference::{Difference, DifferenceKind, ObjectPath};
use harness::ratchet::{KnownDifferences, KnownDifferencesError};
use harness_report::Sha256;

fn sha(fill: u8) -> Sha256 {
    Sha256::from_digest([fill; 32])
}

fn missed_detection(input: u8, signature: &str) -> Difference {
    Difference {
        input: sha(input),
        kind: DifferenceKind::DetectionOnlyInReference {
            path: ObjectPath(vec![]),
            signature: signature.to_owned(),
        },
    }
}

fn known(differences: &[Difference]) -> KnownDifferences {
    let text = differences
        .iter()
        .map(|difference| serde_json::to_string(difference).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    KnownDifferences::read(text.as_bytes()).unwrap()
}

fn inputs(fills: &[u8]) -> BTreeSet<Sha256> {
    fills.iter().map(|fill| sha(*fill)).collect()
}

#[test]
fn a_difference_on_the_known_list_does_not_fail_the_run() {
    let judgement = known(&[missed_detection(1, "Eicar")])
        .judge(&inputs(&[1]), vec![missed_detection(1, "Eicar")]);

    assert_eq!(judgement.new, Vec::<Difference>::new());
    assert_eq!(judgement.known, [missed_detection(1, "Eicar")]);
    assert_eq!(judgement.no_longer_occurring, Vec::<Difference>::new());
    assert!(!judgement.fails());
}

#[test]
fn a_difference_missing_from_the_known_list_fails_the_run() {
    let judgement = known(&[]).judge(&inputs(&[1]), vec![missed_detection(1, "Eicar")]);

    assert_eq!(judgement.new, [missed_detection(1, "Eicar")]);
    assert!(judgement.fails());
}

#[test]
fn a_known_difference_that_no_longer_occurs_is_reported_without_failing() {
    let judgement = known(&[missed_detection(1, "Eicar")]).judge(&inputs(&[1]), vec![]);

    assert_eq!(
        judgement.no_longer_occurring,
        [missed_detection(1, "Eicar")]
    );
    assert!(!judgement.fails());
}

#[test]
fn known_differences_of_inputs_not_compared_are_left_alone() {
    let judgement = known(&[missed_detection(2, "Eicar")]).judge(&inputs(&[1]), vec![]);

    assert_eq!(judgement.no_longer_occurring, Vec::<Difference>::new());
}

#[test]
fn each_known_entry_covers_one_occurrence() {
    let judgement = known(&[missed_detection(1, "Eicar")]).judge(
        &inputs(&[1]),
        vec![missed_detection(1, "Eicar"), missed_detection(1, "Eicar")],
    );

    assert_eq!(judgement.known, [missed_detection(1, "Eicar")]);
    assert_eq!(judgement.new, [missed_detection(1, "Eicar")]);
}

#[test]
fn a_known_entry_must_match_the_difference_exactly() {
    let judgement = known(&[missed_detection(1, "Eicar")])
        .judge(&inputs(&[1]), vec![missed_detection(1, "Eicar-Signature")]);

    assert_eq!(judgement.new, [missed_detection(1, "Eicar-Signature")]);
    assert_eq!(
        judgement.no_longer_occurring,
        [missed_detection(1, "Eicar")]
    );
}

#[test]
fn blank_lines_in_the_known_list_are_ignored() {
    let line = serde_json::to_string(&missed_detection(1, "Eicar")).unwrap();
    let list = KnownDifferences::read(format!("\n{line}\n\n").as_bytes()).unwrap();

    assert_eq!(list.len(), 1);
}

#[test]
fn a_malformed_line_in_the_known_list_is_named() {
    let line = serde_json::to_string(&missed_detection(1, "Eicar")).unwrap();
    let outcome = KnownDifferences::read(format!("{line}\nnot json\n").as_bytes());

    assert!(matches!(
        outcome,
        Err(KnownDifferencesError::Malformed { line: 2, .. })
    ));
}
