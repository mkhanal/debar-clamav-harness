use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};

use crate::{Object, ObjectId, ReportError, SCHEMA_VERSION, Scanner, Sha256, Verdict};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    #[serde(rename = "schema")]
    _schema: u64,
    id: ObjectId,
    parent: Option<ObjectId>,
    depth: u32,
    #[serde(rename = "type")]
    file_type: Option<String>,
    size: u64,
    sha256: Sha256,
    detections: Vec<String>,
    #[serde(default)]
    verdict: Option<Verdict>,
    #[serde(default)]
    scanner: Option<Scanner>,
}

#[derive(Serialize)]
struct WrittenRecord<'report> {
    schema: u64,
    id: ObjectId,
    parent: Option<ObjectId>,
    depth: u32,
    #[serde(rename = "type")]
    file_type: Option<&'report str>,
    size: u64,
    sha256: Sha256,
    detections: &'report [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    verdict: Option<Verdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scanner: Option<&'report Scanner>,
}

impl Record {
    pub(crate) fn into_object(self) -> Object {
        Object {
            id: self.id,
            parent: self.parent,
            depth: self.depth,
            file_type: self.file_type,
            size: self.size,
            sha256: self.sha256,
            detections: self.detections,
        }
    }
}

pub(crate) fn read_lines(input: impl BufRead) -> Result<Vec<Record>, ReportError> {
    (1..)
        .zip(input.lines())
        .map(|(line, text)| parse_record(line, &text?))
        .collect()
}

fn parse_record(line: usize, text: &str) -> Result<Record, ReportError> {
    let malformed = |error: serde_json::Error| ReportError::Malformed {
        line,
        reason: error.to_string(),
    };
    let value: serde_json::Value = serde_json::from_str(text).map_err(malformed)?;
    match value.get("schema").and_then(serde_json::Value::as_u64) {
        Some(SCHEMA_VERSION) => serde_json::from_value(value).map_err(malformed),
        Some(schema) => Err(ReportError::UnsupportedSchema { line, schema }),
        None => Err(ReportError::Malformed {
            line,
            reason: "no schema version".to_owned(),
        }),
    }
}

pub(crate) fn top_level_facts(records: &[Record]) -> Result<(Scanner, Verdict), ReportError> {
    let Some((top_level, descendants)) = records.split_first() else {
        return Err(ReportError::NoTopLevelObject);
    };
    if top_level.parent.is_some() {
        return Err(ReportError::FirstRecordIsNotTopLevel);
    }
    for (line, descendant) in (2..).zip(descendants) {
        if descendant.parent.is_none() {
            return Err(ReportError::SecondTopLevelObject { line });
        }
        if descendant.verdict.is_some() || descendant.scanner.is_some() {
            return Err(ReportError::VerdictOnChild { line });
        }
    }
    match (&top_level.scanner, top_level.verdict) {
        (Some(scanner), Some(verdict)) => Ok((scanner.clone(), verdict)),
        _ => Err(ReportError::TopLevelWithoutVerdict),
    }
}

pub(crate) fn write_lines<'report>(
    mut output: impl Write,
    scanner: &Scanner,
    verdict: Verdict,
    objects: impl Iterator<Item = &'report Object>,
) -> Result<(), ReportError> {
    for (index, object) in objects.enumerate() {
        let is_top_level = index == 0;
        let record = WrittenRecord {
            schema: SCHEMA_VERSION,
            id: object.id,
            parent: object.parent,
            depth: object.depth,
            file_type: object.file_type.as_deref(),
            size: object.size,
            sha256: object.sha256,
            detections: &object.detections,
            verdict: is_top_level.then_some(verdict),
            scanner: is_top_level.then_some(scanner),
        };
        serde_json::to_writer(&mut output, &record).map_err(std::io::Error::from)?;
        output.write_all(b"\n")?;
    }
    output.flush()?;
    Ok(())
}
