use std::collections::BTreeMap;
use std::fmt;

use harness_report::{Object, ObjectId, Report, Sha256};

use crate::difference::{Difference, DifferenceKind, ObjectPath};

#[derive(Debug, PartialEq, Eq)]
pub struct DifferentInputs {
    pub reference: Sha256,
    pub debar: Sha256,
}

impl fmt::Display for DifferentInputs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the reports describe different inputs: reference {}, Debar {}",
            self.reference, self.debar
        )
    }
}

impl std::error::Error for DifferentInputs {}

pub fn compare(reference: &Report, debar: &Report) -> Result<Vec<Difference>, DifferentInputs> {
    let input = reference.top_level().sha256;
    if debar.top_level().sha256 != input {
        return Err(DifferentInputs {
            reference: input,
            debar: debar.top_level().sha256,
        });
    }
    let mut comparison = Comparison {
        reference: children_by_parent(reference),
        debar: children_by_parent(debar),
        kinds: Vec::new(),
    };
    if reference.scanner().databases != debar.scanner().databases {
        comparison.kinds.push(DifferenceKind::DatabasesDiffer {
            reference: reference.scanner().databases.clone(),
            debar: debar.scanner().databases.clone(),
        });
    }
    if reference.verdict() != debar.verdict() {
        comparison.kinds.push(DifferenceKind::VerdictDiffers {
            reference: reference.verdict(),
            debar: debar.verdict(),
        });
    }
    comparison.compare_paired(
        &ObjectPath(Vec::new()),
        reference.top_level(),
        debar.top_level(),
    );
    Ok(comparison
        .kinds
        .into_iter()
        .map(|kind| Difference { input, kind })
        .collect())
}

type ChildrenByParent<'report> = BTreeMap<ObjectId, Vec<&'report Object>>;

fn children_by_parent(report: &Report) -> ChildrenByParent<'_> {
    let mut children: ChildrenByParent<'_> = BTreeMap::new();
    for object in report.objects() {
        if let Some(parent) = object.parent {
            children.entry(parent).or_default().push(object);
        }
    }
    children
}

struct Comparison<'report> {
    reference: ChildrenByParent<'report>,
    debar: ChildrenByParent<'report>,
    kinds: Vec<DifferenceKind>,
}

enum Side {
    Reference,
    Debar,
}

impl Comparison<'_> {
    fn compare_paired(&mut self, path: &ObjectPath, reference: &Object, debar: &Object) {
        self.compare_facts(path, reference, debar);
        self.compare_detections(path, &reference.detections, &debar.detections);
        self.compare_children(path, reference.id, debar.id);
    }

    fn compare_facts(&mut self, path: &ObjectPath, reference: &Object, debar: &Object) {
        if reference.file_type != debar.file_type {
            self.kinds.push(DifferenceKind::TypeDiffers {
                path: path.clone(),
                reference: reference.file_type.clone(),
                debar: debar.file_type.clone(),
            });
        }
        if reference.depth != debar.depth {
            self.kinds.push(DifferenceKind::DepthDiffers {
                path: path.clone(),
                reference: reference.depth,
                debar: debar.depth,
            });
        }
        if reference.size != debar.size {
            self.kinds.push(DifferenceKind::SizeDiffers {
                path: path.clone(),
                reference: reference.size,
                debar: debar.size,
            });
        } else if reference.sha256 != debar.sha256 {
            self.kinds.push(DifferenceKind::HashDiffers {
                path: path.clone(),
                reference: reference.sha256,
                debar: debar.sha256,
            });
        }
    }

    fn compare_detections(&mut self, path: &ObjectPath, reference: &[String], debar: &[String]) {
        let mut unmatched_in_debar: Vec<Option<&String>> = debar.iter().map(Some).collect();
        for signature in reference {
            let counterpart = unmatched_in_debar
                .iter_mut()
                .find(|candidate| *candidate == &Some(signature));
            match counterpart {
                Some(matched) => *matched = None,
                None => self.kinds.push(DifferenceKind::DetectionOnlyInReference {
                    path: path.clone(),
                    signature: signature.clone(),
                }),
            }
        }
        for signature in unmatched_in_debar.into_iter().flatten() {
            self.kinds.push(DifferenceKind::DetectionOnlyInDebar {
                path: path.clone(),
                signature: signature.clone(),
            });
        }
    }

    fn compare_children(&mut self, path: &ObjectPath, reference: ObjectId, debar: ObjectId) {
        let reference_children = self.reference.get(&reference).cloned().unwrap_or_default();
        let debar_children = self.debar.get(&debar).cloned().unwrap_or_default();
        let pairing = pair_children(&reference_children, &debar_children);
        for (child, counterpart) in reference_children.iter().zip(&pairing.counterparts) {
            match counterpart.and_then(|index| debar_children.get(index)) {
                Some(debar_child) => {
                    self.compare_paired(&path.child(child.sha256), child, debar_child);
                }
                None => self.report_unmatched(path, child, &Side::Reference),
            }
        }
        for debar_child in pairing
            .unpaired_in_debar
            .iter()
            .filter_map(|index| debar_children.get(*index))
        {
            self.report_unmatched(path, debar_child, &Side::Debar);
        }
    }

    fn report_unmatched(&mut self, parent_path: &ObjectPath, object: &Object, side: &Side) {
        let path = parent_path.child(object.sha256);
        let file_type = object.file_type.clone();
        let detections = object.detections.clone();
        let (kind, children) = match side {
            Side::Reference => (
                DifferenceKind::ObjectOnlyInReference {
                    path: path.clone(),
                    file_type,
                    detections,
                },
                self.reference.get(&object.id).cloned().unwrap_or_default(),
            ),
            Side::Debar => (
                DifferenceKind::ObjectOnlyInDebar {
                    path: path.clone(),
                    file_type,
                    detections,
                },
                self.debar.get(&object.id).cloned().unwrap_or_default(),
            ),
        };
        self.kinds.push(kind);
        for child in children {
            self.report_unmatched(&path, child, side);
        }
    }
}

struct Pairing {
    counterparts: Vec<Option<usize>>,
    unpaired_in_debar: Vec<usize>,
}

fn same_content(reference: &Object, debar: &Object) -> bool {
    reference.sha256 == debar.sha256
}

fn same_type(reference: &Object, debar: &Object) -> bool {
    reference.file_type == debar.file_type
}

fn pair_children(reference: &[&Object], debar: &[&Object]) -> Pairing {
    let mut counterparts: Vec<Option<usize>> = vec![None; reference.len()];
    let mut taken = vec![false; debar.len()];
    for belong_together in [same_content, same_type] {
        for (counterpart, reference_child) in counterparts.iter_mut().zip(reference) {
            if counterpart.is_some() {
                continue;
            }
            let candidate = debar.iter().zip(taken.iter_mut()).enumerate().find(
                |(_, (debar_child, already_taken))| {
                    !**already_taken && belong_together(reference_child, debar_child)
                },
            );
            if let Some((index, (_, already_taken))) = candidate {
                *already_taken = true;
                *counterpart = Some(index);
            }
        }
    }
    let unpaired_in_debar = taken
        .iter()
        .enumerate()
        .filter(|(_, already_taken)| !**already_taken)
        .map(|(index, _)| index)
        .collect();
    Pairing {
        counterparts,
        unpaired_in_debar,
    }
}
