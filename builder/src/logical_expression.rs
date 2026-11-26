use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogicalExpression {
    Subsignature {
        index: usize,
        condition: Option<CountCondition>,
    },
    Both(Box<LogicalExpression>, Box<LogicalExpression>),
    Either(Box<LogicalExpression>, Box<LogicalExpression>),
    Block {
        inner: Box<LogicalExpression>,
        condition: CountCondition,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountCondition {
    pub comparison: CountComparison,
    pub distinct_subsignatures: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountComparison {
    Exactly(u32),
    MoreThan(u32),
    FewerThan(u32),
}

impl CountComparison {
    fn holds_for(self, matches: u64) -> bool {
        match self {
            Self::Exactly(expected) => matches == u64::from(expected),
            Self::MoreThan(bound) => matches > u64::from(bound),
            Self::FewerThan(bound) => matches < u64::from(bound),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MalformedExpression(pub String);

impl fmt::Display for MalformedExpression {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "malformed logical expression {:?}", self.0)
    }
}

pub type MatchCounts = BTreeMap<usize, u32>;

const MOST_PLANS_KEPT: usize = 128;

struct Evaluation {
    satisfied: bool,
    matches: u64,
    matched_subsignatures: BTreeSet<usize>,
}

impl Evaluation {
    fn unsatisfied() -> Self {
        Self {
            satisfied: false,
            matches: 0,
            matched_subsignatures: BTreeSet::new(),
        }
    }
}

impl LogicalExpression {
    pub fn parse(text: &str) -> Result<Self, MalformedExpression> {
        let compact: Vec<u8> = text
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        parse_expression(&compact).ok_or_else(|| MalformedExpression(text.to_owned()))
    }

    #[must_use]
    pub fn single_subsignature() -> Self {
        Self::Subsignature {
            index: 0,
            condition: None,
        }
    }

    #[must_use]
    pub fn is_satisfied_by(&self, counts: &MatchCounts) -> bool {
        self.evaluate(counts).satisfied
    }

    #[must_use]
    pub fn subsignature_indices(&self) -> BTreeSet<usize> {
        let mut indices = BTreeSet::new();
        self.collect_indices(&mut indices);
        indices
    }

    #[must_use]
    pub fn satisfying_plans(&self) -> Vec<MatchCounts> {
        let mut plans: Vec<MatchCounts> = self
            .candidate_plans()
            .into_iter()
            .filter(|plan| self.is_satisfied_by(plan))
            .collect();
        plans.sort_by_key(|plan| plan.values().map(|count| u64::from(*count)).sum::<u64>());
        plans.dedup();
        plans
    }

    fn evaluate(&self, counts: &MatchCounts) -> Evaluation {
        match self {
            Self::Subsignature { index, condition } => {
                let matches = u64::from(counts.get(index).copied().unwrap_or(0));
                let satisfied = match condition {
                    Some(condition) => condition.comparison.holds_for(matches),
                    None => matches > 0,
                };
                if !satisfied {
                    return Evaluation::unsatisfied();
                }
                Evaluation {
                    satisfied,
                    matches,
                    matched_subsignatures: BTreeSet::from([*index]),
                }
            }
            Self::Both(left, right) | Self::Either(left, right) => {
                let left = left.evaluate(counts);
                let right = right.evaluate(counts);
                let satisfied = if matches!(self, Self::Both(..)) {
                    left.satisfied && right.satisfied
                } else {
                    left.satisfied || right.satisfied
                };
                if !satisfied {
                    return Evaluation::unsatisfied();
                }
                Evaluation {
                    satisfied,
                    matches: left.matches.saturating_add(right.matches),
                    matched_subsignatures: left
                        .matched_subsignatures
                        .union(&right.matched_subsignatures)
                        .copied()
                        .collect(),
                }
            }
            Self::Block { inner, condition } => {
                let inner = inner.evaluate(counts);
                let distinct = u32::try_from(inner.matched_subsignatures.len()).unwrap_or(u32::MAX);
                let satisfied = condition.comparison.holds_for(inner.matches)
                    && distinct >= condition.distinct_subsignatures;
                if !satisfied {
                    return Evaluation::unsatisfied();
                }
                Evaluation {
                    satisfied,
                    matches: inner.matches,
                    matched_subsignatures: BTreeSet::new(),
                }
            }
        }
    }

    fn collect_indices(&self, indices: &mut BTreeSet<usize>) {
        match self {
            Self::Subsignature { index, .. } => {
                indices.insert(*index);
            }
            Self::Both(left, right) | Self::Either(left, right) => {
                left.collect_indices(indices);
                right.collect_indices(indices);
            }
            Self::Block { inner, .. } => inner.collect_indices(indices),
        }
    }

    fn candidate_plans(&self) -> Vec<MatchCounts> {
        let mut plans = match self {
            Self::Subsignature { index, condition } => {
                let count = match condition.map(|condition| condition.comparison) {
                    None => Some(1),
                    Some(CountComparison::Exactly(expected)) => Some(expected),
                    Some(CountComparison::MoreThan(bound)) => bound.checked_add(1),
                    Some(CountComparison::FewerThan(bound)) => (bound > 0).then_some(0),
                };
                count.map_or_else(Vec::new, |count| vec![MatchCounts::from([(*index, count)])])
            }
            Self::Both(left, right) => {
                let right_plans = right.candidate_plans();
                left.candidate_plans()
                    .iter()
                    .flat_map(|left_plan| {
                        right_plans
                            .iter()
                            .map(|right_plan| merged(left_plan, right_plan))
                            .collect::<Vec<_>>()
                    })
                    .collect()
            }
            Self::Either(left, right) => {
                let mut plans = left.candidate_plans();
                plans.extend(right.candidate_plans());
                plans
            }
            Self::Block { inner, condition } => block_plans(inner, *condition),
        };
        plans.truncate(MOST_PLANS_KEPT);
        plans
    }
}

fn merged(left: &MatchCounts, right: &MatchCounts) -> MatchCounts {
    let mut plan = left.clone();
    for (index, count) in right {
        let entry = plan.entry(*index).or_insert(0);
        *entry = (*entry).max(*count);
    }
    plan
}

fn block_plans(inner: &LogicalExpression, condition: CountCondition) -> Vec<MatchCounts> {
    let leaves = inner.subsignature_indices();
    let all_absent: MatchCounts = leaves.iter().map(|index| (*index, 0)).collect();
    let required_matches = match condition.comparison {
        CountComparison::Exactly(0) | CountComparison::FewerThan(_)
            if condition.distinct_subsignatures == 0 =>
        {
            return vec![all_absent];
        }
        CountComparison::Exactly(expected) => expected,
        CountComparison::MoreThan(bound) => bound.saturating_add(1),
        CountComparison::FewerThan(_) => 1,
    };
    let mut plans = inner.candidate_plans();
    plans.push(MatchCounts::new());
    plans
        .into_iter()
        .map(|mut plan| {
            for index in &leaves {
                let distinct = plan.values().filter(|count| **count > 0).count();
                if u32::try_from(distinct).unwrap_or(u32::MAX) >= condition.distinct_subsignatures {
                    break;
                }
                plan.entry(*index)
                    .and_modify(|count| *count = (*count).max(1))
                    .or_insert(1);
            }
            let total: u32 = plan
                .values()
                .fold(0, |sum, count| sum.saturating_add(*count));
            if total < required_matches {
                let shortfall = required_matches.saturating_sub(total);
                let grown = plan
                    .iter()
                    .find(|(_, count)| **count > 0)
                    .map(|(index, _)| *index)
                    .or_else(|| leaves.first().copied());
                if let Some(index) = grown {
                    let count = plan.entry(index).or_insert(0);
                    *count = count.saturating_add(shortfall);
                }
            }
            plan
        })
        .collect()
}

fn parse_expression(text: &[u8]) -> Option<LogicalExpression> {
    if let Some(position) = top_level_operator(text, OperatorChoice::First) {
        return binary(text, position);
    }
    if text.first() == Some(&b'(') {
        let closing = matching_parenthesis(text)?;
        let inner = parse_group(text.get(1..closing)?)?;
        let rest = text.get(closing.checked_add(1)?..)?;
        if rest.is_empty() {
            return Some(inner);
        }
        return Some(LogicalExpression::Block {
            inner: Box::new(inner),
            condition: parse_condition(rest)?,
        });
    }
    let digits_end = text
        .iter()
        .position(|byte| !byte.is_ascii_digit())
        .unwrap_or(text.len());
    let index = std::str::from_utf8(text.get(..digits_end)?)
        .ok()?
        .parse()
        .ok()?;
    let rest = text.get(digits_end..)?;
    let condition = if rest.is_empty() {
        None
    } else {
        Some(parse_condition(rest)?)
    };
    Some(LogicalExpression::Subsignature { index, condition })
}

fn parse_group(inner: &[u8]) -> Option<LogicalExpression> {
    match top_level_operator(inner, OperatorChoice::Last) {
        Some(position) => binary(inner, position),
        None => parse_expression(inner),
    }
}

fn binary(text: &[u8], position: usize) -> Option<LogicalExpression> {
    let left = Box::new(parse_expression(text.get(..position)?)?);
    let right = Box::new(parse_expression(text.get(position.checked_add(1)?..)?)?);
    match text.get(position)? {
        b'&' => Some(LogicalExpression::Both(left, right)),
        _ => Some(LogicalExpression::Either(left, right)),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OperatorChoice {
    First,
    Last,
}

fn top_level_operator(text: &[u8], choice: OperatorChoice) -> Option<usize> {
    let mut depth: usize = 0;
    let mut found = None;
    for (position, byte) in text.iter().enumerate() {
        match byte {
            b'(' => depth = depth.saturating_add(1),
            b')' => depth = depth.saturating_sub(1),
            b'&' | b'|' if depth == 0 => {
                found = Some(position);
                if choice == OperatorChoice::First {
                    return found;
                }
            }
            _ => {}
        }
    }
    found
}

fn matching_parenthesis(text: &[u8]) -> Option<usize> {
    let mut depth: usize = 0;
    for (position, byte) in text.iter().enumerate() {
        match byte {
            b'(' => depth = depth.saturating_add(1),
            b')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(position);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_condition(text: &[u8]) -> Option<CountCondition> {
    let (symbol, numbers) = text.split_first()?;
    let numbers = std::str::from_utf8(numbers).ok()?;
    let (count, distinct) = match numbers.split_once(',') {
        Some((count, distinct)) => (count.parse().ok()?, distinct.parse().ok()?),
        None => (numbers.parse().ok()?, 0),
    };
    let comparison = match symbol {
        b'=' => CountComparison::Exactly(count),
        b'>' => CountComparison::MoreThan(count),
        b'<' => CountComparison::FewerThan(count),
        _ => return None,
    };
    Some(CountCondition {
        comparison,
        distinct_subsignatures: distinct,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(pairs: &[(usize, u32)]) -> MatchCounts {
        pairs.iter().copied().collect()
    }

    fn holds(expression: &str, pairs: &[(usize, u32)]) -> bool {
        LogicalExpression::parse(expression)
            .unwrap()
            .is_satisfied_by(&counts(pairs))
    }

    #[test]
    fn and_or_and_parentheses_combine_subsignatures() {
        assert!(holds("(0&1)|2", &[(2, 1)]));
        assert!(holds("(0&1)|2", &[(0, 1), (1, 1)]));
        assert!(!holds("(0&1)|2", &[(0, 1)]));
    }

    #[test]
    fn an_unparenthesised_chain_splits_at_its_first_operator() {
        assert!(holds("0&1|2", &[(0, 1), (2, 1)]));
        assert!(!holds("0&1|2", &[(2, 1)]));
    }

    #[test]
    fn a_parenthesised_chain_splits_at_its_last_operator() {
        assert!(holds("(0&1|2)", &[(2, 1)]));
    }

    #[test]
    fn counts_compare_a_single_subsignature() {
        assert!(holds("0>2", &[(0, 3)]));
        assert!(!holds("0>2", &[(0, 2)]));
        assert!(holds("0=0&1", &[(1, 1)]));
        assert!(!holds("0=0&1", &[(0, 1), (1, 1)]));
        assert!(holds("0<2&1", &[(0, 1), (1, 1)]));
    }

    #[test]
    fn spaces_inside_the_expression_are_ignored() {
        assert!(holds("0 & 1 > 2", &[(0, 1), (1, 3)]));
    }

    #[test]
    fn a_block_count_sums_its_matches_and_may_demand_distinct_subsignatures() {
        assert!(holds("(0|1|2)>5,2", &[(0, 5), (1, 1)]));
        assert!(!holds("(0|1|2)>5,2", &[(0, 6)]));
        assert!(holds("(0|1)=2", &[(0, 1), (1, 1)]));
    }

    #[test]
    fn plans_satisfy_the_expression_with_fewest_matches_first() {
        for expression in [
            "0",
            "0&1&2",
            "(0|1|2)>5,2",
            "0&1=0",
            "((0|1)&(2|3))&4",
            "0 & 1 > 200",
            "(0&1)=0&2",
            "(0|1)>1,2&2",
        ] {
            let parsed = LogicalExpression::parse(expression).unwrap();
            let plans = parsed.satisfying_plans();
            assert!(!plans.is_empty(), "{expression}");
            assert!(parsed.is_satisfied_by(&plans[0]), "{expression}");
        }
        let plans = LogicalExpression::parse("0|1&2")
            .unwrap()
            .satisfying_plans();
        assert_eq!(plans[0], counts(&[(0, 1)]));
    }

    #[test]
    fn malformed_expressions_are_rejected() {
        for expression in ["", "(0&1", "0&", "a", "0>", "0#1"] {
            assert!(
                LogicalExpression::parse(expression).is_err(),
                "{expression}"
            );
        }
    }
}
