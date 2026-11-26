use std::cell::Cell;
use std::collections::BTreeSet;

use crate::body_pattern::{CharacterClassTest, PatternElement};
use crate::pattern_offset::PatternOffset;
use crate::pattern_rendering::split_edge_classes;
use crate::pattern_signature::{BodySubsignature, CharacterWidth};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchExhausted;

const SEARCH_STEP_BUDGET: u64 = 20_000_000;

type SearchResult = Result<bool, SearchExhausted>;

pub fn count_matches(view: &[u8], subsignature: &BodySubsignature) -> Result<u32, SearchExhausted> {
    let steps_left = Cell::new(SEARCH_STEP_BUDGET);
    let encodings: &[Encoding] = match subsignature.modifiers.width {
        CharacterWidth::NarrowOrWide => &[Encoding::Narrow, Encoding::Wide],
        CharacterWidth::Wide => &[Encoding::Wide],
        CharacterWidth::Narrow => &[Encoding::Narrow],
    };
    let mut starts = BTreeSet::new();
    for encoding in encodings {
        let search = Search {
            view,
            subsignature,
            encoding: *encoding,
            steps_left: &steps_left,
        };
        for start in candidate_starts(view.len(), &subsignature.offset)
            .into_iter()
            .flatten()
        {
            if search.matches_at(start)? {
                starts.insert(start);
            }
        }
    }
    Ok(u32::try_from(starts.len()).unwrap_or(u32::MAX))
}

fn candidate_starts(
    length: usize,
    offset: &PatternOffset,
) -> Option<std::ops::RangeInclusive<usize>> {
    match offset {
        PatternOffset::Anywhere => Some(0..=length.checked_sub(1)?),
        PatternOffset::FromStart { distance, shift } => {
            Some(*distance..=distance.saturating_add(*shift))
        }
        PatternOffset::BeforeEnd { distance, shift } => {
            let start = length.checked_sub(*distance)?;
            Some(start..=start.saturating_add(*shift))
        }
        PatternOffset::ExecutableAnchor(_) | PatternOffset::VersionInfo => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Narrow,
    Wide,
}

struct Search<'search> {
    view: &'search [u8],
    subsignature: &'search BodySubsignature,
    encoding: Encoding,
    steps_left: &'search Cell<u64>,
}

impl Search<'_> {
    fn matches_at(&self, start: usize) -> SearchResult {
        if start >= self.view.len() {
            return Ok(false);
        }
        let (leading, core, trailing) = split_edge_classes(&self.subsignature.pattern.elements);
        let previous = start
            .checked_sub(1)
            .and_then(|index| self.view.get(index))
            .copied();
        if leading.is_some_and(|test| !test.accepts_before(previous)) {
            return Ok(false);
        }
        if self.subsignature.modifiers.matches_whole_words()
            && previous.is_some_and(|byte| byte.is_ascii_alphanumeric())
        {
            return Ok(false);
        }
        self.sequence(core, start, &|end| Ok(self.ends_well(end, trailing)))
    }

    fn ends_well(&self, end: usize, trailing: Option<CharacterClassTest>) -> bool {
        let following = self.view.get(end..).unwrap_or_default();
        if trailing.is_some_and(|test| !test.accepts_after(following)) {
            return false;
        }
        !(self.subsignature.modifiers.matches_whole_words()
            && following.first().is_some_and(u8::is_ascii_alphanumeric))
    }

    fn sequence(
        &self,
        elements: &[PatternElement],
        position: usize,
        rest: &dyn Fn(usize) -> SearchResult,
    ) -> SearchResult {
        self.spend_step()?;
        let Some((first, remaining)) = elements.split_first() else {
            return rest(position);
        };
        let continue_at = |next: usize| self.sequence(remaining, next, rest);
        let next_single = position.saturating_add(1);
        match first {
            PatternElement::Literal(byte) => match self.literal_end(position, *byte) {
                Some(next) => continue_at(next),
                None => Ok(false),
            },
            PatternElement::PartialByte(partial) => {
                if self
                    .byte_at(position)
                    .is_some_and(|byte| partial.accepts(byte))
                {
                    continue_at(next_single)
                } else {
                    Ok(false)
                }
            }
            PatternElement::AnyByte => {
                if position < self.view.len() {
                    continue_at(next_single)
                } else {
                    Ok(false)
                }
            }
            PatternElement::CharacterClass(test) => {
                if self
                    .byte_at(position)
                    .is_some_and(|byte| test.accepts_inside(byte))
                {
                    continue_at(next_single)
                } else {
                    Ok(false)
                }
            }
            PatternElement::Gap(gap) => {
                let available = self.view.len().saturating_sub(position);
                let longest = gap.maximum.unwrap_or(available).min(available);
                for length in gap.minimum..=longest {
                    if continue_at(position.saturating_add(length))? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            PatternElement::Alternatives(alternatives) if alternatives.negated => {
                let width = alternatives.choices.first().map_or(0, Vec::len);
                let end = position.saturating_add(match self.encoding {
                    Encoding::Narrow => width,
                    Encoding::Wide => width.saturating_mul(2),
                });
                if end > self.view.len() {
                    return Ok(false);
                }
                for choice in &alternatives.choices {
                    if self.sequence(choice, position, &|choice_end| Ok(choice_end == end))? {
                        return Ok(false);
                    }
                }
                continue_at(end)
            }
            PatternElement::Alternatives(alternatives) => {
                for choice in &alternatives.choices {
                    if self.sequence(choice, position, &continue_at)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }

    fn literal_end(&self, position: usize, literal: u8) -> Option<usize> {
        let byte = self.byte_at(position)?;
        let equal = byte == literal
            || (self.subsignature.modifiers.ignores_case() && byte.eq_ignore_ascii_case(&literal));
        if !equal {
            return None;
        }
        let next = position.checked_add(1)?;
        match self.encoding {
            Encoding::Narrow => Some(next),
            Encoding::Wide => (self.byte_at(next)? == 0).then(|| next.checked_add(1))?,
        }
    }

    fn byte_at(&self, position: usize) -> Option<u8> {
        self.view.get(position).copied()
    }

    fn spend_step(&self) -> Result<(), SearchExhausted> {
        let left = self
            .steps_left
            .get()
            .checked_sub(1)
            .ok_or(SearchExhausted)?;
        self.steps_left.set(left);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body_pattern::BodyPattern;
    use crate::pattern_signature::{LetterCase, MatchExtent, SubsignatureModifiers};

    fn subsignature(
        offset: PatternOffset,
        pattern: &str,
        modifiers: SubsignatureModifiers,
    ) -> BodySubsignature {
        BodySubsignature {
            offset,
            pattern: BodyPattern::parse(pattern).unwrap(),
            modifiers,
        }
    }

    fn count(view: &[u8], pattern: &str) -> u32 {
        count_matches(
            view,
            &subsignature(
                PatternOffset::Anywhere,
                pattern,
                SubsignatureModifiers::default(),
            ),
        )
        .unwrap()
    }

    #[test]
    fn each_distinct_start_counts_once() {
        assert_eq!(count(b"ABxABxAB", "4142"), 3);
        assert_eq!(count(b"AAAA", "41*41"), 3);
    }

    #[test]
    fn wildcards_gaps_and_alternatives_match_what_they_describe() {
        assert_eq!(count(b"A..B", "41{0-1}42"), 0);
        assert_eq!(count(b"A..B", "41{2-3}42"), 1);
        assert_eq!(count(b"AzC", "41(7a|79)43"), 1);
        assert_eq!(count(b"AzC", "41!(7a|79)43"), 0);
        assert_eq!(count(b"AqC", "41!(7a|79)43"), 1);
        assert_eq!(count(b"\x4f", "4?"), 1);
    }

    #[test]
    fn offsets_restrict_where_a_match_may_start() {
        let at_two = subsignature(
            PatternOffset::FromStart {
                distance: 2,
                shift: 0,
            },
            "4142",
            SubsignatureModifiers::default(),
        );
        assert_eq!(count_matches(b"ABAB", &at_two).unwrap(), 1);
        assert_eq!(count_matches(b"xABx", &at_two).unwrap(), 0);
        let before_end = subsignature(
            PatternOffset::BeforeEnd {
                distance: 3,
                shift: 0,
            },
            "4142",
            SubsignatureModifiers::default(),
        );
        assert_eq!(count_matches(b"ABxABx", &before_end).unwrap(), 1);
    }

    #[test]
    fn modifiers_change_what_counts_as_a_match() {
        let nocase = SubsignatureModifiers {
            letter_case: LetterCase::Insensitive,
            ..SubsignatureModifiers::default()
        };
        let wide = SubsignatureModifiers {
            width: CharacterWidth::Wide,
            ..SubsignatureModifiers::default()
        };
        let fullword = SubsignatureModifiers {
            extent: MatchExtent::WholeWord,
            ..SubsignatureModifiers::default()
        };
        let both = SubsignatureModifiers {
            width: CharacterWidth::NarrowOrWide,
            ..SubsignatureModifiers::default()
        };
        assert_eq!(
            count_matches(
                b"ab",
                &subsignature(PatternOffset::Anywhere, "4142", nocase)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            count_matches(
                b"A\0B\0",
                &subsignature(PatternOffset::Anywhere, "4142", wide)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            count_matches(b"AB", &subsignature(PatternOffset::Anywhere, "4142", wide)).unwrap(),
            0
        );
        assert_eq!(
            count_matches(
                b"AB A\0B\0",
                &subsignature(PatternOffset::Anywhere, "4142", both)
            )
            .unwrap(),
            2
        );
        assert_eq!(
            count_matches(
                b"xAB AB",
                &subsignature(PatternOffset::Anywhere, "4142", fullword)
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn edge_character_classes_test_the_neighbouring_bytes() {
        assert_eq!(count(b"xAB AB", "(B)4142"), 1);
        assert_eq!(count(b"AB.AB=", "4142(B)"), 1);
        assert_eq!(count(b"A\nB", "41(L)42"), 1);
    }
}
