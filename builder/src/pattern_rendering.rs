use crate::body_pattern::{Alternatives, CharacterClassTest, PatternElement};
use crate::pattern_signature::{BodySubsignature, CharacterWidth, SubsignatureModifiers};
use crate::text_normalisation::{survives_html_normalisation, survives_text_normalisation};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedPiece {
    pub leading_context: Option<u8>,
    pub core: Vec<u8>,
    pub trailing_context: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteAllowance {
    Any,
    NormalisedText,
    NormalisedHtml,
}

impl ByteAllowance {
    #[must_use]
    pub fn allows(self, bytes: &[u8]) -> bool {
        match self {
            Self::Any => true,
            Self::NormalisedText => survives_text_normalisation(bytes),
            Self::NormalisedHtml => survives_html_normalisation(bytes),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderError {
    ByteNotInNormalisedForm,
    NoSequenceOutsideNegatedSet,
}

const FALLBACK_BYTES: &[u8] = b"xq.z0_-#~ \x00\xff";

#[derive(Clone, Copy)]
struct RenderSettings {
    filler: u8,
    allowance: ByteAllowance,
    modifiers: SubsignatureModifiers,
}

pub fn render_subsignature(
    subsignature: &BodySubsignature,
    filler: u8,
    allowance: ByteAllowance,
) -> Result<RenderedPiece, RenderError> {
    let settings = RenderSettings {
        filler,
        allowance,
        modifiers: subsignature.modifiers,
    };
    let (leading, core_elements, trailing) = split_edge_classes(&subsignature.pattern.elements);
    let mut core = Vec::new();
    render_elements(core_elements, settings, &mut core)?;
    if !allowance.allows(&core) {
        return Err(RenderError::ByteNotInNormalisedForm);
    }
    let fullword_context = subsignature.modifiers.matches_whole_words().then_some(b' ');
    Ok(RenderedPiece {
        leading_context: leading
            .map(CharacterClassTest::satisfying_byte)
            .or(fullword_context),
        core,
        trailing_context: trailing
            .map(CharacterClassTest::satisfying_byte)
            .or(fullword_context),
    })
}

#[must_use]
pub fn split_edge_classes(
    elements: &[PatternElement],
) -> (
    Option<CharacterClassTest>,
    &[PatternElement],
    Option<CharacterClassTest>,
) {
    let (leading, rest) = match elements.split_first() {
        Some((PatternElement::CharacterClass(test), rest)) => (Some(*test), rest),
        _ => (None, elements),
    };
    match rest.split_last() {
        Some((PatternElement::CharacterClass(test), core)) => (leading, core, Some(*test)),
        _ => (leading, rest, None),
    }
}

fn render_elements(
    elements: &[PatternElement],
    settings: RenderSettings,
    output: &mut Vec<u8>,
) -> Result<(), RenderError> {
    for element in elements {
        match element {
            PatternElement::Literal(byte) => push_literal(*byte, settings, output),
            PatternElement::PartialByte(partial) => {
                let byte = std::iter::once(settings.filler)
                    .chain(FALLBACK_BYTES.iter().copied())
                    .chain(0..=u8::MAX)
                    .map(|filler| partial.completed_with(filler))
                    .find(|byte| settings.allowance.allows(&[*byte]))
                    .ok_or(RenderError::ByteNotInNormalisedForm)?;
                output.push(byte);
            }
            PatternElement::AnyByte => output.push(settings.filler),
            PatternElement::Gap(gap) => {
                output.extend(std::iter::repeat_n(settings.filler, gap.minimum));
            }
            PatternElement::CharacterClass(test) => output.push(test.satisfying_byte()),
            PatternElement::Alternatives(alternatives) if alternatives.negated => {
                output.extend(outside_negated_set(alternatives, settings)?);
            }
            PatternElement::Alternatives(alternatives) => {
                output.extend(first_renderable_choice(alternatives, settings)?);
            }
        }
    }
    Ok(())
}

fn push_literal(byte: u8, settings: RenderSettings, output: &mut Vec<u8>) {
    let byte = if settings.modifiers.ignores_case() && settings.allowance != ByteAllowance::Any {
        byte.to_ascii_lowercase()
    } else {
        byte
    };
    output.push(byte);
    if settings.modifiers.width == CharacterWidth::Wide {
        output.push(0);
    }
}

fn first_renderable_choice(
    alternatives: &Alternatives,
    settings: RenderSettings,
) -> Result<Vec<u8>, RenderError> {
    let mut last_error = RenderError::ByteNotInNormalisedForm;
    for choice in &alternatives.choices {
        let mut rendered = Vec::new();
        match render_elements(choice, settings, &mut rendered) {
            Ok(()) if settings.allowance.allows(&rendered) => return Ok(rendered),
            Ok(()) => {}
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

fn outside_negated_set(
    alternatives: &Alternatives,
    settings: RenderSettings,
) -> Result<Vec<u8>, RenderError> {
    let length = alternatives.choices.first().map_or(0, Vec::len);
    std::iter::once(settings.filler)
        .chain(FALLBACK_BYTES.iter().copied())
        .chain(0..=u8::MAX)
        .map(|byte| vec![byte; length])
        .find(|candidate| {
            settings.allowance.allows(candidate)
                && !alternatives
                    .choices
                    .iter()
                    .any(|choice| choice_accepts(choice, candidate, settings.modifiers))
        })
        .map(|candidate| {
            if settings.modifiers.width == CharacterWidth::Wide {
                candidate.iter().flat_map(|byte| [*byte, 0]).collect()
            } else {
                candidate
            }
        })
        .ok_or(RenderError::NoSequenceOutsideNegatedSet)
}

fn choice_accepts(
    choice: &[PatternElement],
    candidate: &[u8],
    modifiers: SubsignatureModifiers,
) -> bool {
    choice.len() == candidate.len()
        && choice
            .iter()
            .zip(candidate)
            .all(|(element, byte)| match element {
                PatternElement::Literal(literal) => {
                    literal == byte
                        || (modifiers.ignores_case() && literal.eq_ignore_ascii_case(byte))
                }
                PatternElement::PartialByte(partial) => partial.accepts(*byte),
                _ => true,
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body_pattern::BodyPattern;
    use crate::pattern_offset::PatternOffset;

    fn subsignature(pattern: &str, modifiers: SubsignatureModifiers) -> BodySubsignature {
        BodySubsignature {
            offset: PatternOffset::Anywhere,
            pattern: BodyPattern::parse(pattern).unwrap(),
            modifiers,
        }
    }

    fn render(pattern: &str) -> RenderedPiece {
        render_subsignature(
            &subsignature(pattern, SubsignatureModifiers::default()),
            b'.',
            ByteAllowance::Any,
        )
        .unwrap()
    }

    #[test]
    fn wildcards_and_gaps_take_the_filler_at_their_shortest() {
        assert_eq!(render("41??42{2-5}43*44{-3}45").core, b"A.B..CDE".to_vec());
    }

    #[test]
    fn half_byte_wildcards_keep_their_known_half() {
        assert_eq!(render("4?").core, vec![0x4e]);
        assert_eq!(render("?1").core, vec![0x21]);
    }

    #[test]
    fn alternatives_take_their_first_choice_and_negations_a_byte_outside_the_set() {
        assert_eq!(render("(4142|43)").core, b"AB".to_vec());
        assert_eq!(render("41!(2e|78)").core, b"Aq".to_vec());
    }

    #[test]
    fn edge_character_classes_become_context_around_the_core() {
        let piece = render("(B)4142(L)");
        assert_eq!(piece.leading_context, Some(b' '));
        assert_eq!(piece.core, b"AB".to_vec());
        assert_eq!(piece.trailing_context, Some(b'\n'));
    }

    #[test]
    fn wide_subsignatures_interleave_zero_bytes_after_literals_only() {
        let modifiers = SubsignatureModifiers {
            width: CharacterWidth::Wide,
            ..SubsignatureModifiers::default()
        };
        let piece =
            render_subsignature(&subsignature("41??42", modifiers), b'.', ByteAllowance::Any)
                .unwrap();
        assert_eq!(piece.core, b"A\0.B\0".to_vec());
    }

    #[test]
    fn normalised_text_accepts_only_bytes_the_normaliser_leaves_alone() {
        let plain = SubsignatureModifiers::default();
        let nocase = SubsignatureModifiers {
            letter_case: crate::pattern_signature::LetterCase::Insensitive,
            ..plain
        };
        assert!(
            render_subsignature(
                &subsignature("4142", plain),
                b'x',
                ByteAllowance::NormalisedText
            )
            .is_err()
        );
        assert_eq!(
            render_subsignature(
                &subsignature("4142", nocase),
                b'x',
                ByteAllowance::NormalisedText
            )
            .unwrap()
            .core,
            b"ab".to_vec()
        );
        assert!(
            render_subsignature(
                &subsignature("610a62", plain),
                b'x',
                ByteAllowance::NormalisedText
            )
            .is_err()
        );
    }
}
