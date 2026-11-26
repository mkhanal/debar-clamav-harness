use std::fmt;

use crate::input_layout::{LayoutError, LayoutFrame, PieceAnchor, PlacedPiece, lay_out};
use crate::logical_expression::MatchCounts;
use crate::pattern_offset::PatternOffset;
use crate::pattern_rendering::{ByteAllowance, RenderError, render_subsignature};
use crate::pattern_search::count_matches;
use crate::pattern_signature::{BodySubsignature, PatternSignature, Subsignature};
use crate::target_type::{ContainerKind, InputRoute, TargetType};
use crate::text_normalisation::normalised_text;

pub const PINNED_FUNCTIONALITY_LEVEL: u64 = 234;
const SMALLEST_SCANNED_LENGTH: usize = 6;
const TYPE_RECOGNITION_WINDOW: usize = 1024;
const HTML_TAGS_TYPING_A_PAGE: &[&[u8]] = &[
    b"html", b"head", b"script", b"iframe", b"img", b"object", b"table",
];
const BYTES_ENDING_A_TAG_NAME: &[u8] = b"> \t\n\x0b\x0c\r/";
const SERVER_PAGE_OPENING: &[u8] = b"<%@ LANGUAGE =";
const MAGIC_OF_UNSCANNED_TYPES: &[&[u8]] = &[
    b"ID3",
    b"OggS",
    b".RMF",
    b"\xff\xfb\x90",
    b"SQLite format 3\0",
];
const HTML_CONTENT_START: usize = 1;
const LARGEST_BUILT_LENGTH: usize = 1 << 20;
const PLANS_TRIED: usize = 8;
const MAIL_HEADER: &[u8] = b"Subject: debar\n\n";
const HTML_OPENING: &[u8] = b"<html><body>";
const HTML_CLOSING: &[u8] = b"</body></html>";
const RAW_FILLERS: &[u8] = b".\0z";
const TEXT_FILLERS: &[u8] = b"xq.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NotBuiltReason {
    OutsideFunctionalityLevel,
    TargetNotLoaded,
    NeedsContainer(ContainerKind),
    ContainerCondition,
    IntermediatesCondition,
    HandlerTypeRescan,
    ExecutableHeaderCondition,
    IconGroupCondition,
    NeedsSubsignature(UnbuildableSubsignature),
    OffsetInNormalisedHtml,
    CannotSurviveNormalisation,
    TypedHtmlBeforeRawScan,
    TypedAsUnscanned,
    NoSequenceOutsideNegatedSet,
    ConflictingOffsets,
    EndOffsetShorterThanPattern,
    FileSizeUnreachable,
    TooLarge,
    ExpressionUnsatisfiable,
    SelfCheckFailed,
    SelfCheckExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnbuildableSubsignature {
    RegularExpression,
    ByteComparison,
    Macro,
    ImageFuzzyHash,
    ExecutableOffset,
    VersionInfoOffset,
}

impl fmt::Display for NotBuiltReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutsideFunctionalityLevel => write!(
                formatter,
                "not loaded at functionality level {PINNED_FUNCTIONALITY_LEVEL}"
            ),
            Self::TargetNotLoaded => formatter.write_str("target type not loaded"),
            Self::NeedsContainer(kind) => write!(formatter, "needs {kind} container"),
            Self::ContainerCondition => formatter.write_str("needs Container: condition"),
            Self::IntermediatesCondition => formatter.write_str("needs Intermediates: condition"),
            Self::HandlerTypeRescan => formatter.write_str("HandlerType re-scan, no alert"),
            Self::ExecutableHeaderCondition => {
                formatter.write_str("needs executable header condition")
            }
            Self::IconGroupCondition => formatter.write_str("needs icon group condition"),
            Self::NeedsSubsignature(kind) => write!(formatter, "needs {kind}"),
            Self::OffsetInNormalisedHtml => formatter.write_str("offset into normalised HTML"),
            Self::CannotSurviveNormalisation => {
                formatter.write_str("bytes cannot appear in normalised output")
            }
            Self::TypedHtmlBeforeRawScan => formatter.write_str("typed HTML before its raw scan"),
            Self::TypedAsUnscanned => formatter.write_str("typed as a type that is never scanned"),
            Self::NoSequenceOutsideNegatedSet => {
                formatter.write_str("no bytes outside a negated set")
            }
            Self::ConflictingOffsets => formatter.write_str("subsignature offsets conflict"),
            Self::EndOffsetShorterThanPattern => {
                formatter.write_str("end offset shorter than its pattern")
            }
            Self::FileSizeUnreachable => formatter.write_str("FileSize: condition unreachable"),
            Self::TooLarge => formatter.write_str("built input too large"),
            Self::ExpressionUnsatisfiable => {
                formatter.write_str("logical expression not satisfiable by the builder")
            }
            Self::SelfCheckFailed => formatter.write_str("built input fails its own check"),
            Self::SelfCheckExhausted => formatter.write_str("own check ran out of steps"),
        }
    }
}

impl fmt::Display for UnbuildableSubsignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RegularExpression => "regular-expression subsignature",
            Self::ByteComparison => "byte-comparison subsignature",
            Self::Macro => "macro subsignature",
            Self::ImageFuzzyHash => "image fuzzy hash subsignature",
            Self::ExecutableOffset => "executable offset (EP, Sx, SL, SE)",
            Self::VersionInfoOffset => "version-info offset (VI)",
        })
    }
}

pub fn build_input(signature: &PatternSignature) -> Result<Vec<u8>, NotBuiltReason> {
    let route = admissible_route(signature)?;
    let plans = signature.expression.satisfying_plans();
    let mut first_failure = None;
    for plan in plans.iter().take(PLANS_TRIED) {
        let attempt = required_bodies(signature, plan).and_then(|bodies| {
            let mut last_failure = NotBuiltReason::ExpressionUnsatisfiable;
            for filler in fillers(route) {
                match build_with(signature, route, &bodies, *filler) {
                    Ok(bytes) => return Ok(bytes),
                    Err(reason) => last_failure = reason,
                }
            }
            Err(last_failure)
        });
        match attempt {
            Ok(bytes) => return Ok(bytes),
            Err(reason) => {
                first_failure.get_or_insert(reason);
            }
        }
    }
    Err(first_failure.unwrap_or(NotBuiltReason::ExpressionUnsatisfiable))
}

fn admissible_route(signature: &PatternSignature) -> Result<InputRoute, NotBuiltReason> {
    if !signature
        .functionality_levels
        .contains(PINNED_FUNCTIONALITY_LEVEL)
    {
        return Err(NotBuiltReason::OutsideFunctionalityLevel);
    }
    let target =
        TargetType::from_code(signature.target_code).ok_or(NotBuiltReason::TargetNotLoaded)?;
    let route = target.route();
    if let InputRoute::Container(kind) = route {
        return Err(NotBuiltReason::NeedsContainer(kind));
    }
    let conditions = &signature.conditions;
    if conditions.container.is_some() {
        return Err(NotBuiltReason::ContainerCondition);
    }
    if conditions.intermediates.is_some() {
        return Err(NotBuiltReason::IntermediatesCondition);
    }
    if conditions.handler_type.is_some() {
        return Err(NotBuiltReason::HandlerTypeRescan);
    }
    if conditions.executable_header.is_some() {
        return Err(NotBuiltReason::ExecutableHeaderCondition);
    }
    if conditions.icon_group.is_some() {
        return Err(NotBuiltReason::IconGroupCondition);
    }
    Ok(route)
}

fn required_bodies<'signature>(
    signature: &'signature PatternSignature,
    plan: &MatchCounts,
) -> Result<Vec<(&'signature BodySubsignature, u32)>, NotBuiltReason> {
    plan.iter()
        .filter(|(_, count)| **count > 0)
        .map(|(index, count)| {
            let body = match signature.subsignatures.get(*index) {
                Some(Subsignature::Body(body)) => body,
                Some(other) => return Err(NotBuiltReason::NeedsSubsignature(unbuildable(other))),
                None => return Err(NotBuiltReason::ExpressionUnsatisfiable),
            };
            match body.offset {
                PatternOffset::ExecutableAnchor(_) => Err(NotBuiltReason::NeedsSubsignature(
                    UnbuildableSubsignature::ExecutableOffset,
                )),
                PatternOffset::VersionInfo => Err(NotBuiltReason::NeedsSubsignature(
                    UnbuildableSubsignature::VersionInfoOffset,
                )),
                PatternOffset::Anywhere
                | PatternOffset::FromStart { .. }
                | PatternOffset::BeforeEnd { .. } => Ok((body, *count)),
            }
        })
        .collect()
}

fn unbuildable(subsignature: &Subsignature) -> UnbuildableSubsignature {
    match subsignature {
        Subsignature::RegularExpression | Subsignature::Body(_) => {
            UnbuildableSubsignature::RegularExpression
        }
        Subsignature::ByteComparison => UnbuildableSubsignature::ByteComparison,
        Subsignature::Macro => UnbuildableSubsignature::Macro,
        Subsignature::ImageFuzzyHash => UnbuildableSubsignature::ImageFuzzyHash,
    }
}

fn fillers(route: InputRoute) -> &'static [u8] {
    match route {
        InputRoute::NormalisedText | InputRoute::NormalisedHtml => TEXT_FILLERS,
        InputRoute::RawBytes | InputRoute::MailMessage | InputRoute::Container(_) => RAW_FILLERS,
    }
}

fn allowance(route: InputRoute) -> ByteAllowance {
    match route {
        InputRoute::NormalisedText => ByteAllowance::NormalisedText,
        InputRoute::NormalisedHtml => ByteAllowance::NormalisedHtml,
        InputRoute::RawBytes | InputRoute::MailMessage | InputRoute::Container(_) => {
            ByteAllowance::Any
        }
    }
}

fn build_with(
    signature: &PatternSignature,
    route: InputRoute,
    bodies: &[(&BodySubsignature, u32)],
    filler: u8,
) -> Result<Vec<u8>, NotBuiltReason> {
    let allowance = allowance(route);
    let mut placed = Vec::new();
    let mut built_length: usize = 0;
    for (body, count) in bodies {
        let anchor = match body.offset {
            PatternOffset::Anywhere => PieceAnchor::Floating,
            PatternOffset::FromStart { .. } | PatternOffset::BeforeEnd { .. }
                if route == InputRoute::NormalisedHtml =>
            {
                return Err(NotBuiltReason::OffsetInNormalisedHtml);
            }
            PatternOffset::FromStart { distance, .. } => PieceAnchor::FromStart(distance),
            PatternOffset::BeforeEnd { distance, .. } => PieceAnchor::BeforeEnd(distance),
            PatternOffset::ExecutableAnchor(_) | PatternOffset::VersionInfo => {
                return Err(NotBuiltReason::NeedsSubsignature(
                    UnbuildableSubsignature::ExecutableOffset,
                ));
            }
        };
        let piece = render_subsignature(body, filler, allowance).map_err(|error| match error {
            RenderError::ByteNotInNormalisedForm => NotBuiltReason::CannotSurviveNormalisation,
            RenderError::NoSequenceOutsideNegatedSet => NotBuiltReason::NoSequenceOutsideNegatedSet,
        })?;
        let copies = usize::try_from(*count).map_err(|_| NotBuiltReason::TooLarge)?;
        built_length =
            built_length.saturating_add(piece.core.len().saturating_add(3).saturating_mul(copies));
        if built_length > LARGEST_BUILT_LENGTH {
            return Err(NotBuiltReason::TooLarge);
        }
        placed.extend(std::iter::repeat_n(PlacedPiece { anchor, piece }, copies));
    }
    let framed = frame(route, &placed, filler, signature);
    let laid_out = match lay_out(&placed, &framed) {
        Err(LayoutError::FileSizeUnreachable) if framed.floating_start > 0 => lay_out(
            &placed,
            &LayoutFrame {
                floating_start: 0,
                ..framed
            },
        ),
        first_attempt => first_attempt,
    }
    .map_err(|error| match error {
        LayoutError::ConflictingOffsets => NotBuiltReason::ConflictingOffsets,
        LayoutError::EndOffsetShorterThanPattern => NotBuiltReason::EndOffsetShorterThanPattern,
        LayoutError::FileSizeUnreachable => NotBuiltReason::FileSizeUnreachable,
    })?;
    if !allowance.allows(&laid_out) {
        return Err(NotBuiltReason::CannotSurviveNormalisation);
    }
    if route == InputRoute::RawBytes && starts_like_a_web_page(&laid_out) {
        return Err(NotBuiltReason::TypedHtmlBeforeRawScan);
    }
    if MAGIC_OF_UNSCANNED_TYPES
        .iter()
        .any(|magic| laid_out.starts_with(magic))
    {
        return Err(NotBuiltReason::TypedAsUnscanned);
    }
    let (input, view) = match route {
        InputRoute::NormalisedText => {
            let view = normalised_text(&laid_out);
            (laid_out, view)
        }
        InputRoute::NormalisedHtml => (
            html_page_showing(&laid_out),
            [HTML_OPENING, &laid_out, HTML_CLOSING].concat(),
        ),
        InputRoute::RawBytes | InputRoute::MailMessage | InputRoute::Container(_) => {
            (laid_out.clone(), laid_out)
        }
    };
    if signature
        .expression
        .is_satisfied_by(&observed_counts(signature, &view)?)
    {
        Ok(input)
    } else {
        Err(NotBuiltReason::SelfCheckFailed)
    }
}

fn starts_like_a_web_page(bytes: &[u8]) -> bool {
    let window = bytes.get(..TYPE_RECOGNITION_WINDOW).unwrap_or(bytes);
    bytes.starts_with(SERVER_PAGE_OPENING)
        || window.iter().enumerate().any(|(position, byte)| {
            *byte == b'<'
                && HTML_TAGS_TYPING_A_PAGE.iter().any(|tag| {
                    let name_start = position.saturating_add(1);
                    let name_end = name_start.saturating_add(tag.len());
                    window
                        .get(name_start..name_end)
                        .is_some_and(|name| name.eq_ignore_ascii_case(tag))
                        && window
                            .get(name_end)
                            .is_some_and(|ending| BYTES_ENDING_A_TAG_NAME.contains(ending))
                })
        })
}

fn html_page_showing(text: &[u8]) -> Vec<u8> {
    let mut page = HTML_OPENING.to_vec();
    for byte in text {
        match byte {
            b'&' => page.extend_from_slice(b"&amp;"),
            b'<' => page.extend_from_slice(b"&lt;"),
            b'>' => page.extend_from_slice(b"&gt;"),
            _ => page.push(*byte),
        }
    }
    page.extend_from_slice(HTML_CLOSING);
    page
}

fn frame<'frame>(
    route: InputRoute,
    placed: &[PlacedPiece],
    filler: u8,
    signature: &PatternSignature,
) -> LayoutFrame<'frame> {
    let prefix: &[u8] = match route {
        InputRoute::MailMessage
            if !placed.iter().any(|piece| {
                matches!(piece.anchor, PieceAnchor::FromStart(distance) if distance < MAIL_HEADER.len())
            }) =>
        {
            MAIL_HEADER
        }
        InputRoute::RawBytes
        | InputRoute::NormalisedText
        | InputRoute::NormalisedHtml
        | InputRoute::MailMessage
        | InputRoute::Container(_) => b"",
    };
    LayoutFrame {
        prefix,
        suffix: b"",
        filler,
        floating_start: match route {
            InputRoute::RawBytes => TYPE_RECOGNITION_WINDOW,
            InputRoute::NormalisedHtml => HTML_CONTENT_START,
            InputRoute::NormalisedText | InputRoute::MailMessage | InputRoute::Container(_) => 0,
        },
        smallest_length: SMALLEST_SCANNED_LENGTH,
        file_size: signature.conditions.file_size,
    }
}

fn observed_counts(
    signature: &PatternSignature,
    view: &[u8],
) -> Result<MatchCounts, NotBuiltReason> {
    let mut counts = MatchCounts::new();
    for (index, subsignature) in signature.subsignatures.iter().enumerate() {
        if let Subsignature::Body(body) = subsignature {
            let count =
                count_matches(view, body).map_err(|_| NotBuiltReason::SelfCheckExhausted)?;
            counts.insert(index, count);
        }
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extended(line: &str) -> Result<Vec<u8>, NotBuiltReason> {
        build_input(&PatternSignature::parse_extended(line).unwrap())
    }

    fn logical(line: &str) -> Result<Vec<u8>, NotBuiltReason> {
        build_input(&PatternSignature::parse_logical(line).unwrap())
    }

    #[test]
    fn a_generic_signature_is_built_from_its_own_bytes_beyond_the_type_recognition_window() {
        let built = extended("T:0:*:414243").unwrap();
        assert!(built.ends_with(b".ABC"));
        assert!(built.len() > TYPE_RECOGNITION_WINDOW);
        assert!(
            built
                .iter()
                .take(TYPE_RECOGNITION_WINDOW)
                .all(|byte| *byte == b'.')
        );
    }

    #[test]
    fn offsets_are_honoured_by_padding() {
        assert_eq!(extended("T:0:8:4142").unwrap(), b"........AB".to_vec());
        assert_eq!(extended("T:0:EOF-10:4142").unwrap(), b"AB........".to_vec());
    }

    #[test]
    fn executable_targets_are_not_built_and_say_which_container_they_need() {
        assert_eq!(
            extended("T:1:*:4142"),
            Err(NotBuiltReason::NeedsContainer(
                ContainerKind::PortableExecutable
            ))
        );
        assert_eq!(
            logical("T;Engine:51-255,Target:0;0;EP+0:4142"),
            Err(NotBuiltReason::NeedsSubsignature(
                UnbuildableSubsignature::ExecutableOffset
            ))
        );
    }

    #[test]
    fn ascii_targets_are_built_as_text_that_normalises_to_the_pattern() {
        assert_eq!(extended("T:7:*:6576616c28").unwrap(), b"eval(x".to_vec());
        assert_eq!(
            extended("T:7:*:4556414c"),
            Err(NotBuiltReason::CannotSurviveNormalisation)
        );
    }

    #[test]
    fn logical_signatures_get_the_fewest_subsignatures_that_satisfy_them() {
        let built = logical("T;Engine:51-255,Target:0;0|1;41414141;42424242").unwrap();
        assert!(built.ends_with(b".AAAA"));
        assert!(!built.contains(&b'B'));
        let counted = logical("T;Engine:51-255,Target:0;0>2;41414141").unwrap();
        assert!(counted.ends_with(b".AAAA.AAAA.AAAA"));
    }

    #[test]
    fn a_subsignature_that_must_be_absent_stays_absent() {
        let built = logical("T;Engine:51-255,Target:0;0&1=0;4142;2e2e").unwrap();
        assert!(!built.windows(2).any(|pair| pair == b".."));
    }

    #[test]
    fn conditions_needing_a_container_or_unsupported_subsignatures_are_not_built() {
        assert_eq!(
            logical("T;Engine:51-255,Target:0,Container:CL_TYPE_ZIP;0;4142"),
            Err(NotBuiltReason::ContainerCondition)
        );
        assert_eq!(
            logical("T;Engine:81-255,Target:0;0&1;4142;0/abc/"),
            Err(NotBuiltReason::NeedsSubsignature(
                UnbuildableSubsignature::RegularExpression
            ))
        );
        assert_eq!(
            logical("T;Engine:1-20,Target:0;0;4142"),
            Err(NotBuiltReason::OutsideFunctionalityLevel)
        );
    }

    #[test]
    fn a_file_size_condition_is_met_by_padding() {
        let built = logical("T;Engine:51-255,Target:0,FileSize:100-200;0;4142").unwrap();
        assert_eq!(built.len(), 100);
    }

    #[test]
    fn generic_content_that_would_be_typed_html_before_its_raw_scan_is_not_built() {
        assert_eq!(
            logical("T;Engine:51-255,Target:0;0;0:3c5343524950543e"),
            Err(NotBuiltReason::TypedHtmlBeforeRawScan)
        );
    }

    #[test]
    fn content_typed_as_never_scanned_is_not_built() {
        assert_eq!(
            extended("T:0:0:494433*4142"),
            Err(NotBuiltReason::TypedAsUnscanned)
        );
        assert_eq!(
            extended("T:0:0:3c2540204c414e4755414745203d*4142"),
            Err(NotBuiltReason::TypedHtmlBeforeRawScan)
        );
    }

    #[test]
    fn html_targets_are_built_as_escaped_text_whose_normalised_page_shows_the_pattern() {
        assert_eq!(
            extended("T:3:*:3c6120687265663d22783e").unwrap(),
            b"<html><body>xx&lt;a href=\"x&gt;</body></html>".to_vec()
        );
    }

    #[test]
    fn mail_targets_get_a_header_that_types_them_as_mail() {
        assert!(extended("T:4:*:4142").unwrap().starts_with(MAIL_HEADER));
    }
}
