use std::fmt;

use crate::body_pattern::{BodyPattern, PatternError};
use crate::logical_expression::{LogicalExpression, MalformedExpression};
use crate::pattern_offset::{MalformedOffset, PatternOffset};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternSignature {
    pub name: String,
    pub form: SignatureForm,
    pub target_code: u32,
    pub functionality_levels: LevelRange,
    pub conditions: TargetConditions,
    pub expression: LogicalExpression,
    pub subsignatures: Vec<Subsignature>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureForm {
    Extended,
    Logical,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LevelRange {
    pub minimum: Option<u64>,
    pub maximum: Option<u64>,
}

impl LevelRange {
    #[must_use]
    pub fn contains(self, level: u64) -> bool {
        self.minimum.is_none_or(|minimum| minimum <= level)
            && self.maximum.is_none_or(|maximum| level <= maximum)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetConditions {
    pub file_size: Option<LevelRange>,
    pub container: Option<String>,
    pub intermediates: Option<String>,
    pub handler_type: Option<String>,
    pub executable_header: Option<String>,
    pub icon_group: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subsignature {
    Body(BodySubsignature),
    RegularExpression,
    ByteComparison,
    Macro,
    ImageFuzzyHash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodySubsignature {
    pub offset: PatternOffset,
    pub pattern: BodyPattern,
    pub modifiers: SubsignatureModifiers,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SubsignatureModifiers {
    pub letter_case: LetterCase,
    pub width: CharacterWidth,
    pub extent: MatchExtent,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LetterCase {
    #[default]
    Exact,
    Insensitive,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CharacterWidth {
    #[default]
    Narrow,
    Wide,
    NarrowOrWide,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MatchExtent {
    #[default]
    Anywhere,
    WholeWord,
}

impl SubsignatureModifiers {
    #[must_use]
    pub fn ignores_case(self) -> bool {
        self.letter_case == LetterCase::Insensitive
    }

    #[must_use]
    pub fn matches_whole_words(self) -> bool {
        self.extent == MatchExtent::WholeWord
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    MissingField(&'static str),
    MalformedNumber {
        field: &'static str,
        text: String,
    },
    UnknownAttribute(String),
    UnknownModifier(char),
    Pattern {
        subsignature: usize,
        error: PatternError,
    },
    Offset(MalformedOffset),
    Expression(MalformedExpression),
}

impl fmt::Display for SignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => write!(formatter, "missing {field}"),
            Self::MalformedNumber { field, text } => {
                write!(formatter, "malformed {field} {text:?}")
            }
            Self::UnknownAttribute(attribute) => {
                write!(formatter, "unknown attribute {attribute:?}")
            }
            Self::UnknownModifier(modifier) => write!(formatter, "unknown modifier {modifier:?}"),
            Self::Pattern {
                subsignature,
                error,
            } => write!(formatter, "subsignature {subsignature}: {error}"),
            Self::Offset(MalformedOffset(text)) => write!(formatter, "malformed offset {text:?}"),
            Self::Expression(error) => error.fmt(formatter),
        }
    }
}

impl PatternSignature {
    pub fn parse_extended(line: &str) -> Result<Self, SignatureError> {
        let mut fields = line.split(':');
        let name = fields.next().ok_or(SignatureError::MissingField("name"))?;
        let target = fields
            .next()
            .ok_or(SignatureError::MissingField("target"))?;
        let offset = fields
            .next()
            .ok_or(SignatureError::MissingField("offset"))?;
        let pattern = fields
            .next()
            .ok_or(SignatureError::MissingField("pattern"))?;
        let functionality_levels = LevelRange {
            minimum: optional_number(fields.next(), "minimum level")?,
            maximum: optional_number(fields.next(), "maximum level")?,
        };
        let body = BodySubsignature {
            offset: PatternOffset::parse(offset).map_err(SignatureError::Offset)?,
            pattern: BodyPattern::parse(pattern).map_err(|error| SignatureError::Pattern {
                subsignature: 0,
                error,
            })?,
            modifiers: SubsignatureModifiers::default(),
        };
        Ok(Self {
            name: name.to_owned(),
            form: SignatureForm::Extended,
            target_code: number(target, "target")?,
            functionality_levels,
            conditions: TargetConditions::default(),
            expression: LogicalExpression::single_subsignature(),
            subsignatures: vec![Subsignature::Body(body)],
        })
    }

    pub fn parse_logical(line: &str) -> Result<Self, SignatureError> {
        let mut fields = line.split(';');
        let name = fields.next().ok_or(SignatureError::MissingField("name"))?;
        let description = fields
            .next()
            .ok_or(SignatureError::MissingField("target description"))?;
        let expression = fields
            .next()
            .ok_or(SignatureError::MissingField("expression"))?;
        let mut target_code = None;
        let mut functionality_levels = LevelRange::default();
        let mut conditions = TargetConditions::default();
        for attribute in description
            .split(',')
            .filter(|attribute| !attribute.is_empty())
        {
            let (key, value) = attribute
                .split_once(':')
                .ok_or_else(|| SignatureError::UnknownAttribute(attribute.to_owned()))?;
            match key {
                "Engine" => functionality_levels = range(value, "engine levels")?,
                "Target" => target_code = Some(number(value, "target")?),
                "FileSize" => conditions.file_size = Some(range(value, "file size")?),
                "Container" => conditions.container = Some(value.to_owned()),
                "Intermediates" => conditions.intermediates = Some(value.to_owned()),
                "HandlerType" => conditions.handler_type = Some(value.to_owned()),
                "EntryPoint" | "NumberOfSections" => {
                    conditions.executable_header = Some(key.to_owned());
                }
                "IconGroup1" | "IconGroup2" => conditions.icon_group = Some(value.to_owned()),
                _ => return Err(SignatureError::UnknownAttribute(attribute.to_owned())),
            }
        }
        let subsignatures = fields
            .enumerate()
            .map(|(index, text)| parse_subsignature(index, text))
            .collect::<Result<Vec<_>, _>>()?;
        if subsignatures.is_empty() {
            return Err(SignatureError::MissingField("subsignature"));
        }
        Ok(Self {
            name: name.to_owned(),
            form: SignatureForm::Logical,
            target_code: target_code.ok_or(SignatureError::MissingField("Target"))?,
            functionality_levels,
            conditions,
            expression: LogicalExpression::parse(expression).map_err(SignatureError::Expression)?,
            subsignatures,
        })
    }
}

fn parse_subsignature(index: usize, text: &str) -> Result<Subsignature, SignatureError> {
    if text.starts_with("fuzzy_img#") {
        return Ok(Subsignature::ImageFuzzyHash);
    }
    if text.starts_with('$') {
        return Ok(Subsignature::Macro);
    }
    if text.contains('/') {
        return Ok(Subsignature::RegularExpression);
    }
    if is_byte_comparison(text) {
        return Ok(Subsignature::ByteComparison);
    }
    let (located, modifiers) = match text.split_once("::") {
        Some((located, modifiers)) => (located, parse_modifiers(modifiers)?),
        None => (text, SubsignatureModifiers::default()),
    };
    let (offset, pattern) = match located.split_once(':') {
        Some((offset, pattern)) => (
            PatternOffset::parse(offset).map_err(SignatureError::Offset)?,
            pattern,
        ),
        None => (PatternOffset::Anywhere, located),
    };
    Ok(Subsignature::Body(BodySubsignature {
        offset,
        pattern: BodyPattern::parse(pattern).map_err(|error| SignatureError::Pattern {
            subsignature: index,
            error,
        })?,
        modifiers,
    }))
}

fn is_byte_comparison(text: &str) -> bool {
    let after_trigger = text.trim_start_matches(|character: char| character.is_ascii_digit());
    after_trigger.len() < text.len() && after_trigger.starts_with('(') && text.contains('#')
}

fn parse_modifiers(text: &str) -> Result<SubsignatureModifiers, SignatureError> {
    let mut modifiers = SubsignatureModifiers::default();
    let mut wide = false;
    let mut ascii = false;
    for modifier in text.chars() {
        match modifier {
            'i' => modifiers.letter_case = LetterCase::Insensitive,
            'w' => wide = true,
            'a' => ascii = true,
            'f' => modifiers.extent = MatchExtent::WholeWord,
            _ => return Err(SignatureError::UnknownModifier(modifier)),
        }
    }
    modifiers.width = match (wide, ascii) {
        (true, true) => CharacterWidth::NarrowOrWide,
        (true, false) => CharacterWidth::Wide,
        (false, _) => CharacterWidth::Narrow,
    };
    Ok(modifiers)
}

fn number<T: std::str::FromStr>(text: &str, field: &'static str) -> Result<T, SignatureError> {
    text.parse().map_err(|_| SignatureError::MalformedNumber {
        field,
        text: text.to_owned(),
    })
}

fn optional_number(text: Option<&str>, field: &'static str) -> Result<Option<u64>, SignatureError> {
    match text {
        None | Some("") => Ok(None),
        Some(text) => number(text, field).map(Some),
    }
}

fn range(text: &str, field: &'static str) -> Result<LevelRange, SignatureError> {
    if let Some((minimum, maximum)) = text.split_once('-') {
        return Ok(LevelRange {
            minimum: optional_number(Some(minimum), field)?,
            maximum: optional_number(Some(maximum), field)?,
        });
    }
    let exact = number(text, field)?;
    Ok(LevelRange {
        minimum: Some(exact),
        maximum: Some(exact),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_extended_signature_reads_name_target_offset_pattern_and_levels() {
        let signature =
            PatternSignature::parse_extended("Test.Sample-1:7:EOF-10:41424344:51:255").unwrap();
        assert_eq!(signature.name, "Test.Sample-1");
        assert_eq!(signature.target_code, 7);
        assert_eq!(
            signature.functionality_levels,
            LevelRange {
                minimum: Some(51),
                maximum: Some(255)
            }
        );
        let Subsignature::Body(body) = &signature.subsignatures[0] else {
            panic!("expected a body subsignature");
        };
        assert_eq!(
            body.offset,
            PatternOffset::BeforeEnd {
                distance: 10,
                shift: 0
            }
        );
    }

    #[test]
    fn a_logical_signature_reads_its_description_expression_and_subsignatures() {
        let signature = PatternSignature::parse_logical(
            "Test.Logical-1;Engine:81-255,Target:0,FileSize:10-900;0&1&2&3&4&5;41414141::i;EOF-4:42424242::wa;0/abc/i;0(>>4#hb2#=0);$12$;fuzzy_img#af2ad01ed42993c7",
        )
        .unwrap();
        assert_eq!(signature.target_code, 0);
        assert_eq!(
            signature.conditions.file_size,
            Some(LevelRange {
                minimum: Some(10),
                maximum: Some(900)
            })
        );
        assert!(
            matches!(&signature.subsignatures[0], Subsignature::Body(body) if body.modifiers.ignores_case())
        );
        assert!(
            matches!(&signature.subsignatures[1], Subsignature::Body(body)
            if body.modifiers.width == CharacterWidth::NarrowOrWide
            && body.offset == PatternOffset::BeforeEnd { distance: 4, shift: 0 })
        );
        assert_eq!(signature.subsignatures[2], Subsignature::RegularExpression);
        assert_eq!(signature.subsignatures[3], Subsignature::ByteComparison);
        assert_eq!(signature.subsignatures[4], Subsignature::Macro);
        assert_eq!(signature.subsignatures[5], Subsignature::ImageFuzzyHash);
    }

    #[test]
    fn container_and_executable_conditions_are_kept() {
        let signature = PatternSignature::parse_logical(
            "T;Engine:51-255,Target:1,Container:CL_TYPE_ZIP,NumberOfSections:3-5,IconGroup1:x;0;4142",
        )
        .unwrap();
        assert_eq!(
            signature.conditions.container.as_deref(),
            Some("CL_TYPE_ZIP")
        );
        assert_eq!(
            signature.conditions.executable_header.as_deref(),
            Some("NumberOfSections")
        );
        assert_eq!(signature.conditions.icon_group.as_deref(), Some("x"));
    }

    #[test]
    fn unknown_attributes_and_modifiers_are_errors() {
        assert!(PatternSignature::parse_logical("T;Target:0,Colour:red;0;4142").is_err());
        assert!(PatternSignature::parse_logical("T;Target:0;0;4142::z").is_err());
        assert!(PatternSignature::parse_logical("T;Engine:51-255;0;4142").is_err());
    }
}
