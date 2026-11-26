use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyPattern {
    pub elements: Vec<PatternElement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternElement {
    Literal(u8),
    PartialByte(PartialByte),
    AnyByte,
    Gap(GapLength),
    Alternatives(Alternatives),
    CharacterClass(CharacterClassTest),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartialByte {
    pub known_bits: u8,
    pub value: u8,
}

impl PartialByte {
    #[must_use]
    pub fn accepts(self, candidate: u8) -> bool {
        candidate & self.known_bits == self.value
    }

    #[must_use]
    pub fn completed_with(self, filler: u8) -> u8 {
        self.value | (filler & !self.known_bits)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapLength {
    pub minimum: usize,
    pub maximum: Option<usize>,
}

impl GapLength {
    #[must_use]
    pub fn admits(self, length: usize) -> bool {
        length >= self.minimum && self.maximum.is_none_or(|maximum| length <= maximum)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alternatives {
    pub negated: bool,
    pub choices: Vec<Vec<PatternElement>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharacterClassTest {
    pub class: CharacterClass,
    pub negated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharacterClass {
    WordBoundary,
    LineBoundary,
    NonAlphanumeric,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    Empty,
    UnexpectedCharacter { character: char, position: usize },
    UnfinishedByte { position: usize },
    UnclosedGroup { position: usize },
    MalformedRange { text: String },
}

impl fmt::Display for PatternError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(formatter, "empty pattern"),
            Self::UnexpectedCharacter {
                character,
                position,
            } => write!(formatter, "unexpected {character:?} at {position}"),
            Self::UnfinishedByte { position } => {
                write!(formatter, "unfinished byte at {position}")
            }
            Self::UnclosedGroup { position } => {
                write!(formatter, "unclosed group opened at {position}")
            }
            Self::MalformedRange { text } => write!(formatter, "malformed range {text:?}"),
        }
    }
}

impl BodyPattern {
    pub fn parse(text: &str) -> Result<Self, PatternError> {
        let mut reader = PatternReader {
            text: text.as_bytes(),
            position: 0,
        };
        let elements = reader.read_sequence(Nesting::TopLevel)?;
        if let Some(character) = reader.peek() {
            return Err(PatternError::UnexpectedCharacter {
                character: char::from(character),
                position: reader.position,
            });
        }
        if elements.is_empty() {
            return Err(PatternError::Empty);
        }
        Ok(Self { elements })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Nesting {
    TopLevel,
    InsideGroup,
}

struct PatternReader<'text> {
    text: &'text [u8],
    position: usize,
}

impl PatternReader<'_> {
    fn read_sequence(&mut self, nesting: Nesting) -> Result<Vec<PatternElement>, PatternError> {
        let mut elements = Vec::new();
        while let Some(character) = self.peek() {
            match character {
                b'|' | b')' if nesting == Nesting::InsideGroup => break,
                b'*' => {
                    self.advance();
                    elements.push(PatternElement::Gap(GapLength {
                        minimum: 0,
                        maximum: None,
                    }));
                }
                b'{' => elements.push(PatternElement::Gap(self.read_delimited_range(b'}')?)),
                b'[' => elements.push(PatternElement::Gap(self.read_delimited_range(b']')?)),
                b'(' => elements.push(self.read_group(false)?),
                b'!' => {
                    self.advance();
                    if self.peek() != Some(b'(') {
                        return Err(self.unexpected());
                    }
                    elements.push(self.read_group(true)?);
                }
                _ => elements.push(self.read_byte()?),
            }
        }
        Ok(elements)
    }

    fn read_group(&mut self, negated: bool) -> Result<PatternElement, PatternError> {
        let opened_at = self.position;
        self.advance();
        if let Some(class) = self.read_character_class() {
            return Ok(PatternElement::CharacterClass(CharacterClassTest {
                class,
                negated,
            }));
        }
        let mut choices = Vec::new();
        loop {
            choices.push(self.read_sequence(Nesting::InsideGroup)?);
            match self.peek() {
                Some(b'|') => self.advance(),
                Some(b')') => {
                    self.advance();
                    break;
                }
                _ => {
                    return Err(PatternError::UnclosedGroup {
                        position: opened_at,
                    });
                }
            }
        }
        Ok(PatternElement::Alternatives(Alternatives {
            negated,
            choices,
        }))
    }

    fn read_character_class(&mut self) -> Option<CharacterClass> {
        let class = match self
            .text
            .get(self.position..self.position.checked_add(2)?)?
        {
            b"B)" => CharacterClass::WordBoundary,
            b"L)" => CharacterClass::LineBoundary,
            b"W)" => CharacterClass::NonAlphanumeric,
            _ => return None,
        };
        self.advance();
        self.advance();
        Some(class)
    }

    fn read_delimited_range(&mut self, closing: u8) -> Result<GapLength, PatternError> {
        self.advance();
        let start = self.position;
        while let Some(character) = self.peek() {
            if character == closing {
                let text = self
                    .text
                    .get(start..self.position)
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .unwrap_or_default()
                    .to_owned();
                self.advance();
                return parse_range(&text);
            }
            self.advance();
        }
        Err(PatternError::UnclosedGroup {
            position: start.saturating_sub(1),
        })
    }

    fn read_byte(&mut self) -> Result<PatternElement, PatternError> {
        let position = self.position;
        let high = self
            .peek()
            .ok_or(PatternError::UnfinishedByte { position })?;
        self.advance();
        let low = self
            .peek()
            .ok_or(PatternError::UnfinishedByte { position })?;
        self.advance();
        let element = match (nibble(high), nibble(low)) {
            (Some(Nibble::Wildcard), Some(Nibble::Wildcard)) => PatternElement::AnyByte,
            (Some(Nibble::Known(high)), Some(Nibble::Known(low))) => {
                PatternElement::Literal(high << 4 | low)
            }
            (Some(Nibble::Known(high)), Some(Nibble::Wildcard)) => {
                PatternElement::PartialByte(PartialByte {
                    known_bits: 0xf0,
                    value: high << 4,
                })
            }
            (Some(Nibble::Wildcard), Some(Nibble::Known(low))) => {
                PatternElement::PartialByte(PartialByte {
                    known_bits: 0x0f,
                    value: low,
                })
            }
            (None, _) => {
                return Err(PatternError::UnexpectedCharacter {
                    character: char::from(high),
                    position,
                });
            }
            (_, None) => {
                return Err(PatternError::UnexpectedCharacter {
                    character: char::from(low),
                    position: position.saturating_add(1),
                });
            }
        };
        Ok(element)
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.position).copied()
    }

    fn advance(&mut self) {
        self.position = self.position.saturating_add(1);
    }

    fn unexpected(&self) -> PatternError {
        match self.peek() {
            Some(character) => PatternError::UnexpectedCharacter {
                character: char::from(character),
                position: self.position,
            },
            None => PatternError::UnfinishedByte {
                position: self.position,
            },
        }
    }
}

enum Nibble {
    Known(u8),
    Wildcard,
}

fn nibble(character: u8) -> Option<Nibble> {
    match character {
        b'?' => Some(Nibble::Wildcard),
        b'0'..=b'9' => Some(Nibble::Known(character.wrapping_sub(b'0'))),
        b'a'..=b'f' => Some(Nibble::Known(character.wrapping_sub(b'a').wrapping_add(10))),
        b'A'..=b'F' => Some(Nibble::Known(character.wrapping_sub(b'A').wrapping_add(10))),
        _ => None,
    }
}

fn parse_range(text: &str) -> Result<GapLength, PatternError> {
    let malformed = || PatternError::MalformedRange {
        text: text.to_owned(),
    };
    let number = |digits: &str| digits.parse::<usize>().map_err(|_| malformed());
    let range = match text.split_once('-') {
        None => {
            let exact = number(text)?;
            GapLength {
                minimum: exact,
                maximum: Some(exact),
            }
        }
        Some(("", maximum)) => GapLength {
            minimum: 0,
            maximum: Some(number(maximum)?),
        },
        Some((minimum, "")) => GapLength {
            minimum: number(minimum)?,
            maximum: None,
        },
        Some((minimum, maximum)) => GapLength {
            minimum: number(minimum)?,
            maximum: Some(number(maximum)?),
        },
    };
    if range.maximum.is_some_and(|maximum| maximum < range.minimum) {
        return Err(malformed());
    }
    Ok(range)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elements(text: &str) -> Vec<PatternElement> {
        BodyPattern::parse(text).unwrap().elements
    }

    fn gap(minimum: usize, maximum: Option<usize>) -> PatternElement {
        PatternElement::Gap(GapLength { minimum, maximum })
    }

    #[test]
    fn hex_pairs_in_either_case_are_literal_bytes() {
        assert_eq!(
            elements("4dE5"),
            vec![PatternElement::Literal(0x4d), PatternElement::Literal(0xe5)]
        );
    }

    #[test]
    fn question_marks_are_whole_or_half_byte_wildcards() {
        assert_eq!(
            elements("??a??b"),
            vec![
                PatternElement::AnyByte,
                PatternElement::PartialByte(PartialByte {
                    known_bits: 0xf0,
                    value: 0xa0
                }),
                PatternElement::PartialByte(PartialByte {
                    known_bits: 0x0f,
                    value: 0x0b
                }),
            ]
        );
    }

    #[test]
    fn every_gap_form_reads_as_its_bounds() {
        assert_eq!(
            elements("aa*bb{3}cc{-4}dd{5-}ee{6-7}ff[1-2]00"),
            vec![
                PatternElement::Literal(0xaa),
                gap(0, None),
                PatternElement::Literal(0xbb),
                gap(3, Some(3)),
                PatternElement::Literal(0xcc),
                gap(0, Some(4)),
                PatternElement::Literal(0xdd),
                gap(5, None),
                PatternElement::Literal(0xee),
                gap(6, Some(7)),
                PatternElement::Literal(0xff),
                gap(1, Some(2)),
                PatternElement::Literal(0x00),
            ]
        );
    }

    #[test]
    fn alternatives_hold_choices_of_any_length_and_may_be_negated() {
        assert_eq!(
            elements("(aa|bbcc)!(01|02)"),
            vec![
                PatternElement::Alternatives(Alternatives {
                    negated: false,
                    choices: vec![
                        vec![PatternElement::Literal(0xaa)],
                        vec![PatternElement::Literal(0xbb), PatternElement::Literal(0xcc)],
                    ],
                }),
                PatternElement::Alternatives(Alternatives {
                    negated: true,
                    choices: vec![
                        vec![PatternElement::Literal(0x01)],
                        vec![PatternElement::Literal(0x02)],
                    ],
                }),
            ]
        );
    }

    #[test]
    fn letters_in_parentheses_are_character_classes() {
        assert_eq!(
            elements("(B)41!(L)42(W)"),
            vec![
                PatternElement::CharacterClass(CharacterClassTest {
                    class: CharacterClass::WordBoundary,
                    negated: false
                }),
                PatternElement::Literal(0x41),
                PatternElement::CharacterClass(CharacterClassTest {
                    class: CharacterClass::LineBoundary,
                    negated: true
                }),
                PatternElement::Literal(0x42),
                PatternElement::CharacterClass(CharacterClassTest {
                    class: CharacterClass::NonAlphanumeric,
                    negated: false
                }),
            ]
        );
    }

    #[test]
    fn malformed_patterns_are_errors_not_guesses() {
        assert!(BodyPattern::parse("").is_err());
        assert!(BodyPattern::parse("abc").is_err());
        assert!(BodyPattern::parse("aa(bb|cc").is_err());
        assert!(BodyPattern::parse("aa{9-3}bb").is_err());
        assert!(BodyPattern::parse("aazz").is_err());
        assert!(BodyPattern::parse("aa)").is_err());
    }
}
