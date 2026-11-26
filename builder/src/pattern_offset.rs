#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternOffset {
    Anywhere,
    FromStart { distance: usize, shift: usize },
    BeforeEnd { distance: usize, shift: usize },
    ExecutableAnchor(String),
    VersionInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MalformedOffset(pub String);

impl PatternOffset {
    pub fn parse(text: &str) -> Result<Self, MalformedOffset> {
        let malformed = || MalformedOffset(text.to_owned());
        if text == "*" {
            return Ok(Self::Anywhere);
        }
        if text == "VI" {
            return Ok(Self::VersionInfo);
        }
        if is_executable_anchor(text) {
            return Ok(Self::ExecutableAnchor(text.to_owned()));
        }
        let (position, shift) = match text.split_once(',') {
            Some((position, shift)) => (position, decimal(shift).ok_or_else(malformed)?),
            None => (text, 0),
        };
        if let Some(distance) = position.strip_prefix("EOF-") {
            return Ok(Self::BeforeEnd {
                distance: decimal(distance).ok_or_else(malformed)?,
                shift,
            });
        }
        Ok(Self::FromStart {
            distance: decimal(position).ok_or_else(malformed)?,
            shift,
        })
    }
}

fn is_executable_anchor(text: &str) -> bool {
    ["EP+", "EP-", "SL+", "SE"]
        .iter()
        .any(|prefix| text.starts_with(prefix))
        || text
            .strip_prefix('S')
            .is_some_and(|rest| rest.starts_with(|character: char| character.is_ascii_digit()))
}

fn decimal(text: &str) -> Option<usize> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_floating_offsets_count_from_the_start() {
        assert_eq!(
            PatternOffset::parse("12"),
            Ok(PatternOffset::FromStart {
                distance: 12,
                shift: 0
            })
        );
        assert_eq!(
            PatternOffset::parse("12,4"),
            Ok(PatternOffset::FromStart {
                distance: 12,
                shift: 4
            })
        );
    }

    #[test]
    fn end_of_file_offsets_count_back_from_the_end() {
        assert_eq!(
            PatternOffset::parse("EOF-30,2"),
            Ok(PatternOffset::BeforeEnd {
                distance: 30,
                shift: 2
            })
        );
    }

    #[test]
    fn executable_and_version_info_anchors_are_recognised() {
        for anchor in ["EP+0", "EP-12,3", "S2+40", "SL+550", "SE1"] {
            assert_eq!(
                PatternOffset::parse(anchor),
                Ok(PatternOffset::ExecutableAnchor(anchor.to_owned()))
            );
        }
        assert_eq!(PatternOffset::parse("VI"), Ok(PatternOffset::VersionInfo));
        assert_eq!(PatternOffset::parse("*"), Ok(PatternOffset::Anywhere));
    }

    #[test]
    fn other_text_is_malformed() {
        assert!(PatternOffset::parse("EOF+3").is_err());
        assert!(PatternOffset::parse("x").is_err());
        assert!(PatternOffset::parse("3,").is_err());
    }
}
