use crate::body_pattern::{CharacterClass, CharacterClassTest};

const BOUNDARY_BEFORE_A_WORD: &[u8] = b" -/_.<@";
const BOUNDARY_AFTER_A_WORD: &[u8] = b"\n\r\"'=> -/_";
const BYTE_SATISFYING_ANY_CLASS: u8 = b' ';
const BYTE_SATISFYING_NO_CLASS: u8 = b'x';
const LINE_BREAK: u8 = b'\n';

impl CharacterClassTest {
    #[must_use]
    pub fn accepts_inside(self, byte: u8) -> bool {
        let in_class = match self.class {
            CharacterClass::WordBoundary => {
                BOUNDARY_BEFORE_A_WORD.contains(&byte) || BOUNDARY_AFTER_A_WORD.contains(&byte)
            }
            CharacterClass::LineBoundary => byte == LINE_BREAK,
            CharacterClass::NonAlphanumeric => !byte.is_ascii_alphanumeric(),
        };
        in_class != self.negated
    }

    #[must_use]
    pub fn accepts_before(self, previous: Option<u8>) -> bool {
        let in_class = match (self.class, previous) {
            (_, None) => true,
            (CharacterClass::WordBoundary, Some(byte)) => BOUNDARY_BEFORE_A_WORD.contains(&byte),
            (CharacterClass::LineBoundary, Some(byte)) => byte == LINE_BREAK,
            (CharacterClass::NonAlphanumeric, Some(byte)) => !byte.is_ascii_alphanumeric(),
        };
        in_class != self.negated
    }

    #[must_use]
    pub fn accepts_after(self, following: &[u8]) -> bool {
        let in_class = match (self.class, following) {
            (_, []) | (CharacterClass::LineBoundary, [b'\n', ..] | [b'\r', b'\n', ..]) => true,
            (CharacterClass::WordBoundary, [byte, ..]) => BOUNDARY_AFTER_A_WORD.contains(byte),
            (CharacterClass::LineBoundary, _) => false,
            (CharacterClass::NonAlphanumeric, [byte, ..]) => !byte.is_ascii_alphanumeric(),
        };
        in_class != self.negated
    }

    #[must_use]
    pub fn satisfying_byte(self) -> u8 {
        match (self.class, self.negated) {
            (_, true) => BYTE_SATISFYING_NO_CLASS,
            (CharacterClass::LineBoundary, false) => LINE_BREAK,
            (CharacterClass::WordBoundary | CharacterClass::NonAlphanumeric, false) => {
                BYTE_SATISFYING_ANY_CLASS
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test(class: CharacterClass, negated: bool) -> CharacterClassTest {
        CharacterClassTest { class, negated }
    }

    #[test]
    fn the_satisfying_byte_satisfies_its_class_in_every_position() {
        for class in [
            CharacterClass::WordBoundary,
            CharacterClass::LineBoundary,
            CharacterClass::NonAlphanumeric,
        ] {
            for negated in [false, true] {
                let test = test(class, negated);
                let byte = test.satisfying_byte();
                assert!(test.accepts_inside(byte));
                assert!(test.accepts_before(Some(byte)));
                assert!(test.accepts_after(&[byte]));
            }
        }
    }

    #[test]
    fn a_word_boundary_differs_before_and_after_a_word() {
        let boundary = test(CharacterClass::WordBoundary, false);
        assert!(boundary.accepts_before(Some(b'.')));
        assert!(!boundary.accepts_after(b"."));
        assert!(boundary.accepts_after(b"="));
        assert!(!boundary.accepts_before(Some(b'=')));
    }

    #[test]
    fn the_file_edges_satisfy_a_class_and_fail_its_negation() {
        assert!(test(CharacterClass::LineBoundary, false).accepts_before(None));
        assert!(!test(CharacterClass::LineBoundary, true).accepts_after(&[]));
    }
}
