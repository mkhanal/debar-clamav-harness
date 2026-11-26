#[must_use]
pub fn normalised_text(bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(bytes.len());
    let mut in_whitespace_run = false;
    for byte in bytes {
        match byte {
            b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ' => {
                if !in_whitespace_run {
                    output.push(b' ');
                }
                in_whitespace_run = true;
            }
            b'A'..=b'Z' => {
                output.push(byte.to_ascii_lowercase());
                in_whitespace_run = false;
            }
            0x21..=0x7e => {
                output.push(*byte);
                in_whitespace_run = false;
            }
            _ => {}
        }
    }
    output
}

#[must_use]
pub fn survives_text_normalisation(bytes: &[u8]) -> bool {
    normalised_text(bytes) == bytes
}

#[must_use]
pub fn survives_html_normalisation(bytes: &[u8]) -> bool {
    let mut previous_was_space = false;
    bytes.iter().all(|byte| {
        let allowed = match byte {
            b' ' => !previous_was_space,
            b'A'..=b'Z' => false,
            0x21..=0x7e | 0x80..=0xff => true,
            _ => false,
        };
        previous_was_space = *byte == b' ';
        allowed
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_lowercased_with_whitespace_runs_collapsed_and_other_bytes_dropped() {
        assert_eq!(
            normalised_text(b"H\xc3\xa9llo  W\x01orld\r\nSecond\tLINE\n"),
            b"hllo world second line ".to_vec()
        );
    }

    #[test]
    fn already_normal_text_survives_normalisation() {
        assert!(survives_text_normalisation(b"eval(unescape('%u9090')) x"));
        assert!(!survives_text_normalisation(b"Eval"));
        assert!(!survives_text_normalisation(b"a  b"));
    }

    #[test]
    fn html_normalisation_keeps_high_bytes_but_not_capitals_or_line_breaks() {
        assert!(survives_html_normalisation(b"<a href=\"x\">\xc3\xa9</a>"));
        assert!(!survives_html_normalisation(b"<A>"));
        assert!(!survives_html_normalisation(b"a\nb"));
    }
}
