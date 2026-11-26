use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

const DIGEST_LENGTH: usize = 32;
const HEX_RADIX: u32 = 16;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256([u8; DIGEST_LENGTH]);

#[derive(Debug, PartialEq, Eq)]
pub struct NotLowercaseHexSha256;

impl Sha256 {
    #[must_use]
    pub fn from_digest(digest: [u8; DIGEST_LENGTH]) -> Self {
        Self(digest)
    }
}

impl FromStr for Sha256 {
    type Err = NotLowercaseHexSha256;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut digest = [0_u8; DIGEST_LENGTH];
        let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
        if pairs.len() != DIGEST_LENGTH || !remainder.is_empty() {
            return Err(NotLowercaseHexSha256);
        }
        for (byte, [high, low]) in digest.iter_mut().zip(pairs) {
            *byte = lowercase_hex_digit(*high)
                .zip(lowercase_hex_digit(*low))
                .and_then(|(high, low)| high.checked_mul(16)?.checked_add(low))
                .ok_or(NotLowercaseHexSha256)?;
        }
        Ok(Self(digest))
    }
}

fn lowercase_hex_digit(character: u8) -> Option<u8> {
    if character.is_ascii_uppercase() {
        return None;
    }
    char::from(character)
        .to_digit(HEX_RADIX)
        .and_then(|digit| u8::try_from(digit).ok())
}

impl fmt::Display for Sha256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
            .iter()
            .try_for_each(|byte| write!(formatter, "{byte:02x}"))
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for NotLowercaseHexSha256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a SHA-256 is 64 lowercase hexadecimal digits")
    }
}

impl Serialize for Sha256 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Sha256 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}
