//! Encoding transformations.

use super::Transformation;
use std::borrow::Cow;

/// Base64 encode transformation.
pub struct Base64Encode;

impl Transformation for Base64Encode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        use base64::Engine;
        Cow::Owned(base64::engine::general_purpose::STANDARD.encode(input))
    }

    fn name(&self) -> &'static str {
        "base64Encode"
    }
}

/// Hex encode transformation.
pub struct HexEncode;

impl Transformation for HexEncode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let encoded: String = input.bytes().map(|b| format!("{:02x}", b)).collect();
        Cow::Owned(encoded)
    }

    fn name(&self) -> &'static str {
        "hexEncode"
    }
}

/// URL encode transformation.
pub struct UrlEncode;

impl Transformation for UrlEncode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
        let encoded = utf8_percent_encode(input, NON_ALPHANUMERIC).to_string();
        if encoded == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(encoded)
        }
    }

    fn name(&self) -> &'static str {
        "urlEncode"
    }
}

/// MD5 hash transformation.
pub struct Md5;

impl Transformation for Md5 {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        use md5::{Digest, Md5 as Md5Hasher};
        let mut hasher = Md5Hasher::new();
        hasher.update(input.as_bytes());
        let result = hasher.finalize();
        Cow::Owned(format!("{:x}", result))
    }

    fn name(&self) -> &'static str {
        "md5"
    }
}

/// SHA1 hash transformation.
pub struct Sha1;

impl Transformation for Sha1 {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        use sha1::{Digest, Sha1 as Sha1Hasher};
        let mut hasher = Sha1Hasher::new();
        hasher.update(input.as_bytes());
        let result = hasher.finalize();
        Cow::Owned(format!("{:x}", result))
    }

    fn name(&self) -> &'static str {
        "sha1"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        let t = Base64Encode;
        assert_eq!(t.transform("hello"), "aGVsbG8=");
    }

    #[test]
    fn test_hex_encode() {
        let t = HexEncode;
        assert_eq!(t.transform("AB"), "4142");
    }

    #[test]
    fn test_md5() {
        let t = Md5;
        // MD5 of "hello"
        assert_eq!(t.transform("hello"), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_sha1() {
        let t = Sha1;
        // SHA1 of "hello"
        assert_eq!(t.transform("hello"), "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
    }
}
