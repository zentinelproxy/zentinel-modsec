//! Decoding transformations.

use super::Transformation;
use std::borrow::Cow;

/// URL decode transformation.
pub struct UrlDecode;

impl Transformation for UrlDecode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        match percent_encoding::percent_decode_str(input).decode_utf8() {
            Ok(decoded) => {
                if decoded == input {
                    Cow::Borrowed(input)
                } else {
                    Cow::Owned(decoded.into_owned())
                }
            }
            Err(_) => Cow::Borrowed(input),
        }
    }

    fn name(&self) -> &'static str {
        "urlDecode"
    }
}

/// URL decode with Unicode support.
pub struct UrlDecodeUni;

impl Transformation for UrlDecodeUni {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        // Handle %uXXXX unicode escapes in addition to standard URL encoding
        let mut result = String::new();
        let mut chars = input.chars().peekable();
        let mut modified = false;

        while let Some(c) = chars.next() {
            if c == '%' {
                if chars.peek() == Some(&'u') || chars.peek() == Some(&'U') {
                    chars.next(); // consume 'u'
                    // Read 4 hex digits
                    let mut hex = String::new();
                    for _ in 0..4 {
                        if let Some(h) = chars.next() {
                            hex.push(h);
                        }
                    }
                    if let Ok(code) = u32::from_str_radix(&hex, 16) {
                        if let Some(decoded) = char::from_u32(code) {
                            result.push(decoded);
                            modified = true;
                            continue;
                        }
                    }
                    result.push('%');
                    result.push('u');
                    result.push_str(&hex);
                } else {
                    // Standard URL encoding
                    let mut hex = String::new();
                    for _ in 0..2 {
                        if let Some(h) = chars.next() {
                            hex.push(h);
                        }
                    }
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte as char);
                        modified = true;
                    } else {
                        result.push('%');
                        result.push_str(&hex);
                    }
                }
            } else {
                result.push(c);
            }
        }

        if modified {
            Cow::Owned(result)
        } else {
            Cow::Borrowed(input)
        }
    }

    fn name(&self) -> &'static str {
        "urlDecodeUni"
    }
}

/// Base64 decode transformation.
pub struct Base64Decode;

impl Transformation for Base64Decode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(input) {
            Ok(bytes) => Cow::Owned(String::from_utf8_lossy(&bytes).into_owned()),
            Err(_) => Cow::Borrowed(input),
        }
    }

    fn name(&self) -> &'static str {
        "base64Decode"
    }
}

/// Extended base64 decode (handles URL-safe base64).
pub struct Base64DecodeExt;

impl Transformation for Base64DecodeExt {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        use base64::Engine;
        // Try URL-safe first, then standard
        let result = base64::engine::general_purpose::URL_SAFE
            .decode(input)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(input));

        match result {
            Ok(bytes) => Cow::Owned(String::from_utf8_lossy(&bytes).into_owned()),
            Err(_) => Cow::Borrowed(input),
        }
    }

    fn name(&self) -> &'static str {
        "base64DecodeExt"
    }
}

/// Hex decode transformation.
pub struct HexDecode;

impl Transformation for HexDecode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = Vec::new();
        let mut chars = input.chars().peekable();

        while let Some(c1) = chars.next() {
            if let Some(c2) = chars.next() {
                let hex = format!("{}{}", c1, c2);
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte);
                } else {
                    // Invalid hex, keep original
                    return Cow::Borrowed(input);
                }
            } else {
                // Odd number of chars
                return Cow::Borrowed(input);
            }
        }

        Cow::Owned(String::from_utf8_lossy(&result).into_owned())
    }

    fn name(&self) -> &'static str {
        "hexDecode"
    }
}

/// HTML entity decode transformation.
pub struct HtmlEntityDecode;

impl Transformation for HtmlEntityDecode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let decoded = html_escape::decode_html_entities(input);
        if decoded == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(decoded.into_owned())
        }
    }

    fn name(&self) -> &'static str {
        "htmlEntityDecode"
    }
}

/// JavaScript decode transformation.
pub struct JsDecode;

impl Transformation for JsDecode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = String::new();
        let mut chars = input.chars().peekable();
        let mut modified = false;

        while let Some(c) = chars.next() {
            if c == '\\' {
                modified = true;
                match chars.next() {
                    Some('n') => result.push('\n'),
                    Some('r') => result.push('\r'),
                    Some('t') => result.push('\t'),
                    Some('\\') => result.push('\\'),
                    Some('"') => result.push('"'),
                    Some('\'') => result.push('\''),
                    Some('x') => {
                        // \xHH
                        let mut hex = String::new();
                        for _ in 0..2 {
                            if let Some(h) = chars.next() {
                                hex.push(h);
                            }
                        }
                        if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                            result.push(byte as char);
                        } else {
                            result.push('\\');
                            result.push('x');
                            result.push_str(&hex);
                        }
                    }
                    Some('u') => {
                        // \uHHHH
                        let mut hex = String::new();
                        for _ in 0..4 {
                            if let Some(h) = chars.next() {
                                hex.push(h);
                            }
                        }
                        if let Ok(code) = u32::from_str_radix(&hex, 16) {
                            if let Some(decoded) = char::from_u32(code) {
                                result.push(decoded);
                            } else {
                                result.push('\\');
                                result.push('u');
                                result.push_str(&hex);
                            }
                        } else {
                            result.push('\\');
                            result.push('u');
                            result.push_str(&hex);
                        }
                    }
                    Some(other) => {
                        result.push('\\');
                        result.push(other);
                    }
                    None => result.push('\\'),
                }
            } else {
                result.push(c);
            }
        }

        if modified {
            Cow::Owned(result)
        } else {
            Cow::Borrowed(input)
        }
    }

    fn name(&self) -> &'static str {
        "jsDecode"
    }
}

/// CSS decode transformation.
pub struct CssDecode;

impl Transformation for CssDecode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = String::new();
        let mut chars = input.chars().peekable();
        let mut modified = false;

        while let Some(c) = chars.next() {
            if c == '\\' {
                modified = true;
                // CSS escape: \HH or \HHHHHH
                let mut hex = String::new();
                while hex.len() < 6 {
                    match chars.peek() {
                        Some(h) if h.is_ascii_hexdigit() => {
                            hex.push(chars.next().unwrap());
                        }
                        _ => break,
                    }
                }
                // Skip optional whitespace after hex
                if let Some(' ') | Some('\t') | Some('\n') = chars.peek() {
                    chars.next();
                }

                if !hex.is_empty() {
                    if let Ok(code) = u32::from_str_radix(&hex, 16) {
                        if let Some(decoded) = char::from_u32(code) {
                            result.push(decoded);
                            continue;
                        }
                    }
                }
                result.push('\\');
                result.push_str(&hex);
            } else {
                result.push(c);
            }
        }

        if modified {
            Cow::Owned(result)
        } else {
            Cow::Borrowed(input)
        }
    }

    fn name(&self) -> &'static str {
        "cssDecode"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_decode() {
        let t = UrlDecode;
        assert_eq!(t.transform("hello%20world"), "hello world");
        assert_eq!(t.transform("test%2Fpath"), "test/path");
    }

    #[test]
    fn test_base64_decode() {
        let t = Base64Decode;
        assert_eq!(t.transform("aGVsbG8="), "hello");
    }

    #[test]
    fn test_html_entity_decode() {
        let t = HtmlEntityDecode;
        assert_eq!(t.transform("&lt;script&gt;"), "<script>");
        assert_eq!(t.transform("&#60;"), "<");
    }

    #[test]
    fn test_js_decode() {
        let t = JsDecode;
        assert_eq!(t.transform(r"\x3cscript\x3e"), "<script>");
        assert_eq!(t.transform(r"\u003c"), "<");
    }
}
