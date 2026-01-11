//! Normalization transformations.

use super::Transformation;
use std::borrow::Cow;

/// Lowercase transformation.
pub struct Lowercase;

impl Transformation for Lowercase {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let lower = input.to_lowercase();
        if lower == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(lower)
        }
    }

    fn name(&self) -> &'static str {
        "lowercase"
    }
}

/// Uppercase transformation.
pub struct Uppercase;

impl Transformation for Uppercase {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let upper = input.to_uppercase();
        if upper == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(upper)
        }
    }

    fn name(&self) -> &'static str {
        "uppercase"
    }
}

/// Compress whitespace transformation.
pub struct CompressWhitespace;

impl Transformation for CompressWhitespace {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = String::new();
        let mut last_was_space = false;
        let mut modified = false;

        for c in input.chars() {
            if c.is_whitespace() {
                if !last_was_space {
                    result.push(' ');
                } else {
                    modified = true;
                }
                last_was_space = true;
            } else {
                result.push(c);
                last_was_space = false;
            }
        }

        if modified || result.chars().any(|c| c.is_whitespace() && c != ' ') {
            Cow::Owned(result)
        } else if result == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(result)
        }
    }

    fn name(&self) -> &'static str {
        "compressWhitespace"
    }
}

/// Remove whitespace transformation.
pub struct RemoveWhitespace;

impl Transformation for RemoveWhitespace {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let result: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        if result == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(result)
        }
    }

    fn name(&self) -> &'static str {
        "removeWhitespace"
    }
}

/// Remove null bytes transformation.
pub struct RemoveNulls;

impl Transformation for RemoveNulls {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if !input.contains('\0') {
            return Cow::Borrowed(input);
        }
        Cow::Owned(input.replace('\0', ""))
    }

    fn name(&self) -> &'static str {
        "removeNulls"
    }
}

/// Replace null bytes with spaces transformation.
pub struct ReplaceNulls;

impl Transformation for ReplaceNulls {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if !input.contains('\0') {
            return Cow::Borrowed(input);
        }
        Cow::Owned(input.replace('\0', " "))
    }

    fn name(&self) -> &'static str {
        "replaceNulls"
    }
}

/// Trim transformation.
pub struct Trim;

impl Transformation for Trim {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let trimmed = input.trim();
        if trimmed.len() == input.len() {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(trimmed.to_string())
        }
    }

    fn name(&self) -> &'static str {
        "trim"
    }
}

/// Trim left transformation.
pub struct TrimLeft;

impl Transformation for TrimLeft {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let trimmed = input.trim_start();
        if trimmed.len() == input.len() {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(trimmed.to_string())
        }
    }

    fn name(&self) -> &'static str {
        "trimLeft"
    }
}

/// Trim right transformation.
pub struct TrimRight;

impl Transformation for TrimRight {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let trimmed = input.trim_end();
        if trimmed.len() == input.len() {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(trimmed.to_string())
        }
    }

    fn name(&self) -> &'static str {
        "trimRight"
    }
}

/// Normalize path transformation (Unix-style).
pub struct NormalizePath;

impl Transformation for NormalizePath {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = String::new();
        let mut modified = false;

        // Replace backslashes with forward slashes
        let normalized = if input.contains('\\') {
            modified = true;
            Cow::Owned(input.replace('\\', "/"))
        } else {
            Cow::Borrowed(input)
        };

        // Collapse multiple slashes
        let mut last_was_slash = false;
        for c in normalized.chars() {
            if c == '/' {
                if !last_was_slash {
                    result.push('/');
                } else {
                    modified = true;
                }
                last_was_slash = true;
            } else {
                result.push(c);
                last_was_slash = false;
            }
        }

        // Remove . and .. components
        let parts: Vec<&str> = result.split('/').collect();
        let mut stack: Vec<&str> = Vec::new();

        for part in parts {
            match part {
                "." => {
                    modified = true;
                }
                ".." => {
                    modified = true;
                    stack.pop();
                }
                "" if !stack.is_empty() => {
                    // Keep leading empty string for absolute paths
                }
                other => {
                    stack.push(other);
                }
            }
        }

        if modified {
            Cow::Owned(stack.join("/"))
        } else {
            Cow::Borrowed(input)
        }
    }

    fn name(&self) -> &'static str {
        "normalizePath"
    }
}

/// Normalize path transformation (Windows-style).
pub struct NormalizePathWin;

impl Transformation for NormalizePathWin {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        // Same as NormalizePath but preserves backslashes
        let np = NormalizePath;
        let result = np.transform(input);
        // Convert back to backslashes
        if result.contains('/') {
            Cow::Owned(result.replace('/', "\\"))
        } else {
            result
        }
    }

    fn name(&self) -> &'static str {
        "normalizePathWin"
    }
}

/// Remove comments transformation.
pub struct RemoveComments;

impl Transformation for RemoveComments {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = String::new();
        let mut in_comment = false;
        let mut chars = input.chars().peekable();

        while let Some(c) = chars.next() {
            if in_comment {
                if c == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    in_comment = false;
                }
            } else if c == '/' && chars.peek() == Some(&'*') {
                chars.next();
                in_comment = true;
            } else {
                result.push(c);
            }
        }

        if result == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(result)
        }
    }

    fn name(&self) -> &'static str {
        "removeComments"
    }
}

/// Command line normalization transformation.
pub struct CmdLine;

impl Transformation for CmdLine {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = String::new();
        let mut modified = false;

        for c in input.chars() {
            match c {
                // Replace with space
                ',' | ';' | '\'' | '"' | '`' => {
                    result.push(' ');
                    modified = true;
                }
                // Remove caret (Windows escape)
                '^' => {
                    modified = true;
                }
                // Lowercase
                c if c.is_ascii_uppercase() => {
                    result.push(c.to_ascii_lowercase());
                    modified = true;
                }
                _ => {
                    result.push(c);
                }
            }
        }

        // Compress whitespace
        let compressed: String = result
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        if modified || compressed != result {
            Cow::Owned(compressed)
        } else {
            Cow::Borrowed(input)
        }
    }

    fn name(&self) -> &'static str {
        "cmdLine"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lowercase() {
        let t = Lowercase;
        assert_eq!(t.transform("Hello World"), "hello world");
        assert_eq!(t.transform("already lower"), "already lower");
    }

    #[test]
    fn test_compress_whitespace() {
        let t = CompressWhitespace;
        assert_eq!(t.transform("hello   world"), "hello world");
        assert_eq!(t.transform("a\t\nb"), "a b");
    }

    #[test]
    fn test_remove_whitespace() {
        let t = RemoveWhitespace;
        assert_eq!(t.transform("hello world"), "helloworld");
    }

    #[test]
    fn test_normalize_path() {
        let t = NormalizePath;
        assert_eq!(t.transform("/a/b/../c"), "/a/c");
        assert_eq!(t.transform("/a//b/./c"), "/a/b/c");
        assert_eq!(t.transform("a\\b\\c"), "a/b/c");
    }

    #[test]
    fn test_cmdline() {
        let t = CmdLine;
        // Semicolon replaced with space, uppercase to lowercase
        assert_eq!(t.transform("CMD;/C"), "cmd /c");
        // Caret is the Windows escape character - it's simply removed
        assert_eq!(t.transform("echo^hello"), "echohello");
        // Multiple transformations
        assert_eq!(t.transform("CMD,/C;DIR"), "cmd /c dir");
    }
}
