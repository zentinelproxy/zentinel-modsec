//! Lexer for ModSecurity configuration syntax.

use std::iter::Peekable;
use std::str::Chars;

/// Token produced by the lexer.
#[derive(Debug, Clone)]
pub struct Token {
    /// The type of token.
    pub kind: TokenKind,
    /// Line number (1-indexed).
    pub line: usize,
    /// Column number (1-indexed).
    pub column: usize,
}

/// Types of tokens.
#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    /// A directive name (e.g., SecRule, SecAction).
    Directive(String),
    /// An unquoted word.
    Word(String),
    /// A quoted string (single or double quotes).
    QuotedString(String),
    /// A comment (starting with #).
    Comment,
    /// A newline.
    Newline,
    /// End of input.
    Eof,
}

/// Whether `c` ends a line. Besides `\n` these are the Unicode line
/// terminators, which a text editor shows as a line break.
fn is_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// Lexer for ModSecurity configuration.
pub struct Lexer<'a> {
    input: Peekable<Chars<'a>>,
    line: usize,
    column: usize,
    at_line_start: bool,
}

impl<'a> Lexer<'a> {
    /// Create a new lexer for the given input.
    pub fn new(input: &'a str) -> Self {
        Self {
            input: input.chars().peekable(),
            line: 1,
            column: 1,
            at_line_start: true,
        }
    }

    /// Peek at the next character without consuming it.
    pub fn peek(&mut self) -> Option<char> {
        self.input.peek().copied()
    }

    /// Consume the next character.
    fn advance(&mut self) -> Option<char> {
        let c = self.input.next();
        if let Some(ch) = c {
            if is_line_terminator(ch) {
                self.line += 1;
                self.column = 1;
                self.at_line_start = true;
            } else {
                self.column += 1;
                if !ch.is_whitespace() {
                    self.at_line_start = false;
                }
            }
        }
        c
    }

    /// Skip whitespace (but not newlines), including backslash-newline continuations.
    pub fn skip_whitespace(&mut self) {
        loop {
            match self.input.peek() {
                // Every whitespace character read_word stops at, '\r' and
                // form feed included, has to be consumed here: otherwise the
                // token stream ends at it and silently drops every directive
                // after it. Line terminators are left for next_token.
                Some(&c) if c.is_whitespace() && !is_line_terminator(c) => {
                    self.advance();
                }
                Some(&'\\') => {
                    // Check for line continuation
                    let mut chars = self.input.clone();
                    chars.next(); // consume the backslash
                    if chars.peek() == Some(&'\n') {
                        self.advance(); // consume backslash
                        self.advance(); // consume newline
                                        // Continue skipping whitespace on next line
                    } else if chars.peek() == Some(&'\r') {
                        chars.next();
                        if chars.peek() == Some(&'\n') {
                            self.advance(); // consume backslash
                            self.advance(); // consume \r
                            self.advance(); // consume \n
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }
    }

    /// Skip whitespace including newlines.
    ///
    /// Part of the tokenizer's API; no directive parser needs it yet.
    #[allow(dead_code)]
    fn skip_all_whitespace(&mut self) {
        while let Some(&c) = self.input.peek() {
            if c.is_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }

    /// Get the next token.
    pub fn next_token(&mut self) -> Option<Token> {
        self.skip_whitespace();

        let line = self.line;
        let column = self.column;

        match self.peek()? {
            c if is_line_terminator(c) => {
                self.advance();
                Some(Token {
                    kind: TokenKind::Newline,
                    line,
                    column,
                })
            }
            '#' => {
                // Comment - skip to end of line
                while let Some(c) = self.advance() {
                    if c == '\n' {
                        break;
                    }
                }
                Some(Token {
                    kind: TokenKind::Comment,
                    line,
                    column,
                })
            }
            '"' | '\'' => {
                let quote = self.advance().unwrap();
                let s = self.read_quoted_string(quote);
                Some(Token {
                    kind: TokenKind::QuotedString(s),
                    line,
                    column,
                })
            }
            '\\' if !self.backslash_starts_word() => {
                // skip_whitespace has consumed every line continuation, so
                // this backslash is stray. It has always been ignored.
                tracing::warn!(line, column, "ignoring stray backslash");
                self.advance();
                self.next_token()
            }
            _ => {
                // Capture at_line_start BEFORE reading the word (since advance() will set it to false)
                let was_at_line_start = self.at_line_start;
                let word = self.read_word();
                if word.is_empty() {
                    return None;
                }

                // Check if this is a directive (at start of line, starts with Sec or Include)
                let kind = if was_at_line_start
                    && (word.to_lowercase().starts_with("sec") || word.to_lowercase() == "include")
                {
                    TokenKind::Directive(word)
                } else {
                    TokenKind::Word(word)
                };

                Some(Token { kind, line, column })
            }
        }
    }

    /// Whether the backslashes at the current position lead into a word, as
    /// in `\\server\share`, rather than standing alone before whitespace, a
    /// quote, a comment or the end of input.
    fn backslash_starts_word(&self) -> bool {
        self.input
            .clone()
            .find(|&c| c != '\\')
            .is_some_and(|c| !c.is_whitespace() && !matches!(c, '"' | '\'' | '#'))
    }

    /// Consume a `\r` that directly precedes `\n`, so a CRLF line ending is
    /// treated like LF wherever a line continuation is recognised.
    fn skip_cr_before_lf(&mut self) {
        if self.input.peek() == Some(&'\r') {
            let mut ahead = self.input.clone();
            ahead.next();
            if ahead.peek() == Some(&'\n') {
                self.advance();
            }
        }
    }

    /// Read a quoted string, handling line continuation.
    fn read_quoted_string(&mut self, quote: char) -> String {
        let mut s = String::new();
        let mut escaped = false;

        while let Some(c) = self.advance() {
            if escaped {
                match c {
                    '\n' => {
                        // Line continuation inside quoted string - skip newline and leading whitespace
                        while self.peek().map(|c| c == ' ' || c == '\t').unwrap_or(false) {
                            self.advance();
                        }
                    }
                    '\r' => {
                        // Handle Windows line endings
                        if self.peek() == Some('\n') {
                            self.advance();
                        }
                        // Skip leading whitespace
                        while self.peek().map(|c| c == ' ' || c == '\t').unwrap_or(false) {
                            self.advance();
                        }
                    }
                    'n' => s.push('\n'),
                    't' => s.push('\t'),
                    'r' => s.push('\r'),
                    '\\' => s.push('\\'),
                    '"' => s.push('"'),
                    '\'' => s.push('\''),
                    _ => {
                        s.push('\\');
                        s.push(c);
                    }
                }
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == quote {
                break;
            } else {
                s.push(c);
            }
        }

        s
    }

    /// Read an unquoted word, handling backslash-newline continuation.
    fn read_word(&mut self) -> String {
        let mut s = String::new();

        while let Some(&c) = self.input.peek() {
            if c == '\\' {
                // Check for line continuation
                self.advance();
                self.skip_cr_before_lf();
                if self.peek() == Some('\n') {
                    self.advance();
                    // Continue reading on next line
                    continue;
                } else {
                    // Not a line continuation, include the backslash
                    s.push('\\');
                    continue;
                }
            }
            if c.is_whitespace() || c == '"' || c == '\'' || c == '#' {
                break;
            }
            s.push(c);
            self.advance();
        }

        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lex_directive() {
        let mut lexer = Lexer::new("SecRule");
        let token = lexer.next_token().unwrap();
        assert!(matches!(token.kind, TokenKind::Directive(s) if s == "SecRule"));
    }

    #[test]
    fn test_lex_quoted_string() {
        let mut lexer = Lexer::new(r#""hello world""#);
        let token = lexer.next_token().unwrap();
        assert!(matches!(token.kind, TokenKind::QuotedString(s) if s == "hello world"));
    }

    #[test]
    fn test_lex_escaped_quote() {
        let mut lexer = Lexer::new(r#""hello \"world\"""#);
        let token = lexer.next_token().unwrap();
        assert!(matches!(token.kind, TokenKind::QuotedString(s) if s == r#"hello "world""#));
    }

    #[test]
    fn test_lex_comment() {
        let mut lexer = Lexer::new("# this is a comment\nSecRule");
        let token = lexer.next_token().unwrap();
        assert!(matches!(token.kind, TokenKind::Comment));

        let token = lexer.next_token().unwrap();
        assert!(matches!(token.kind, TokenKind::Directive(s) if s == "SecRule"));
    }

    #[test]
    fn test_lex_line_continuation() {
        // Line continuation in middle of word should join them
        let mut lexer = Lexer::new("Sec\\\nRule");
        let token = lexer.next_token().unwrap();
        // Should be joined into "SecRule" and recognized as a directive
        assert!(matches!(token.kind, TokenKind::Directive(s) if s == "SecRule"));
    }

    #[test]
    fn test_lex_line_continuation_between_tokens() {
        // Line continuation between tokens
        let mut lexer = Lexer::new("SecRule \\\n  REQUEST_URI");
        let token = lexer.next_token().unwrap();
        assert!(matches!(token.kind, TokenKind::Directive(s) if s == "SecRule"));

        let token = lexer.next_token().unwrap();
        assert!(matches!(token.kind, TokenKind::Word(s) if s == "REQUEST_URI"));
    }

    #[test]
    fn test_lex_full_rule() {
        let mut lexer = Lexer::new(r#"SecRule REQUEST_URI "@contains /admin" "id:1,deny""#);

        let token = lexer.next_token().unwrap();
        assert!(matches!(token.kind, TokenKind::Directive(s) if s == "SecRule"));

        let token = lexer.next_token().unwrap();
        assert!(matches!(token.kind, TokenKind::Word(s) if s == "REQUEST_URI"));

        let token = lexer.next_token().unwrap();
        assert!(matches!(token.kind, TokenKind::QuotedString(s) if s == "@contains /admin"));

        let token = lexer.next_token().unwrap();
        assert!(matches!(token.kind, TokenKind::QuotedString(s) if s == "id:1,deny"));
    }

    #[test]
    fn test_crlf_line_endings_do_not_end_the_token_stream() {
        let mut lexer =
            Lexer::new("SecRuleEngine On\r\nSecRule REQUEST_URI \"@contains a\" \"id:1,deny\"\r\n");
        let mut directives = 0;
        while let Some(t) = lexer.next_token() {
            if matches!(t.kind, TokenKind::Directive(_)) {
                directives += 1;
            }
        }
        assert_eq!(directives, 2, "both directives must be seen");
    }

    #[test]
    fn test_whitespace_other_than_space_and_tab_does_not_end_the_token_stream() {
        for separator in ["\x0c", "\x0b", "\u{a0}", "\u{2003}"] {
            let input = format!("SecRuleEngine On\n{separator}\nSecRuleEngine Off");
            let mut lexer = Lexer::new(&input);
            let mut directives = 0;
            while let Some(t) = lexer.next_token() {
                if matches!(t.kind, TokenKind::Directive(_)) {
                    directives += 1;
                }
            }
            assert_eq!(directives, 2, "{separator:?}");
        }
    }

    fn kinds(input: &str) -> Vec<TokenKind> {
        let mut lexer = Lexer::new(input);
        std::iter::from_fn(|| lexer.next_token())
            .map(|token| token.kind)
            .collect()
    }

    #[test]
    fn test_unicode_line_terminators_start_a_new_line() {
        for terminator in ["\u{85}", "\u{2028}", "\u{2029}"] {
            assert_eq!(
                kinds(&format!("SecRuleEngine On{terminator}SecRuleEngine Off")),
                kinds("SecRuleEngine On\nSecRuleEngine Off"),
                "{terminator:?}"
            );
        }
    }

    #[test]
    fn test_stray_backslash_is_ignored() {
        for (with_backslash, without) in [
            ("SecRuleEngine On \\", "SecRuleEngine On "),
            (
                "SecRuleEngine On \\ \nSecRuleEngine Off",
                "SecRuleEngine On  \nSecRuleEngine Off",
            ),
            (
                "SecRuleEngine On\n\\ \nSecRuleEngine Off",
                "SecRuleEngine On\n \nSecRuleEngine Off",
            ),
            ("SecRuleEngine On \\\rOff", "SecRuleEngine On \rOff"),
            ("SecRuleEngine \\\"On\"", "SecRuleEngine \"On\""),
            ("SecRuleEngine On \\# note", "SecRuleEngine On # note"),
            // The first backslash is stray, the second continues the line.
            (
                "SecRuleEngine On \\\\\nSecRuleEngine Off",
                "SecRuleEngine On \\\nSecRuleEngine Off",
            ),
        ] {
            assert_eq!(kinds(with_backslash), kinds(without), "{with_backslash:?}");
        }
    }

    #[test]
    fn test_word_keeps_its_leading_backslashes() {
        let mut lexer = Lexer::new(r"Include \\server\share\rules.conf");
        let token = lexer.next_token().unwrap();
        assert!(matches!(token.kind, TokenKind::Directive(s) if s == "Include"));
        let token = lexer.next_token().unwrap();
        assert!(matches!(token.kind, TokenKind::Word(s) if s == r"\\server\share\rules.conf"));
    }

    #[test]
    fn test_crlf_line_continuation() {
        let mut lexer = Lexer::new("SecRule \\\r\n  REQUEST_URI");
        let token = lexer.next_token().unwrap();
        assert!(matches!(token.kind, TokenKind::Directive(s) if s == "SecRule"));
        let token = lexer.next_token().unwrap();
        assert!(matches!(token.kind, TokenKind::Word(s) if s == "REQUEST_URI"));
    }
}
