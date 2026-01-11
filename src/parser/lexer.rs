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
            if ch == '\n' {
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

    /// Skip whitespace (but not newlines).
    pub fn skip_whitespace(&mut self) {
        while let Some(&c) = self.input.peek() {
            if c == ' ' || c == '\t' {
                self.advance();
            } else {
                break;
            }
        }
    }

    /// Skip whitespace including newlines.
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
            '\n' => {
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
            '\\' => {
                // Line continuation
                self.advance();
                if self.peek() == Some('\n') {
                    self.advance();
                }
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
                    && (word.to_lowercase().starts_with("sec")
                        || word.to_lowercase() == "include")
                {
                    TokenKind::Directive(word)
                } else {
                    TokenKind::Word(word)
                };

                Some(Token { kind, line, column })
            }
        }
    }

    /// Read a quoted string.
    fn read_quoted_string(&mut self, quote: char) -> String {
        let mut s = String::new();
        let mut escaped = false;

        while let Some(c) = self.advance() {
            if escaped {
                match c {
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
}
