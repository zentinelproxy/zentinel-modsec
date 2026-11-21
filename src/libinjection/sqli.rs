//! SQL injection detection: a line-by-line port of libinjection's SQLi
//! detector (`src/libinjection_sqli.c`, libinjection v4.0.2,
//! <https://github.com/libinjection/libinjection>, BSD-3-Clause). That is the
//! version ModSecurity v3 vendors (`others/libinjection` on `v3/master`) and
//! calls from `src/operators/detect_sqli.cc`.
//!
//! libinjection is Copyright 2012-2016 Nick Galbreath and 2021 LibInjection,
//! under the BSD 3-Clause license (`COPYING` in the libinjection repository).
//!
//! The input is tokenized, the tokens are folded down to at most five, and the
//! resulting fingerprint is looked up in libinjection's fingerprint list
//! (`sqli_data.rs`, generated from `libinjection_sqli_data.h`). A listed
//! fingerprint is then passed through libinjection's false-positive filter
//! (`libinjection_sqli_not_whitelist`). The input is analyzed as-is and, when
//! it contains a quote, again as if it started inside a quoted string.
//!
//! The port keeps the C structure and names so the two can be compared side by
//! side, including the C quirks that decide verdicts:
//!
//! - `char` is signed (as on x86-64), so bytes >= 0x80 compare below ASCII.
//! - Set membership mirrors `strchr`, which also matches the NUL byte.
//! - Token values are truncated to 31 bytes (`stoken_t.val[32]`).
//! - Reads one past the end of the input see the NUL terminator that
//!   ModSecurity's `std::string` provides.

// Branches with identical bodies are kept apart so each lines up with its C
// counterpart.
#![allow(clippy::if_same_then_else)]

use super::sqli_data::{CHAR_PARSE_MAP, SQL_KEYWORDS};
use super::DetectionResult;

const TOKEN_SIZE: usize = 32;
const MAX_TOKENS: usize = 5;

const FLAG_QUOTE_NONE: u32 = 1;
const FLAG_QUOTE_SINGLE: u32 = 2;
const FLAG_QUOTE_DOUBLE: u32 = 4;
const FLAG_SQL_ANSI: u32 = 8;
const FLAG_SQL_MYSQL: u32 = 16;

const CHAR_NULL: u8 = 0;
const CHAR_SINGLE: u8 = b'\'';
const CHAR_DOUBLE: u8 = b'"';
const CHAR_TICK: u8 = b'`';

const TYPE_NONE: u8 = 0;
const TYPE_KEYWORD: u8 = b'k';
const TYPE_UNION: u8 = b'U';
const TYPE_GROUP: u8 = b'B';
const TYPE_EXPRESSION: u8 = b'E';
const TYPE_SQLTYPE: u8 = b't';
const TYPE_FUNCTION: u8 = b'f';
const TYPE_BAREWORD: u8 = b'n';
const TYPE_NUMBER: u8 = b'1';
const TYPE_VARIABLE: u8 = b'v';
const TYPE_STRING: u8 = b's';
const TYPE_OPERATOR: u8 = b'o';
const TYPE_LOGIC_OPERATOR: u8 = b'&';
const TYPE_COMMENT: u8 = b'c';
const TYPE_COLLATE: u8 = b'A';
const TYPE_LEFTPARENS: u8 = b'(';
const TYPE_RIGHTPARENS: u8 = b')';
const TYPE_LEFTBRACE: u8 = b'{';
const TYPE_RIGHTBRACE: u8 = b'}';
const TYPE_DOT: u8 = b'.';
const TYPE_COMMA: u8 = b',';
const TYPE_COLON: u8 = b':';
const TYPE_SEMICOLON: u8 = b';';
const TYPE_TSQL: u8 = b'T';
const TYPE_UNKNOWN: u8 = b'?';
const TYPE_EVIL: u8 = b'X';
const TYPE_FINGERPRINT: u8 = b'F';
const TYPE_BACKSLASH: u8 = b'\\';

/// The per-character tokenizer entry points (`char_parse_map` in C).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Parser {
    White,
    Operator1,
    Operator2,
    Other,
    Char,
    Hash,
    Dash,
    Slash,
    Backslash,
    String,
    Word,
    Var,
    Number,
    Money,
    Tick,
    Ustring,
    Qstring,
    Nqstring,
    Xstring,
    Bstring,
    Estring,
    Bword,
}

/// Check if the input contains SQL injection.
pub fn is_sqli(input: &str) -> bool {
    detect_sqli(input).is_injection
}

/// Get the fingerprint libinjection reports for a detected injection.
pub fn sqli_fingerprint(input: &str) -> Option<String> {
    detect_sqli(input).fingerprint
}

/// Detect SQL injection in input (`libinjection_sqli`).
pub fn detect_sqli(input: &str) -> DetectionResult {
    let mut state = State::new(input.as_bytes());
    if state.is_sqli() {
        DetectionResult::detected(state.fingerprint_str())
    } else {
        DetectionResult::safe()
    }
}

/// `strchr(set, ch) != NULL`: the terminating NUL is part of every set.
fn in_set(set: &[u8], ch: u8) -> bool {
    ch == 0 || set.contains(&ch)
}

/// `strlenspn`: length of the prefix made only of bytes in `accept`.
fn strlenspn(s: &[u8], accept: &[u8]) -> usize {
    s.iter()
        .position(|&c| !in_set(accept, c))
        .unwrap_or(s.len())
}

/// `strlencspn`: length of the prefix made only of bytes not in `reject`.
fn strlencspn(s: &[u8], reject: &[u8]) -> usize {
    s.iter().position(|&c| in_set(reject, c)).unwrap_or(s.len())
}

fn char_is_white(ch: u8) -> bool {
    in_set(b" \t\n\x0b\x0c\r\xa0", ch)
}

/// `memchr2`: position of the two-byte sequence `c0 c1` in `hay`.
fn memchr2(hay: &[u8], c0: u8, c1: u8) -> Option<usize> {
    hay.windows(2).position(|w| w[0] == c0 && w[1] == c1)
}

fn memmem(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// `cstrcasecmp`: compares the upper-case, NUL-terminated `a` with the first
/// `n` bytes of `b`, upper-casing ASCII letters of `b`. Signed-char arithmetic.
fn cstrcasecmp(a: &[u8], b: &[u8], n: usize) -> i32 {
    for i in 0..n {
        let ai = a.get(i).copied().unwrap_or(0) as i8 as i32;
        let mut cb = b.get(i).copied().unwrap_or(0);
        if cb.is_ascii_lowercase() {
            cb -= 0x20;
        }
        let cb = cb as i8 as i32;
        if ai != cb {
            return ai - cb;
        } else if ai == 0 {
            return -1;
        }
    }
    if a.len() <= n {
        0
    } else {
        1
    }
}

/// `bsearch_keyword_type`: the keyword/fingerprint table lookup.
fn lookup_word(key: &[u8], len: usize) -> u8 {
    let mut left = 0;
    let mut right = SQL_KEYWORDS.len() - 1;
    while left < right {
        let pos = (left + right) >> 1;
        if cstrcasecmp(SQL_KEYWORDS[pos].0, key, len) < 0 {
            left = pos + 1;
        } else {
            right = pos;
        }
    }
    if left == right && cstrcasecmp(SQL_KEYWORDS[left].0, key, len) == 0 {
        SQL_KEYWORDS[left].1
    } else {
        CHAR_NULL
    }
}

fn flag2delim(flags: u32) -> u8 {
    if flags & FLAG_QUOTE_SINGLE != 0 {
        CHAR_SINGLE
    } else if flags & FLAG_QUOTE_DOUBLE != 0 {
        CHAR_DOUBLE
    } else {
        CHAR_NULL
    }
}

/// `stoken_t`.
#[derive(Debug, Clone, Copy, Default)]
struct Token {
    pos: usize,
    len: usize,
    count: i32,
    ttype: u8,
    str_open: u8,
    str_close: u8,
    val: [u8; TOKEN_SIZE],
}

impl Token {
    fn assign_char(&mut self, stype: u8, pos: usize, value: u8) {
        self.ttype = stype;
        self.pos = pos;
        self.len = 1;
        self.val[0] = value;
        self.val[1] = CHAR_NULL;
    }

    fn assign(&mut self, stype: u8, pos: usize, len: usize, value: &[u8]) {
        let last = len.min(TOKEN_SIZE - 1);
        self.ttype = stype;
        self.pos = pos;
        self.len = last;
        self.val[..last].copy_from_slice(&value[..last]);
        self.val[last] = CHAR_NULL;
    }

    fn is_arithmetic_op(&self) -> bool {
        let ch = self.val[0];
        self.ttype == TYPE_OPERATOR
            && self.len == 1
            && matches!(ch, b'*' | b'/' | b'-' | b'+' | b'%')
    }

    fn is_unary_op(&self) -> bool {
        if self.ttype != TYPE_OPERATOR {
            return false;
        }
        match self.len {
            1 => matches!(self.val[0], b'+' | b'-' | b'!' | b'~'),
            2 => self.val[0] == b'!' && self.val[1] == b'!',
            3 => cstrcasecmp(b"NOT", &self.val, 3) == 0,
            _ => false,
        }
    }

    /// `cstrcasecmp(word, val, len) == 0`.
    fn is(&self, word: &[u8]) -> bool {
        cstrcasecmp(word, &self.val, self.len) == 0
    }
}

/// `struct libinjection_sqli_state`.
struct State<'a> {
    s: &'a [u8],
    flags: u32,
    pos: usize,
    tokenvec: [Token; 8],
    current: usize,
    fingerprint: [u8; 8],
    stats_comment_ddx: i32,
    stats_comment_hash: i32,
    stats_tokens: i32,
}

impl<'a> State<'a> {
    /// `libinjection_sqli_init` with flags 0.
    fn new(s: &'a [u8]) -> Self {
        let mut state = State {
            s,
            flags: 0,
            pos: 0,
            tokenvec: [Token::default(); 8],
            current: 0,
            fingerprint: [0; 8],
            stats_comment_ddx: 0,
            stats_comment_hash: 0,
            stats_tokens: 0,
        };
        state.reset(0);
        state
    }

    /// `libinjection_sqli_reset`.
    fn reset(&mut self, flags: u32) {
        let flags = if flags == 0 {
            FLAG_QUOTE_NONE | FLAG_SQL_ANSI
        } else {
            flags
        };
        let s = self.s;
        *self = State {
            s,
            flags,
            pos: 0,
            tokenvec: [Token::default(); 8],
            current: 0,
            fingerprint: [0; 8],
            stats_comment_ddx: 0,
            stats_comment_hash: 0,
            stats_tokens: 0,
        };
    }

    fn slen(&self) -> usize {
        self.s.len()
    }

    /// Byte at `i`, or the NUL terminator past the end.
    fn byte(&self, i: usize) -> u8 {
        self.s.get(i).copied().unwrap_or(0)
    }

    fn cur(&mut self) -> &mut Token {
        &mut self.tokenvec[self.current]
    }

    fn fingerprint_len(&self) -> usize {
        self.fingerprint.iter().position(|&c| c == 0).unwrap_or(8)
    }

    fn fingerprint_str(&self) -> String {
        let len = self.fingerprint_len();
        String::from_utf8_lossy(&self.fingerprint[..len]).into_owned()
    }

    // ---- parsers -------------------------------------------------------

    fn dispatch(&mut self, parser: Parser) -> usize {
        match parser {
            Parser::White => self.pos + 1,
            Parser::Operator1 => self.parse_operator1(),
            Parser::Operator2 => self.parse_operator2(),
            Parser::Other => self.parse_other(),
            Parser::Char => self.parse_char(),
            Parser::Hash => self.parse_hash(),
            Parser::Dash => self.parse_dash(),
            Parser::Slash => self.parse_slash(),
            Parser::Backslash => self.parse_backslash(),
            Parser::String => self.parse_string(),
            Parser::Word => self.parse_word(),
            Parser::Var => self.parse_var(),
            Parser::Number => self.parse_number(),
            Parser::Money => self.parse_money(),
            Parser::Tick => self.parse_tick(),
            Parser::Ustring => self.parse_ustring(),
            Parser::Qstring => self.parse_qstring_core(0),
            Parser::Nqstring => self.parse_nqstring(),
            Parser::Xstring => self.parse_xstring(),
            Parser::Bstring => self.parse_bstring(),
            Parser::Estring => self.parse_estring(),
            Parser::Bword => self.parse_bword(),
        }
    }

    fn parse_operator1(&mut self) -> usize {
        let pos = self.pos;
        let ch = self.s[pos];
        self.cur().assign_char(TYPE_OPERATOR, pos, ch);
        pos + 1
    }

    fn parse_other(&mut self) -> usize {
        let pos = self.pos;
        let ch = self.s[pos];
        self.cur().assign_char(TYPE_UNKNOWN, pos, ch);
        pos + 1
    }

    fn parse_char(&mut self) -> usize {
        let pos = self.pos;
        let ch = self.s[pos];
        self.cur().assign_char(ch, pos, ch);
        pos + 1
    }

    fn parse_eol_comment(&mut self) -> usize {
        let s = self.s;
        let pos = self.pos;
        match s[pos..].iter().position(|&c| c == b'\n') {
            None => {
                self.cur()
                    .assign(TYPE_COMMENT, pos, s.len() - pos, &s[pos..]);
                s.len()
            }
            Some(off) => {
                self.cur().assign(TYPE_COMMENT, pos, off, &s[pos..]);
                pos + off + 1
            }
        }
    }

    fn parse_hash(&mut self) -> usize {
        self.stats_comment_hash += 1;
        if self.flags & FLAG_SQL_MYSQL != 0 {
            self.stats_comment_hash += 1;
            self.parse_eol_comment()
        } else {
            let pos = self.pos;
            self.cur().assign_char(TYPE_OPERATOR, pos, b'#');
            pos + 1
        }
    }

    fn parse_dash(&mut self) -> usize {
        let s = self.s;
        let slen = s.len();
        let pos = self.pos;
        if pos + 2 < slen && s[pos + 1] == b'-' && char_is_white(s[pos + 2]) {
            self.parse_eol_comment()
        } else if pos + 2 == slen && s[pos + 1] == b'-' {
            self.parse_eol_comment()
        } else if pos + 1 < slen && s[pos + 1] == b'-' && self.flags & FLAG_SQL_ANSI != 0 {
            self.stats_comment_ddx += 1;
            self.parse_eol_comment()
        } else {
            self.cur().assign_char(TYPE_OPERATOR, pos, b'-');
            pos + 1
        }
    }

    fn parse_slash(&mut self) -> usize {
        let s = self.s;
        let slen = s.len();
        let pos = self.pos;
        let pos1 = pos + 1;
        if pos1 == slen || s[pos1] != b'*' {
            return self.parse_operator1();
        }
        // Skip over the initial "/*".
        let ptr = memchr2(&s[pos + 2..], b'*', b'/').map(|off| pos + 2 + off);
        let clen = match ptr {
            None => slen - pos,
            Some(p) => p + 2 - pos,
        };
        // A nested "/*" (PostgreSQL) or a MySQL "/*!" comment is evil.
        let mut ctype = TYPE_COMMENT;
        if let Some(p) = ptr {
            if memchr2(&s[pos + 2..pos + 2 + (p - (pos + 1))], b'/', b'*').is_some() {
                ctype = TYPE_EVIL;
            }
        }
        if ctype != TYPE_EVIL && pos + 2 < slen && s[pos + 2] == b'!' {
            ctype = TYPE_EVIL;
        }
        self.cur().assign(ctype, pos, clen, &s[pos..]);
        pos + clen
    }

    fn parse_backslash(&mut self) -> usize {
        let s = self.s;
        let pos = self.pos;
        // MySQL alias for NULL, "\N" (capital N only).
        if pos + 1 < s.len() && s[pos + 1] == b'N' {
            self.cur().assign(TYPE_NUMBER, pos, 2, &s[pos..]);
            pos + 2
        } else {
            self.cur().assign_char(TYPE_BACKSLASH, pos, s[pos]);
            pos + 1
        }
    }

    fn parse_operator2(&mut self) -> usize {
        let s = self.s;
        let slen = s.len();
        let pos = self.pos;
        if pos + 1 >= slen {
            return self.parse_operator1();
        }
        if pos + 2 < slen && s[pos] == b'<' && s[pos + 1] == b'=' && s[pos + 2] == b'>' {
            self.cur().assign(TYPE_OPERATOR, pos, 3, &s[pos..]);
            return pos + 3;
        }
        let ch = lookup_word(&s[pos..], 2);
        if ch != CHAR_NULL {
            self.cur().assign(ch, pos, 2, &s[pos..]);
            return pos + 2;
        }
        if s[pos] == b':' {
            self.cur().assign(TYPE_COLON, pos, 1, &s[pos..]);
            pos + 1
        } else {
            self.parse_operator1()
        }
    }

    /// `parse_string_core`: a string delimited by `delim`, starting at
    /// `pos + offset` (offset 0 means the opening quote is implied).
    fn parse_string_core(&mut self, pos: usize, delim: u8, offset: usize) -> usize {
        let s = self.s;
        let len = s.len();
        let start = pos + offset;
        let find = |from: usize| s[from..].iter().position(|&c| c == delim).map(|o| from + o);

        let mut qpos = find(start);
        let tok = &mut self.tokenvec[self.current];
        tok.str_open = if offset > 0 { delim } else { CHAR_NULL };

        loop {
            match qpos {
                None => {
                    tok.assign(TYPE_STRING, start, len - start, &s[start..]);
                    tok.str_close = CHAR_NULL;
                    return len;
                }
                Some(q) if is_backslash_escaped(s, q, start) => {
                    qpos = find(q + 1);
                }
                Some(q) if q + 1 < len && s[q + 1] == s[q] => {
                    qpos = find(q + 2);
                }
                Some(q) => {
                    tok.assign(TYPE_STRING, start, q - start, &s[start..]);
                    tok.str_close = delim;
                    return q + 1;
                }
            }
        }
    }

    fn parse_string(&mut self) -> usize {
        let pos = self.pos;
        let delim = self.s[pos];
        self.parse_string_core(pos, delim, 1)
    }

    /// N'...' (MySQL) or E'...' (PostgreSQL).
    fn parse_estring(&mut self) -> usize {
        let s = self.s;
        let pos = self.pos;
        if pos + 2 >= s.len() || s[pos + 1] != CHAR_SINGLE {
            return self.parse_word();
        }
        self.parse_string_core(pos, CHAR_SINGLE, 2)
    }

    fn parse_ustring(&mut self) -> usize {
        let s = self.s;
        let pos = self.pos;
        if pos + 2 < s.len() && s[pos + 1] == b'&' && s[pos + 2] == b'\'' {
            self.pos += 2;
            let pos = self.parse_string();
            let tok = self.cur();
            tok.str_open = b'u';
            if tok.str_close == b'\'' {
                tok.str_close = b'u';
            }
            pos
        } else {
            self.parse_word()
        }
    }

    /// Oracle's q'...' strings.
    fn parse_qstring_core(&mut self, offset: usize) -> usize {
        let s = self.s;
        let slen = s.len();
        let pos = self.pos + offset;
        if pos >= slen
            || (s[pos] != b'q' && s[pos] != b'Q')
            || pos + 2 >= slen
            || s[pos + 1] != b'\''
        {
            return self.parse_word();
        }
        let mut ch = s[pos + 2];
        // Signed char: bytes >= 0x80 are negative, so below 33 too.
        if (ch as i8) < 33 {
            return self.parse_word();
        }
        ch = match ch {
            b'(' => b')',
            b'[' => b']',
            b'{' => b'}',
            b'<' => b'>',
            other => other,
        };
        let tok = &mut self.tokenvec[self.current];
        match memchr2(&s[pos + 3..], ch, b'\'') {
            None => {
                tok.assign(TYPE_STRING, pos + 3, slen - pos - 3, &s[pos + 3..]);
                tok.str_open = b'q';
                tok.str_close = CHAR_NULL;
                slen
            }
            Some(off) => {
                tok.assign(TYPE_STRING, pos + 3, off, &s[pos + 3..]);
                tok.str_open = b'q';
                tok.str_close = b'q';
                pos + 3 + off + 2
            }
        }
    }

    /// MySQL N'...' or Oracle nq'...'.
    fn parse_nqstring(&mut self) -> usize {
        let pos = self.pos;
        if pos + 2 < self.slen() && self.s[pos + 1] == CHAR_SINGLE {
            return self.parse_estring();
        }
        self.parse_qstring_core(1)
    }

    /// b'0101' and x'ABCD' literals.
    fn parse_radix_string(&mut self, digits: &[u8]) -> usize {
        let s = self.s;
        let slen = s.len();
        let pos = self.pos;
        if pos + 2 >= slen || s[pos + 1] != b'\'' {
            return self.parse_word();
        }
        let wlen = strlenspn(&s[pos + 2..], digits);
        if pos + 2 + wlen >= slen || s[pos + 2 + wlen] != b'\'' {
            return self.parse_word();
        }
        self.cur().assign(TYPE_NUMBER, pos, wlen + 3, &s[pos..]);
        pos + 2 + wlen + 1
    }

    fn parse_bstring(&mut self) -> usize {
        self.parse_radix_string(b"01")
    }

    fn parse_xstring(&mut self) -> usize {
        self.parse_radix_string(b"0123456789ABCDEFabcdef")
    }

    /// SQL Server [bracket words].
    fn parse_bword(&mut self) -> usize {
        let s = self.s;
        let pos = self.pos;
        match s[pos..].iter().position(|&c| c == b']') {
            None => {
                self.cur()
                    .assign(TYPE_BAREWORD, pos, s.len() - pos, &s[pos..]);
                s.len()
            }
            Some(off) => {
                self.cur().assign(TYPE_BAREWORD, pos, off + 1, &s[pos..]);
                pos + off + 1
            }
        }
    }

    fn parse_word(&mut self) -> usize {
        let s = self.s;
        let pos = self.pos;
        let wlen = strlencspn(
            &s[pos..],
            b" []{}<>:\\?=@!#~+-*/&|^%(),';\t\n\x0b\x0c\r\"\xa0",
        );
        self.cur().assign(TYPE_BAREWORD, pos, wlen, &s[pos..]);

        // "SELECT.1" or SELECT`column`: split at a '.' or '`' that follows a
        // keyword.
        let tok = self.tokenvec[self.current];
        for i in 0..tok.len {
            let delim = tok.val[i];
            if delim == b'.' || delim == b'`' {
                let ch = lookup_word(&tok.val, i);
                if ch != TYPE_NONE && ch != TYPE_BAREWORD {
                    *self.cur() = Token::default();
                    self.cur().assign(ch, pos, i, &s[pos..]);
                    return pos + i;
                }
            }
        }

        if wlen < TOKEN_SIZE {
            let mut ch = lookup_word(&tok.val, wlen);
            if ch == CHAR_NULL {
                ch = TYPE_BAREWORD;
            }
            self.cur().ttype = ch;
        }
        pos + wlen
    }

    /// MySQL backticks: part string, part bare word.
    fn parse_tick(&mut self) -> usize {
        let pos = self.parse_string_core(self.pos, CHAR_TICK, 1);
        let tok = self.cur();
        let ch = lookup_word(&tok.val, tok.len);
        tok.ttype = if ch == TYPE_FUNCTION {
            TYPE_FUNCTION
        } else {
            TYPE_BAREWORD
        };
        pos
    }

    fn parse_var(&mut self) -> usize {
        let s = self.s;
        let slen = s.len();
        let mut pos = self.pos + 1;

        if pos < slen && s[pos] == b'@' {
            pos += 1;
            self.cur().count = 2;
        } else {
            self.cur().count = 1;
        }

        // MySQL allows @@`version`.
        if pos < slen {
            if s[pos] == b'`' {
                self.pos = pos;
                let pos = self.parse_tick();
                self.cur().ttype = TYPE_VARIABLE;
                return pos;
            } else if s[pos] == CHAR_SINGLE || s[pos] == CHAR_DOUBLE {
                self.pos = pos;
                let pos = self.parse_string();
                self.cur().ttype = TYPE_VARIABLE;
                return pos;
            }
        }

        let xlen = strlencspn(&s[pos..], b" <>:\\?=@!#~+-*/&|^%(),';\t\n\x0b\x0c\r'`\"");
        self.cur().assign(TYPE_VARIABLE, pos, xlen, &s[pos..]);
        pos + xlen
    }

    fn parse_money(&mut self) -> usize {
        let s = self.s;
        let slen = s.len();
        let pos = self.pos;

        if pos + 1 == slen {
            self.cur().assign_char(TYPE_BAREWORD, pos, b'$');
            return slen;
        }

        // $1,000.00 or $1.000,00
        let xlen = strlenspn(&s[pos + 1..], b"0123456789.,");
        if xlen == 0 {
            if s[pos + 1] == b'$' {
                // $$ ... $$ string
                let tok = &mut self.tokenvec[self.current];
                return match memchr2(&s[pos + 2..], b'$', b'$') {
                    None => {
                        tok.assign(TYPE_STRING, pos + 2, slen - (pos + 2), &s[pos + 2..]);
                        tok.str_open = b'$';
                        tok.str_close = CHAR_NULL;
                        slen
                    }
                    Some(off) => {
                        tok.assign(TYPE_STRING, pos + 2, off, &s[pos + 2..]);
                        tok.str_open = b'$';
                        tok.str_close = b'$';
                        pos + 2 + off + 2
                    }
                };
            }
            // Maybe a PostgreSQL $tag$ ... $tag$ string.
            let xlen = strlenspn(
                &s[pos + 1..],
                b"abcdefghjiklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            );
            if xlen == 0 || pos + xlen + 1 == slen || s[pos + xlen + 1] != b'$' {
                self.cur().assign_char(TYPE_BAREWORD, pos, b'$');
                return pos + 1;
            }
            let tag = &s[pos..pos + xlen + 2];
            let body = pos + xlen + 2;
            let tok = &mut self.tokenvec[self.current];
            match memmem(&s[body..], tag) {
                None => {
                    tok.assign(TYPE_STRING, body, slen - body, &s[body..]);
                    tok.str_open = b'$';
                    tok.str_close = CHAR_NULL;
                    slen
                }
                Some(off) => {
                    tok.assign(TYPE_STRING, body, off, &s[body..]);
                    tok.str_open = b'$';
                    tok.str_close = b'$';
                    body + off + xlen + 2
                }
            }
        } else if xlen == 1 && s[pos + 1] == b'.' {
            // "$." is a word
            self.parse_word()
        } else {
            self.cur().assign(TYPE_NUMBER, pos, 1 + xlen, &s[pos..]);
            pos + 1 + xlen
        }
    }

    fn parse_number(&mut self) -> usize {
        let s = self.s;
        let slen = s.len();
        let mut pos = self.pos;

        if s[pos] == b'0' && pos + 1 < slen {
            let digits: Option<&[u8]> = match s[pos + 1] {
                b'X' | b'x' => Some(b"0123456789ABCDEFabcdef"),
                b'B' | b'b' => Some(b"01"),
                _ => None,
            };
            if let Some(digits) = digits {
                let xlen = strlenspn(&s[pos + 2..], digits);
                if xlen == 0 {
                    self.cur().assign(TYPE_BAREWORD, pos, 2, &s[pos..]);
                    return pos + 2;
                }
                self.cur().assign(TYPE_NUMBER, pos, 2 + xlen, &s[pos..]);
                return pos + 2 + xlen;
            }
        }

        let start = pos;
        while pos < slen && s[pos].is_ascii_digit() {
            pos += 1;
        }

        if pos < slen && s[pos] == b'.' {
            pos += 1;
            while pos < slen && s[pos].is_ascii_digit() {
                pos += 1;
            }
            if pos - start == 1 {
                // only "." read so far
                self.cur().assign_char(TYPE_DOT, start, b'.');
                return pos;
            }
        }

        let mut have_e = false;
        let mut have_exp = false;
        if pos < slen && (s[pos] == b'E' || s[pos] == b'e') {
            have_e = true;
            pos += 1;
            if pos < slen && (s[pos] == b'+' || s[pos] == b'-') {
                pos += 1;
            }
            while pos < slen && s[pos].is_ascii_digit() {
                have_exp = true;
                pos += 1;
            }
        }

        // Oracle float/double suffix, taken at end of input, before white
        // space or ';', and before 'u' (so "1fUNION" reads as "1f UNION").
        if pos < slen
            && matches!(s[pos], b'd' | b'D' | b'f' | b'F')
            && (pos + 1 == slen
                || char_is_white(s[pos + 1])
                || matches!(s[pos + 1], b';' | b'u' | b'U'))
        {
            pos += 1;
        }

        // "1.e", "10.10E", ".E": no token (MySQL ignores it).
        if !(have_e && !have_exp) {
            self.cur()
                .assign(TYPE_NUMBER, start, pos - start, &s[start..]);
        }
        pos
    }

    // ---- tokenizer and folding ----------------------------------------

    /// `libinjection_sqli_tokenize`: the next token into `tokenvec[current]`.
    fn tokenize(&mut self) -> bool {
        let slen = self.slen();
        if slen == 0 {
            return false;
        }
        *self.cur() = Token::default();

        // At the start of input in a quote context, pretend it opens a string.
        if self.pos == 0 && self.flags & (FLAG_QUOTE_SINGLE | FLAG_QUOTE_DOUBLE) != 0 {
            self.pos = self.parse_string_core(0, flag2delim(self.flags), 0);
            self.stats_tokens += 1;
            return true;
        }

        while self.pos < slen {
            let parser = CHAR_PARSE_MAP[self.s[self.pos] as usize];
            self.pos = self.dispatch(parser);
            if self.cur().ttype != CHAR_NULL {
                self.stats_tokens += 1;
                return true;
            }
        }
        false
    }

    /// `syntax_merge_words`: "UNION" + "ALL" -> "UNION ALL", and so on.
    fn syntax_merge_words(&mut self, ia: usize, ib: usize) -> bool {
        const LEFT: [u8; 8] = [
            TYPE_KEYWORD,
            TYPE_BAREWORD,
            TYPE_OPERATOR,
            TYPE_UNION,
            TYPE_FUNCTION,
            TYPE_EXPRESSION,
            TYPE_TSQL,
            TYPE_SQLTYPE,
        ];
        let a = self.tokenvec[ia];
        let b = self.tokenvec[ib];
        if !LEFT.contains(&a.ttype) {
            return false;
        }
        if !(LEFT.contains(&b.ttype) || b.ttype == TYPE_LOGIC_OPERATOR) {
            return false;
        }
        let sz1 = a.len;
        let sz2 = b.len;
        let sz3 = sz1 + sz2 + 1;
        if sz3 >= TOKEN_SIZE {
            return false;
        }
        let mut tmp = [0u8; TOKEN_SIZE];
        tmp[..sz1].copy_from_slice(&a.val[..sz1]);
        tmp[sz1] = b' ';
        tmp[sz1 + 1..sz3].copy_from_slice(&b.val[..sz2]);
        let ch = lookup_word(&tmp, sz3);
        if ch != CHAR_NULL {
            self.tokenvec[ia].assign(ch, a.pos, sz3, &tmp);
            true
        } else {
            false
        }
    }

    /// Reads tokens into `tokenvec[pos..]` until `pos - left == want`,
    /// remembering a trailing comment instead of keeping it.
    fn fill(
        &mut self,
        more: &mut bool,
        pos: &mut usize,
        left: usize,
        want: usize,
        last_comment: &mut Token,
    ) {
        while *more && *pos <= MAX_TOKENS && *pos - left < want {
            self.current = *pos;
            *more = self.tokenize();
            if *more {
                if self.tokenvec[*pos].ttype == TYPE_COMMENT {
                    *last_comment = self.tokenvec[*pos];
                } else {
                    last_comment.ttype = CHAR_NULL;
                    *pos += 1;
                }
            }
        }
    }

    /// `libinjection_sqli_fold`: returns the number of fingerprint tokens.
    fn fold(&mut self) -> usize {
        let mut last_comment = Token::default();
        let mut pos: usize = 0;
        let mut left: usize = 0;
        let mut more;

        // Skip all initial comments, left parens, SQL types and unary operators.
        self.current = 0;
        loop {
            more = self.tokenize();
            let t = &self.tokenvec[0];
            if !(t.ttype == TYPE_COMMENT
                || t.ttype == TYPE_LEFTPARENS
                || t.ttype == TYPE_SQLTYPE
                || t.is_unary_op())
            {
                break;
            }
            if !more {
                break;
            }
        }

        if !more {
            return 0;
        }
        pos += 1;

        loop {
            if pos >= MAX_TOKENS {
                let tv = |i: usize| self.tokenvec[i].ttype;
                if (tv(0) == TYPE_NUMBER
                    && (tv(1) == TYPE_OPERATOR || tv(1) == TYPE_COMMA)
                    && tv(2) == TYPE_LEFTPARENS
                    && tv(3) == TYPE_NUMBER
                    && tv(4) == TYPE_RIGHTPARENS)
                    || (tv(0) == TYPE_BAREWORD
                        && tv(1) == TYPE_OPERATOR
                        && tv(2) == TYPE_LEFTPARENS
                        && (tv(3) == TYPE_BAREWORD || tv(3) == TYPE_NUMBER)
                        && tv(4) == TYPE_RIGHTPARENS)
                    || (tv(0) == TYPE_NUMBER
                        && tv(1) == TYPE_RIGHTPARENS
                        && tv(2) == TYPE_COMMA
                        && tv(3) == TYPE_LEFTPARENS
                        && tv(4) == TYPE_NUMBER)
                    || (tv(0) == TYPE_BAREWORD
                        && tv(1) == TYPE_RIGHTPARENS
                        && tv(2) == TYPE_OPERATOR
                        && tv(3) == TYPE_LEFTPARENS
                        && tv(4) == TYPE_BAREWORD)
                {
                    if pos > MAX_TOKENS {
                        self.tokenvec[1] = self.tokenvec[MAX_TOKENS];
                        pos = 2;
                    } else {
                        pos = 1;
                    }
                    left = 0;
                }
            }

            if !more || left >= MAX_TOKENS {
                left = pos;
                break;
            }

            // Get up to two tokens.
            self.fill(&mut more, &mut pos, left, 2, &mut last_comment);
            if pos - left < 2 {
                left = pos;
                continue;
            }

            let t0 = self.tokenvec[left];
            let t1 = self.tokenvec[left + 1];

            if t0.ttype == TYPE_STRING && t1.ttype == TYPE_STRING {
                // "ss" -> "s"
                pos -= 1;
                continue;
            } else if t0.ttype == TYPE_SEMICOLON && t1.ttype == TYPE_SEMICOLON {
                pos -= 1;
                continue;
            } else if (t0.ttype == TYPE_OPERATOR || t0.ttype == TYPE_LOGIC_OPERATOR)
                && (t1.is_unary_op() || t1.ttype == TYPE_SQLTYPE)
            {
                pos -= 1;
                left = 0;
                continue;
            } else if t0.ttype == TYPE_LEFTPARENS && t1.is_unary_op() {
                pos -= 1;
                left = left.saturating_sub(1);
                continue;
            } else if self.syntax_merge_words(left, left + 1) {
                pos -= 1;
                left = left.saturating_sub(1);
                continue;
            } else if t0.ttype == TYPE_SEMICOLON
                && t1.ttype == TYPE_FUNCTION
                && (t1.val[0] == b'I' || t1.val[0] == b'i')
                && (t1.val[1] == b'F' || t1.val[1] == b'f')
            {
                // T-SQL "; IF ..."
                self.tokenvec[left + 1].ttype = TYPE_TSQL;
                continue;
            } else if (t0.ttype == TYPE_BAREWORD || t0.ttype == TYPE_VARIABLE)
                && t1.ttype == TYPE_LEFTPARENS
                && [
                    &b"USER_ID"[..],
                    b"USER_NAME",
                    b"DATABASE",
                    b"PASSWORD",
                    b"USER",
                    b"CURRENT_USER",
                    b"CURRENT_DATE",
                    b"CURRENT_TIME",
                    b"CURRENT_TIMESTAMP",
                    b"LOCALTIME",
                    b"LOCALTIMESTAMP",
                ]
                .iter()
                .any(|w| t0.is(w))
            {
                self.tokenvec[left].ttype = TYPE_FUNCTION;
                continue;
            } else if t0.ttype == TYPE_KEYWORD && (t0.is(b"IN") || t0.is(b"NOT IN")) {
                self.tokenvec[left].ttype = if t1.ttype == TYPE_LEFTPARENS {
                    TYPE_OPERATOR
                } else {
                    TYPE_BAREWORD
                };
                continue;
            } else if t0.ttype == TYPE_OPERATOR && (t0.is(b"LIKE") || t0.is(b"NOT LIKE")) {
                if t1.ttype == TYPE_LEFTPARENS
                    && !(left > 0
                        && matches!(
                            self.tokenvec[left - 1].ttype,
                            TYPE_NUMBER
                                | TYPE_STRING
                                | TYPE_BAREWORD
                                | TYPE_VARIABLE
                                | TYPE_RIGHTPARENS
                        ))
                {
                    // SELECT LIKE(...: a function
                    self.tokenvec[left].ttype = TYPE_FUNCTION;
                }
            } else if t0.ttype == TYPE_SQLTYPE
                && matches!(
                    t1.ttype,
                    TYPE_BAREWORD
                        | TYPE_NUMBER
                        | TYPE_SQLTYPE
                        | TYPE_LEFTPARENS
                        | TYPE_FUNCTION
                        | TYPE_VARIABLE
                        | TYPE_STRING
                )
            {
                self.tokenvec[left] = t1;
                pos -= 1;
                left = 0;
                continue;
            } else if t0.ttype == TYPE_COLLATE && t1.ttype == TYPE_BAREWORD {
                // A collation name with '_' is a SQL type (strchr stops at NUL).
                let vlen = t1.val.iter().position(|&c| c == 0).unwrap_or(TOKEN_SIZE);
                if t1.val[..vlen].contains(&b'_') {
                    self.tokenvec[left + 1].ttype = TYPE_SQLTYPE;
                    left = 0;
                }
            } else if t0.ttype == TYPE_BACKSLASH {
                if t1.is_arithmetic_op() {
                    // T-SQL parses '\%1' as '0 % 1'
                    self.tokenvec[left].ttype = TYPE_NUMBER;
                } else {
                    self.tokenvec[left] = t1;
                    pos -= 1;
                }
                left = 0;
                continue;
            } else if (t0.ttype == TYPE_LEFTPARENS && t1.ttype == TYPE_LEFTPARENS)
                || (t0.ttype == TYPE_RIGHTPARENS && t1.ttype == TYPE_RIGHTPARENS)
            {
                pos -= 1;
                left = 0;
                continue;
            } else if t0.ttype == TYPE_LEFTBRACE && t1.ttype == TYPE_BAREWORD {
                // MySQL "{ ``" is blacklisted outright.
                if t1.len == 0 {
                    self.tokenvec[left + 1].ttype = TYPE_EVIL;
                    return left + 2;
                }
                // ODBC "{foo expr}" -> "expr"
                left = 0;
                pos -= 2;
                continue;
            } else if t1.ttype == TYPE_RIGHTBRACE {
                pos -= 1;
                left = 0;
                continue;
            }

            // No two-token fold applied: get a third token.
            self.fill(&mut more, &mut pos, left, 3, &mut last_comment);
            if pos - left < 3 {
                left = pos;
                continue;
            }

            let t0 = self.tokenvec[left].ttype;
            let t1 = self.tokenvec[left + 1];
            let t2 = self.tokenvec[left + 2];
            let t2t = t2.ttype;

            if t0 == TYPE_NUMBER && t1.ttype == TYPE_OPERATOR && t2t == TYPE_NUMBER {
                pos -= 2;
                left = 0;
                continue;
            } else if t0 == TYPE_OPERATOR && t1.ttype != TYPE_LEFTPARENS && t2t == TYPE_OPERATOR {
                left = 0;
                pos -= 2;
                continue;
            } else if t0 == TYPE_LOGIC_OPERATOR && t2t == TYPE_LOGIC_OPERATOR {
                pos -= 2;
                left = 0;
                continue;
            } else if t0 == TYPE_VARIABLE
                && t1.ttype == TYPE_OPERATOR
                && matches!(t2t, TYPE_VARIABLE | TYPE_NUMBER | TYPE_BAREWORD)
            {
                pos -= 2;
                left = 0;
                continue;
            } else if (t0 == TYPE_BAREWORD || t0 == TYPE_NUMBER)
                && t1.ttype == TYPE_OPERATOR
                && (t2t == TYPE_NUMBER || t2t == TYPE_BAREWORD)
            {
                pos -= 2;
                left = 0;
                continue;
            } else if matches!(
                t0,
                TYPE_BAREWORD | TYPE_NUMBER | TYPE_VARIABLE | TYPE_STRING
            ) && t1.ttype == TYPE_OPERATOR
                && t1.len == 2
                && &t1.val[..3] == b"::\0"
                && t2t == TYPE_SQLTYPE
            {
                pos -= 2;
                left = 0;
                continue;
            } else if matches!(
                t0,
                TYPE_BAREWORD | TYPE_NUMBER | TYPE_STRING | TYPE_VARIABLE
            ) && t1.ttype == TYPE_COMMA
                && matches!(
                    t2t,
                    TYPE_NUMBER | TYPE_BAREWORD | TYPE_STRING | TYPE_VARIABLE
                )
            {
                pos -= 2;
                left = 0;
                continue;
            } else if matches!(t0, TYPE_EXPRESSION | TYPE_GROUP | TYPE_COMMA)
                && t1.is_unary_op()
                && t2t == TYPE_LEFTPARENS
            {
                // SELECT + (, LIMIT + ( -> drop the unary operator
                self.tokenvec[left + 1] = t2;
                pos -= 1;
                left = 0;
                continue;
            } else if matches!(t0, TYPE_KEYWORD | TYPE_EXPRESSION | TYPE_GROUP)
                && t1.is_unary_op()
                && matches!(
                    t2t,
                    TYPE_NUMBER | TYPE_BAREWORD | TYPE_VARIABLE | TYPE_STRING | TYPE_FUNCTION
                )
            {
                // select - 1
                self.tokenvec[left + 1] = t2;
                pos -= 1;
                left = 0;
                continue;
            } else if t0 == TYPE_COMMA
                && t1.is_unary_op()
                && matches!(
                    t2t,
                    TYPE_NUMBER | TYPE_BAREWORD | TYPE_VARIABLE | TYPE_STRING
                )
            {
                // ", -1" -> ",1", then back up: "1,-1" -> "1"
                self.tokenvec[left + 1] = t2;
                left = 0;
                pos -= 3;
                continue;
            } else if t0 == TYPE_COMMA && t1.is_unary_op() && t2t == TYPE_FUNCTION {
                // 1,-sin(1) -> 1,sin(1)
                self.tokenvec[left + 1] = t2;
                pos -= 1;
                left = 0;
                continue;
            } else if t0 == TYPE_BAREWORD && t1.ttype == TYPE_DOT && t2t == TYPE_BAREWORD {
                // databasename.table
                pos -= 2;
                left = 0;
                continue;
            } else if t0 == TYPE_EXPRESSION && t1.ttype == TYPE_DOT && t2t == TYPE_BAREWORD {
                // select . `foo` -> select `foo`
                self.tokenvec[left + 1] = t2;
                pos -= 1;
                left = 0;
                continue;
            } else if t0 == TYPE_FUNCTION && t1.ttype == TYPE_LEFTPARENS && t2t != TYPE_RIGHTPARENS
            {
                // USER(foo): USER is not the zero-argument function.
                if self.tokenvec[left].is(b"USER") {
                    self.tokenvec[left].ttype = TYPE_BAREWORD;
                }
            }

            left += 1;
        }

        // With four or fewer tokens, add a trailing comment back.
        if left < MAX_TOKENS && last_comment.ttype == TYPE_COMMENT {
            self.tokenvec[left] = last_comment;
            left += 1;
        }

        // A sixth token may have been read to type the fifth.
        left.min(MAX_TOKENS)
    }

    /// `libinjection_sqli_fingerprint`.
    fn compute_fingerprint(&mut self, flags: u32) {
        self.reset(flags);
        let tlen = self.fold();

        // PHP's magic backquote comment: an empty, unclosed `
        if tlen > 2 {
            let t = &mut self.tokenvec[tlen - 1];
            if t.ttype == TYPE_BAREWORD
                && t.str_open == CHAR_TICK
                && t.len == 0
                && t.str_close == CHAR_NULL
            {
                t.ttype = TYPE_COMMENT;
            }
        }

        for i in 0..tlen {
            self.fingerprint[i] = self.tokenvec[i].ttype;
        }
        self.fingerprint[tlen] = CHAR_NULL;

        // Unparsable input: the fingerprint is just "X".
        if self.fingerprint[..tlen].contains(&TYPE_EVIL) {
            self.fingerprint = [0; 8];
            self.fingerprint[0] = TYPE_EVIL;
            self.tokenvec[0].val = [0; TOKEN_SIZE];
            self.tokenvec[0].ttype = TYPE_EVIL;
            self.tokenvec[0].val[0] = TYPE_EVIL;
            self.tokenvec[1].ttype = CHAR_NULL;
        }
    }

    /// `libinjection_sqli_check_fingerprint`.
    fn check_fingerprint(&self) -> bool {
        self.blacklist() && self.not_whitelist()
    }

    /// `libinjection_sqli_blacklist`: is the fingerprint a known SQLi shape?
    fn blacklist(&self) -> bool {
        let len = self.fingerprint_len();
        if len < 1 {
            return false;
        }
        let mut fp2 = [0u8; 8];
        fp2[0] = b'0';
        for i in 0..len {
            fp2[i + 1] = self.fingerprint[i].to_ascii_uppercase();
        }
        lookup_word(&fp2, len + 1) == TYPE_FINGERPRINT
    }

    /// `libinjection_sqli_not_whitelist`: false-positive reduction for a
    /// blacklisted fingerprint. True means SQLi.
    fn not_whitelist(&self) -> bool {
        let fp = &self.fingerprint;
        let tlen = self.fingerprint_len();
        let tv = &self.tokenvec;

        if tlen > 1 && fp[tlen - 1] == TYPE_COMMENT && memmem(self.s, b"sp_password").is_some() {
            return true;
        }

        match tlen {
            2 => {
                if fp[1] == TYPE_UNION {
                    // "1 union" alone is common text; only with folding.
                    return self.stats_tokens != 2;
                }
                // A '#' comment: too many false positives.
                if tv[1].val[0] == b'#' {
                    return false;
                }
                // "nc": only /* comments count.
                if tv[0].ttype == TYPE_BAREWORD
                    && tv[1].ttype == TYPE_COMMENT
                    && tv[1].val[0] != b'/'
                {
                    return false;
                }
                if tv[0].ttype == TYPE_NUMBER && tv[1].ttype == TYPE_COMMENT && tv[1].val[0] == b'/'
                {
                    return true;
                }
                // "1c": the number must really end where a comment starts
                // (checked against the original input, by token length).
                if tv[0].ttype == TYPE_NUMBER && tv[1].ttype == TYPE_COMMENT {
                    if self.stats_tokens > 2 {
                        return true;
                    }
                    let n = tv[0].len;
                    let ch = self.byte(n);
                    // Signed char: bytes >= 0x80 count as whitespace here.
                    if (ch as i8) <= 32 {
                        return true;
                    }
                    if ch == b'/' && self.byte(n + 1) == b'*' {
                        return true;
                    }
                    if ch == b'-' && self.byte(n + 1) == b'-' {
                        return true;
                    }
                    return false;
                }
                // "--" not at the end of input is common in plain text.
                if tv[1].len > 2 && tv[1].val[0] == b'-' {
                    return false;
                }
            }
            3 => {
                let f = &fp[..3];
                if f == b"sos" || f == b"s&s" {
                    // ...foo' + 'bar...: no opening and no closing quote
                    return tv[0].str_open == CHAR_NULL
                        && tv[2].str_close == CHAR_NULL
                        && tv[0].str_close == tv[2].str_open;
                } else if f == b"s&n" || f == b"n&1" || f == b"1&1" || f == b"1&v" || f == b"1&s" {
                    // 'sexy and 17' is not SQLi; 'sexy and 17<18' is
                    if self.stats_tokens == 3 {
                        return false;
                    }
                } else if tv[1].ttype == TYPE_KEYWORD
                    && (tv[1].len < 5 || cstrcasecmp(b"INTO", &tv[1].val, 4) != 0)
                {
                    // Only "INTO OUTFILE" / "INTO DUMPFILE" stay SQLi.
                    return false;
                }
            }
            _ => {}
        }
        true
    }

    fn reparse_as_mysql(&self) -> bool {
        self.stats_comment_ddx != 0 || self.stats_comment_hash != 0
    }

    /// `libinjection_is_sqli`.
    fn is_sqli(&mut self) -> bool {
        let s = self.s;
        if s.is_empty() {
            return false;
        }

        self.compute_fingerprint(FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
        if self.check_fingerprint() {
            return true;
        } else if self.reparse_as_mysql() {
            self.compute_fingerprint(FLAG_QUOTE_NONE | FLAG_SQL_MYSQL);
            if self.check_fingerprint() {
                return true;
            }
        }

        if s.contains(&CHAR_SINGLE) {
            self.compute_fingerprint(FLAG_QUOTE_SINGLE | FLAG_SQL_ANSI);
            if self.check_fingerprint() {
                return true;
            } else if self.reparse_as_mysql() {
                self.compute_fingerprint(FLAG_QUOTE_SINGLE | FLAG_SQL_MYSQL);
                if self.check_fingerprint() {
                    return true;
                }
            }
        }

        if s.contains(&CHAR_DOUBLE) {
            self.compute_fingerprint(FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL);
            if self.check_fingerprint() {
                return true;
            }
        }

        false
    }
}

/// `is_backslash_escaped(qpos - 1, start)`: an odd run of backslashes ends
/// just before `q` (not looking before `start`).
fn is_backslash_escaped(s: &[u8], q: usize, start: usize) -> bool {
    let mut n = 0;
    let mut i = q;
    while i > start {
        i -= 1;
        if s[i] != b'\\' {
            break;
        }
        n += 1;
        if i == start {
            break;
        }
    }
    // C: for (ptr = end; ptr >= start; ptr--) if (*ptr != '\\') break;
    //    return (end - ptr) & 1;
    n & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classic_injection() {
        assert!(is_sqli("1' OR '1'='1"));
        assert!(is_sqli("' OR 1=1--"));
        assert!(is_sqli("admin'--"));
        assert!(is_sqli("1 OR 1=1"));
    }

    #[test]
    fn test_union_injection() {
        assert!(is_sqli("1 UNION SELECT * FROM users"));
        assert!(is_sqli("' UNION SELECT username, password FROM users--"));
        assert!(is_sqli("1' UNION SELECT NULL,NULL,NULL--"));
    }

    #[test]
    fn test_comment_injection() {
        assert!(is_sqli("admin'/*"));
        assert!(is_sqli("1--"));
    }

    #[test]
    fn test_stacked_queries() {
        assert!(is_sqli("1; DROP TABLE users"));
        assert!(is_sqli("'; DELETE FROM users--"));
    }

    #[test]
    fn test_safe_input() {
        assert!(!is_sqli("hello world"));
        assert!(!is_sqli("normal search query"));
        assert!(!is_sqli("user@example.com"));
        assert!(!is_sqli("John O'Brien"));
        assert!(!is_sqli(""));
    }
}
