//! `%{...}` macros in operator arguments and `setvar` operands.
//!
//! What a macro may name is decided here and nowhere else: the transaction
//! expands with [`expand`], and the ruleset asks [`unresolvable`] at load time
//! which macros that expansion cannot give the value libmodsecurity would.

use once_cell::sync::Lazy;
use regex::{Captures, Regex};

static PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"%\{([^}]+)\}").expect("static macro regex is valid"));

/// A macro the engine can resolve against a transaction.
pub(super) enum OperandMacro<'a> {
    /// `%{MATCHED_VAR}`.
    MatchedVar,
    /// `%{MATCHED_VAR_NAME}`.
    MatchedVarName,
    /// `%{tx.<name>}`.
    Tx(&'a str),
    /// A bare `%{<name>}`, expanded as `tx.<name>`. libmodsecurity reads it
    /// as the variable of that name instead, which is not resolved here.
    Bare(&'a str),
    /// `%{request_headers.<name>}` (CRS 943110: `!@endsWith
    /// %{request_headers.host}`).
    RequestHeader(&'a str),
}

impl<'a> OperandMacro<'a> {
    /// Classify the text between `%{` and `}`, or `None` if it names a
    /// collection the engine does not resolve.
    fn parse(inner: &'a str) -> Option<Self> {
        if inner.eq_ignore_ascii_case("matched_var") {
            return Some(Self::MatchedVar);
        }
        if inner.eq_ignore_ascii_case("matched_var_name") {
            return Some(Self::MatchedVarName);
        }
        let Some((collection, name)) = inner.split_once('.') else {
            return Some(Self::Bare(inner));
        };
        if collection.eq_ignore_ascii_case("tx") {
            Some(Self::Tx(name))
        } else if collection.eq_ignore_ascii_case("request_headers") {
            Some(Self::RequestHeader(name))
        } else {
            None
        }
    }
}

/// Replace every macro in `arg` with what `resolve` returns for it. A macro
/// the engine does not resolve becomes an empty string.
pub(super) fn expand(arg: &str, resolve: impl Fn(OperandMacro) -> String) -> String {
    PATTERN
        .replace_all(arg, |caps: &Captures| {
            OperandMacro::parse(&caps[1])
                .map(&resolve)
                .unwrap_or_default()
        })
        .into_owned()
}

/// The macros in `arg` whose value in libmodsecurity [`expand`] cannot
/// produce, as written: one on a collection it leaves empty
/// (`%{env.MAX_LEN}`), or a bare variable name (`%{REMOTE_PORT}`).
pub(super) fn unresolvable(arg: &str) -> impl Iterator<Item = &str> {
    PATTERN.captures_iter(arg).filter_map(|caps| {
        let (written, [inner]) = caps.extract();
        matches!(
            OperandMacro::parse(inner),
            None | Some(OperandMacro::Bare(_))
        )
        .then_some(written)
    })
}
