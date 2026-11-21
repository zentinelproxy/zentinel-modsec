//! `%{...}` macros in operator arguments and `setvar` operands.
//!
//! What a macro may name is decided here and nowhere else: the transaction
//! expands with [`expand`], and the ruleset asks [`unresolvable`] at load time
//! which macros that expansion will leave empty.

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
    /// `%{tx.<name>}`, or a bare `%{<name>}`.
    Tx(&'a str),
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
            return Some(Self::Tx(inner));
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

/// The macros in `arg` that [`expand`] replaces with an empty string whatever
/// the transaction holds, as written (`%{env.MAX_LEN}`).
pub(super) fn unresolvable(arg: &str) -> impl Iterator<Item = &str> {
    PATTERN.captures_iter(arg).filter_map(|caps| {
        let (written, [inner]) = caps.extract();
        OperandMacro::parse(inner).is_none().then_some(written)
    })
}
