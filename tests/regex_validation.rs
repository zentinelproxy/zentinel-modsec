//! Tests for how an unusable `@rx` pattern is handled.
//!
//! A regex was compiled lazily on first use, and a compilation failure was
//! swallowed into a no-match:
//!
//! ```ignore
//! let regex = match self.get_regex() {
//!     Ok(r) => r,
//!     Err(_) => return OperatorResult::no_match(),
//! };
//! ```
//!
//! So a typo in a pattern produced a rule that could never match, for every
//! request, forever, with nothing logged — a dead rule that looks alive. The
//! `RxOperator::new` doc claimed the pattern was validated at load; it only
//! checked for an empty string.
//!
//! Reported as part of zentinelproxy/zentinel#340.

use zentinel_modsec::ModSecurity;

fn load(rules: &str) -> Result<ModSecurity, String> {
    ModSecurity::from_string(rules).map_err(|e| e.to_string())
}

fn blocked(msc: &ModSecurity, uri: &str) -> bool {
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.has_intervention()
}

const INVALID_PATTERNS: &[&str] = &[
    "(unclosed",
    "a{2,1}",
    "[z-a]",
    "*nostart",
    "(?P<n>a)(?P<n>b)",
];

/// An unusable pattern must not stop the rest of the ruleset from loading.
///
/// Rejecting it outright would fix the silence but introduce a worse failure:
/// one pattern this engine cannot parse would take the whole WAF down at
/// startup. The rule is kept, is reported at load, and can never match.
#[test]
fn an_invalid_pattern_does_not_prevent_the_ruleset_from_loading() {
    for pattern in INVALID_PATTERNS {
        let rules = format!(
            "SecRuleEngine On\n\
             SecRule REQUEST_URI \"@rx {pattern}\" \"id:1,phase:1,deny\"\n\
             SecRule REQUEST_URI \"@rx /attack\" \"id:2,phase:1,deny\""
        );
        let msc = load(&rules).unwrap_or_else(|e| panic!("{pattern:?} should still load: {e}"));

        assert!(
            blocked(&msc, "/attack"),
            "the valid rule must still be enforced alongside {pattern:?}"
        );
        assert!(
            !blocked(&msc, "/harmless"),
            "the invalid rule must not match anything ({pattern:?})"
        );
    }
}

/// The dangerous case.
///
/// A rule whose operator can never match, combined with a preserved negation,
/// inverts into one that matches *every* request. That would turn a silently
/// dead rule into one that blocks all traffic — much worse than the bug being
/// fixed. The negation is dropped along with the pattern.
#[test]
fn a_negated_invalid_pattern_does_not_block_everything() {
    for pattern in INVALID_PATTERNS {
        let rules = format!(
            "SecRuleEngine On\n\
             SecRule REQUEST_URI \"!@rx {pattern}\" \"id:1,phase:1,deny\""
        );
        let msc = load(&rules).unwrap_or_else(|e| panic!("!{pattern:?} should load: {e}"));

        assert!(
            !blocked(&msc, "/anything"),
            "a negated invalid pattern must not match every request ({pattern:?})"
        );
    }
}

/// A negated *valid* pattern still inverts, so the test above is not passing
/// because negation stopped working generally.
#[test]
fn a_negated_valid_pattern_still_inverts() {
    let rules = "SecRuleEngine On\n\
         SecRule REQUEST_URI \"!@rx /allowed\" \"id:1,phase:1,deny\"";
    let msc = load(rules).expect("should load");

    assert!(!blocked(&msc, "/allowed"), "the allowed path must pass");
    assert!(blocked(&msc, "/other"), "anything else must be blocked");
}

/// A chain starter that can never match must not let its continuation run on
/// its own — the same failure the chain fix addressed.
#[test]
fn an_invalid_pattern_in_a_chain_starter_disables_the_chain() {
    let rules = "SecRuleEngine On\n\
         SecRule REQUEST_URI \"@rx (unclosed\" \"id:1,phase:1,deny,chain\"\n\
         SecRule REQUEST_METHOD \"@streq GET\"";
    let msc = load(rules).expect("should load");

    assert!(!blocked(&msc, "/anything"));
}

/// Patterns of the kind CRS actually ships must keep loading. If validation
/// were too strict, the cure would be worse than the disease.
#[test]
fn realistic_patterns_still_load() {
    for pattern in [
        r"(?i)(?:union.*select|select.*from|insert.*into)",
        r"(?i:\bor\b\s+\d+\s*=\s*\d+)",
        r"^[\w.-]+@[\w.-]+\.[a-z]{2,}$",
        r"(?:<script[^>]*>|javascript:)",
        r"\b(?:s(?:elect\b.{1,100}?\b(?:length|count)|ys\w+\()|c(?:ast\b|oncat\b))",
        r"[\x00-\x08\x0b\x0c\x0e-\x1f]",
    ] {
        let rules =
            format!("SecRuleEngine On\nSecRule ARGS \"@rx {pattern}\" \"id:1,phase:1,deny\"");
        assert!(
            load(&rules).is_ok(),
            "a realistic pattern must load: {pattern}"
        );
    }
}

/// The valid rule keeps working when the invalid one comes second, too —
/// loading does not stop at the first bad pattern.
#[test]
fn loading_continues_past_an_invalid_pattern() {
    let rules = "SecRuleEngine On\n\
         SecRule REQUEST_URI \"@rx /first\" \"id:1,phase:1,deny\"\n\
         SecRule REQUEST_URI \"@rx (bad\" \"id:2,phase:1,deny\"\n\
         SecRule REQUEST_URI \"@rx /third\" \"id:3,phase:1,deny\"";
    let msc = load(rules).expect("should load");

    assert!(blocked(&msc, "/first"));
    assert!(blocked(&msc, "/third"));
    assert!(!blocked(&msc, "/second"));
}

/// An empty pattern is handled the same way as any other unusable one.
///
/// It used to be the single case that failed the load, because it was the
/// only one checked eagerly. Now that every unusable pattern is detected at
/// load, they all behave alike: reported, rule kept, never matches. Treating
/// this one differently would only be a leftover of when it was the only one
/// we could see.
#[test]
fn an_empty_pattern_is_reported_like_any_other_unusable_pattern() {
    let rules = "SecRuleEngine On\n\
         SecRule REQUEST_URI \"@rx \" \"id:1,phase:1,deny\"\n\
         SecRule REQUEST_URI \"@rx /attack\" \"id:2,phase:1,deny\"";
    let msc = load(rules).expect("an empty pattern should not stop the load");

    assert!(
        !blocked(&msc, "/harmless"),
        "the empty-pattern rule must not match"
    );
    assert!(blocked(&msc, "/attack"), "the valid rule must still work");
}
