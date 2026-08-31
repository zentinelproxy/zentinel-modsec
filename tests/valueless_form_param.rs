//! Form-body parameters with no `=`.
//!
//! `pay=AND 1=1` submitted with its separators percent-encoded arrives as
//! `pay%3DAND+1%3D1` — a body containing no literal `=` at all. Application
//! frameworks parse that as one parameter whose *name* is the whole decoded
//! string and whose value is empty; PHP's `parse_str`, Python's `parse_qs` with
//! `keep_blank_values`, and Rack all agree.
//!
//! This parser dropped such a pair entirely, so the body became invisible to
//! `ARGS` and `ARGS_NAMES` while the origin still saw a parameter. That is a
//! bypass, and encoding the `=` is a one-character change for an attacker.
//! The query-string parser has always handled the shape; only the body parser
//! did not.

use zentinel_modsec::ModSecurity;

/// Does `target` see anything at all for this urlencoded body?
fn body_populates(target: &str, body: &[u8]) -> bool {
    let rules = format!("SecRuleEngine On\nSecRule {target} \"@rx .\" \"id:1,phase:2,deny,t:none\"");
    let m = ModSecurity::from_string(&rules).expect("rules load");
    let mut tx = m.new_transaction();
    tx.process_uri("/post", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(body).unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

/// Does a rule matching `rx` against `target` fire for this body?
fn matches(target: &str, rx: &str, body: &[u8]) -> bool {
    let rules =
        format!("SecRuleEngine On\nSecRule {target} \"@rx {rx}\" \"id:1,phase:2,deny,t:none\"");
    let m = ModSecurity::from_string(&rules).expect("rules load");
    let mut tx = m.new_transaction();
    tx.process_uri("/post", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(body).unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

#[test]
fn a_body_with_no_separator_is_still_a_parameter() {
    assert!(body_populates("ARGS_NAMES", b"justatoken"));
}

#[test]
fn the_name_carries_the_decoded_text() {
    // `pay%3DAND+7639%3D%28` -> name `pay=AND 7639=(`, value empty.
    assert!(matches(
        "ARGS_NAMES",
        r"^pay=AND 7639=\($",
        b"pay%3DAND+7639%3D%28"
    ));
}

#[test]
fn its_value_is_empty_rather_than_the_name_repeated() {
    // ARGS holds values; an empty one must not masquerade as content.
    assert!(!body_populates("ARGS", b"justatoken"));
}

#[test]
fn a_valueless_pair_alongside_ordinary_ones_is_not_lost() {
    assert!(matches("ARGS_NAMES", "^bare$", b"a=1&bare&b=2"));
    assert!(matches("ARGS", "^1$", b"a=1&bare&b=2"));
    assert!(matches("ARGS", "^2$", b"a=1&bare&b=2"));
}

#[test]
fn empty_segments_do_not_become_arguments() {
    // `a=1&&b=2` and a trailing `&` must not invent a nameless parameter.
    assert!(!matches("ARGS_NAMES", "^$", b"a=1&&b=2&"));
}

#[test]
fn the_query_string_still_behaves_the_same_way() {
    // The shape the body parser was missing; asserted so the two cannot drift.
    let rules = "SecRuleEngine On\nSecRule ARGS_NAMES \"@rx ^bare$\" \"id:1,phase:2,deny,t:none\"";
    let m = ModSecurity::from_string(rules).unwrap();
    let mut tx = m.new_transaction();
    tx.process_uri("/p?bare", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert!(tx.has_intervention());
}

#[test]
fn an_sqli_payload_cannot_hide_by_encoding_its_separators() {
    // CRS 942210's shape: the rule targets ARGS_NAMES as well as ARGS, so the
    // payload is caught whichever half of the pair it lands in.
    let rx = r"(?i)\bor\b.{0,20}?\b\d+\s*=\s*\d+";
    assert!(matches("ARGS|ARGS_NAMES", rx, b"pay=or 120=121"));
    assert!(matches("ARGS|ARGS_NAMES", rx, b"pay%3Dor+120%3D121"));
}
