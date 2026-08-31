//! `+` as a space in form-encoded input.
//!
//! In `application/x-www-form-urlencoded` a `+` is a space — it is what a
//! browser emits for a space in a submitted form. Decoding only percent-escapes
//! left the argument holding a literal `+` where the origin application sees a
//! space, so a rule matching a payload containing whitespace missed while the
//! same request reached the application intact. That is a bypass, not a
//! coverage gap, which is why these tests assert both halves: that `+` decodes,
//! and that a plus genuinely sent as `%2B` is not turned into one.

use zentinel_modsec::ModSecurity;

fn query(rx: &str, uri: &str) -> bool {
    let rules = format!("SecRuleEngine On\nSecRule ARGS \"@rx {rx}\" \"id:1,phase:2,deny,t:none\"");
    let m = ModSecurity::from_string(&rules).expect("rules load");
    let mut tx = m.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

fn form(rx: &str, body: &[u8]) -> bool {
    let rules = format!("SecRuleEngine On\nSecRule ARGS \"@rx {rx}\" \"id:1,phase:2,deny,t:none\"");
    let m = ModSecurity::from_string(&rules).expect("rules load");
    let mut tx = m.new_transaction();
    tx.process_uri("/g", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(body).unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

fn arg_name(rx: &str, uri: &str) -> bool {
    let rules =
        format!("SecRuleEngine On\nSecRule ARGS_NAMES \"@rx {rx}\" \"id:1,phase:2,deny,t:none\"");
    let m = ModSecurity::from_string(&rules).expect("rules load");
    let mut tx = m.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

// ---------------------------------------------------------------------------
// `+` is a space
// ---------------------------------------------------------------------------

#[test]
fn plus_is_a_space_in_a_query_string() {
    assert!(query("^a b$", "/g?foo=a+b"));
}

#[test]
fn plus_is_a_space_in_a_urlencoded_body() {
    assert!(form("^a b$", b"foo=a+b"));
}

#[test]
fn plus_is_a_space_in_an_argument_name() {
    assert!(arg_name("^a b$", "/g?a+b=x"));
}

#[test]
fn plus_is_a_space_in_a_valueless_argument() {
    assert!(arg_name("^a b$", "/g?a+b"));
}

#[test]
fn percent_20_is_still_a_space() {
    assert!(query("^a b$", "/g?foo=a%20b"));
    assert!(form("^a b$", b"foo=a%20b"));
}

// ---------------------------------------------------------------------------
// A plus that was meant as a plus
// ---------------------------------------------------------------------------

#[test]
fn an_escaped_plus_stays_a_plus() {
    // %2B must survive as '+', not become a space. A naive replace *after*
    // percent-decoding gets this wrong.
    assert!(query(r"^a\+b$", "/g?foo=a%2Bb"));
    assert!(form(r"^a\+b$", b"foo=a%2Bb"));
    assert!(!query("^a b$", "/g?foo=a%2Bb"));
}

#[test]
fn a_double_encoded_plus_is_not_over_decoded() {
    // %252B decodes once to the literal text "%2B".
    assert!(query(r"^%2Bb$", "/g?foo=%252Bb"));
}

// ---------------------------------------------------------------------------
// The bypass this closes
// ---------------------------------------------------------------------------

#[test]
fn a_space_separated_payload_cannot_hide_behind_plus_encoding() {
    // The shape a CRS rule looks for; both encodings must be seen alike.
    let rule = r"(?i)\bunion\b.{1,100}?\bselect\b";
    assert!(query(rule, "/u?id=1%20UNION%20SELECT%20password%20FROM%20users"));
    assert!(query(rule, "/u?id=1+UNION+SELECT+password+FROM+users"));
    assert!(form(rule, b"id=1+UNION+SELECT+password+FROM+users"));
}

#[test]
fn a_windows_command_line_becomes_readable() {
    // The input that led here: CRS 932140's test 11, whose spaces are `+`.
    // With `+` decoded the words separate; whether 932140 itself then matches
    // additionally depends on `t:cmdLine`, which is a separate fix, so this
    // asserts only the part form-decoding is responsible for.
    let uri = "/g?foo=FOR+%25a+IN+%28set%29+DO+abc";
    let rules = "SecRuleEngine On\nSecRule ARGS \"@rx ^for %a in \\(set\\) do abc$\" \
                 \"id:1,phase:2,deny,t:none,t:lowercase\"";
    let m = ModSecurity::from_string(rules).expect("rules load");
    let mut tx = m.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert!(tx.has_intervention());
}

// ---------------------------------------------------------------------------
// Encodings that are not form-encoded must be left alone
// ---------------------------------------------------------------------------

#[test]
fn a_json_body_keeps_its_pluses() {
    let rules = "SecRuleEngine On\nSecRule ARGS \"@rx ^a\\+b$\" \"id:1,phase:2,deny,t:none\"";
    let m = ModSecurity::from_string(rules).unwrap();
    let mut tx = m.new_transaction();
    tx.process_uri("/g", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/json").unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(br#"{"foo":"a+b"}"#).unwrap();
    tx.process_request_body().unwrap();
    assert!(tx.has_intervention(), "a plus in JSON is a plus");
}

#[test]
fn an_xml_body_keeps_its_pluses() {
    let rules = "SecRuleEngine On\nSecRule ARGS \"@rx ^a\\+b$\" \"id:1,phase:2,deny,t:none\"";
    let m = ModSecurity::from_string(rules).unwrap();
    let mut tx = m.new_transaction();
    tx.process_uri("/g", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/xml").unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(b"<r><q>a+b</q></r>").unwrap();
    tx.process_request_body().unwrap();
    assert!(tx.has_intervention(), "a plus in XML is a plus");
}

#[test]
fn the_request_uri_is_not_form_decoded() {
    // REQUEST_URI is the raw request target, not a form-encoded component.
    let rules =
        "SecRuleEngine On\nSecRule REQUEST_URI \"@rx \\+\" \"id:1,phase:2,deny,t:none\"";
    let m = ModSecurity::from_string(rules).unwrap();
    let mut tx = m.new_transaction();
    tx.process_uri("/g?foo=a+b", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert!(tx.has_intervention(), "REQUEST_URI should still contain the '+'");
}
