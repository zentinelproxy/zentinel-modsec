//! Tests for the JSON request body processor.
//!
//! JSON bodies used to fall through to the urlencoded parser, which extracts
//! nothing usable from them. `ARGS` was therefore empty for every JSON
//! request, and CRS rule 942100 (`SecRule ARGS "@detectSQLi"`) — the core SQLi
//! rule — had nothing to inspect. The same payload was blocked in a form body
//! and passed unexamined in a JSON body:
//!
//! ```text
//! urlencoded body, SQLi in q -> blocked=true
//! JSON body, SQLi in q       -> blocked=false
//! ```
//!
//! For a JSON API that is most of the attack surface the WAF was deployed to
//! cover. Part of zentinelproxy/zentinel#340.

use zentinel_modsec::ModSecurity;

fn run(rules: &str, content_type: &str, body: &[u8]) -> bool {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri("/api/search", "POST", "HTTP/1.1").unwrap();
    if !content_type.is_empty() {
        tx.add_request_header("Content-Type", content_type).unwrap();
    }
    tx.process_request_headers().unwrap();
    tx.append_request_body(body).unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

/// Blocks when `ARGS:<name>` is present with any value.
fn rule_on_arg(name: &str) -> String {
    format!("SecRuleEngine On\nSecRule ARGS:{name} \"@rx .\" \"id:1,phase:2,deny\"")
}

/// Blocks when `ARGS:<name>` equals `value`.
fn rule_on_arg_value(name: &str, value: &str) -> String {
    format!("SecRuleEngine On\nSecRule ARGS:{name} \"@streq {value}\" \"id:1,phase:2,deny\"")
}

const SQLI_RULE: &str = "SecRuleEngine On\n\
     SecRule ARGS \"@detectSQLi\" \"id:942100,phase:2,deny,status:403\"";

const SQLI: &[u8] = br#"{"q":"1 UNION SELECT password FROM users"}"#;

// ---------------------------------------------------------------------------
// The bypass this exists to close
// ---------------------------------------------------------------------------

#[test]
fn sqli_in_a_json_body_is_detected() {
    assert!(run(SQLI_RULE, "application/json", SQLI));
}

#[test]
fn the_same_payload_is_detected_in_a_form_body() {
    // Control: if this ever fails, the test above proves nothing about JSON.
    assert!(run(
        SQLI_RULE,
        "application/x-www-form-urlencoded",
        b"q=1 UNION SELECT password FROM users"
    ));
}

#[test]
fn sqli_nested_in_an_object_is_detected() {
    assert!(run(
        SQLI_RULE,
        "application/json",
        br#"{"filter":{"deeply":{"nested":"1 UNION SELECT password FROM users"}}}"#
    ));
}

#[test]
fn sqli_inside_an_array_is_detected() {
    assert!(run(
        SQLI_RULE,
        "application/json",
        br#"{"ids":["ok","1 UNION SELECT password FROM users"]}"#
    ));
}

#[test]
fn clean_json_traffic_passes() {
    assert!(!run(
        SQLI_RULE,
        "application/json",
        br#"{"q":"hello world","page":2,"ok":true}"#
    ));
}

// ---------------------------------------------------------------------------
// Argument naming — CRS exclusions are written against these names
// ---------------------------------------------------------------------------

#[test]
fn scalars_are_named_by_their_path() {
    assert!(run(
        &rule_on_arg_value("json.user.name", "bob"),
        "application/json",
        br#"{"user":{"name":"bob"}}"#
    ));
}

#[test]
fn array_elements_are_named_by_index() {
    assert!(run(
        &rule_on_arg_value("json.tags.1", "b"),
        "application/json",
        br#"{"tags":["a","b"]}"#
    ));
}

#[test]
fn non_string_scalars_become_their_textual_form() {
    for (body, name, value) in [
        (&br#"{"page":42}"#[..], "json.page", "42"),
        (&br#"{"ok":true}"#[..], "json.ok", "true"),
        (&br#"{"ratio":1.5}"#[..], "json.ratio", "1.5"),
    ] {
        assert!(
            run(&rule_on_arg_value(name, value), "application/json", body),
            "{name} should be {value}"
        );
    }
}

#[test]
fn null_is_present_with_an_empty_value() {
    // A rule testing for the presence of a key should still see it. `@rx .`
    // would not match an empty value, so test presence via the count operator.
    let rules = "SecRuleEngine On\n\
         SecRule &ARGS:json.opt \"@eq 1\" \"id:1,phase:2,deny\"";
    assert!(run(rules, "application/json", br#"{"opt":null}"#));
}

#[test]
fn a_top_level_array_is_flattened() {
    assert!(run(
        &rule_on_arg_value("json.0", "x"),
        "application/json",
        br#"["x","y"]"#
    ));
}

// ---------------------------------------------------------------------------
// Content-Type dispatch
// ---------------------------------------------------------------------------

#[test]
fn json_content_types_are_recognised() {
    for ct in [
        "application/json",
        "application/json; charset=utf-8",
        "APPLICATION/JSON",
        "text/json",
        // RFC 6839 structured suffix: these are JSON and must be inspected.
        "application/vnd.api+json",
        "application/problem+json",
    ] {
        assert!(
            run(SQLI_RULE, ct, SQLI),
            "Content-Type {ct} should be processed as JSON"
        );
    }
}

#[test]
fn a_non_json_content_type_is_not_processed_as_json() {
    // text/plain is not JSON; it should not be flattened into ARGS.
    assert!(!run(
        &rule_on_arg("json.q"),
        "text/plain",
        br#"{"q":"value"}"#
    ));
}

#[test]
fn ctl_can_force_the_json_processor() {
    // The header is absent, so sniffing would extract nothing. This is why
    // CRS sets the processor explicitly.
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON\"\n\
         SecRule ARGS \"@detectSQLi\" \"id:942100,phase:2,deny\"";
    assert!(run(rules, "", SQLI));
}

#[test]
fn reqbody_processor_reports_json() {
    let rules = "SecRuleEngine On\n\
         SecRule REQBODY_PROCESSOR \"@streq JSON\" \"id:1,phase:2,deny\"";
    assert!(run(rules, "application/json", br#"{"a":1}"#));
}

// ---------------------------------------------------------------------------
// Failures must be visible, not silent
// ---------------------------------------------------------------------------

/// The reason this matters: a strict parser rejecting a payload that the
/// origin application accepts is itself a bypass, if the rejection is quiet.
/// CRS rule 200002 exists to block exactly that, and it can only work if
/// `REQBODY_ERROR` is observable.
#[test]
fn malformed_json_sets_reqbody_error() {
    let crs_200002 = "SecRuleEngine On\n\
         SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,deny,status:400\"";

    assert!(
        run(crs_200002, "application/json", br#"{"q": "unterminated"#),
        "a body that failed to parse must be visible to REQBODY_ERROR"
    );
}

#[test]
fn well_formed_json_leaves_reqbody_error_at_zero() {
    let crs_200002 = "SecRuleEngine On\n\
         SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,deny,status:400\"";

    assert!(
        !run(crs_200002, "application/json", br#"{"q":"fine"}"#),
        "a clean body must not trip the parse-failure rule"
    );
}

#[test]
fn the_error_message_is_available() {
    let rules = "SecRuleEngine On\n\
         SecRule REQBODY_ERROR_MSG \"@contains JSON parsing error\" \"id:1,phase:2,deny\"";
    assert!(run(rules, "application/json", br#"{bad"#));
}

#[test]
fn a_malformed_body_does_not_abort_the_transaction() {
    // Phase 2 still runs, so the ruleset decides what to do about the failure
    // rather than the engine deciding for it.
    let rules = "SecRuleEngine On\n\
         SecRule REQUEST_URI \"@contains /api\" \"id:1,phase:2,deny\"";
    assert!(run(rules, "application/json", br#"{bad"#));
}

/// A body can be small on the wire and expand into an enormous number of
/// arguments. Hitting the cap is reported as a processing error rather than
/// silently truncating, because a partially inspected body is not a safe one.
#[test]
fn exceeding_the_argument_cap_is_reported_as_an_error() {
    let crs_200002 = "SecRuleEngine On\n\
         SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,deny,status:400\"";

    let huge = format!("[{}]", vec!["1"; 5000].join(","));
    assert!(
        run(crs_200002, "application/json", huge.as_bytes()),
        "a body past the argument cap must set REQBODY_ERROR"
    );
}

#[test]
fn deeply_nested_json_does_not_overflow_the_stack() {
    // serde_json refuses to parse past its own recursion limit, so this is
    // reported as a parse error rather than crashing.
    let crs_200002 = "SecRuleEngine On\n\
         SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,deny,status:400\"";

    let deep = format!("{}1{}", "[".repeat(2000), "]".repeat(2000));
    assert!(run(crs_200002, "application/json", deep.as_bytes()));
}

/// An empty body is nothing to inspect, not a failure to parse.
///
/// Clients legitimately send `Content-Type: application/json` with an empty
/// body on POST and DELETE. Reporting that through `REQBODY_ERROR` would make
/// CRS rule 200002 block them — a false positive introduced by the WAF rather
/// than a threat caught by it.
#[test]
fn an_empty_body_is_not_a_parse_error() {
    let crs_200002 = "SecRuleEngine On\n\
         SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,deny,status:400\"";
    assert!(!run(crs_200002, "application/json", b""));
    assert!(!run(crs_200002, "application/json", b"   \n\t "));
}

/// Duplicate keys must not hide a payload.
///
/// `serde_json::Value` keeps only the last value for a repeated key, so
/// `{"a":"<payload>","a":"safe"}` would present only `safe` to the rules while
/// an origin application whose parser keeps the first occurrence receives the
/// payload. Every value that was sent is inspected instead.
#[test]
fn every_value_of_a_duplicated_key_is_inspected() {
    const SQLI_TEXT: &str = "1 UNION SELECT password FROM users";
    for body in [
        format!(r#"{{"a":"{SQLI_TEXT}","a":"safe"}}"#),
        format!(r#"{{"a":"safe","a":"{SQLI_TEXT}"}}"#),
    ] {
        assert!(
            run(SQLI_RULE, "application/json", body.as_bytes()),
            "payload must be found regardless of duplicate ordering: {body}"
        );
    }
}

/// Large integers keep their exact value rather than going through f64.
#[test]
fn large_numbers_are_not_rounded() {
    assert!(run(
        &rule_on_arg_value("json.id", "9007199254740993"),
        "application/json",
        br#"{"id":9007199254740993}"#
    ));
}

// ---------------------------------------------------------------------------
// Exclusions still work against JSON argument names
// ---------------------------------------------------------------------------

#[test]
fn a_json_argument_can_be_excluded_by_path() {
    // The whole point of the naming convention: CRS exclusions target these.
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:json.q\"\n\
         SecRule ARGS \"@detectSQLi\" \"id:942100,phase:2,deny\"";

    assert!(
        !run(rules, "application/json", SQLI),
        "excluding ARGS:json.q should suppress the match"
    );
}

#[test]
fn excluding_one_json_path_leaves_the_others_live() {
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:json.q\"\n\
         SecRule ARGS \"@detectSQLi\" \"id:942100,phase:2,deny\"";

    assert!(
        run(
            rules,
            "application/json",
            br#"{"other":"1 UNION SELECT password FROM users"}"#
        ),
        "a different key must still be inspected"
    );
}
