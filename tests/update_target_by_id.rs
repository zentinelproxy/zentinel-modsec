//! Tests for `SecRuleUpdateTargetById`, the directive OWASP CRS deployments
//! rely on to tune away false positives without disabling whole rules.
//!
//! Before this was implemented the directive was rejected outright, so the
//! standard CRS exclusion workflow — `SecRuleUpdateTargetById 942100
//! "!ARGS:password"` — could not be expressed at all. See issue
//! zentinelproxy/zentinel#342.

use zentinel_modsec::ModSecurity;

/// Load `rules` and run `GET uri` through both request phases, reporting
/// whether the request was blocked.
fn blocked(rules: &str, uri: &str) -> bool {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

/// A rule that blocks any request whose ARGS contain "secret".
const BASE_RULE: &str = "SecRuleEngine On\n\
     SecRule ARGS \"@contains secret\" \"id:942100,phase:2,deny\"";

#[test]
fn rule_blocks_without_any_exclusion() {
    assert!(blocked(BASE_RULE, "/login?password=secret"));
    assert!(blocked(BASE_RULE, "/login?comment=secret"));
}

#[test]
fn exclusion_stops_inspection_of_the_named_target() {
    let rules = format!("{BASE_RULE}\nSecRuleUpdateTargetById 942100 \"!ARGS:password\"");

    // The excluded argument is no longer inspected...
    assert!(!blocked(&rules, "/login?password=secret"));
    // ...but every other argument still is.
    assert!(blocked(&rules, "/login?comment=secret"));
}

#[test]
fn exclusion_applies_regardless_of_directive_order() {
    // CRS exclusion files are conventionally included *after* the rules, but
    // ModSecurity also accepts the directive before its target rule.
    let after = format!("{BASE_RULE}\nSecRuleUpdateTargetById 942100 \"!ARGS:password\"");
    let before =
        format!("SecRuleEngine On\nSecRuleUpdateTargetById 942100 \"!ARGS:password\"\nSecRule ARGS \"@contains secret\" \"id:942100,phase:2,deny\"");

    assert!(!blocked(&after, "/login?password=secret"));
    assert!(!blocked(&before, "/login?password=secret"));
}

#[test]
fn exclusion_for_a_different_rule_id_is_ignored() {
    let rules = format!("{BASE_RULE}\nSecRuleUpdateTargetById 999999 \"!ARGS:password\"");
    assert!(blocked(&rules, "/login?password=secret"));
}

#[test]
fn id_ranges_are_honoured() {
    let rules = format!("{BASE_RULE}\nSecRuleUpdateTargetById 942000-942999 \"!ARGS:password\"");
    assert!(!blocked(&rules, "/login?password=secret"));
    assert!(blocked(&rules, "/login?comment=secret"));
}

#[test]
fn multiple_exclusions_accumulate() {
    let rules = format!(
        "{BASE_RULE}\n\
         SecRuleUpdateTargetById 942100 \"!ARGS:password\"\n\
         SecRuleUpdateTargetById 942100 \"!ARGS:token\""
    );

    assert!(!blocked(&rules, "/login?password=secret"));
    assert!(!blocked(&rules, "/login?token=secret"));
    assert!(blocked(&rules, "/login?comment=secret"));
}

#[test]
fn appending_a_target_extends_inspection() {
    // A rule that only inspects ARGS, extended to also inspect a header.
    let rules = "SecRuleEngine On\n\
         SecRule ARGS \"@contains secret\" \"id:942100,phase:2,deny\"\n\
         SecRuleUpdateTargetById 942100 \"REQUEST_HEADERS:X-Custom\"";
    let msc = ModSecurity::from_string(rules).expect("rules should load");

    let mut tx = msc.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("X-Custom", "secret").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();

    assert!(
        tx.has_intervention(),
        "appended REQUEST_HEADERS:X-Custom target should be inspected"
    );
}

#[test]
fn replace_form_matches_multi_word_collections() {
    // Regression: target matching compared the VariableName enum's Debug
    // output, so it worked for ARGS but not REQUEST_HEADERS — the variant
    // renders as "RequestHeaders" while SecLang writes "REQUEST_HEADERS".
    // The replace form silently did nothing for every multi-word collection.
    let rules = "SecRuleEngine On\n\
         SecRule REQUEST_HEADERS:X-Test \"@contains bad\" \"id:942100,phase:2,deny\"\n\
         SecRuleUpdateTargetById 942100 \"ARGS:safe\" \"REQUEST_HEADERS:X-Test\"";
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.add_request_header("X-Test", "bad").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();

    assert!(
        !tx.has_intervention(),
        "the REQUEST_HEADERS:X-Test target should have been replaced"
    );
}
