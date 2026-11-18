//! Tests for `ctl:ruleRemoveByTag` and `ctl:ruleRemoveTargetByTag`.
//!
//! Both were parsed as unsupported and ignored, with a warning logged once per
//! transaction. CRS uses them in rules 941010 (drop `REQUEST_FILENAME` from the
//! XSS rules when it is harmless), 901450 (sampling mode) and 905100/905110
//! (Apache internal dummy connections).

use zentinel_modsec::ModSecurity;

fn engine(rules: &str) -> ModSecurity {
    ModSecurity::from_string(rules).expect("rules should load")
}

/// Which rule IDs matched for one GET request.
fn matched_rules(rules: &str, uri: &str) -> Vec<String> {
    let msc = engine(rules);
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.matched_rules().to_vec()
}

fn blocked(rules: &str, uri: &str) -> bool {
    let msc = engine(rules);
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

// ---------------------------------------------------------------------------
// ctl:ruleRemoveByTag
// ---------------------------------------------------------------------------

#[test]
fn remove_by_tag_skips_every_rule_carrying_the_tag() {
    // The shape of CRS 901450 / 905100: one tag disables the whole CRS.
    let rules = r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,ctl:ruleRemoveByTag=OWASP_CRS"
SecRule REQUEST_URI "@contains /" "id:2,phase:1,pass,tag:'application-multi',tag:'OWASP_CRS'"
SecRule REQUEST_URI "@contains /" "id:3,phase:2,deny,tag:'OWASP_CRS'"
SecRule REQUEST_URI "@contains /" "id:4,phase:1,pass,tag:'local'"
"#;
    let matched = matched_rules(rules, "/");
    assert!(!matched.contains(&"2".to_string()), "{matched:?}");
    assert!(!matched.contains(&"3".to_string()), "{matched:?}");
    assert!(
        matched.contains(&"4".to_string()),
        "untagged rule must still run: {matched:?}"
    );
    assert!(!blocked(rules, "/"));
}

#[test]
fn remove_by_tag_is_exact_and_case_sensitive() {
    let rules = r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,ctl:ruleRemoveByTag=OWASP_CRS"
SecRule REQUEST_URI "@contains /" "id:2,phase:1,pass,tag:'OWASP_CRS/attack-xss'"
SecRule REQUEST_URI "@contains /" "id:3,phase:1,pass,tag:'owasp_crs'"
"#;
    let matched = matched_rules(rules, "/");
    assert!(matched.contains(&"2".to_string()), "{matched:?}");
    assert!(matched.contains(&"3".to_string()), "{matched:?}");
}

#[test]
fn remove_by_tag_only_affects_rules_evaluated_after_it() {
    let rules = r#"
SecRuleEngine On
SecRule REQUEST_URI "@contains /" "id:1,phase:1,pass,tag:'OWASP_CRS'"
SecAction "id:2,phase:1,pass,nolog,ctl:ruleRemoveByTag=OWASP_CRS"
SecRule REQUEST_URI "@contains /" "id:3,phase:1,pass,tag:'OWASP_CRS'"
"#;
    let matched = matched_rules(rules, "/");
    assert!(matched.contains(&"1".to_string()), "{matched:?}");
    assert!(!matched.contains(&"3".to_string()), "{matched:?}");
}

#[test]
fn remove_by_tag_skips_a_whole_chain() {
    let rules = r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,ctl:ruleRemoveByTag=OWASP_CRS"
SecRule REQUEST_URI "@contains /" "id:2,phase:1,deny,chain,tag:'OWASP_CRS'"
    SecRule REQUEST_METHOD "@streq GET" ""
"#;
    assert!(!blocked(rules, "/"));
}

#[test]
fn remove_by_tag_is_per_transaction() {
    // The removal must not leak into the next transaction on the same engine.
    let msc = engine(
        r#"
SecRuleEngine On
SecRule REQUEST_URI "@contains skip" "id:1,phase:1,pass,nolog,ctl:ruleRemoveByTag=OWASP_CRS"
SecRule REQUEST_URI "@contains /" "id:2,phase:1,deny,tag:'OWASP_CRS'"
"#,
    );
    let run = |uri: &str| {
        let mut tx = msc.new_transaction();
        tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.has_intervention()
    };
    assert!(!run("/skip"));
    assert!(run("/other"));
}

// ---------------------------------------------------------------------------
// ctl:ruleRemoveTargetByTag
// ---------------------------------------------------------------------------

/// The shape of CRS 941010 and the 941xxx rules it applies to.
const XSS_PERF: &str = r#"
SecRuleEngine On
SecRule REQUEST_FILENAME "!@validateByteRange 20,45-47,48-57,65-90,95,97-122" "id:941010,phase:1,pass,nolog,tag:'OWASP_CRS',ctl:ruleRemoveTargetByTag=xss-perf-disable;REQUEST_FILENAME"
SecRule REQUEST_FILENAME|ARGS "@contains abc" "id:941100,phase:2,deny,tag:'attack-xss',tag:'xss-perf-disable',tag:'OWASP_CRS'"
SecRule REQUEST_FILENAME "@contains abc" "id:942100,phase:2,pass,tag:'attack-sqli',tag:'OWASP_CRS'"
"#;

#[test]
fn remove_target_by_tag_drops_the_target_from_tagged_rules() {
    // A harmless path: 941010 removes REQUEST_FILENAME from 941100, so the
    // path alone no longer triggers it.
    let matched = matched_rules(XSS_PERF, "/abc.html");
    assert!(!matched.contains(&"941100".to_string()), "{matched:?}");
    assert!(!blocked(XSS_PERF, "/abc.html"));
    // A rule without the tag keeps the target.
    assert!(matched.contains(&"942100".to_string()), "{matched:?}");
}

#[test]
fn remove_target_by_tag_keeps_the_other_targets() {
    // REQUEST_FILENAME is excluded, ARGS is not.
    assert!(blocked(XSS_PERF, "/index.html?q=abc"));
}

#[test]
fn remove_target_by_tag_does_not_fire_for_a_suspicious_path() {
    // The path contains '<', outside the byte range: 941010 does not fire and
    // 941100 keeps inspecting REQUEST_FILENAME.
    assert!(blocked(XSS_PERF, "/abc%3C.html"));
}
