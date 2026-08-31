//! Regression tests for the four defects that stopped stock OWASP CRS from
//! evaluating correctly.
//!
//! Each is written against the rule *shape* CRS uses rather than against a CRS
//! checkout, so the suite stays self-contained. The shapes matter more than
//! they look: three of the four defects masked each other, and the combination
//! meant a stock CRS deployment denied 100% of requests while its anomaly
//! scoring never ran at all.
//!
//! The assertions are on **which rule fired**, not merely on whether the
//! request was blocked. Under the old behaviour everything blocked, so a
//! blocked-or-not assertion passed for the wrong reason — which is how this
//! survived as long as it did.

use zentinel_modsec::ModSecurity;

/// Rule IDs that matched, in order.
fn matched(rules: &str) -> Vec<String> {
    let m = ModSecurity::from_string(&format!("SecRuleEngine On\n{rules}")).expect("rules load");
    let mut tx = m.new_transaction();
    tx.process_uri("/api", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.add_request_header("Content-Length", "7").unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(b"q=hello").unwrap();
    tx.process_request_body().unwrap();
    tx.matched_rules().to_vec()
}

/// Whether the transaction was interrupted.
fn blocks(rules: &str) -> bool {
    let m = ModSecurity::from_string(&format!("SecRuleEngine On\n{rules}")).expect("rules load");
    let mut tx = m.new_transaction();
    tx.process_uri("/docs/report.pdf", "POST", "HTTP/1.1")
        .unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.add_request_header("Content-Length", "7").unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(b"q=hello").unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

// ---------------------------------------------------------------------------
// skipAfter and SecMarker
// ---------------------------------------------------------------------------

#[test]
fn skip_after_resumes_at_the_marker_in_phase_1() {
    assert_eq!(
        matched(
            "SecAction \"id:1,phase:1,pass,nolog,skipAfter:M\"\n\
             SecRule REQUEST_METHOD \"@streq POST\" \"id:2,phase:1,pass,nolog\"\n\
             SecMarker M\n\
             SecRule REQUEST_METHOD \"@streq POST\" \"id:3,phase:1,pass,nolog\""
        ),
        vec!["1", "3"]
    );
}

#[test]
fn skip_after_resumes_at_the_marker_in_phase_2() {
    // A marker used to be recorded only under phase 1, so a phase-2 skipAfter
    // found nothing to resume at and silently dropped the rest of the phase.
    assert_eq!(
        matched(
            "SecAction \"id:1,phase:2,pass,nolog,skipAfter:M\"\n\
             SecRule ARGS \"@rx hello\" \"id:2,phase:2,pass,nolog\"\n\
             SecMarker M\n\
             SecRule ARGS \"@rx hello\" \"id:3,phase:2,pass,nolog\""
        ),
        vec!["1", "3"]
    );
}

#[test]
fn consecutive_skip_regions_each_resume() {
    // CRS gates every rule file this way, one region per file.
    assert_eq!(
        matched(
            "SecAction \"id:1,phase:2,pass,nolog,skipAfter:END-A\"\n\
             SecRule ARGS \"@rx hello\" \"id:2,phase:2,pass,nolog\"\n\
             SecMarker END-A\n\
             SecAction \"id:3,phase:2,pass,nolog,skipAfter:END-B\"\n\
             SecRule ARGS \"@rx hello\" \"id:4,phase:2,pass,nolog\"\n\
             SecMarker END-B\n\
             SecRule ARGS \"@rx hello\" \"id:5,phase:2,pass,nolog\""
        ),
        vec!["1", "3", "5"]
    );
}

#[test]
fn a_paranoia_gate_does_not_swallow_the_blocking_evaluation() {
    // The CRS shape: a per-file paranoia gate skips that file's rules, and
    // 949110 — which performs the actual anomaly-score block — sits after it.
    assert_eq!(
        matched(
            "SecAction \"id:900,phase:1,pass,nolog,setvar:'tx.detection_paranoia_level=1'\"\n\
             SecRule TX:detection_paranoia_level \"@lt 2\" \
               \"id:942013,phase:2,pass,nolog,skipAfter:END-942\"\n\
             SecRule ARGS \"@detectSQLi\" \"id:942100,phase:2,pass,nolog\"\n\
             SecMarker END-942\n\
             SecRule ARGS \"@rx hello\" \"id:949110,phase:2,pass,nolog\""
        ),
        vec!["900", "942013", "949110"]
    );
}

#[test]
fn a_skip_that_is_not_taken_leaves_the_phase_intact() {
    assert_eq!(
        matched(
            "SecRule ARGS \"@rx nomatch\" \"id:1,phase:2,pass,nolog,skipAfter:M\"\n\
             SecRule ARGS \"@rx hello\" \"id:2,phase:2,pass,nolog\"\n\
             SecMarker M\n\
             SecRule ARGS \"@rx hello\" \"id:3,phase:2,pass,nolog\""
        ),
        vec!["2", "3"]
    );
}

// ---------------------------------------------------------------------------
// TX collection keys are case-insensitive
// ---------------------------------------------------------------------------

#[test]
fn tx_keys_are_case_insensitive() {
    // CRS writes `tx.blocking_paranoia_level` and reads
    // `TX:BLOCKING_PARANOIA_LEVEL`. Treating those as different keys stops the
    // anomaly score accumulating, so nothing ever reaches the threshold.
    let set = "SecAction \"id:1,phase:2,pass,nolog,setvar:'tx.paranoia=1'\"\n";
    for read in ["TX:paranoia", "TX:PARANOIA", "TX:Paranoia"] {
        assert!(
            blocks(&format!(
                "{set}SecRule {read} \"@ge 1\" \"id:2,phase:2,deny\""
            )),
            "reading {read} should find a value written as tx.paranoia"
        );
    }
}

#[test]
fn tx_keys_written_uppercase_are_read_lowercase() {
    assert!(blocks(
        "SecAction \"id:1,phase:2,pass,nolog,setvar:'TX.PARANOIA=1'\"\n\
         SecRule TX:paranoia \"@ge 1\" \"id:2,phase:2,deny\""
    ));
}

#[test]
fn tx_macro_expansion_is_case_insensitive() {
    // The increment form CRS uses for scoring: `=+%{TX.CRITICAL_ANOMALY_SCORE}`.
    assert!(blocks(
        "SecAction \"id:1,phase:2,pass,nolog,setvar:'tx.critical_anomaly_score=5'\"\n\
         SecAction \"id:2,phase:2,pass,nolog,setvar:'tx.score=+%{TX.CRITICAL_ANOMALY_SCORE}'\"\n\
         SecRule TX:score \"@streq 5\" \"id:3,phase:2,deny\""
    ));
}

// ---------------------------------------------------------------------------
// `block` inherits the disruptive action from SecDefaultAction
// ---------------------------------------------------------------------------

#[test]
fn block_inherits_pass_from_secdefaultaction() {
    // CRS sets `SecDefaultAction "phase:2,log,auditlog,pass"` and tags nearly
    // every rule `block`, meaning "score me and let 949110 decide". Treating
    // `block` as a deny of its own turns anomaly scoring into
    // block-on-first-match.
    assert!(!blocks(
        "SecDefaultAction \"phase:2,log,auditlog,pass\"\n\
         SecRule REQUEST_METHOD \"@streq POST\" \"id:1,phase:2,block\""
    ));
}

#[test]
fn block_inherits_deny_from_secdefaultaction() {
    assert!(blocks(
        "SecDefaultAction \"phase:2,log,auditlog,deny\"\n\
         SecRule REQUEST_METHOD \"@streq POST\" \"id:1,phase:2,block\""
    ));
}

#[test]
fn secdefaultaction_is_per_phase() {
    // Phase 1 denies, phase 2 passes. A single flat list would let whichever
    // directive was parsed last govern both.
    assert!(!blocks(
        "SecDefaultAction \"phase:1,log,deny\"\n\
         SecDefaultAction \"phase:2,log,pass\"\n\
         SecRule REQUEST_METHOD \"@streq POST\" \"id:1,phase:2,block\""
    ));
    assert!(blocks(
        "SecDefaultAction \"phase:1,log,deny\"\n\
         SecDefaultAction \"phase:2,log,pass\"\n\
         SecRule REQUEST_METHOD \"@streq POST\" \"id:1,phase:1,block\""
    ));
}

#[test]
fn block_without_secdefaultaction_still_blocks() {
    // A deliberate divergence from ModSecurity, whose built-in default is
    // `pass`. Silently downgrading a hand-written `block` to `pass` would
    // disable protection the author asked for; CRS always sets
    // SecDefaultAction, so its behaviour is unaffected either way.
    assert!(blocks(
        "SecRule REQUEST_METHOD \"@streq POST\" \"id:1,phase:2,block\""
    ));
}

#[test]
fn an_explicit_rule_action_still_overrides_the_default() {
    assert!(blocks(
        "SecDefaultAction \"phase:2,log,auditlog,pass\"\n\
         SecRule REQUEST_METHOD \"@streq POST\" \"id:1,phase:2,deny\""
    ));
}

// ---------------------------------------------------------------------------
// Absent variables, and the negation that inverted them
// ---------------------------------------------------------------------------

#[test]
fn request_line_is_populated() {
    assert!(blocks(
        "SecRule REQUEST_LINE \"@streq POST /docs/report.pdf HTTP/1.1\" \"id:1,phase:2,deny\""
    ));
}

#[test]
fn crs_920100_does_not_fire_on_an_ordinary_request() {
    // Verbatim from CRS. REQUEST_LINE being unresolvable made this negated
    // regex match every request, so a stock CRS deployment denied all traffic.
    let r920100 = "SecRule REQUEST_LINE \"!@rx (?i)^(?:connect (?:(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\.?(?::[0-9]+)?|[\\--9A-Z_a-z]+:[0-9]+)|options \\*|[a-z]{3,10}[\\s\\x0b]+(?:[0-9A-Z_a-z]{3,7}?://[\\--9A-Z_a-z]*(?::[0-9]+)?)?/[^#\\?]*(?:\\?[^\\s\\x0b#]*)?(?:#[^\\s\\x0b]*)?)[\\s\\x0b]+[\\.-9A-Z_a-z]+$\" \"id:920100,phase:2,deny\"";
    assert!(!blocks(r920100));
}

#[test]
fn request_basename_is_populated() {
    assert!(blocks(
        "SecRule REQUEST_BASENAME \"@streq report.pdf\" \"id:1,phase:2,deny\""
    ));
    // The negated form CRS uses; it must not fire on a genuine .pdf.
    assert!(!blocks(
        "SecRule REQUEST_BASENAME \"!@endsWith .pdf\" \"id:2,phase:2,deny\""
    ));
}

#[test]
fn args_combined_size_counts_names_and_values() {
    // Body is `q=hello`: one argument, name 1 + value 5.
    assert!(blocks(
        "SecRule ARGS_COMBINED_SIZE \"@eq 6\" \"id:1,phase:2,deny\""
    ));
}

#[test]
fn a_negated_operator_does_not_match_an_absent_variable() {
    // The general form of the 920100 failure: absence must not be reported as
    // a match just because the operator is negated. Absence is tested with
    // `&VAR "@eq 0"`, which resolves to a count and is unaffected.
    assert!(!blocks(
        "SecRule REQUEST_HEADERS:X-Not-Sent \"!@rx anything\" \"id:1,phase:2,deny\""
    ));
    assert!(blocks(
        "SecRule &REQUEST_HEADERS:X-Not-Sent \"@eq 0\" \"id:2,phase:2,deny\""
    ));
}

#[test]
fn an_unimplemented_variable_is_classified_as_such() {
    use zentinel_modsec::parser::VariableName;
    assert!(VariableName::RequestLine.is_implemented());
    assert!(VariableName::RequestBasename.is_implemented());
    assert!(VariableName::ArgsCombinedSize.is_implemented());
    // `XML:` resolves against the flattened XML body; see tests/xml_targets.rs.
    assert!(VariableName::Xml.is_implemented());
    // Still unimplemented; a rule targeting only these is reported at load time.
    assert!(!VariableName::UniqueId.is_implemented());
    assert!(!VariableName::FilesCombinedSize.is_implemented());
}
