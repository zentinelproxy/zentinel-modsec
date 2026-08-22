//! Tests for the XML request body processor.
//!
//! XML bodies were not inspected at all: they fell through to the urlencoded
//! parser, which finds nothing in them, so `ARGS` was empty and rules like
//! CRS 942100 had nothing to look at — the same gap the JSON processor
//! closed, and the last one from zentinelproxy/zentinel#340.
//!
//! XML brings hazards JSON does not, and most of this file is about them.
//! Expanding attacker-supplied entity definitions is the mechanism behind
//! both XXE and billion-laughs, so this engine does not expand them — and
//! says so through `REQBODY_ERROR` rather than quietly inspecting less than
//! the origin application will.

use zentinel_modsec::ModSecurity;

fn run(rules: &str, content_type: &str, body: &[u8]) -> bool {
    let m = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = m.new_transaction();
    tx.process_uri("/api", "POST", "HTTP/1.1").unwrap();
    if !content_type.is_empty() {
        tx.add_request_header("Content-Type", content_type).unwrap();
    }
    tx.process_request_headers().unwrap();
    tx.append_request_body(body).unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

fn contains(body: &[u8], needle: &str) -> bool {
    let rules =
        format!("SecRuleEngine On\nSecRule ARGS \"@contains {needle}\" \"id:1,phase:2,deny\"");
    run(&rules, "application/xml", body)
}

const SQLI_RULE: &str = "SecRuleEngine On\n\
     SecRule ARGS \"@detectSQLi\" \"id:942100,phase:2,deny,status:403\"";

const BODY_ERROR_RULE: &str = "SecRuleEngine On\n\
     SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,deny,status:400\"";

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

#[test]
fn sqli_in_element_text_is_detected() {
    assert!(run(
        SQLI_RULE,
        "application/xml",
        br#"<order><q>1 UNION SELECT password FROM users</q></order>"#
    ));
}

#[test]
fn sqli_in_an_attribute_is_detected() {
    assert!(run(
        SQLI_RULE,
        "application/xml",
        br#"<order q="1 UNION SELECT password FROM users"/>"#
    ));
}

/// CDATA is text deliberately marked as not-markup, which makes it an obvious
/// place to hide a payload.
#[test]
fn sqli_in_cdata_is_detected() {
    assert!(run(
        SQLI_RULE,
        "application/xml",
        br#"<o><q><![CDATA[1 UNION SELECT password FROM users]]></q></o>"#
    ));
}

#[test]
fn sqli_nested_deeply_is_detected() {
    assert!(run(
        SQLI_RULE,
        "application/xml",
        br#"<a><b><c><d>1 UNION SELECT password FROM users</d></c></b></a>"#
    ));
}

#[test]
fn clean_xml_traffic_passes() {
    assert!(!run(
        SQLI_RULE,
        "application/xml",
        br#"<order><q>laptop</q><qty>2</qty></order>"#
    ));
}

#[test]
fn xml_content_types_are_recognised() {
    let payload = br#"<o><q>1 UNION SELECT password FROM users</q></o>"#;
    for ct in [
        "application/xml",
        "text/xml",
        "APPLICATION/XML",
        "application/xml; charset=utf-8",
        // RFC 6839 structured suffix — SOAP is the one that matters here.
        "application/soap+xml",
        "application/atom+xml",
    ] {
        assert!(run(SQLI_RULE, ct, payload), "{ct} should be parsed as XML");
    }
}

#[test]
fn ctl_can_force_the_xml_processor() {
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=XML\"\n\
         SecRule ARGS \"@detectSQLi\" \"id:942100,phase:2,deny\"";
    assert!(run(
        rules,
        "",
        br#"<o><q>1 UNION SELECT password FROM users</q></o>"#
    ));
}

#[test]
fn reqbody_processor_reports_xml() {
    let rules = "SecRuleEngine On\n\
         SecRule REQBODY_PROCESSOR \"@streq XML\" \"id:1,phase:2,deny\"";
    assert!(run(rules, "application/xml", br#"<a>x</a>"#));
}

// ---------------------------------------------------------------------------
// Argument naming
// ---------------------------------------------------------------------------

#[test]
fn elements_are_named_by_their_path() {
    let rules = "SecRuleEngine On\n\
         SecRule ARGS:xml.order.item \"@streq widget\" \"id:1,phase:2,deny\"";
    assert!(run(
        rules,
        "application/xml",
        br#"<order><item>widget</item></order>"#
    ));
}

#[test]
fn attributes_are_named_with_an_at_sign() {
    let rules = "SecRuleEngine On\n\
         SecRule ARGS:xml.order.item.@id \"@streq 7\" \"id:1,phase:2,deny\"";
    assert!(run(
        rules,
        "application/xml",
        br#"<order><item id="7">widget</item></order>"#
    ));
}

// ---------------------------------------------------------------------------
// Entities: the part that matters
// ---------------------------------------------------------------------------

#[test]
fn predefined_entities_are_decoded() {
    assert!(contains(br#"<a>x&amp;y</a>"#, "x&y"));
    assert!(contains(br#"<a>a&lt;b</a>"#, "a<b"));
}

#[test]
fn numeric_character_references_are_decoded() {
    assert!(contains(br#"<a>UNION&#32;SELECT x</a>"#, "UNION SELECT"));
    assert!(contains(br#"<a>UNION&#x20;SELECT x</a>"#, "UNION SELECT"));
}

/// An evasion the first version of this processor was vulnerable to.
///
/// quick-xml delivers text in fragments split around every entity reference.
/// Emitting each fragment as its own argument would cut a payload into pieces
/// too small for any rule to match, so text is accumulated per element and
/// flushed whole.
#[test]
fn a_payload_split_by_an_entity_reference_is_reassembled() {
    assert!(run(
        SQLI_RULE,
        "application/xml",
        br#"<o><q>1 UNION&#32;SELECT password FROM users</q></o>"#
    ));
}

/// XXE. The file must not be read, and its contents must not reach `ARGS`.
#[test]
fn an_external_entity_is_not_resolved() {
    let xxe = br#"<?xml version="1.0"?>
        <!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]>
        <d>&x;</d>"#;

    assert!(
        !contains(xxe, "root:"),
        "external entity content must never reach ARGS"
    );
}

/// Billion laughs. Must not expand, and must not take measurable time.
#[test]
fn an_entity_expansion_bomb_does_not_expand() {
    let bomb = br#"<?xml version="1.0"?><!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]><lolz>&lol9;</lolz>"#;

    let start = std::time::Instant::now();
    let _ = run(SQLI_RULE, "application/xml", bomb);
    let elapsed = start.elapsed();

    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "entity expansion should not be happening at all, took {elapsed:?}"
    );
}

/// Not expanding a custom entity is safe, but it means the origin application
/// may see content this engine did not. That must be visible rather than
/// silently treated as a fully inspected body — the same reasoning as the
/// JSON processing limits.
#[test]
fn an_unexpanded_custom_entity_sets_reqbody_error() {
    let hidden = br#"<?xml version="1.0"?>
        <!DOCTYPE d [<!ENTITY p "1 UNION SELECT password FROM users">]>
        <d>&p;</d>"#;

    assert!(
        !contains(hidden, "UNION SELECT"),
        "the entity must not be expanded"
    );
    assert!(
        run(BODY_ERROR_RULE, "application/xml", hidden),
        "but the operator must be able to see that something was not inspected"
    );
}

/// The counterpart: ordinary XML, including documents using the predefined
/// entities, must not trip that error. A body-error rule that fires on normal
/// traffic would be turned off within a day.
#[test]
fn ordinary_xml_does_not_set_reqbody_error() {
    assert!(!run(
        BODY_ERROR_RULE,
        "application/xml",
        br#"<order><q>laptop</q></order>"#
    ));
    assert!(!run(
        BODY_ERROR_RULE,
        "application/xml",
        br#"<order><q>Bell &amp; Sons &lt;Ltd&gt;</q></order>"#
    ));
}

// ---------------------------------------------------------------------------
// Malformed input and limits
// ---------------------------------------------------------------------------

#[test]
fn mismatched_tags_set_reqbody_error() {
    assert!(run(BODY_ERROR_RULE, "application/xml", b"<a><b></a>"));
}

#[test]
fn truncated_markup_sets_reqbody_error() {
    assert!(run(BODY_ERROR_RULE, "application/xml", b"<a><b>text"));
}

#[test]
fn an_empty_body_is_not_a_parse_error() {
    // Routine on POST and DELETE; reporting it would be a false positive.
    assert!(!run(BODY_ERROR_RULE, "application/xml", b""));
    assert!(!run(BODY_ERROR_RULE, "application/xml", b"  \n\t "));
}

#[test]
fn deeply_nested_xml_is_reported_rather_than_silently_truncated() {
    let deep = format!("{}payload{}", "<a>".repeat(500), "</a>".repeat(500));
    assert!(run(BODY_ERROR_RULE, "application/xml", deep.as_bytes()));
}

#[test]
fn a_huge_number_of_elements_is_reported() {
    let many: String = (0..5000).map(|i| format!("<v>{i}</v>")).collect();
    let doc = format!("<root>{many}</root>");
    assert!(run(BODY_ERROR_RULE, "application/xml", doc.as_bytes()));
}

#[test]
fn a_malformed_body_does_not_abort_the_transaction() {
    // Phase 2 still runs, so the ruleset decides what to do about the failure.
    let rules = "SecRuleEngine On\n\
         SecRule REQUEST_URI \"@contains /api\" \"id:1,phase:2,deny\"";
    assert!(run(rules, "application/xml", b"<a><b></a>"));
}

#[test]
fn a_non_xml_content_type_is_not_parsed_as_xml() {
    let rules = "SecRuleEngine On\n\
         SecRule ARGS:xml.a \"@rx .\" \"id:1,phase:2,deny\"";
    assert!(!run(rules, "text/plain", b"<a>value</a>"));
}
