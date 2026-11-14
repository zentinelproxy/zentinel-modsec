//! Namespace declarations are document structure, not data: they must not
//! surface as arguments (zentinelproxy/zentinel-modsec#60). Flattened, the
//! name `xml.o:order.@xmlns:o` put `xmlns` into ARGS_NAMES, which CRS 941130
//! reads as an XSS attribute vector -- so every namespaced body was blocked.

use zentinel_modsec::ModSecurity;

/// The part of CRS 941130 that fired: `xmlns` in an argument name.
const RULE_941130_SHAPE: &str = "SecRuleEngine On\n\
    SecRequestBodyAccess On\n\
    SecRule ARGS_NAMES \"@rx (?i)xmlns\" \"id:941130,phase:2,deny,status:403\"";

fn run(rules: &str, body: &str) -> zentinel_modsec::engine::Transaction {
    let m = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = m.new_transaction();
    tx.process_uri("/api/orders", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.add_request_header("Content-Type", "application/xml; charset=utf-8")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(body.as_bytes()).unwrap();
    tx.process_request_body().unwrap();
    tx
}

fn blocked(rules: &str, body: &str) -> bool {
    run(rules, body).has_intervention()
}

#[test]
fn a_prefixed_namespace_declaration_is_not_an_argument() {
    let body = r#"<?xml version="1.0"?><o:order xmlns:o="urn:example:orders"><o:item>widget</o:item></o:order>"#;
    assert!(!blocked(RULE_941130_SHAPE, body));
}

#[test]
fn a_default_namespace_declaration_is_not_an_argument() {
    let body = r#"<order xmlns="urn:example:orders"><item>widget</item></order>"#;
    assert!(!blocked(RULE_941130_SHAPE, body));
}

#[test]
fn a_nested_declaration_is_not_an_argument() {
    // RFC 4918 section 9.1.3: a WebDAV PROPFIND body.
    let body = r#"<?xml version="1.0" encoding="utf-8" ?>
<D:propfind xmlns:D="DAV:">
  <D:prop xmlns:R="http://ns.example.com/boxschema/">
    <R:bigbox/>
    <R:author/>
  </D:prop>
</D:propfind>"#;
    assert!(!blocked(RULE_941130_SHAPE, body));
}

#[test]
fn element_text_and_other_attributes_are_still_arguments() {
    let body = r#"<o:order xmlns:o="urn:x" o:id="7"><o:item>widget</o:item></o:order>"#;
    let item = "SecRuleEngine On\n\
        SecRule ARGS:xml.o:order.o:item \"@streq widget\" \"id:1,phase:2,deny\"";
    assert!(blocked(item, body));
    let attr = "SecRuleEngine On\n\
        SecRule ARGS:xml.o:order.@o:id \"@streq 7\" \"id:2,phase:2,deny\"";
    assert!(blocked(attr, body));
}

#[test]
fn an_attribute_that_merely_starts_with_xmlns_is_still_an_argument() {
    // `xmlnsfoo` is an ordinary attribute, not a declaration.
    let body = r#"<order xmlnsfoo="bar"><item>widget</item></order>"#;
    assert!(blocked(RULE_941130_SHAPE, body));
}

#[test]
fn a_declaration_is_still_visible_in_request_body() {
    let rules = "SecRuleEngine On\n\
        SecRequestBodyAccess On\n\
        SecRule REQUEST_BODY \"@contains urn:example:orders\" \"id:3,phase:2,deny\"";
    let body = r#"<o:order xmlns:o="urn:example:orders"><o:item>w</o:item></o:order>"#;
    assert!(blocked(rules, body));
}
