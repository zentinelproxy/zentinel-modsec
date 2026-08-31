//! `XML:` rule targets, resolved against the flattened XML body.
//!
//! ModSecurity selects XML through XPath. This engine has no XPath evaluator
//! and flattens XML bodies into `ARGS` instead — which already covers stock
//! CRS, because 175 of the 176 CRS rules naming an `XML:` target also name
//! `ARGS` in the same rule. But a rule targeting `XML:` *alone* used to resolve
//! to nothing and match nothing, with no complaint at load time, and that is
//! the failure mode this engine should never have.
//!
//! The two selectors CRS actually writes — `XML:/*` (177 occurrences) and
//! `XML://@*` (176) — are exactly the element-text and attribute halves of the
//! flattening, so they need no XPath engine. Anything richer is reported when
//! the rules load rather than silently matching nothing.

use zentinel_modsec::ModSecurity;

fn blocks(rules: &str, body: &[u8]) -> bool {
    let m = ModSecurity::from_string(rules).expect("rules load");
    let mut tx = m.new_transaction();
    tx.process_uri("/api", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/xml").unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(body).unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

const SQLI: &str = "1' UNION SELECT password FROM users-- ";

// ---------------------------------------------------------------------------
// The two selectors CRS uses
// ---------------------------------------------------------------------------

#[test]
fn xml_elements_selector_sees_element_text() {
    assert!(blocks(
        "SecRuleEngine On\nSecRule XML:/* \"@detectSQLi\" \"id:1,phase:2,deny\"",
        format!("<o><q>{SQLI}</q></o>").as_bytes()
    ));
}

#[test]
fn xml_elements_selector_does_not_see_attributes() {
    assert!(!blocks(
        "SecRuleEngine On\nSecRule XML:/* \"@detectSQLi\" \"id:1,phase:2,deny\"",
        format!("<o q=\"{SQLI}\"/>").as_bytes()
    ));
}

#[test]
fn xml_attributes_selector_sees_attributes() {
    assert!(blocks(
        "SecRuleEngine On\nSecRule XML://@* \"@detectSQLi\" \"id:1,phase:2,deny\"",
        format!("<o q=\"{SQLI}\"/>").as_bytes()
    ));
}

#[test]
fn xml_attributes_selector_does_not_see_element_text() {
    assert!(!blocks(
        "SecRuleEngine On\nSecRule XML://@* \"@detectSQLi\" \"id:1,phase:2,deny\"",
        format!("<o><q>{SQLI}</q></o>").as_bytes()
    ));
}

#[test]
fn a_bare_xml_target_sees_both() {
    for body in [
        format!("<o><q>{SQLI}</q></o>"),
        format!("<o q=\"{SQLI}\"/>"),
    ] {
        assert!(blocks(
            "SecRuleEngine On\nSecRule XML \"@detectSQLi\" \"id:1,phase:2,deny\"",
            body.as_bytes()
        ));
    }
}

#[test]
fn nested_elements_and_soap_are_reached() {
    assert!(blocks(
        "SecRuleEngine On\nSecRule XML:/* \"@detectSQLi\" \"id:1,phase:2,deny\"",
        format!(
            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\
             <soap:Body><q>{SQLI}</q></soap:Body></soap:Envelope>"
        )
        .as_bytes()
    ));
}

// ---------------------------------------------------------------------------
// Ordinary traffic
// ---------------------------------------------------------------------------

#[test]
fn benign_xml_matches_nothing() {
    for target in ["XML:/*", "XML://@*", "XML"] {
        assert!(
            !blocks(
                &format!("SecRuleEngine On\nSecRule {target} \"@detectSQLi\" \"id:1,phase:2,deny\""),
                br#"<order><item id="7">widget</item><qty>3</qty></order>"#
            ),
            "{target} fired on benign XML"
        );
    }
}

#[test]
fn an_xml_target_is_empty_when_the_body_is_not_xml() {
    let m = ModSecurity::from_string(
        "SecRuleEngine On\nSecRule XML:/* \"@detectSQLi\" \"id:1,phase:2,deny\"",
    )
    .unwrap();
    let mut tx = m.new_transaction();
    tx.process_uri("/api", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(format!("q={SQLI}").as_bytes()).unwrap();
    tx.process_request_body().unwrap();
    assert!(!tx.has_intervention());
}

// ---------------------------------------------------------------------------
// The CRS rule shape, and unsupported XPath
// ---------------------------------------------------------------------------

#[test]
fn the_stock_crs_target_list_still_works() {
    // 175 of 176 CRS rules naming XML: also name ARGS. Both halves must fire.
    let rule = "SecRuleEngine On\n\
        SecRule ARGS|ARGS_NAMES|XML:/*|XML://@* \"@detectSQLi\" \"id:942100,phase:2,deny\"";
    assert!(blocks(rule, format!("<o><q>{SQLI}</q></o>").as_bytes()));
    assert!(blocks(rule, format!("<o q=\"{SQLI}\"/>").as_bytes()));
    assert!(!blocks(rule, br#"<order><item id="7">widget</item></order>"#));
}

#[test]
fn an_unsupported_xpath_expression_still_loads_the_ruleset() {
    // It cannot match, and says so at load time, but it must not stop the rest
    // of the rules loading — the same posture as an unusable @rx pattern.
    for target in ["XML:/order/item[1]", "XML://user/@name", "XML:/*[position()=1]"] {
        let rules =
            format!("SecRuleEngine On\nSecRule {target} \"@detectSQLi\" \"id:1,phase:2,deny\"\n\
                     SecRule ARGS \"@detectSQLi\" \"id:2,phase:2,deny\"");
        let m = ModSecurity::from_string(&rules)
            .unwrap_or_else(|e| panic!("{target} should still load: {e}"));
        assert_eq!(m.rule_count(), 2, "{target}");
    }
}

#[test]
fn an_unsupported_xpath_expression_matches_nothing() {
    assert!(!blocks(
        "SecRuleEngine On\nSecRule XML:/order/item[1] \"@detectSQLi\" \"id:1,phase:2,deny\"",
        format!("<order><item>{SQLI}</item></order>").as_bytes()
    ));
}

#[test]
fn xml_target_selection_is_classified() {
    use zentinel_modsec::parser::{Selection, XmlTarget};
    assert_eq!(XmlTarget::from_selection(None), Some(XmlTarget::All));
    assert_eq!(
        XmlTarget::from_selection(Some(&Selection::Key("/*".into()))),
        Some(XmlTarget::Elements)
    );
    assert_eq!(
        XmlTarget::from_selection(Some(&Selection::Key("//@*".into()))),
        Some(XmlTarget::Attributes)
    );
    assert_eq!(
        XmlTarget::from_selection(Some(&Selection::Key("/order/item".into()))),
        None
    );
}
