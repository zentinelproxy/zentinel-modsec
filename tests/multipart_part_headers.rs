//! Tests for the `MULTIPART_PART_HEADERS` collection.
//!
//! OWASP CRS 4.x `REQUEST-922-MULTIPART-ATTACK.conf` inspects the header lines
//! of each multipart part through this collection. The variable name parsed
//! before, so rulesets loaded, but nothing ever populated the collection — the
//! CRS multipart rules silently matched nothing. See issue
//! zentinelproxy/zentinel#341.

use zentinel_modsec::ModSecurity;

const BODY: &str = "--X\r\n\
     Content-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"\r\n\
     Content-Type: text/plain\r\n\
     \r\n\
     harmless\r\n\
     --X--\r\n";

/// Run a multipart POST through both request phases and report whether the
/// request was blocked.
fn blocked_multipart(rules: &str, body: &str) -> bool {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri("/upload", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.add_request_header("Content-Type", "multipart/form-data; boundary=X")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(body.as_bytes()).unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

#[test]
fn ruleset_using_the_variable_loads() {
    // The load-time regression from #341: a ruleset naming the variable must
    // not fail to parse.
    ModSecurity::from_string(
        "SecRuleEngine On\n\
         SecRule MULTIPART_PART_HEADERS \"@rx nothing\" \"id:922100,phase:2,deny\"",
    )
    .expect("MULTIPART_PART_HEADERS ruleset should load");
}

#[test]
fn part_headers_are_matched() {
    // A CRS-shaped rule: inspect part headers for a suspicious Content-Type.
    let rules = "SecRuleEngine On\n\
         SecRule MULTIPART_PART_HEADERS \"@contains text/plain\" \"id:922100,phase:2,deny\"";
    assert!(
        blocked_multipart(rules, BODY),
        "part header Content-Type: text/plain should be visible to the rule"
    );
}

#[test]
fn part_headers_do_not_match_absent_content() {
    let rules = "SecRuleEngine On\n\
         SecRule MULTIPART_PART_HEADERS \"@contains application/x-httpd-php\" \"id:922100,phase:2,deny\"";
    assert!(
        !blocked_multipart(rules, BODY),
        "a header value that is not present must not match"
    );
}

#[test]
fn part_body_content_is_not_treated_as_a_header() {
    // Only the header block of each part belongs in this collection; the part
    // *content* must not leak into it, or CRS multipart rules would fire on
    // ordinary uploaded text.
    let body = "--X\r\n\
         Content-Disposition: form-data; name=\"note\"\r\n\
         \r\n\
         Content-Type: application/x-httpd-php\r\n\
         --X--\r\n";
    let rules = "SecRuleEngine On\n\
         SecRule MULTIPART_PART_HEADERS \"@contains application/x-httpd-php\" \"id:922100,phase:2,deny\"";
    assert!(
        !blocked_multipart(rules, body),
        "part content that looks like a header must not populate MULTIPART_PART_HEADERS"
    );
}
