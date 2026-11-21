//! `@detectSQLi` gives libinjection's verdict and fingerprint.
//!
//! ModSecurity v3 implements the operator with libinjection
//! (`src/operators/detect_sqli.cc` calls `libinjection_sqli`). The engine used
//! a regex-and-heuristics approximation instead, which flagged ordinary
//! crawler User-Agents such as `Mozilla/5.0 (compatible; AhrefsBot/7.0; ...)`
//! (CRS 942100 inspects `REQUEST_HEADERS:User-Agent`), issue #84. It is now a
//! port of libinjection v4.0.2. The fingerprints below are what C libinjection
//! v4.0.2 reports for the same input.

use zentinel_modsec::libinjection::sqli::detect_sqli;
use zentinel_modsec::ModSecurity;

/// User-Agents from issue #84 and other common crawlers. C libinjection flags
/// none of them (each folds to `n(n;n` or `n(n:o`, which is not a SQLi
/// fingerprint).
const CRAWLER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)",
    "Mozilla/5.0 (Linux; Android 7.0;) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
];

#[test]
fn crawler_user_agents_are_not_sqli() {
    for ua in CRAWLER_AGENTS {
        assert!(!detect_sqli(ua).is_injection, "flagged: {ua}");
        // CRS decodes with t:urlDecodeUni, which turns '+' into a space.
        let decoded = ua.replace('+', " ");
        assert!(!detect_sqli(&decoded).is_injection, "flagged: {decoded}");
    }
}

#[test]
fn injections_keep_libinjection_fingerprints() {
    let cases = [
        ("1' OR '1'='1", "s&sos"),
        ("' OR 1=1--", "s&1c"),
        ("1 UNION SELECT * FROM users", "1UEok"),
        ("admin'--", "sc"),
        ("1--", "1c"),
        ("1; DROP TABLE users", "1;Tnn"),
        ("1' AND SLEEP(5)#", "s&f(1"),
        ("1 AND 1=1", "1&1"),
        ("' UNION SELECT username, password FROM users--", "sUEnk"),
        // MySQL conditional comment: unparsable, always flagged.
        ("1/*!50000UNION*/ SELECT 1", "X"),
    ];
    for (input, fingerprint) in cases {
        let result = detect_sqli(input);
        assert!(result.is_injection, "missed: {input}");
        assert_eq!(result.fingerprint.as_deref(), Some(fingerprint), "{input}");
    }
}

#[test]
fn libinjection_false_positive_filter_applies() {
    // Blacklisted fingerprints that `libinjection_sqli_not_whitelist` clears.
    for input in ["John O'Brien", "1 union", "sexy and 17", "hello world", ""] {
        assert!(!detect_sqli(input).is_injection, "flagged: {input}");
    }
}

#[test]
fn detect_sqli_rule_on_user_agent() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_HEADERS:User-Agent \"@detectSQLi\" \
        \"id:100,phase:1,pass,nolog,t:none,t:urlDecodeUni\"";
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let run = |ua: &str| {
        let mut tx = msc.new_transaction();
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.add_request_header("Host", "example.com").unwrap();
        tx.add_request_header("User-Agent", ua).unwrap();
        tx.process_request_headers().unwrap();
        tx.matched_rules().contains(&"100".to_string())
    };
    for ua in CRAWLER_AGENTS {
        assert!(!run(ua), "rule matched crawler: {ua}");
    }
    assert!(run("1' OR '1'='1"));
}
