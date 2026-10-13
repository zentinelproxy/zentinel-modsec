//! A rule file with CRLF line endings stopped parsing at the first line end:
//! the lexer did not treat `\r` as whitespace, and the token stream ended
//! without an error.

use zentinel_modsec::ModSecurity;

fn run(rules: &str, uri: &str) -> zentinel_modsec::engine::Transaction {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx
}

fn tx_var(tx: &zentinel_modsec::engine::Transaction, name: &str) -> String {
    use zentinel_modsec::variables::Collection;
    tx.tx()
        .get(name)
        .and_then(|v| v.first().map(|s| s.to_string()))
        .unwrap_or_else(|| "-".to_string())
}

#[test]
fn crlf_rule_text_is_parsed_to_the_end() {
    let rules = "SecRuleEngine On\r\n\
        SecRule REQUEST_URI \"@contains a\" \"id:50,phase:2,pass,nolog,setvar:'tx.one=1'\"\r\n\
        SecRule REQUEST_URI \"@contains a\" \"id:51,phase:2,pass,nolog,\\\r\n    setvar:'tx.two=1'\"\r\n\
        SecRule REQUEST_URI \"@contains a\" \"id:52,phase:2,deny\"\r\n";
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    assert_eq!(
        msc.rule_count(),
        3,
        "every rule after the first line must load"
    );
    let tx = run(rules, "/a");
    assert_eq!(tx_var(&tx, "one"), "1");
    assert_eq!(tx_var(&tx, "two"), "1");
    assert!(tx.has_intervention());
}
