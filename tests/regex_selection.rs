//! A regular-expression selection (`TX:/.../`, `ARGS:/.../`) compares keys
//! case-insensitively, as a key selection (`ARGS:p`) does and as ModSecurity
//! does. TX keys are stored lowercased, so CRS's 922110, reading
//! `TX:/MULTIPART_HEADERS_CONTENT_TYPES_*/`, found none of the keys its 922150
//! had set, and never fired.

use zentinel_modsec::ModSecurity;

fn blocked(rules: &str, uri: &str) -> bool {
    let m = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = m.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

#[test]
fn an_uppercase_tx_selection_finds_keys_set_in_any_case() {
    let rules = "SecRuleEngine On\n\
        SecAction \"id:1,phase:1,pass,nolog,setvar:'tx.multipart_headers_content_types_0=text/plain; charset=utf-7'\"\n\
        SecRule TX:/MULTIPART_HEADERS_CONTENT_TYPES_*/ \"@contains utf-7\" \"id:2,phase:1,deny\"";
    assert!(blocked(rules, "/"));
}

#[test]
fn an_args_selection_ignores_case_like_a_key_selection() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS:/^USER/ \"@streq bob\" \"id:1,phase:2,deny\"";
    assert!(blocked(rules, "/?username=bob"));
    assert!(!blocked(rules, "/?name=bob"));
}

#[test]
fn an_exclusion_by_regex_ignores_case_too() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS|!ARGS:/^TOKEN/ \"@streq x\" \"id:1,phase:2,deny\"";
    assert!(!blocked(rules, "/?token_a=x"));
    assert!(blocked(rules, "/?other=x"));
}
