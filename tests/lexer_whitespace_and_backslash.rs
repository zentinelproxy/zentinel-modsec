//! Whitespace other than space or tab between directives used to end the
//! configuration: every rule after it was dropped without an error. A stray
//! backslash has always been ignored and must stay that way.

use zentinel_modsec::ModSecurity;

const FIRST: &str = r#"SecAction "id:701,phase:1,pass""#;
const LAST: &str = r#"SecAction "id:702,phase:1,pass""#;

fn matched_rules(rules: &str) -> Vec<String> {
    let engine = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.matched_rules().iter().map(|id| id.to_string()).collect()
}

#[test]
fn rules_after_other_whitespace_are_loaded() {
    for separator in ["\x0c\n", "\x0b\n", "\u{a0}", "\u{2003}"] {
        let rules = format!("{FIRST}\n{separator}{LAST}");
        assert_eq!(matched_rules(&rules), ["701", "702"], "{separator:?}");
    }
}

#[test]
fn unicode_line_terminators_end_a_directive() {
    for terminator in ["\u{85}", "\u{2028}", "\u{2029}"] {
        let rules = format!("{FIRST}{terminator}{LAST}");
        assert_eq!(matched_rules(&rules), ["701", "702"], "{terminator:?}");
    }
}

#[test]
fn stray_backslashes_are_ignored() {
    for rules in [
        format!("{FIRST}\n{LAST} \\"),
        format!("{FIRST} \\ \n{LAST}"),
        format!("{FIRST}\n\\\n{LAST}"),
        format!("{FIRST}\n\\ \n{LAST}"),
        format!("{FIRST} \\\\\n{LAST}"),
    ] {
        assert_eq!(matched_rules(&rules), ["701", "702"], "{rules:?}");
    }
}
