//! Whitespace other than space or tab between directives used to end the
//! configuration: every rule after it was dropped without an error. A stray
//! backslash has always been ignored and must stay that way.

use std::io;
use std::sync::{Arc, Mutex};

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
fn unicode_line_terminators_end_a_comment() {
    for terminator in ["\u{85}", "\u{2028}", "\u{2029}"] {
        let rules = format!("{FIRST}\n# note{terminator}{LAST}");
        assert_eq!(matched_rules(&rules), ["701", "702"], "{terminator:?}");
    }
}

/// Log output shared between a subscriber and the test that reads it back.
#[derive(Clone, Default)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Loads `rules` and returns the warnings logged while doing so.
fn load_warnings(rules: &str) -> String {
    let log = CapturedLog::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        ModSecurity::from_string(rules).expect("rules should load");
    });
    let bytes = log.0.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

#[test]
fn whitespace_modsecurity_v3_rejects_is_warned_about() {
    for (separator, code_point) in [
        ("\x0c", "U+000C"),
        ("\x0b", "U+000B"),
        ("\u{a0}", "U+00A0"),
        ("\u{2003}", "U+2003"),
        ("\u{85}", "U+0085"),
        ("\u{2028}", "U+2028"),
        ("\u{2029}", "U+2029"),
    ] {
        let rules = format!("{FIRST}\n{separator}{LAST}");
        let warnings = load_warnings(&rules);
        assert!(warnings.contains("WARN"), "{rules:?}: {warnings}");
        assert!(warnings.contains(code_point), "{rules:?}: {warnings}");
        assert!(
            warnings.contains("line=2 column=1"),
            "{rules:?}: {warnings}"
        );
    }
}

#[test]
fn unicode_line_terminator_ending_a_comment_is_warned_about() {
    let warnings = load_warnings(&format!("{FIRST}\n# note\u{2028}{LAST}"));
    assert!(warnings.contains("U+2028"), "{warnings}");
    assert!(warnings.contains("line=2 column=7"), "{warnings}");
}

#[test]
fn each_unsupported_whitespace_character_is_warned_about_once() {
    let warnings = load_warnings(&format!("{FIRST}\x0c\x0c\n\x0c\u{a0}{LAST}\x0c\n"));
    assert_eq!(warnings.matches("U+000C").count(), 1, "{warnings}");
    assert_eq!(warnings.matches("U+00A0").count(), 1, "{warnings}");
}

#[test]
fn whitespace_modsecurity_v3_accepts_is_not_warned_about() {
    for rules in [
        format!("{FIRST}\n \t{LAST}\n"),
        format!("{FIRST}\r\n# note\r\n\t{LAST}\r\n"),
        // Inside a comment or a quoted string the character separates nothing.
        format!("{FIRST}\n# a\u{a0}note\x0c\n{LAST}"),
        "SecAction \"id:701,phase:1,pass,msg:'a\u{a0}b'\"".to_string(),
    ] {
        assert_eq!(load_warnings(&rules), "", "{rules:?}");
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
