//! `@eq`, `@gt`, `@lt`, `@ge` and `@le` convert both operands to an integer
//! and never refuse to compare.
//!
//! libmodsecurity reads the input and the operator argument with `atoll`
//! (`operators/gt.cc`, `lt.cc`, `ge.cc`, `le.cc`) or with `stoi`, taking 0 if
//! it throws (`operators/eq.cc`). Both skip leading whitespace, take an
//! optional sign and the digits after it, and stop at the first other byte, so
//! an empty or non-numeric operand is 0.
//!
//! The engine used to give up on an operand that was not a complete integer:
//! the operator reported no match, and a negated rule turned that into a
//! match. `SecRule ... "!@eq 0"`, the form the recommended configuration uses
//! for its request body checks (200002, 200003), then denied a request whose
//! value was empty.
//!
//! The one operand that is still not compared is a macro on a collection the
//! engine cannot resolve (`%{env.MAX_LEN}`). libmodsecurity would resolve it;
//! here it expands to nothing, and reading that as 0 would compare against a
//! limit nobody wrote. Such a rule keeps reporting no match and is named in a
//! warning when the ruleset loads.

use std::io;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;
use zentinel_modsec::operators::{
    EqOperator, GeOperator, GtOperator, LeOperator, LtOperator, Operator,
};
use zentinel_modsec::ModSecurity;

/// Every operator's verdict on `input` against `argument`, as
/// `[eq, gt, lt, ge, le]`.
fn verdicts(argument: &str, input: &str) -> [bool; 5] {
    [
        EqOperator::new(argument).execute(input).matched,
        GtOperator::new(argument).execute(input).matched,
        LtOperator::new(argument).execute(input).matched,
        GeOperator::new(argument).execute(input).matched,
        LeOperator::new(argument).execute(input).matched,
    ]
}

const EQUAL: [bool; 5] = [true, false, false, true, true];
const GREATER: [bool; 5] = [false, true, false, true, false];
const LESS: [bool; 5] = [false, false, true, false, true];

#[test]
fn inputs_are_read_as_the_integer_they_start_with() {
    for (input, number) in [
        // Empty and non-numeric values are 0.
        ("", 0),
        ("abc", 0),
        ("-", 0),
        ("+", 0),
        ("- 7", 0),
        ("x7", 0),
        // Leading whitespace is skipped, as C's `isspace` defines it.
        (" 7", 7),
        ("\t\n\x0b\x0c\r 7", 7),
        // Conversion stops at the first byte that is not a digit.
        ("7 ", 7),
        ("7abc", 7),
        ("1.9", 1),
        ("0x10", 0),
        // A sign belongs to the number.
        ("+7", 7),
        ("-7", -7),
        (" -7x", -7),
        // Out of range saturates, as glibc's `atoll` does.
        ("9223372036854775807", i64::MAX),
        ("9223372036854775808", i64::MAX),
        ("-9223372036854775808", i64::MIN),
        ("-99999999999999999999", i64::MIN),
    ] {
        assert_eq!(verdicts(&number.to_string(), input), EQUAL, "{input:?}");
        if number < i64::MAX {
            assert_eq!(verdicts(&(number + 1).to_string(), input), LESS);
        }
        if number > i64::MIN {
            assert_eq!(verdicts(&(number - 1).to_string(), input), GREATER);
        }
    }
}

#[test]
fn arguments_are_converted_the_same_way() {
    for argument in ["", "abc", " 0", "0abc", "%{tx.unresolved}"] {
        assert_eq!(verdicts(argument, "0"), EQUAL, "{argument:?}");
        assert_eq!(verdicts(argument, ""), EQUAL, "{argument:?}");
        assert_eq!(verdicts(argument, "1"), GREATER, "{argument:?}");
        assert_eq!(verdicts(argument, "-1"), LESS, "{argument:?}");
    }
    assert_eq!(verdicts(" 10 ", "10"), EQUAL);
    assert_eq!(verdicts("10abc", "9"), LESS);
}

/// Send `GET <uri>` with an empty `X-Count` header through phases 1 and 2 and
/// return the id of the rule that denied it, if any.
fn denied_by(rules: &str, uri: &str) -> Option<String> {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.add_request_header("X-Count", "").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.intervention().and_then(|i| i.rule_ids.first().cloned())
}

/// Rule 200003 of `modsecurity.conf-recommended`, and the same check against
/// variables that are present but empty.
const STRICT_CHECKS: &str = r#"SecRuleEngine On
SecRequestBodyAccess On
SecRule MULTIPART_STRICT_ERROR "!@eq 0" \
"id:200003,phase:2,t:none,log,deny,status:400, \
msg:'Multipart request body failed strict validation: \
PE %{REQBODY_PROCESSOR_ERROR}, \
BQ %{MULTIPART_BOUNDARY_QUOTED}, \
BW %{MULTIPART_BOUNDARY_WHITESPACE}, \
DB %{MULTIPART_DATA_BEFORE}, \
DA %{MULTIPART_DATA_AFTER}, \
DH %{MULTIPART_DUPLICATE_PART_HEADER}, \
HF %{MULTIPART_HEADER_FOLDING}, \
LF %{MULTIPART_LF_LINE}, \
SM %{MULTIPART_MISSING_SEMICOLON}, \
IQ %{MULTIPART_INVALID_QUOTING}, \
IP %{MULTIPART_INVALID_PART}, \
IH %{MULTIPART_INVALID_HEADER_FOLDING}, \
FL %{MULTIPART_FILE_LIMIT_EXCEEDED}'"
SecRule ARGS:strict_error "!@eq 0" "id:1,phase:2,t:none,log,deny,status:400"
SecRule REQUEST_HEADERS:X-Count "!@eq 0" "id:2,phase:2,t:none,log,deny,status:400"
SecRule ARGS:strict_error "!@eq %{tx.unset}" "id:3,phase:2,t:none,log,deny,status:400"
"#;

#[test]
fn a_negated_comparison_with_zero_passes_an_empty_value() {
    assert_eq!(denied_by(STRICT_CHECKS, "/?strict_error="), None);
    assert_eq!(denied_by(STRICT_CHECKS, "/?strict_error=0"), None);
}

#[test]
fn a_negated_comparison_with_zero_still_denies_a_nonzero_value() {
    assert_eq!(
        denied_by(STRICT_CHECKS, "/?strict_error=1").as_deref(),
        Some("1")
    );
}

#[test]
fn an_oversized_value_exceeds_a_numeric_limit() {
    let rules = r#"SecRuleEngine On
SecRule ARGS:size "@gt 1048576" "id:1,phase:2,deny,status:413"
"#;
    assert_eq!(
        denied_by(rules, "/?size=99999999999999999999").as_deref(),
        Some("1")
    );
    assert_eq!(denied_by(rules, "/?size=1048576"), None);
}

const OPERATORS: [&str; 5] = ["eq", "gt", "lt", "ge", "le"];

/// One rule comparing `ARGS:size` with `operator`, e.g. `!@gt %{env.MAX_LEN}`.
fn size_rule(operator: &str) -> String {
    format!("SecRuleEngine On\nSecRule ARGS:size \"{operator}\" \"id:1,phase:2,deny,status:413\"\n")
}

#[test]
fn a_macro_the_engine_cannot_resolve_never_matches() {
    let rules = size_rule("@gt %{env.MAX_LEN}");
    assert_eq!(denied_by(&rules, "/?size=5"), None);

    for collection in ["env", "ip", "session", "global", "ENV"] {
        for operator in OPERATORS {
            let rules = size_rule(&format!("@{operator} %{{{collection}.x}}"));
            for uri in ["/?size=-5", "/?size=0", "/?size=5", "/?size="] {
                assert_eq!(
                    denied_by(&rules, uri),
                    None,
                    "{collection} {operator} {uri}"
                );
            }
        }
    }
}

#[test]
fn a_negated_comparison_with_an_unresolvable_macro_always_matches() {
    for collection in ["env", "ip", "session", "global"] {
        for operator in OPERATORS {
            let rules = size_rule(&format!("!@{operator} %{{{collection}.x}}"));
            for uri in ["/?size=-5", "/?size=0", "/?size=5", "/?size="] {
                assert_eq!(
                    denied_by(&rules, uri).as_deref(),
                    Some("1"),
                    "{collection} {operator} {uri}"
                );
            }
        }
    }
}

#[test]
fn one_unresolvable_macro_is_enough_to_leave_the_operand_uncompared() {
    let rules = "SecRuleEngine On\n\
        SecAction \"id:1,phase:1,pass,nolog,setvar:tx.base=1\"\n\
        SecRule ARGS:size \"@gt %{tx.base}%{env.SUFFIX}\" \"id:2,phase:2,deny,status:413\"\n";
    assert_eq!(denied_by(rules, "/?size=5"), None);
}

#[test]
fn a_resolvable_macro_without_a_value_compares_as_zero() {
    for (operator, uri) in [
        ("@eq %{tx.unset}", "/?size=0"),
        ("@eq %{tx.unset}", "/?size="),
        ("@gt %{tx.unset}", "/?size=5"),
        ("@lt %{tx.unset}", "/?size=-5"),
        ("@ge %{tx.unset}", "/?size=0"),
        ("@le %{tx.unset}", "/?size=0"),
        ("@gt %{request_headers.x-count}", "/?size=5"),
        ("@gt %{request_headers.absent}", "/?size=5"),
    ] {
        assert_eq!(
            denied_by(&size_rule(operator), uri).as_deref(),
            Some("1"),
            "{operator} {uri}"
        );
    }
    assert_eq!(denied_by(&size_rule("@gt %{tx.unset}"), "/?size=0"), None);
}

/// Collects formatted log output so a test can assert on load-time warnings.
#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl io::Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for LogBuffer {
    type Writer = Self;

    fn make_writer(&self) -> Self {
        self.clone()
    }
}

/// The warnings logged while `rules` load, one per line.
fn load_warnings(rules: &str) -> Vec<String> {
    let log = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(log.clone())
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, || ModSecurity::from_string(rules))
        .expect("rules should load");
    let log = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    log.lines()
        .filter(|line| line.contains("WARN"))
        .map(str::to_string)
        .collect()
}

#[test]
fn an_unresolvable_macro_is_reported_once_when_the_rules_load() {
    let warnings = load_warnings(
        r#"SecRuleEngine On
SecRule REQUEST_HEADERS:Content-Length "@gt %{env.MAX_LEN}" "id:1,phase:1,deny"
SecRule ARGS:size "!@le %{env.MAX_LEN}" "id:2,phase:2,deny"
SecRule ARGS:size "@eq %{ip.count}" "id:3,phase:2,deny"
SecRule ARGS:size "@ge %{tx.limit}" "id:4,phase:2,deny"
SecRule ARGS:name "@streq %{session.name}" "id:5,phase:2,deny"
"#,
    );
    assert_eq!(warnings.len(), 2, "{warnings:#?}");
    assert!(warnings[0].contains("%{env.MAX_LEN}"), "{warnings:#?}");
    assert!(warnings[0].contains("rules_affected=2"), "{warnings:#?}");
    assert!(warnings[1].contains("%{ip.count}"), "{warnings:#?}");
    assert!(warnings[1].contains("rules_affected=1"), "{warnings:#?}");
    for warning in &warnings {
        assert!(warning.contains("will never match"), "{warning}");
    }
}

#[test]
fn resolvable_macros_load_without_a_warning() {
    let warnings = load_warnings(
        r#"SecRuleEngine On
SecRule ARGS:size "@gt %{tx.limit}" "id:1,phase:2,deny"
SecRule ARGS:size "@eq %{request_headers.x-count}" "id:2,phase:2,deny"
SecRule ARGS:size "@ge %{MATCHED_VAR}" "id:3,phase:2,deny"
"#,
    );
    assert!(warnings.is_empty(), "{warnings:#?}");
}
