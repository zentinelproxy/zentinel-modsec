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
