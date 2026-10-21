//! The same rules and the same request must give the same answer, every time.
//!
//! Every collection (`REQUEST_HEADERS`, `ARGS`, `REQUEST_COOKIES`, `TX`, ...)
//! used to be a `std::collections::HashMap`, whose iteration order is seeded
//! per map. A rule over a collection reports the *first* variable that
//! matched, so `MATCHED_VAR`, `MATCHED_VAR_NAME`, the audit log's matched data
//! and anything read from them depended on the hash seed, not on the request.
//! Nothing in the CRS corpus could see that until captures were wired up
//! (#52), at which point its pass count started varying between runs of the
//! same commit (zentinelproxy/zentinel-modsec#53).
//!
//! Collections now iterate in insertion order, the order the request carried
//! them in, so a collection rule reports the first matching variable in that
//! order.

use zentinel_modsec::ModSecurity;

/// Enough keys that a hash-ordered map would almost never iterate them in
/// insertion order by chance.
const KEYS: usize = 16;

/// Repetitions, each in a fresh engine and a fresh transaction: `HashMap`
/// seeds differ per map, so one run that happens to agree proves nothing.
const RUNS: usize = 25;

fn key(i: usize) -> String {
    format!("k{i:02}")
}

/// The name of the variable the rule with `id` matched on, in a fresh engine.
fn first_match(rules: &str, id: &str, drive: impl Fn(&mut zentinel_modsec::Transaction)) -> String {
    let m = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = m.new_transaction();
    drive(&mut tx);
    tx.matched_data()
        .iter()
        .find(|d| d.rule_id.as_deref() == Some(id))
        .map(|d| d.variable.clone())
        .unwrap_or_else(|| panic!("rule {id} should have matched"))
}

fn assert_stable(what: &str, expected: &str, mut run: impl FnMut() -> String) {
    for i in 0..RUNS {
        let got = run();
        assert_eq!(
            got, expected,
            "{what}: run {i} reported {got}, expected {expected} -- collection \
             iteration order must follow the request, not a hash seed"
        );
    }
}

#[test]
fn request_headers_are_evaluated_in_request_order() {
    let rules = "SecRuleEngine DetectionOnly\n\
         SecRule REQUEST_HEADERS \"@rx ^v\" \"id:1,phase:1,pass,log\"";
    assert_stable("REQUEST_HEADERS", "REQUEST_HEADERS:k00", || {
        first_match(rules, "1", |tx| {
            tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
            for i in 0..KEYS {
                tx.add_request_header(&key(i), &format!("v{i}")).unwrap();
            }
            tx.process_request_headers().unwrap();
        })
    });
}

#[test]
fn request_headers_names_are_evaluated_in_request_order() {
    // The shape of CRS 920450: every header name matches, so which one is
    // reported is decided by iteration order alone.
    let rules = "SecRuleEngine DetectionOnly\n\
         SecRule REQUEST_HEADERS_NAMES \"@rx ^.*$\" \"id:1,phase:1,pass,log\"";
    assert_stable("REQUEST_HEADERS_NAMES", "REQUEST_HEADERS_NAMES:k00", || {
        first_match(rules, "1", |tx| {
            tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
            for i in 0..KEYS {
                tx.add_request_header(&key(i), "x").unwrap();
            }
            tx.process_request_headers().unwrap();
        })
    });
}

#[test]
fn args_are_evaluated_in_request_order() {
    let query: Vec<String> = (0..KEYS).map(|i| format!("{}=v{i}", key(i))).collect();
    let uri = format!("/?{}", query.join("&"));
    let rules = "SecRuleEngine DetectionOnly\n\
         SecRule ARGS \"@rx ^v\" \"id:1,phase:1,pass,log\"";
    assert_stable("ARGS", "ARGS:k00", || {
        first_match(rules, "1", |tx| {
            tx.process_uri(&uri, "GET", "HTTP/1.1").unwrap();
            tx.add_request_header("Host", "localhost").unwrap();
            tx.process_request_headers().unwrap();
        })
    });
}

#[test]
fn tx_is_evaluated_in_the_order_it_was_set() {
    let setvars: Vec<String> = (0..KEYS)
        .map(|i| format!("setvar:tx.{}=v{i}", key(i)))
        .collect();
    let rules = format!(
        "SecRuleEngine DetectionOnly\n\
         SecAction \"id:1,phase:1,pass,nolog,{}\"\n\
         SecRule TX:/^k/ \"@rx ^v\" \"id:2,phase:1,pass,log\"",
        setvars.join(",")
    );
    assert_stable("TX", "TX:k00", || {
        first_match(&rules, "2", |tx| {
            tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
            tx.add_request_header("Host", "localhost").unwrap();
            tx.process_request_headers().unwrap();
        })
    });
}
