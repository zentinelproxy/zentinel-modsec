//! Comparison benchmarks against libmodsecurity (C++).
//!
//! This benchmark requires libmodsecurity to be installed.
//! Run with: cargo bench --features libmodsec-compare
//!
//! Install libmodsecurity:
//!   macOS: brew install modsecurity
//!   Ubuntu: apt-get install libmodsecurity-dev

#![cfg(feature = "libmodsec-compare")]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::time::Duration;

// ============================================================================
// libmodsecurity FFI Bindings
// ============================================================================

#[repr(C)]
pub struct ModSecurity {
    _private: [u8; 0],
}

#[repr(C)]
pub struct Rules {
    _private: [u8; 0],
}

#[repr(C)]
pub struct Transaction {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ModSecurityIntervention {
    pub status: c_int,
    pub pause: c_int,
    pub url: *mut c_char,
    pub log: *mut c_char,
    pub disruptive: c_int,
}

#[link(name = "modsecurity")]
extern "C" {
    fn msc_init() -> *mut ModSecurity;
    fn msc_cleanup(msc: *mut ModSecurity);
    fn msc_set_connector_info(msc: *mut ModSecurity, info: *const c_char);

    fn msc_create_rules_set() -> *mut Rules;
    fn msc_rules_cleanup(rules: *mut Rules);
    fn msc_rules_add(
        rules: *mut Rules,
        plain_rules: *const c_char,
        error: *mut *const c_char,
    ) -> c_int;
    fn msc_rules_add_file(
        rules: *mut Rules,
        file: *const c_char,
        error: *mut *const c_char,
    ) -> c_int;

    fn msc_new_transaction(
        msc: *mut ModSecurity,
        rules: *mut Rules,
        log_cb: *mut c_void,
    ) -> *mut Transaction;
    fn msc_transaction_cleanup(tx: *mut Transaction);
    fn msc_process_uri(
        tx: *mut Transaction,
        uri: *const c_char,
        method: *const c_char,
        version: *const c_char,
    ) -> c_int;
    fn msc_add_request_header(
        tx: *mut Transaction,
        key: *const c_char,
        value: *const c_char,
    ) -> c_int;
    fn msc_process_request_headers(tx: *mut Transaction) -> c_int;
    fn msc_append_request_body(tx: *mut Transaction, body: *const u8, len: usize) -> c_int;
    fn msc_process_request_body(tx: *mut Transaction) -> c_int;
    fn msc_intervention(tx: *mut Transaction, intervention: *mut ModSecurityIntervention) -> c_int;
    fn msc_process_connection(
        tx: *mut Transaction,
        client: *const c_char,
        c_port: c_int,
        server: *const c_char,
        s_port: c_int,
    ) -> c_int;
    fn msc_process_logging(tx: *mut Transaction) -> c_int;
}

// ============================================================================
// Safe Wrappers
// ============================================================================

struct LibModSecurity {
    msc: *mut ModSecurity,
}

impl LibModSecurity {
    fn new() -> Self {
        unsafe {
            let msc = msc_init();
            let info = CString::new("zentinel-modsec-bench").unwrap();
            msc_set_connector_info(msc, info.as_ptr());
            Self { msc }
        }
    }
}

impl Drop for LibModSecurity {
    fn drop(&mut self) {
        unsafe {
            msc_cleanup(self.msc);
        }
    }
}

struct LibRules {
    rules: *mut Rules,
}

impl LibRules {
    fn new() -> Self {
        unsafe {
            Self {
                rules: msc_create_rules_set(),
            }
        }
    }

    fn add_rules(&self, rules_text: &str) -> Result<(), String> {
        let c_rules = CString::new(rules_text).unwrap();
        let mut error: *const c_char = std::ptr::null();

        unsafe {
            let result = msc_rules_add(self.rules, c_rules.as_ptr(), &mut error);
            if result < 0 {
                if !error.is_null() {
                    let err_str = CStr::from_ptr(error).to_string_lossy().to_string();
                    return Err(err_str);
                }
                return Err("Unknown error".to_string());
            }
        }
        Ok(())
    }
}

impl Drop for LibRules {
    fn drop(&mut self) {
        unsafe {
            msc_rules_cleanup(self.rules);
        }
    }
}

struct LibTransaction {
    tx: *mut Transaction,
}

impl LibTransaction {
    fn new(msc: &LibModSecurity, rules: &LibRules) -> Self {
        unsafe {
            Self {
                tx: msc_new_transaction(msc.msc, rules.rules, std::ptr::null_mut()),
            }
        }
    }

    fn process_uri(&self, uri: &str, method: &str, version: &str) {
        let c_uri = CString::new(uri).unwrap();
        let c_method = CString::new(method).unwrap();
        let c_version = CString::new(version).unwrap();

        unsafe {
            msc_process_uri(
                self.tx,
                c_uri.as_ptr(),
                c_method.as_ptr(),
                c_version.as_ptr(),
            );
        }
    }

    fn add_request_header(&self, key: &str, value: &str) {
        let c_key = CString::new(key).unwrap();
        let c_value = CString::new(value).unwrap();

        unsafe {
            msc_add_request_header(self.tx, c_key.as_ptr(), c_value.as_ptr());
        }
    }

    fn process_request_headers(&self) {
        unsafe {
            msc_process_request_headers(self.tx);
        }
    }

    fn append_request_body(&self, body: &[u8]) {
        unsafe {
            msc_append_request_body(self.tx, body.as_ptr(), body.len());
        }
    }

    fn process_request_body(&self) {
        unsafe {
            msc_process_request_body(self.tx);
        }
    }

    fn process_connection(&self, client: &str, c_port: i32, server: &str, s_port: i32) {
        let c_client = CString::new(client).unwrap();
        let c_server = CString::new(server).unwrap();
        unsafe {
            msc_process_connection(self.tx, c_client.as_ptr(), c_port, c_server.as_ptr(), s_port);
        }
    }

    fn process_logging(&self) {
        unsafe {
            msc_process_logging(self.tx);
        }
    }

    fn intervention(&self) -> Option<i32> {
        let mut intervention = ModSecurityIntervention {
            status: 0,
            pause: 0,
            url: std::ptr::null_mut(),
            log: std::ptr::null_mut(),
            disruptive: 0,
        };

        unsafe {
            if msc_intervention(self.tx, &mut intervention) != 0 {
                Some(intervention.status)
            } else {
                None
            }
        }
    }
}

impl Drop for LibTransaction {
    fn drop(&mut self) {
        unsafe {
            msc_transaction_cleanup(self.tx);
        }
    }
}

// ============================================================================
// Test Data
// ============================================================================

const SIMPLE_RULE: &str = r#"
SecRuleEngine On
SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny,status:403"
"#;

const SQLI_RULE: &str = r#"
SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS "@detectSQLi" "id:942100,phase:2,deny,status:403,msg:'SQL Injection'"
"#;

const COMPLEX_RULE: &str = r#"
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_URI|ARGS|ARGS_NAMES "@rx (?i)(?:union.*select|select.*from|insert.*into)" \
    "id:942101,phase:2,deny,status:403,\
    msg:'SQL Injection Attack',\
    severity:'CRITICAL',\
    t:lowercase,t:urlDecodeUni"
"#;

const CLEAN_REQUESTS: &[(&str, &str)] = &[
    ("/", "GET"),
    ("/api/users", "GET"),
    ("/api/users/123", "GET"),
    ("/search?q=hello+world", "GET"),
];

// Attack payloads that COMPLEX_RULE's rule 942101 actually matches
// (union.*select | select.*from | insert.*into, case-insensitive).
const SQLI_PAYLOADS: &[&str] = &[
    "/api/users?id=1 UNION SELECT * FROM passwords--",
    "/api/users?id=1; SELECT password FROM users--",
    "/search?q=insert into logs values('pwned')--",
];

// ============================================================================
// Sanity Helpers
// ============================================================================
//
// Phase-2 rules only execute during request-body processing on both engines.
// Every comparison below therefore drives phases 1 and 2, and asserts before
// measuring that the ruleset actually fires on attack input and stays quiet
// on clean input, so the measured section can never silently become an empty
// hot path again (issue #15).

fn zentinel_full_request(engine: &zentinel_modsec::ModSecurity, uri: &str, method: &str) -> bool {
    let mut tx = engine.new_transaction();
    tx.process_uri(uri, method, "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.intervention().is_some()
}

fn libmodsec_full_request(msc: &LibModSecurity, rules: &LibRules, uri: &str, method: &str) -> bool {
    let tx = LibTransaction::new(msc, rules);
    tx.process_uri(uri, method, "HTTP/1.1");
    tx.add_request_header("Host", "example.com");
    tx.process_request_headers();
    tx.process_request_body();
    tx.intervention().is_some()
}

fn assert_rules_fire(
    zentinel: &zentinel_modsec::ModSecurity,
    libmsc: &LibModSecurity,
    librules: &LibRules,
) {
    for &uri in SQLI_PAYLOADS {
        assert!(
            zentinel_full_request(zentinel, uri, "GET"),
            "sanity check failed: zentinel-modsec did not block attack payload {uri}"
        );
        assert!(
            libmodsec_full_request(libmsc, librules, uri, "GET"),
            "sanity check failed: libmodsecurity did not block attack payload {uri}"
        );
    }
    for &(uri, method) in CLEAN_REQUESTS {
        assert!(
            !zentinel_full_request(zentinel, uri, method),
            "sanity check failed: zentinel-modsec blocked clean request {uri}"
        );
        assert!(
            !libmodsec_full_request(libmsc, librules, uri, method),
            "sanity check failed: libmodsecurity blocked clean request {uri}"
        );
    }
}

// ============================================================================
// Comparison Benchmarks
// ============================================================================

fn bench_parsing_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("parsing_comparison");

    // zentinel-modsec
    group.bench_function("zentinel/simple_rule", |b| {
        b.iter(|| {
            zentinel_modsec::ModSecurity::from_string(std::hint::black_box(SIMPLE_RULE)).unwrap()
        })
    });

    // libmodsecurity
    group.bench_function("libmodsec/simple_rule", |b| {
        let msc = LibModSecurity::new();
        b.iter(|| {
            let rules = LibRules::new();
            rules.add_rules(std::hint::black_box(SIMPLE_RULE)).unwrap();
            drop(rules);
        });
        drop(msc);
    });

    // Complex rule
    group.bench_function("zentinel/complex_rule", |b| {
        b.iter(|| {
            zentinel_modsec::ModSecurity::from_string(std::hint::black_box(COMPLEX_RULE)).unwrap()
        })
    });

    group.bench_function("libmodsec/complex_rule", |b| {
        let msc = LibModSecurity::new();
        b.iter(|| {
            let rules = LibRules::new();
            rules.add_rules(std::hint::black_box(COMPLEX_RULE)).unwrap();
            drop(rules);
        });
        drop(msc);
    });

    group.finish();
}

fn bench_transaction_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction_comparison");
    group.measurement_time(Duration::from_secs(10));

    // Setup zentinel-modsec
    let zentinel = zentinel_modsec::ModSecurity::from_string(COMPLEX_RULE).unwrap();

    // Setup libmodsecurity
    let libmsc = LibModSecurity::new();
    let librules = LibRules::new();
    librules.add_rules(COMPLEX_RULE).unwrap();

    // COMPLEX_RULE's detection rule is phase 2: both engines must run request
    // body processing, and the payload must match its regex.
    let attack_uri = "/api/users?id=1 UNION SELECT * FROM passwords--";
    assert_rules_fire(&zentinel, &libmsc, &librules);

    // Clean request - zentinel (phases 1 and 2)
    group.bench_function("zentinel/clean_request", |b| {
        b.iter(|| {
            let mut tx = zentinel.new_transaction();
            tx.process_uri(std::hint::black_box("/api/users"), "GET", "HTTP/1.1")
                .unwrap();
            tx.add_request_header("Host", "example.com").unwrap();
            tx.process_request_headers().unwrap();
            tx.process_request_body().unwrap();
            tx.intervention().is_some()
        })
    });

    // Clean request - libmodsecurity (phases 1 and 2)
    group.bench_function("libmodsec/clean_request", |b| {
        b.iter(|| {
            let tx = LibTransaction::new(&libmsc, &librules);
            tx.process_uri(std::hint::black_box("/api/users"), "GET", "HTTP/1.1");
            tx.add_request_header("Host", "example.com");
            tx.process_request_headers();
            tx.process_request_body();
            tx.intervention()
        })
    });

    // SQLi request - zentinel (phases 1 and 2)
    group.bench_function("zentinel/sqli_request", |b| {
        b.iter(|| {
            let mut tx = zentinel.new_transaction();
            tx.process_uri(std::hint::black_box(attack_uri), "GET", "HTTP/1.1")
                .unwrap();
            tx.add_request_header("Host", "example.com").unwrap();
            tx.process_request_headers().unwrap();
            tx.process_request_body().unwrap();
            tx.intervention().is_some()
        })
    });

    // SQLi request - libmodsecurity (phases 1 and 2)
    group.bench_function("libmodsec/sqli_request", |b| {
        b.iter(|| {
            let tx = LibTransaction::new(&libmsc, &librules);
            tx.process_uri(std::hint::black_box(attack_uri), "GET", "HTTP/1.1");
            tx.add_request_header("Host", "example.com");
            tx.process_request_headers();
            tx.process_request_body();
            tx.intervention()
        })
    });

    group.finish();
}

fn bench_body_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("body_comparison");

    // Setup zentinel-modsec
    let zentinel = zentinel_modsec::ModSecurity::from_string(SQLI_RULE).unwrap();

    // Setup libmodsecurity
    let libmsc = LibModSecurity::new();
    let librules = LibRules::new();
    librules.add_rules(SQLI_RULE).unwrap();

    let body = b"username=admin&password=' OR '1'='1' --";

    // Sanity: the SQLi body must trigger the phase-2 rule on both engines.
    {
        let mut tx = zentinel.new_transaction();
        tx.process_uri("/api/login", "POST", "HTTP/1.1").unwrap();
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
            .unwrap();
        tx.process_request_headers().unwrap();
        tx.append_request_body(body).unwrap();
        tx.process_request_body().unwrap();
        assert!(
            tx.intervention().is_some(),
            "sanity check failed: zentinel-modsec did not block SQLi body"
        );

        let ltx = LibTransaction::new(&libmsc, &librules);
        ltx.process_uri("/api/login", "POST", "HTTP/1.1");
        ltx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
        ltx.process_request_headers();
        ltx.append_request_body(body);
        ltx.process_request_body();
        assert!(
            ltx.intervention().is_some(),
            "sanity check failed: libmodsecurity did not block SQLi body"
        );
    }

    // zentinel
    group.bench_function("zentinel/post_body_sqli", |b| {
        b.iter(|| {
            let mut tx = zentinel.new_transaction();
            tx.process_uri("/api/login", "POST", "HTTP/1.1").unwrap();
            tx.add_request_header("Host", "example.com").unwrap();
            tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
                .unwrap();
            tx.process_request_headers().unwrap();
            tx.append_request_body(std::hint::black_box(body)).unwrap();
            tx.process_request_body().unwrap();
            tx.intervention().is_some()
        })
    });

    // libmodsecurity
    group.bench_function("libmodsec/post_body_sqli", |b| {
        b.iter(|| {
            let tx = LibTransaction::new(&libmsc, &librules);
            tx.process_uri("/api/login", "POST", "HTTP/1.1");
            tx.add_request_header("Host", "example.com");
            tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
            tx.process_request_headers();
            tx.append_request_body(std::hint::black_box(body));
            tx.process_request_body();
            tx.intervention()
        })
    });

    group.finish();
}

fn bench_throughput_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput_comparison");
    group.measurement_time(Duration::from_secs(15));

    // Setup zentinel-modsec
    let zentinel = zentinel_modsec::ModSecurity::from_string(COMPLEX_RULE).unwrap();

    // Setup libmodsecurity
    let libmsc = LibModSecurity::new();
    let librules = LibRules::new();
    librules.add_rules(COMPLEX_RULE).unwrap();

    // The detection rule in COMPLEX_RULE is phase 2: the loops below must run
    // request body processing on both engines or no rule executes at all
    // (issue #15). Verify the rules fire before measuring anything.
    assert_rules_fire(&zentinel, &libmsc, &librules);

    // Clean traffic - zentinel (phases 1 and 2)
    group.bench_function("zentinel/clean_traffic", |b| {
        let mut idx = 0;
        b.iter(|| {
            let (uri, method) = CLEAN_REQUESTS[idx % CLEAN_REQUESTS.len()];
            idx += 1;

            let mut tx = zentinel.new_transaction();
            tx.process_uri(std::hint::black_box(uri), method, "HTTP/1.1")
                .unwrap();
            tx.add_request_header("Host", "example.com").unwrap();
            tx.process_request_headers().unwrap();
            tx.process_request_body().unwrap();
            tx.intervention().is_some()
        })
    });

    // Clean traffic - libmodsecurity (phases 1 and 2)
    group.bench_function("libmodsec/clean_traffic", |b| {
        let mut idx = 0;
        b.iter(|| {
            let (uri, method) = CLEAN_REQUESTS[idx % CLEAN_REQUESTS.len()];
            idx += 1;

            let tx = LibTransaction::new(&libmsc, &librules);
            tx.process_uri(std::hint::black_box(uri), method, "HTTP/1.1");
            tx.add_request_header("Host", "example.com");
            tx.process_request_headers();
            tx.process_request_body();
            tx.intervention()
        })
    });

    // Attack traffic - zentinel (phases 1 and 2)
    group.bench_function("zentinel/attack_traffic", |b| {
        let mut idx = 0;
        b.iter(|| {
            let uri = SQLI_PAYLOADS[idx % SQLI_PAYLOADS.len()];
            idx += 1;

            let mut tx = zentinel.new_transaction();
            tx.process_uri(std::hint::black_box(uri), "GET", "HTTP/1.1")
                .unwrap();
            tx.add_request_header("Host", "example.com").unwrap();
            tx.process_request_headers().unwrap();
            tx.process_request_body().unwrap();
            tx.intervention().is_some()
        })
    });

    // Attack traffic - libmodsecurity (phases 1 and 2)
    group.bench_function("libmodsec/attack_traffic", |b| {
        let mut idx = 0;
        b.iter(|| {
            let uri = SQLI_PAYLOADS[idx % SQLI_PAYLOADS.len()];
            idx += 1;

            let tx = LibTransaction::new(&libmsc, &librules);
            tx.process_uri(std::hint::black_box(uri), "GET", "HTTP/1.1");
            tx.add_request_header("Host", "example.com");
            tx.process_request_headers();
            tx.process_request_body();
            tx.intervention()
        })
    });

    group.finish();
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(
    comparison_benches,
    bench_full_crs_comparison,
    bench_parsing_comparison,
    bench_transaction_comparison,
    bench_body_comparison,
    bench_throughput_comparison,
);

criterion_main!(comparison_benches);

// ============================================================================
// Full OWASP CRS 4.25.0 on both engines
// ============================================================================
//
// The same checkout, configuration and requests as `full_crs` in
// modsec_bench.rs, run through both engines: connection, URI, headers, body,
// phases 1, 2 and 5. Set CRS_BENCH_DIR to a CRS v4.25.0 checkout (see
// benches/README.md); without it this group is skipped.
//
// Both engines get the JSON body processor from the rule ModSecurity's
// recommended configuration uses (200001), so a JSON body is parsed into ARGS
// on both sides. Before anything is timed, each engine must block a disallowed
// method and a SQL injection, and must let the three timed requests through,
// so neither side can be measuring an empty hot path (issue #15).

const FULL_CRS_COMMIT: &str = "aabf675fcfc5e489b424b844e6c9f1b39802df69";

const FULL_CRS_REQUESTS: &[(&str, &str, &str, &str, &[u8])] = &[
    ("get", "GET", "/products?category=books", "", b""),
    (
        "form",
        "POST",
        "/checkout",
        "application/x-www-form-urlencoded",
        b"item=notebook&qty=2",
    ),
    (
        "json",
        "POST",
        "/api/cart",
        "application/json",
        br#"{"items":[{"sku":"notebook","qty":2}]}"#,
    ),
];

fn full_crs_config(dir: &std::path::Path) -> String {
    let d = dir.display();
    format!(
        "SecRuleEngine On\nSecRequestBodyAccess On\n\
         SecRule REQUEST_HEADERS:Content-Type \"^application/json\" \
         \"id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON\"\n\
         Include \"{d}/crs-setup.conf.example\"\nInclude \"{d}/rules/*.conf\"\n"
    )
}

fn zentinel_crs_request(
    engine: &zentinel_modsec::ModSecurity,
    method: &str,
    uri: &str,
    content_type: &str,
    body: &[u8],
) -> zentinel_modsec::engine::Transaction {
    let mut tx = engine.new_transaction();
    tx.set_client_addr("127.0.0.1", 40000);
    tx.set_server_addr("127.0.0.1", 443);
    tx.process_uri(uri, method, "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "shop.example").unwrap();
    tx.add_request_header("User-Agent", "Mozilla/5.0").unwrap();
    tx.add_request_header("Accept", "*/*").unwrap();
    if !body.is_empty() {
        tx.add_request_header("Content-Type", content_type).unwrap();
        tx.add_request_header("Content-Length", &body.len().to_string())
            .unwrap();
    }
    tx.process_request_headers().unwrap();
    if !body.is_empty() {
        tx.append_request_body(body).unwrap();
    }
    tx.process_request_body().unwrap();
    tx.process_logging().unwrap();
    tx
}

fn libmodsec_crs_request(
    msc: &LibModSecurity,
    rules: &LibRules,
    method: &str,
    uri: &str,
    content_type: &str,
    body: &[u8],
) -> (LibTransaction, bool) {
    let tx = LibTransaction::new(msc, rules);
    tx.process_connection("127.0.0.1", 40000, "127.0.0.1", 443);
    tx.process_uri(uri, method, "1.1");
    tx.add_request_header("Host", "shop.example");
    tx.add_request_header("User-Agent", "Mozilla/5.0");
    tx.add_request_header("Accept", "*/*");
    if !body.is_empty() {
        tx.add_request_header("Content-Type", content_type);
        tx.add_request_header("Content-Length", &body.len().to_string());
    }
    tx.process_request_headers();
    if !body.is_empty() {
        tx.append_request_body(body);
    }
    tx.process_request_body();
    // Read the intervention after phase 2, as a connector does: what is
    // pending after logging is not the request's verdict.
    let blocked = tx.intervention().is_some();
    tx.process_logging();
    (tx, blocked)
}

fn bench_full_crs_comparison(c: &mut Criterion) {
    let Some(dir) = std::env::var_os("CRS_BENCH_DIR") else {
        return;
    };
    let dir = std::path::Path::new(&dir)
        .canonicalize()
        .expect("OWASP CRS checkout");
    let head = std::process::Command::new("git")
        .current_dir(&dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git");
    assert_eq!(
        String::from_utf8_lossy(&head.stdout).trim(),
        FULL_CRS_COMMIT,
        "expected CRS 4.25.0"
    );
    let config = full_crs_config(&dir);

    let zentinel = zentinel_modsec::ModSecurity::from_string(&config).expect("load CRS");
    let libmsc = LibModSecurity::new();
    let librules = LibRules::new();
    librules.add_rules(&config).expect("libmodsecurity loads CRS");

    let attacks = [
        ("PATCH", "/cart", "disallowed method"),
        ("GET", "/products?id=1%27%20UNION%20SELECT%20password%20FROM%20users--", "SQL injection"),
    ];
    for (method, uri, what) in attacks {
        assert!(
            zentinel_crs_request(&zentinel, method, uri, "", b"")
                .intervention()
                .is_some(),
            "zentinel-modsec did not block the {what}"
        );
        assert!(
            libmodsec_crs_request(&libmsc, &librules, method, uri, "", b"").1,
            "libmodsecurity did not block the {what}"
        );
    }
    for &(name, method, uri, content_type, body) in FULL_CRS_REQUESTS {
        assert!(
            zentinel_crs_request(&zentinel, method, uri, content_type, body)
                .intervention()
                .is_none(),
            "zentinel-modsec blocked {name}"
        );
        assert!(
            !libmodsec_crs_request(&libmsc, &librules, method, uri, content_type, body).1,
            "libmodsecurity blocked {name}"
        );
    }

    let mut group = c.benchmark_group("full_crs_comparison");
    group.measurement_time(Duration::from_secs(10));
    for &(name, method, uri, content_type, body) in FULL_CRS_REQUESTS {
        group.bench_function(format!("zentinel/{name}"), |b| {
            b.iter(|| {
                drop(std::hint::black_box(zentinel_crs_request(
                    &zentinel,
                    method,
                    uri,
                    content_type,
                    body,
                )))
            })
        });
        group.bench_function(format!("libmodsec/{name}"), |b| {
            b.iter(|| {
                drop(std::hint::black_box(libmodsec_crs_request(
                    &libmsc,
                    &librules,
                    method,
                    uri,
                    content_type,
                    body,
                )))
            })
        });
    }
    group.finish();
}
