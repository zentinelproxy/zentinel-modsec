//! Comparison benchmarks against libmodsecurity (C++).
//!
//! This benchmark requires libmodsecurity to be installed.
//! Run with: cargo bench --features libmodsec-compare
//!
//! Install libmodsecurity:
//!   macOS: brew install modsecurity
//!   Ubuntu: apt-get install libmodsecurity-dev

#![cfg(feature = "libmodsec-compare")]

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
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
    fn msc_rules_add(rules: *mut Rules, plain_rules: *const c_char, error: *mut *const c_char) -> c_int;
    fn msc_rules_add_file(rules: *mut Rules, file: *const c_char, error: *mut *const c_char) -> c_int;

    fn msc_new_transaction(msc: *mut ModSecurity, rules: *mut Rules, log_cb: *mut c_void) -> *mut Transaction;
    fn msc_transaction_cleanup(tx: *mut Transaction);
    fn msc_process_uri(tx: *mut Transaction, uri: *const c_char, method: *const c_char, version: *const c_char) -> c_int;
    fn msc_add_request_header(tx: *mut Transaction, key: *const c_char, value: *const c_char) -> c_int;
    fn msc_process_request_headers(tx: *mut Transaction) -> c_int;
    fn msc_append_request_body(tx: *mut Transaction, body: *const u8, len: usize) -> c_int;
    fn msc_process_request_body(tx: *mut Transaction) -> c_int;
    fn msc_intervention(tx: *mut Transaction, intervention: *mut ModSecurityIntervention) -> c_int;
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
            Self { rules: msc_create_rules_set() }
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
            msc_process_uri(self.tx, c_uri.as_ptr(), c_method.as_ptr(), c_version.as_ptr());
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

const SQLI_PAYLOADS: &[&str] = &[
    "/api/users?id=1' OR '1'='1",
    "/api/users?id=1; DROP TABLE users--",
    "/search?q=' OR 1=1--",
];

// ============================================================================
// Comparison Benchmarks
// ============================================================================

fn bench_parsing_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("parsing_comparison");

    // zentinel-modsec
    group.bench_function("zentinel/simple_rule", |b| {
        b.iter(|| {
            zentinel_modsec::ModSecurity::from_string(black_box(SIMPLE_RULE)).unwrap()
        })
    });

    // libmodsecurity
    group.bench_function("libmodsec/simple_rule", |b| {
        let msc = LibModSecurity::new();
        b.iter(|| {
            let rules = LibRules::new();
            rules.add_rules(black_box(SIMPLE_RULE)).unwrap();
            drop(rules);
        });
        drop(msc);
    });

    // Complex rule
    group.bench_function("zentinel/complex_rule", |b| {
        b.iter(|| {
            zentinel_modsec::ModSecurity::from_string(black_box(COMPLEX_RULE)).unwrap()
        })
    });

    group.bench_function("libmodsec/complex_rule", |b| {
        let msc = LibModSecurity::new();
        b.iter(|| {
            let rules = LibRules::new();
            rules.add_rules(black_box(COMPLEX_RULE)).unwrap();
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

    // Clean request - zentinel
    group.bench_function("zentinel/clean_request", |b| {
        b.iter(|| {
            let mut tx = zentinel.new_transaction();
            tx.process_uri(black_box("/api/users"), "GET", "HTTP/1.1").unwrap();
            tx.add_request_header("Host", "example.com").unwrap();
            tx.process_request_headers().unwrap();
            tx.intervention().is_some()
        })
    });

    // Clean request - libmodsecurity
    group.bench_function("libmodsec/clean_request", |b| {
        b.iter(|| {
            let tx = LibTransaction::new(&libmsc, &librules);
            tx.process_uri(black_box("/api/users"), "GET", "HTTP/1.1");
            tx.add_request_header("Host", "example.com");
            tx.process_request_headers();
            tx.intervention()
        })
    });

    // SQLi request - zentinel
    group.bench_function("zentinel/sqli_request", |b| {
        b.iter(|| {
            let mut tx = zentinel.new_transaction();
            tx.process_uri(black_box("/api/users?id=1' OR '1'='1"), "GET", "HTTP/1.1").unwrap();
            tx.add_request_header("Host", "example.com").unwrap();
            tx.process_request_headers().unwrap();
            tx.intervention().is_some()
        })
    });

    // SQLi request - libmodsecurity
    group.bench_function("libmodsec/sqli_request", |b| {
        b.iter(|| {
            let tx = LibTransaction::new(&libmsc, &librules);
            tx.process_uri(black_box("/api/users?id=1' OR '1'='1"), "GET", "HTTP/1.1");
            tx.add_request_header("Host", "example.com");
            tx.process_request_headers();
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

    // zentinel
    group.bench_function("zentinel/post_body_sqli", |b| {
        b.iter(|| {
            let mut tx = zentinel.new_transaction();
            tx.process_uri("/api/login", "POST", "HTTP/1.1").unwrap();
            tx.add_request_header("Host", "example.com").unwrap();
            tx.add_request_header("Content-Type", "application/x-www-form-urlencoded").unwrap();
            tx.process_request_headers().unwrap();
            tx.append_request_body(black_box(body)).unwrap();
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
            tx.append_request_body(black_box(body));
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

    // Clean traffic - zentinel
    group.bench_function("zentinel/clean_traffic", |b| {
        let mut idx = 0;
        b.iter(|| {
            let (uri, method) = CLEAN_REQUESTS[idx % CLEAN_REQUESTS.len()];
            idx += 1;

            let mut tx = zentinel.new_transaction();
            tx.process_uri(black_box(uri), method, "HTTP/1.1").unwrap();
            tx.add_request_header("Host", "example.com").unwrap();
            tx.process_request_headers().unwrap();
            tx.intervention().is_some()
        })
    });

    // Clean traffic - libmodsecurity
    group.bench_function("libmodsec/clean_traffic", |b| {
        let mut idx = 0;
        b.iter(|| {
            let (uri, method) = CLEAN_REQUESTS[idx % CLEAN_REQUESTS.len()];
            idx += 1;

            let tx = LibTransaction::new(&libmsc, &librules);
            tx.process_uri(black_box(uri), method, "HTTP/1.1");
            tx.add_request_header("Host", "example.com");
            tx.process_request_headers();
            tx.intervention()
        })
    });

    // Attack traffic - zentinel
    group.bench_function("zentinel/attack_traffic", |b| {
        let mut idx = 0;
        b.iter(|| {
            let uri = SQLI_PAYLOADS[idx % SQLI_PAYLOADS.len()];
            idx += 1;

            let mut tx = zentinel.new_transaction();
            tx.process_uri(black_box(uri), "GET", "HTTP/1.1").unwrap();
            tx.add_request_header("Host", "example.com").unwrap();
            tx.process_request_headers().unwrap();
            tx.intervention().is_some()
        })
    });

    // Attack traffic - libmodsecurity
    group.bench_function("libmodsec/attack_traffic", |b| {
        let mut idx = 0;
        b.iter(|| {
            let uri = SQLI_PAYLOADS[idx % SQLI_PAYLOADS.len()];
            idx += 1;

            let tx = LibTransaction::new(&libmsc, &librules);
            tx.process_uri(black_box(uri), "GET", "HTTP/1.1");
            tx.add_request_header("Host", "example.com");
            tx.process_request_headers();
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
    bench_parsing_comparison,
    bench_transaction_comparison,
    bench_body_comparison,
    bench_throughput_comparison,
);

criterion_main!(comparison_benches);
