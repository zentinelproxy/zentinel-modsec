//! Benchmarks for zentinel-modsec performance.
//!
//! Run with: cargo bench
//! Compare with libmodsecurity: cargo bench --features libmodsec-compare

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use zentinel_modsec::ModSecurity;
use std::time::Duration;

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

const XSS_RULE: &str = r#"
SecRuleEngine On
SecRule ARGS "@detectXSS" "id:941100,phase:2,deny,status:403,msg:'XSS Attack'"
"#;

const COMPLEX_RULE: &str = r#"
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:Content-Type "application/json" \
    "id:200001,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"

SecRule REQUEST_URI|ARGS|ARGS_NAMES "@rx (?i)(?:union.*select|select.*from|insert.*into)" \
    "id:942101,phase:2,deny,status:403,\
    msg:'SQL Injection Attack',\
    tag:'OWASP_CRS',\
    tag:'attack-sqli',\
    severity:'CRITICAL',\
    t:lowercase,t:urlDecodeUni,t:htmlEntityDecode"
"#;

const CHAIN_RULE: &str = r#"
SecRuleEngine On
SecRule REQUEST_METHOD "POST" \
    "id:100,phase:1,chain,deny,status:403"
    SecRule REQUEST_URI "@beginsWith /api" "chain"
        SecRule ARGS "@detectSQLi" ""
"#;

// Clean request payloads
const CLEAN_REQUESTS: &[(&str, &str)] = &[
    ("/", "GET"),
    ("/api/users", "GET"),
    ("/api/users/123", "GET"),
    ("/search?q=hello+world", "GET"),
    ("/products?category=electronics&page=1", "GET"),
    ("/api/orders", "POST"),
];

// Attack payloads
const SQLI_PAYLOADS: &[&str] = &[
    "/api/users?id=1' OR '1'='1",
    "/api/users?id=1; DROP TABLE users--",
    "/api/users?id=1 UNION SELECT * FROM passwords--",
    "/search?q=' OR 1=1--",
    "/login?user=admin'--",
];

const XSS_PAYLOADS: &[&str] = &[
    "/search?q=<script>alert(1)</script>",
    "/search?q=<img src=x onerror=alert(1)>",
    "/page?content=<svg onload=alert(1)>",
    "/comment?text=<body onload=alert('XSS')>",
];

// Request body sizes for throughput testing
const BODY_SIZES: &[usize] = &[0, 100, 1_000, 10_000, 100_000];

// ============================================================================
// Benchmark: Rule Parsing
// ============================================================================

fn bench_rule_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("parsing");

    group.bench_function("simple_rule", |b| {
        b.iter(|| {
            ModSecurity::from_string(black_box(SIMPLE_RULE)).unwrap()
        })
    });

    group.bench_function("sqli_rule", |b| {
        b.iter(|| {
            ModSecurity::from_string(black_box(SQLI_RULE)).unwrap()
        })
    });

    group.bench_function("xss_rule", |b| {
        b.iter(|| {
            ModSecurity::from_string(black_box(XSS_RULE)).unwrap()
        })
    });

    group.bench_function("complex_rule", |b| {
        b.iter(|| {
            ModSecurity::from_string(black_box(COMPLEX_RULE)).unwrap()
        })
    });

    group.bench_function("chain_rule", |b| {
        b.iter(|| {
            ModSecurity::from_string(black_box(CHAIN_RULE)).unwrap()
        })
    });

    group.finish();
}

fn bench_crs_parsing(c: &mut Criterion) {
    // Only run if CRS is available
    let crs_path = "test-rules/crs/rules";
    if !std::path::Path::new(crs_path).exists() {
        eprintln!("Skipping CRS parsing benchmark - rules not found at {}", crs_path);
        return;
    }

    let mut crs_content = String::new();
    crs_content.push_str("SecRuleEngine On\n");

    // Load a subset of CRS rules for benchmarking
    let rule_files = [
        "REQUEST-901-INITIALIZATION.conf",
        "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
    ];

    for file in &rule_files {
        let path = format!("{}/{}", crs_path, file);
        if let Ok(content) = std::fs::read_to_string(&path) {
            crs_content.push_str(&content);
            crs_content.push('\n');
        }
    }

    let mut group = c.benchmark_group("crs_parsing");
    group.sample_size(20); // Fewer samples for slow operations
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("crs_subset", |b| {
        b.iter(|| {
            ModSecurity::from_string(black_box(&crs_content)).unwrap()
        })
    });

    group.finish();
}

// ============================================================================
// Benchmark: Transaction Processing
// ============================================================================

fn bench_transaction_processing(c: &mut Criterion) {
    let modsec = ModSecurity::from_string(COMPLEX_RULE).unwrap();

    let mut group = c.benchmark_group("transaction");

    // Benchmark clean request processing
    group.bench_function("clean_request", |b| {
        b.iter(|| {
            let mut tx = modsec.new_transaction();
            tx.process_uri(black_box("/api/users"), "GET", "HTTP/1.1").unwrap();
            tx.add_request_header("Host", "example.com").unwrap();
            tx.add_request_header("User-Agent", "Mozilla/5.0").unwrap();
            tx.process_request_headers().unwrap();
            let blocked = tx.intervention().is_some();
            blocked
        })
    });

    // Benchmark attack request processing
    group.bench_function("sqli_request", |b| {
        b.iter(|| {
            let mut tx = modsec.new_transaction();
            tx.process_uri(black_box("/api/users?id=1' OR '1'='1"), "GET", "HTTP/1.1").unwrap();
            tx.add_request_header("Host", "example.com").unwrap();
            tx.process_request_headers().unwrap();
            let blocked = tx.intervention().is_some();
            blocked
        })
    });

    group.finish();
}

fn bench_body_processing(c: &mut Criterion) {
    let modsec = ModSecurity::from_string(SQLI_RULE).unwrap();

    let mut group = c.benchmark_group("body_processing");

    for &size in BODY_SIZES {
        let body = generate_body(size, false);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("clean", size),
            &body,
            |b, body| {
                b.iter(|| {
                    let mut tx = modsec.new_transaction();
                    tx.process_uri("/api/data", "POST", "HTTP/1.1").unwrap();
                    tx.add_request_header("Host", "example.com").unwrap();
                    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded").unwrap();
                    tx.process_request_headers().unwrap();
                    tx.append_request_body(black_box(body.as_bytes())).unwrap();
                    tx.process_request_body().unwrap();
                    let blocked = tx.intervention().is_some();
                    blocked
                })
            },
        );
    }

    // Test with attack payload in body
    let attack_body = "username=admin&password=' OR '1'='1' --";
    group.bench_function("sqli_body", |b| {
        b.iter(|| {
            let mut tx = modsec.new_transaction();
            tx.process_uri("/api/login", "POST", "HTTP/1.1").unwrap();
            tx.add_request_header("Host", "example.com").unwrap();
            tx.add_request_header("Content-Type", "application/x-www-form-urlencoded").unwrap();
            tx.process_request_headers().unwrap();
            tx.append_request_body(black_box(attack_body.as_bytes())).unwrap();
            tx.process_request_body().unwrap();
            let blocked = tx.intervention().is_some();
            blocked
        })
    });

    group.finish();
}

// ============================================================================
// Benchmark: Operators
// ============================================================================

fn bench_operators(c: &mut Criterion) {
    use zentinel_modsec::operators::{Operator, create_operator};
    use zentinel_modsec::parser::OperatorName;

    let mut group = c.benchmark_group("operators");

    // Regex operator
    let rx = create_operator(OperatorName::Rx, r"(?i)select.*from").unwrap();
    group.bench_function("rx_match", |b| {
        b.iter(|| rx.execute(black_box("SELECT * FROM users")))
    });
    group.bench_function("rx_no_match", |b| {
        b.iter(|| rx.execute(black_box("hello world")))
    });

    // Pattern match operator
    let pm = create_operator(OperatorName::Pm, "select union insert delete").unwrap();
    group.bench_function("pm_match", |b| {
        b.iter(|| pm.execute(black_box("trying to union the data")))
    });
    group.bench_function("pm_no_match", |b| {
        b.iter(|| pm.execute(black_box("normal user input here")))
    });

    // SQL injection detection
    let sqli = create_operator(OperatorName::DetectSqli, "").unwrap();
    group.bench_function("detectSQLi_attack", |b| {
        b.iter(|| sqli.execute(black_box("1' OR '1'='1")))
    });
    group.bench_function("detectSQLi_clean", |b| {
        b.iter(|| sqli.execute(black_box("normal search query")))
    });

    // XSS detection
    let xss = create_operator(OperatorName::DetectXss, "").unwrap();
    group.bench_function("detectXSS_attack", |b| {
        b.iter(|| xss.execute(black_box("<script>alert(1)</script>")))
    });
    group.bench_function("detectXSS_clean", |b| {
        b.iter(|| xss.execute(black_box("normal text content")))
    });

    // Contains operator
    let contains = create_operator(OperatorName::Contains, "/admin").unwrap();
    group.bench_function("contains_match", |b| {
        b.iter(|| contains.execute(black_box("/api/admin/users")))
    });
    group.bench_function("contains_no_match", |b| {
        b.iter(|| contains.execute(black_box("/api/users/profile")))
    });

    group.finish();
}

// ============================================================================
// Benchmark: Transformations
// ============================================================================

fn bench_transformations(c: &mut Criterion) {
    use zentinel_modsec::transformations::{Transformation, create_transformation};

    let mut group = c.benchmark_group("transformations");

    // URL decode
    let urldecode = create_transformation("urlDecode").unwrap();
    group.bench_function("urlDecode", |b| {
        b.iter(|| urldecode.transform(black_box("hello%20world%21")))
    });

    // Base64 decode
    let b64decode = create_transformation("base64Decode").unwrap();
    group.bench_function("base64Decode", |b| {
        b.iter(|| b64decode.transform(black_box("SGVsbG8gV29ybGQh")))
    });

    // HTML entity decode
    let htmldecode = create_transformation("htmlEntityDecode").unwrap();
    group.bench_function("htmlEntityDecode", |b| {
        b.iter(|| htmldecode.transform(black_box("&lt;script&gt;alert(1)&lt;/script&gt;")))
    });

    // Lowercase
    let lowercase = create_transformation("lowercase").unwrap();
    group.bench_function("lowercase", |b| {
        b.iter(|| lowercase.transform(black_box("HELLO WORLD")))
    });

    // Normalize path
    let normpath = create_transformation("normalizePath").unwrap();
    group.bench_function("normalizePath", |b| {
        b.iter(|| normpath.transform(black_box("/foo/../bar/./baz")))
    });

    // Command line
    let cmdline = create_transformation("cmdLine").unwrap();
    group.bench_function("cmdLine", |b| {
        b.iter(|| cmdline.transform(black_box("CMD;/C;DIR")))
    });

    group.finish();
}

// ============================================================================
// Benchmark: Throughput
// ============================================================================

fn bench_throughput(c: &mut Criterion) {
    let rules = r#"
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_URI|ARGS "@detectSQLi" "id:942100,phase:2,deny"
SecRule REQUEST_URI|ARGS "@detectXSS" "id:941100,phase:2,deny"
SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
"#;
    let modsec = ModSecurity::from_string(rules).unwrap();

    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Elements(1));

    // Clean traffic throughput
    group.bench_function("clean_traffic", |b| {
        let mut idx = 0;
        b.iter(|| {
            let (uri, method) = CLEAN_REQUESTS[idx % CLEAN_REQUESTS.len()];
            idx += 1;

            let mut tx = modsec.new_transaction();
            tx.process_uri(black_box(uri), method, "HTTP/1.1").unwrap();
            tx.add_request_header("Host", "example.com").unwrap();
            tx.add_request_header("User-Agent", "Mozilla/5.0").unwrap();
            tx.process_request_headers().unwrap();
            let blocked = tx.intervention().is_some();
            blocked
        })
    });

    // Attack traffic throughput
    group.bench_function("attack_traffic", |b| {
        let mut idx = 0;
        b.iter(|| {
            let uri = SQLI_PAYLOADS[idx % SQLI_PAYLOADS.len()];
            idx += 1;

            let mut tx = modsec.new_transaction();
            tx.process_uri(black_box(uri), "GET", "HTTP/1.1").unwrap();
            tx.add_request_header("Host", "example.com").unwrap();
            tx.process_request_headers().unwrap();
            let blocked = tx.intervention().is_some();
            blocked
        })
    });

    // Mixed traffic (80% clean, 20% attack)
    group.bench_function("mixed_traffic", |b| {
        let mut idx = 0;
        b.iter(|| {
            let uri = if idx % 5 == 0 {
                SQLI_PAYLOADS[idx / 5 % SQLI_PAYLOADS.len()]
            } else {
                CLEAN_REQUESTS[idx % CLEAN_REQUESTS.len()].0
            };
            idx += 1;

            let mut tx = modsec.new_transaction();
            tx.process_uri(black_box(uri), "GET", "HTTP/1.1").unwrap();
            tx.add_request_header("Host", "example.com").unwrap();
            tx.process_request_headers().unwrap();
            let blocked = tx.intervention().is_some();
            blocked
        })
    });

    group.finish();
}

// ============================================================================
// Helper Functions
// ============================================================================

fn generate_body(size: usize, with_attack: bool) -> String {
    if size == 0 {
        return String::new();
    }

    let mut body = String::with_capacity(size);

    if with_attack {
        body.push_str("param=' OR '1'='1&");
    }

    // Fill with benign form data
    let mut remaining = size.saturating_sub(body.len());
    let mut param_num = 0;

    while remaining > 0 {
        let param = format!("param{}=value{}&", param_num, param_num);
        if param.len() > remaining {
            break;
        }
        body.push_str(&param);
        remaining -= param.len();
        param_num += 1;
    }

    // Trim trailing &
    if body.ends_with('&') {
        body.pop();
    }

    body
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(
    benches,
    bench_rule_parsing,
    bench_crs_parsing,
    bench_transaction_processing,
    bench_body_processing,
    bench_operators,
    bench_transformations,
    bench_throughput,
);

criterion_main!(benches);
