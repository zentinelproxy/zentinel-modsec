# zentinel-modsec

[![Crates.io](https://img.shields.io/crates/v/zentinel-modsec.svg)](https://crates.io/crates/zentinel-modsec)
[![Documentation](https://docs.rs/zentinel-modsec/badge.svg)](https://docs.rs/zentinel-modsec)
[![License](https://img.shields.io/crates/l/zentinel-modsec.svg)](LICENSE)

**Pure Rust ModSecurity implementation with full OWASP CRS compatibility.**

A complete ModSecurity rule engine written in Rust with zero C/C++ dependencies. Load and execute OWASP Core Rule Set (CRS) rules for web application firewall (WAF) functionality in any Rust application.

## Performance: 4-11x Faster than libmodsecurity

| Benchmark | zentinel-modsec | libmodsecurity (C++) | Speedup |
|-----------|-----------------|----------------------|---------|
| Clean request | 1.34 µs | 5.65 µs | **4.2x faster** |
| SQLi detection | 1.40 µs | 16.03 µs | **11.5x faster** |
| Body processing | 1.45 µs | 12.91 µs | **8.9x faster** |
| Rule parsing (complex) | 2.73 µs | 10.58 µs | **3.9x faster** |
| **Throughput (clean)** | **676K req/s** | 168K req/s | **4.0x higher** |
| **Throughput (attack)** | **701K req/s** | 62K req/s | **11.3x higher** |

<sub>Both engines run the same ruleset through request phases 1 and 2 on the same
machine (Apple M-series, single thread, criterion). Ratios matter more than the
absolute numbers, which are hardware-dependent. Reproduce with
`cargo bench --features libmodsec-compare`.</sub>

> **Earlier numbers were wrong.** This table previously claimed 10-30x and
> 6.2M req/s. Those figures came from a benchmark that never executed the
> detection rules on the zentinel-modsec side — the ruleset's detection rule is
> `phase:2`, but the measured section stopped after phase 1, and the attack
> payloads did not match the rule's pattern in the first place. That was true of
> *both* engines, so the comparison measured transaction setup overhead on an
> empty ruleset rather than rule evaluation. Body-processing and rule-parsing
> figures always ran the rule and were unaffected.
> Reported in [#15](https://github.com/zentinelproxy/zentinel-modsec/issues/15)
> and corrected in the benchmark; these numbers are the re-measurement.
>
> Re-measured again after #17 and #18 (SecRuleUpdateTargetById, MULTIPART_PART_HEADERS population and the chain-semantics fix), which add real per-request work: throughput moved from 797K to 676K req/s and the headline from 4-13x to 4-11x.

## Features

- **Full OWASP CRS Compatibility** - Parse and execute 800+ CRS rules
- **Pure Rust** - No libmodsecurity, no C/C++ dependencies, no FFI
- **SecLang Support** - Load standard ModSecurity `.conf` rule files
- **Built-in Detection** - Native `@detectSQLi` and `@detectXSS` operators (pure Rust libinjection)
- **All Operators** - `@rx`, `@pm`, `@pmFromFile`, `@contains`, `@streq`, `@ipMatch`, and 30+ more
- **All Transformations** - `t:lowercase`, `t:urlDecode`, `t:base64Decode`, `t:htmlEntityDecode`, and 30+ more
- **Thread-Safe** - `Send + Sync`, safe for concurrent request processing
- **Async-Ready** - Works with tokio, async-std, or any async runtime
- **Zero Unsafe** - `#![deny(unsafe_code)]`

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
zentinel-modsec = "0.1"
```

### Basic Usage

```rust
use zentinel_modsec::ModSecurity;

fn main() -> zentinel_modsec::Result<()> {
    // Compile rules once; reuse the engine for all requests.
    let modsec = ModSecurity::from_string(r#"
        SecRuleEngine On
        SecRule REQUEST_URI "@contains /admin" \
            "id:1,phase:1,deny,status:403,msg:'Admin access blocked'"
    "#)?;

    // Process a request
    let mut tx = modsec.new_transaction();
    tx.process_uri("/admin/dashboard", "GET", "HTTP/1.1")?;
    tx.add_request_header("Host", "example.com")?;
    tx.add_request_header("User-Agent", "Mozilla/5.0")?;
    tx.process_request_headers()?;

    // Check for intervention (block/redirect/etc)
    if let Some(intervention) = tx.intervention() {
        println!("Blocked: status={}, rules={:?}",
            intervention.status,
            intervention.rule_ids);
    }

    Ok(())
}
```

### Loading OWASP CRS Rules

```rust
use zentinel_modsec::ModSecurity;

fn main() -> zentinel_modsec::Result<()> {
    // Point at an entry file that `Include`s crs-setup.conf and the rule files
    // (CRS ships such a layout), or a single combined ruleset file.
    let modsec = ModSecurity::from_file("/etc/modsecurity/main.conf")?;

    println!("Loaded {} rules", modsec.rule_count());

    Ok(())
}
```

### SQL Injection Detection

```rust
use zentinel_modsec::ModSecurity;

fn main() -> zentinel_modsec::Result<()> {
    let modsec = ModSecurity::from_string(r#"
        SecRuleEngine On
        SecRule ARGS "@detectSQLi" \
            "id:942100,phase:2,deny,status:403,msg:'SQL Injection detected'"
    "#)?;

    let mut tx = modsec.new_transaction();

    // Simulate a request with SQLi payload
    tx.process_uri("/search?q=' OR 1=1--", "GET", "HTTP/1.1")?;
    tx.process_request_headers()?;

    assert!(tx.has_intervention());
    println!("SQLi attack blocked!");

    Ok(())
}
```

### XSS Detection

```rust
use zentinel_modsec::ModSecurity;

fn main() -> zentinel_modsec::Result<()> {
    let modsec = ModSecurity::from_string(r#"
        SecRuleEngine On
        SecRule ARGS "@detectXSS" \
            "id:941100,phase:2,deny,status:403,msg:'XSS detected'"
    "#)?;

    let mut tx = modsec.new_transaction();

    tx.process_uri("/comment?text=<script>alert(1)</script>", "GET", "HTTP/1.1")?;
    tx.process_request_headers()?;

    assert!(tx.has_intervention());
    println!("XSS attack blocked!");

    Ok(())
}
```

### Request Body Inspection

```rust
use zentinel_modsec::ModSecurity;

fn main() -> zentinel_modsec::Result<()> {
    let modsec = ModSecurity::from_string(r#"
        SecRuleEngine On
        SecRequestBodyAccess On
        SecRule REQUEST_BODY "@detectSQLi" \
            "id:942110,phase:2,deny,status:403,msg:'SQLi in body'"
    "#)?;

    let mut tx = modsec.new_transaction();

    tx.process_uri("/api/login", "POST", "HTTP/1.1")?;
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")?;
    tx.process_request_headers()?;

    // Add request body
    tx.append_request_body(b"username=admin&password=' OR 1=1--")?;
    tx.process_request_body()?;

    assert!(tx.has_intervention());

    Ok(())
}
```

### Detection-Only Mode

```rust
use zentinel_modsec::ModSecurity;

fn main() -> zentinel_modsec::Result<()> {
    let modsec = ModSecurity::from_string(r#"
        SecRuleEngine DetectionOnly
        SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
    "#)?;

    let mut tx = modsec.new_transaction();

    tx.process_uri("/admin", "GET", "HTTP/1.1")?;
    tx.process_request_headers()?;

    // Rule matched but no intervention (detection only)
    assert!(!tx.has_intervention());
    assert!(tx.matched_rules().contains(&"1".to_string()));

    println!("Detected but not blocked: {:?}", tx.matched_rules());

    Ok(())
}
```

### Anomaly Scoring

```rust
use zentinel_modsec::ModSecurity;

fn main() -> zentinel_modsec::Result<()> {
    let modsec = ModSecurity::from_string(r#"
        SecRuleEngine On

        # Increment score for suspicious patterns
        SecRule REQUEST_URI "@contains /admin" \
            "id:1,phase:1,pass,setvar:'TX.anomaly_score=+5'"
        SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" \
            "id:2,phase:1,pass,setvar:'TX.anomaly_score=+10'"

        # Block if score exceeds threshold
        SecRule TX:anomaly_score "@ge 10" \
            "id:100,phase:1,deny,status:403,msg:'Anomaly score exceeded'"
    "#)?;

    let mut tx = modsec.new_transaction();

    tx.process_uri("/admin", "GET", "HTTP/1.1")?;
    tx.add_request_header("User-Agent", "sqlmap/1.0")?;
    tx.process_request_headers()?;

    println!("Anomaly score: {}", tx.anomaly_score());
    assert!(tx.has_intervention());

    Ok(())
}
```

## Framework Integration

### Axum

```rust
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::get,
    Router,
};
use zentinel_modsec::ModSecurity;
use std::sync::Arc;

async fn waf_middleware(
    State(modsec): State<Arc<ModSecurity>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let mut tx = modsec.new_transaction();

    // Process request
    tx.process_uri(
        request.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/"),
        request.method().as_str(),
        "HTTP/1.1",
    ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    for (name, value) in request.headers() {
        if let Ok(v) = value.to_str() {
            let _ = tx.add_request_header(name.as_str(), v);
        }
    }

    tx.process_request_headers()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Check for intervention
    if let Some(intervention) = tx.intervention() {
        return Err(StatusCode::from_u16(intervention.status).unwrap_or(StatusCode::FORBIDDEN));
    }

    Ok(next.run(request).await)
}

#[tokio::main]
async fn main() {
    let modsec = Arc::new(ModSecurity::from_file("/etc/modsecurity/main.conf").unwrap());

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .layer(middleware::from_fn_with_state(modsec.clone(), waf_middleware))
        .with_state(modsec);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

### Actix-web

```rust
use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse, middleware};
use zentinel_modsec::ModSecurity;
use std::sync::Arc;

async fn waf_check(
    req: HttpRequest,
    modsec: web::Data<Arc<ModSecurity>>,
) -> Option<HttpResponse> {
    let mut tx = modsec.new_transaction();

    tx.process_uri(req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/"),
                   req.method().as_str(),
                   "HTTP/1.1").ok()?;

    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            let _ = tx.add_request_header(name.as_str(), v);
        }
    }

    tx.process_request_headers().ok()?;

    tx.intervention().map(|i| {
        HttpResponse::build(actix_web::http::StatusCode::from_u16(i.status).unwrap())
            .body(format!("Blocked by rule: {:?}", i.rule_ids))
    })
}
```

## Supported SecLang Directives

### Directives

| Directive | Status | Description |
|-----------|--------|-------------|
| `SecRule` | ✅ | Main rule directive |
| `SecAction` | ✅ | Unconditional action |
| `SecMarker` | ✅ | Named marker for skipAfter |
| `SecRuleEngine` | ✅ | On/Off/DetectionOnly |
| `SecRequestBodyAccess` | ✅ | Enable body inspection |
| `SecResponseBodyAccess` | ✅ | Enable response inspection |
| `Include` | ✅ | Include other rule files |

### Operators

| Operator | Status | Description |
|----------|--------|-------------|
| `@rx` | ✅ | Regular expression |
| `@pm` | ✅ | Phrase match (Aho-Corasick) |
| `@pmFromFile` | ✅ | Phrase match from file |
| `@contains` | ✅ | String contains |
| `@streq` | ✅ | String equals |
| `@beginsWith` | ✅ | String begins with |
| `@endsWith` | ✅ | String ends with |
| `@within` | ✅ | Value within list |
| `@eq`, `@ne`, `@gt`, `@ge`, `@lt`, `@le` | ✅ | Numeric comparison |
| `@detectSQLi` | ✅ | SQL injection detection |
| `@detectXSS` | ✅ | XSS detection |
| `@ipMatch` | ✅ | IP/CIDR matching |
| `@validateUrlEncoding` | ✅ | URL encoding validation |
| `@validateUtf8Encoding` | ✅ | UTF-8 validation |

### Transformations

| Transformation | Status | Description |
|----------------|--------|-------------|
| `t:lowercase` | ✅ | Convert to lowercase |
| `t:uppercase` | ✅ | Convert to uppercase |
| `t:urlDecode` | ✅ | URL decode |
| `t:urlDecodeUni` | ✅ | URL decode (Unicode) |
| `t:base64Decode` | ✅ | Base64 decode |
| `t:base64Encode` | ✅ | Base64 encode |
| `t:htmlEntityDecode` | ✅ | HTML entity decode |
| `t:removeWhitespace` | ✅ | Remove whitespace |
| `t:compressWhitespace` | ✅ | Compress whitespace |
| `t:normalizePath` | ✅ | Normalize path |
| `t:normalizePathWin` | ✅ | Normalize Windows path |
| `t:cmdLine` | ✅ | Command line normalization |
| `t:md5` | ✅ | MD5 hash |
| `t:sha1` | ✅ | SHA1 hash |
| `t:hexEncode` | ✅ | Hex encode |
| `t:hexDecode` | ✅ | Hex decode |

### Actions

| Action | Status | Description |
|--------|--------|-------------|
| `deny` | ✅ | Block request |
| `block` | ✅ | Block with default status |
| `pass` | ✅ | Continue processing |
| `allow` | ✅ | Skip remaining rules |
| `redirect` | ✅ | Redirect to URL |
| `drop` | ✅ | Drop connection |
| `chain` | ✅ | Chain to next rule |
| `skip` | ✅ | Skip N rules |
| `skipAfter` | ✅ | Skip to marker |
| `setvar` | ✅ | Set variable |
| `capture` | ✅ | Capture regex groups |
| `id` | ✅ | Rule ID |
| `phase` | ✅ | Processing phase |
| `severity` | ✅ | Severity level |
| `msg` | ✅ | Log message |
| `tag` | ✅ | Rule tag |

## Why Pure Rust?

1. **Performance** - 4-11x faster than C++ libmodsecurity, depending on workload
2. **Safety** - Memory safety guaranteed, no buffer overflows
3. **Portability** - Runs anywhere Rust compiles (including WASM)
4. **Simplicity** - `cargo add zentinel-modsec`, no system dependencies
5. **Auditability** - Single-language codebase, easier security review

### Technical Optimizations

- **PHF (Perfect Hash Functions)** - O(1) operator/variable lookup
- **Lazy Regex Compilation** - Defer compilation to first use
- **Aho-Corasick** - O(n) multi-pattern matching for `@pm`
- **RegexSet** - Single-pass multi-regex evaluation for XSS detection
- **Zero-Copy Parsing** - `Cow<str>` avoids allocations when possible
- **No FFI Overhead** - Pure Rust, no cross-language calls

## OWASP CRS Setup

```bash
# Download OWASP Core Rule Set
git clone https://github.com/coreruleset/coreruleset /etc/modsecurity/crs
cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf

# Create an entry file that pulls in the setup and rule files
cat > /etc/modsecurity/main.conf <<'EOF'
Include /etc/modsecurity/crs/crs-setup.conf
Include /etc/modsecurity/crs/rules/*.conf
EOF
```

```rust
// Then load the entry file from your application:
let modsec = zentinel_modsec::ModSecurity::from_file("/etc/modsecurity/main.conf")?;
```

## Comparison

| Feature | zentinel-modsec | libmodsecurity | mod_security |
|---------|-----------------|----------------|--------------|
| Language | Pure Rust | C++ | C |
| Dependencies | None | PCRE, libxml2, etc. | Apache/nginx |
| Performance | 676K req/s | 168K req/s | ~200K req/s |
| CRS Compatible | ✅ | ✅ | ✅ |
| WASM Support | ✅ | ❌ | ❌ |
| Memory Safety | ✅ Guaranteed | ❌ Manual | ❌ Manual |

## License

Apache-2.0

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Related Projects

- [Zentinel](https://zentinelproxy.io) - Extensible reverse proxy using this engine
- [OWASP CRS](https://coreruleset.org) - Core Rule Set for ModSecurity
- [libmodsecurity](https://github.com/SpiderLabs/ModSecurity) - Original C++ implementation
