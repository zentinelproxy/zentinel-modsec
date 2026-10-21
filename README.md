<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">ModSecurity engine in Rust</h3>

<p align="center">A pure Rust ModSecurity (SecLang) rule engine that runs the OWASP Core Rule Set, for Rust applications that want a WAF without libmodsecurity.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-modsec/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-modsec/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
  <img alt="Rust" src="https://img.shields.io/badge/rust-1.94.1%2B-f68d31?style=flat&labelColor=1f161e&logo=rust&logoColor=white">
</p>

<p align="center">
  <a href="https://docs.rs/zentinel-modsec">API reference</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

`zentinel-modsec` parses ModSecurity `.conf` rule files and evaluates them
against requests and responses, with no C or C++ dependency and no FFI
(`#![deny(unsafe_code)]`). SQL injection and XSS detection (`@detectSQLi`,
`@detectXSS`) are a pure Rust port of libinjection. CRS compatibility is
reported as a number, not asserted: CI runs the CRS regression corpus on every
push and fails if the pass count changes (see [CRS conformance](#crs-conformance)).

It is the engine behind Zentinel's
[ZentinelSec agent](https://registry.zentinelproxy.io/zentinelsec/). The
[ModSecurity agent](https://github.com/zentinelproxy/zentinel-agent-modsec) is
a different thing: it wraps the C++ libmodsecurity.

## Quick start

```toml
[dependencies]
zentinel-modsec = "0.5"
```

```rust
use zentinel_modsec::ModSecurity;

fn main() -> zentinel_modsec::Result<()> {
    // Compile rules once; reuse the engine for every request.
    let modsec = ModSecurity::from_string(r#"
        SecRuleEngine On
        SecRule REQUEST_URI "@contains /admin" \
            "id:1,phase:1,deny,status:403,msg:'Admin access blocked'"
    "#)?;

    let mut tx = modsec.new_transaction();
    tx.process_uri("/admin/dashboard", "GET", "HTTP/1.1")?;
    tx.add_request_header("Host", "example.com")?;
    tx.process_request_headers()?; // runs phase 1

    if let Some(i) = tx.intervention() {
        println!("blocked: status={}, rules={:?}", i.status, i.rule_ids);
    }
    Ok(())
}
```

## Install

As a library, from crates.io: `cargo add zentinel-modsec`.

The crate also builds a small CLI for checking rule files:

```bash
cargo install zentinel-modsec

zentinel-modsec check -r rules.conf                 # parse, print the rule count
zentinel-modsec dump  -r rules.conf                 # list rule IDs by phase
zentinel-modsec test  -r rules.conf -u "/search?q=' OR 1=1--" -b ''
```

`test` runs phase 2 only when a body is given, so pass `-b ''` to evaluate
phase-2 rules (which is where most CRS rules live) on a request without a body.

## Usage

### Phases

Each `process_*` call runs one ModSecurity phase. Rules marked `phase:2` (all
argument and body rules, including the CRS SQLi and XSS rules) only run when
you call `process_request_body()`, even for a `GET` with no body:

```rust
let modsec = ModSecurity::from_string(r#"
    SecRuleEngine On
    SecRule ARGS "@detectSQLi" \
        "id:942100,phase:2,deny,status:403,msg:'SQL injection'"
"#)?;

let mut tx = modsec.new_transaction();
tx.process_uri("/search?q=' OR 1=1--", "GET", "HTTP/1.1")?;
tx.process_request_headers()?; // phase 1: no intervention yet
tx.process_request_body()?;    // phase 2: the rule runs here
assert!(tx.has_intervention());
```

Request bodies need `SecRequestBodyAccess On`; feed them with
`append_request_body()` before `process_request_body()`. Response phases are
`process_response_headers()` and `process_response_body()`.

### Detection only and anomaly scoring

Under `SecRuleEngine DetectionOnly` rules match but never intervene;
`tx.matched_rules()` lists what matched. `setvar` on `TX` works as in CRS, and
`tx.anomaly_score()` returns the accumulated score:

```rust
let modsec = ModSecurity::from_string(r#"
    SecRuleEngine On
    SecRule REQUEST_URI "@contains /admin" \
        "id:1,phase:1,pass,setvar:'TX.anomaly_score=+5'"
    SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" \
        "id:2,phase:1,pass,setvar:'TX.anomaly_score=+10'"
    SecRule TX:anomaly_score "@ge 10" \
        "id:100,phase:1,deny,status:403,msg:'Anomaly score exceeded'"
"#)?;
// a request to /admin with User-Agent sqlmap/1.0 scores 15 and is denied
```

### Loading the OWASP CRS

```bash
git clone https://github.com/coreruleset/coreruleset /etc/modsecurity/crs
cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf
cat > /etc/modsecurity/main.conf <<'EOF'
Include /etc/modsecurity/crs/crs-setup.conf
Include /etc/modsecurity/crs/rules/*.conf
EOF
```

```rust
let modsec = zentinel_modsec::ModSecurity::from_file("/etc/modsecurity/main.conf")?;
println!("loaded {} rules", modsec.rule_count());
```

`ModSecurity` is `Send + Sync`: build it once, share it behind an `Arc`, and
create one `Transaction` per request. The API is synchronous, so it can be
called from any async runtime. A minimal Axum middleware:

```rust
async fn waf(
    State(modsec): State<Arc<ModSecurity>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let mut tx = modsec.new_transaction();
    let uri = request.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    tx.process_uri(uri, request.method().as_str(), "HTTP/1.1")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    for (name, value) in request.headers() {
        if let Ok(v) = value.to_str() {
            let _ = tx.add_request_header(name.as_str(), v);
        }
    }
    tx.process_request_headers().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Phase 2 (arguments; add the body first if you inspect bodies).
    tx.process_request_body().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if let Some(i) = tx.intervention() {
        return Err(StatusCode::from_u16(i.status).unwrap_or(StatusCode::FORBIDDEN));
    }
    Ok(next.run(request).await)
}
```

## What is supported

**Directives:** `SecRule`, `SecAction`, `SecMarker`, `SecRuleEngine`,
`SecDefaultAction`, `SecRuleRemoveById`, `SecRuleUpdateTargetById`,
`SecRuleUpdateActionById`, `SecRequestBodyAccess`, `SecResponseBodyAccess`,
`SecRequestBodyLimit`, `SecResponseBodyLimit`, `Include`. Other directives are
logged and skipped.

**Operators:** `@rx`, `@pm`, `@pmf`, `@pmFromFile`, `@contains`, `@beginsWith`,
`@endsWith`, `@streq`, `@within`, `@eq`, `@ne`, `@gt`, `@ge`, `@lt`, `@le`,
`@detectSQLi`, `@detectXSS`, `@ipMatch`, `@ipMatchFromFile`,
`@validateUrlEncoding`, `@validateUtf8Encoding`, `@validateByteRange`,
`@unconditionalMatch`, `@noMatch`. `@containsWord` and `@strmatch` are
approximated by `@contains`.

These parse but **never match**: `@verifyCC`, `@verifySSN`, `@verifyCPF`,
`@validateHash`, `@validateDTD`, `@validateSchema`, `@rbl`, `@geoLookup`,
`@gsbLookup`, `@inspectFile`, `@fuzzyHash`, `@rsub`. A rule that depends on one
of them is inert.

**Transformations:** `lowercase`, `uppercase`, `urlDecode`, `urlDecodeUni`,
`urlEncode`, `base64Decode`, `base64DecodeExt`, `base64Encode`, `hexDecode`,
`hexEncode`, `sqlHexDecode`, `htmlEntityDecode`, `jsDecode`, `cssDecode`,
`escapeSeqDecode`, `utf8toUnicode`, `removeWhitespace`, `compressWhitespace`,
`removeNulls`, `replaceNulls`, `trim`, `trimLeft`, `trimRight`,
`normalizePath`, `normalizePathWin`, `removeComments`, `removeCommentsChar`,
`replaceComments`, `cmdLine`, `md5`, `sha1`, `sha256`, `length`, `parityZero7bit`,
`none`.

**Body processors:** URL-encoded forms, multipart (including
`MULTIPART_PART_HEADERS`), JSON and XML. XML is read with `quick-xml`, which
does not expand entities. XPath is not supported: `XML:/*` and `XML://@*`
(every `XML:` target in stock CRS) resolve against the flattened body, and
richer XPath expressions are reported when the rules load.

**Not implemented:** `UNIQUE_ID` and `FILES_COMBINED_SIZE`; rules that target
only those are inert and reported at load time.

## CRS conformance

The OWASP CRS ships a regression suite of request/expectation pairs, each
naming the rule IDs that must, or must not, appear in the log for a request.
`tests/crs_conformance.rs` runs that corpus against this engine, and the CI
`OWASP CRS conformance` job fails if the pass count differs from
`MIN_PASSING` in either direction.

| | |
|---|---|
| Corpus | CRS `main` (4.31.0-dev), pinned commit in `.github/workflows/ci.yml` |
| Passing | **4,806** (`MIN_PASSING`) |

```bash
mkdir -p test-rules
git clone --depth 1 https://github.com/coreruleset/coreruleset.git test-rules/crs
cp test-rules/crs/crs-setup.conf.example test-rules/crs/crs-setup.conf
cargo test --release --test crs_conformance -- --nocapture
```

Against an unpinned CRS checkout the count can differ from CI.

### What that number does and does not tell you

The corpus runs in the configuration CRS documents for it: `DetectionOnly` at
paranoia level 4. In that mode `block` never blocks, the paranoia gates never
fire, and the anomaly score never reaches rule 949110. It measures whether
individual rules **match**, not whether the WAF **decides** correctly.

That distinction is not academic. A set of defects that made a stock CRS
deployment deny every request, `GET /` included
([#29](https://github.com/zentinelproxy/zentinel-modsec/issues/29)), moved
this number by 23 cases, because none of the machinery they broke runs in this
configuration. `stock_crs_blocks_attacks_and_passes_ordinary_traffic` in the
same file covers the other half: real blocking mode, default paranoia,
asserting the decision for ordinary requests and for attacks. Neither
substitutes for the other.

| | corpus |
|---|---|
| Before the 2026 evaluation fixes | 4,080 |
| Stock CRS evaluation: `skipAfter` in phase 2+, `TX` key case, `block` semantics, `REQUEST_LINE` ([#29](https://github.com/zentinelproxy/zentinel-modsec/issues/29)) | 4,103 |
| `+` decoded as a space in form arguments ([#34](https://github.com/zentinelproxy/zentinel-modsec/issues/34)) | 4,228 |
| Form parameter with no `=` kept rather than dropped ([#38](https://github.com/zentinelproxy/zentinel-modsec/issues/38)) | 4,541 |
| `t:cmdLine` completed ([#31](https://github.com/zentinelproxy/zentinel-modsec/issues/31)) | 4,608 |
| Later fixes, current `main` | 4,806 |

Two of those were bypasses: the `+` encoding and the missing `=` each let a
payload reach the application while the engine inspected nothing.

## Performance

Measured with criterion in `benches/libmodsec_compare.rs`: both engines run the
same ruleset through request phases 1 and 2, single thread, on an Apple
M-series machine. Absolute numbers depend on hardware; the ratios are the
point.

| Benchmark | zentinel-modsec | libmodsecurity 3 (C++) |
|---|---|---|
| Clean request | 1.34 µs | 5.65 µs |
| SQLi detection | 1.40 µs | 16.03 µs |
| Body processing | 1.45 µs | 12.91 µs |
| Rule parsing (complex) | 2.73 µs | 10.58 µs |

Reproduce with `cargo bench --features libmodsec-compare` (needs
libmodsecurity installed); `cargo bench` alone runs the engine's own benches.
An earlier version of this table claimed 10-30x; that benchmark never reached
the phase-2 detection rule on either engine
([#15](https://github.com/zentinelproxy/zentinel-modsec/issues/15)). These
figures are the re-measurement after #15, #17 and #18.

## Development

```bash
cargo build
SKIP_CRS_CONFORMANCE=1 cargo test --all-targets   # unit and integration tests
cargo test --release --test crs_conformance        # needs test-rules/crs, see above
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
```

Minimum Rust: 1.94.1 (`rust-version` in `Cargo.toml`).

## Related

- [ZentinelSec agent](https://registry.zentinelproxy.io/zentinelsec/): the Zentinel agent built on this engine
- [OWASP CRS](https://coreruleset.org)
- [libmodsecurity](https://github.com/owasp-modsecurity/ModSecurity): the reference C++ implementation

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
