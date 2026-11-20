# zentinel-modsec Benchmarks

Performance comparison between zentinel-modsec (pure Rust) and libmodsecurity (C++).

## Benchmark Categories

### 1. Rule Parsing
- Parse CRS rules from string
- Parse individual SecRule directives
- Parse complex rule chains

### 2. Transaction Processing
- Request header processing
- Request body processing (various sizes)
- Full request lifecycle

### 3. Operator Performance
- Regex matching (@rx)
- Pattern matching (@pm, Aho-Corasick)
- SQL injection detection (@detectSQLi)
- XSS detection (@detectXSS)
- Numeric comparisons (@eq, @lt, @gt)

### 4. Transformation Performance
- URL decoding
- Base64 decoding
- HTML entity decoding
- Normalization chains

### 5. Real-world Scenarios
- Clean traffic throughput
- Attack traffic detection
- Mixed traffic patterns

## Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench -- parsing
cargo bench -- transaction
cargo bench -- operators

# Compare against libmodsecurity (requires libmodsecurity installed)
cargo bench --features libmodsec-compare
```

## Full OWASP CRS request benchmark

Measure a GET with query arguments, a form POST and a nested JSON POST against
all 698 compiled rules in OWASP CRS 4.25.0. The engine loads once in blocking
mode. Each sample covers transaction creation, request headers, body parsing,
rule evaluation, logging and drop. Before timing, the harness checks a denied
method, all three benign outcomes, phase-specific CRS matches and JSON processor
selection.

```sh
git clone --depth 1 --branch v4.25.0 https://github.com/coreruleset/coreruleset.git /tmp/crs-4.25.0
export CRS_BENCH_DIR=/tmp/crs-4.25.0
cargo bench --bench modsec_bench -- full_crs --save-baseline before
# With the engine change applied, on the same host and Cargo target directory:
cargo bench --bench modsec_bench -- full_crs --baseline before
```

The benchmark verifies the checkout commit and the working copy before loading
the rules. Criterion reports warmed in-process transaction time for each fixture.

## Requirements for libmodsecurity Comparison

```bash
# macOS
brew install modsecurity

# Ubuntu/Debian
apt-get install libmodsecurity-dev

# Build with comparison
cargo bench --features libmodsec-compare
```

## Metrics Collected

- **Latency**: p50, p95, p99, max
- **Throughput**: operations/second
- **Memory**: peak RSS, allocations
- **CPU**: cycles per operation
