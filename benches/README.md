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
