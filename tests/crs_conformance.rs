//! Conformance against the OWASP CRS regression corpus.
//!
//! The corpus is ~5,000 request/expectation pairs maintained upstream, one file
//! per rule, asserting **which rule IDs appear in the log** for a given request.
//! go-ftw drives it against a live server and reads the audit log; this drives
//! the same YAML directly against the engine, which is fast enough to run on
//! every push and precise enough to catch a rule that stops matching.
//!
//! # What this measures, and what it does not
//!
//! The corpus runs in the configuration upstream documents for it
//! (`tests/regression/README.md`, rule 900005): **`DetectionOnly` at paranoia
//! level 4**. That is deliberate on their part and important to understand
//! here: in detection-only mode `block` never blocks, the paranoia gates never
//! fire, and the anomaly score never reaches 949110. So this measures whether
//! individual rules *match*. It says nothing about whether the WAF *decides*
//! correctly.
//!
//! That distinction is not academic. A set of defects that made a stock CRS
//! deployment deny 100% of requests — including `GET /` — moved this number by
//! 23 out of 5,033, because none of the machinery they broke runs in this
//! configuration. A green corpus is not evidence that the WAF works.
//!
//! `stock_crs_blocks_attacks_and_passes_ordinary_traffic` covers the other
//! half: real blocking mode, default paranoia, asserting on the decision.
//! Both are needed. Neither substitutes for the other.
//!
//! # Running
//!
//! ```text
//! mkdir -p test-rules
//! git clone --depth 1 https://github.com/coreruleset/coreruleset.git test-rules/crs
//! cp test-rules/crs/crs-setup.conf.example test-rules/crs/crs-setup.conf
//! cargo test --test crs_conformance -- --nocapture
//! ```
//!
//! `CRS_DIR` overrides the location. `SKIP_CRS_CONFORMANCE=1` skips these tests
//! when the corpus is not present — CI's unit-test job sets it, because the
//! dedicated `conformance` job fetches the corpus and runs this optimised (~14s
//! against ~5,000 cases, versus minutes unoptimised). That job must never set
//! it: a gate that can silently not run is not a gate.
//!
//! Absence of the checkout is otherwise a failure rather than a skip, with
//! instructions — these tests previously existed in a form that returned early
//! when the fixture was missing, and went years without running.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zentinel_modsec::ModSecurity;

/// Cases the corpus must still pass. Raise it when a fix lands; never lower it
/// without saying which rules regressed and why.
///
/// Measured on CRS `main` (4.30.0-dev). The corpus is a moving target — it is
/// pinned by whatever the checkout holds — so a drop after pulling a newer CRS
/// is worth reading as new tests before reading it as a regression.
const MIN_PASSING: u32 = 4080;

/// Corpus stages that cannot be driven from here: an `encoded_request` payload,
/// or an expectation that is not about rule IDs (`status`, `match_regex`).
/// Reported rather than hidden, so this cap cannot quietly grow.
const EXPECTED_SKIPS_MAX: u32 = 60;

// --- corpus schema (only the fields this harness uses) ---------------------

#[derive(Deserialize)]
struct TestFile {
    tests: Vec<Test>,
}
#[derive(Deserialize)]
struct Test {
    #[serde(default)]
    stages: Vec<Stage>,
}
#[derive(Deserialize)]
struct Stage {
    input: Input,
    #[serde(default)]
    output: Output,
}
#[derive(Deserialize, Default)]
struct Input {
    #[serde(default)]
    dest_addr: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, serde_yaml::Value>,
    #[serde(default)]
    data: Option<serde_yaml::Value>,
    #[serde(default)]
    encoded_request: Option<String>,
    #[serde(default)]
    autocomplete_headers: Option<bool>,
}
#[derive(Deserialize, Default)]
struct Output {
    #[serde(default)]
    log: Option<Log>,
}
#[derive(Deserialize, Default)]
struct Log {
    #[serde(default)]
    expect_ids: Vec<serde_yaml::Value>,
    #[serde(default)]
    no_expect_ids: Vec<serde_yaml::Value>,
}

/// YAML scalars appear as strings or numbers; `data` may be a block sequence.
fn scalar(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Sequence(items) => items.iter().map(scalar).collect::<Vec<_>>().join(""),
        _ => String::new(),
    }
}

// --- fixture ---------------------------------------------------------------

fn crs_dir() -> Option<PathBuf> {
    if std::env::var_os("SKIP_CRS_CONFORMANCE").is_some() {
        return None;
    }
    let dir = std::env::var("CRS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("test-rules/crs"));
    assert!(
        dir.join("crs-setup.conf").is_file(),
        "OWASP CRS checkout not found at {}.\n\
         Fetch it with:\n  \
           mkdir -p test-rules\n  \
           git clone --depth 1 https://github.com/coreruleset/coreruleset.git test-rules/crs\n  \
           cp test-rules/crs/crs-setup.conf.example test-rules/crs/crs-setup.conf\n\
         CRS_DIR overrides the location; SKIP_CRS_CONFORMANCE=1 skips these \
         tests locally. CI must not set it.",
        dir.display()
    );
    Some(dir)
}

/// The configuration the corpus documents for itself: detection-only, paranoia
/// 4, and the size limits its tests assume. Detection-only matters beyond
/// blocking — in blocking mode the first disruptive rule ends the phase, so
/// later rules a test expects would never be recorded.
const FTW_SETUP: &str = r#"SecAction "id:900005,phase:1,nolog,pass,\
    ctl:ruleEngine=DetectionOnly,\
    ctl:ruleRemoveById=910000,\
    setvar:tx.blocking_paranoia_level=4,\
    setvar:tx.crs_validate_utf8_encoding=1,\
    setvar:tx.arg_name_length=100,\
    setvar:tx.arg_length=400,\
    setvar:tx.total_arg_length=64000,\
    setvar:tx.max_num_args=255,\
    setvar:tx.max_file_size=64100,\
    setvar:tx.combined_file_sizes=65535""#;

fn load(dir: &Path, extra: &str) -> ModSecurity {
    let dir = std::fs::canonicalize(dir).expect("CRS dir");
    let d = dir.display();
    // Include directives rather than spliced file contents: CRS `.data` paths
    // are relative to the rule file naming them.
    let cfg = format!(
        "SecRuleEngine On\nSecRequestBodyAccess On\n\
         Include \"{d}/crs-setup.conf\"\n{extra}\nInclude \"{d}/rules/*.conf\"\n"
    );
    ModSecurity::from_string(&cfg).expect("CRS should load")
}

/// Drive one corpus stage and return the rule IDs that matched.
fn run_stage(m: &ModSecurity, input: &Input) -> Vec<String> {
    let mut tx = m.new_transaction();
    let uri = input.uri.clone().unwrap_or_else(|| "/".into());
    let method = input.method.clone().unwrap_or_else(|| "GET".into());
    let version = input.version.clone().unwrap_or_else(|| "HTTP/1.1".into());
    if tx.process_uri(&uri, &method, &version).is_err() {
        return vec![];
    }

    let has = |n: &str| input.headers.keys().any(|k| k.eq_ignore_ascii_case(n));
    for (k, v) in &input.headers {
        let _ = tx.add_request_header(k, &scalar(v));
    }
    let body = input.data.as_ref().map(scalar).unwrap_or_default();
    // go-ftw fills these in unless a test opts out.
    if input.autocomplete_headers.unwrap_or(true) {
        if !has("Host") {
            let host = input.dest_addr.clone().unwrap_or_else(|| "localhost".into());
            let _ = tx.add_request_header("Host", &host);
        }
        if !has("User-Agent") {
            let _ = tx.add_request_header("User-Agent", "go-ftw");
        }
        if !has("Accept") {
            let _ = tx.add_request_header("Accept", "*/*");
        }
        if !body.is_empty() && !has("Content-Length") {
            let _ = tx.add_request_header("Content-Length", &body.len().to_string());
        }
    }
    if tx.process_request_headers().is_err() {
        return tx.matched_rules().to_vec();
    }
    if !body.is_empty() {
        let _ = tx.append_request_body(body.as_bytes());
    }
    let _ = tx.process_request_body();
    tx.matched_rules().to_vec()
}

// --- the gate --------------------------------------------------------------

#[test]
fn crs_regression_corpus() {
    let Some(dir) = crs_dir() else { return };
    let m = load(&dir, FTW_SETUP);

    let (mut pass, mut fail, mut skipped) = (0u32, 0u32, 0u32);
    let mut by_file: BTreeMap<String, u32> = BTreeMap::new();
    let mut missing: BTreeMap<String, u32> = BTreeMap::new();
    let mut spurious: BTreeMap<String, u32> = BTreeMap::new();

    let root = dir.join("tests/regression/tests");
    assert!(root.is_dir(), "corpus not found at {}", root.display());

    for entry in walkdir::WalkDir::new(&root).into_iter().flatten() {
        if entry.path().extension().map(|e| e != "yaml").unwrap_or(true) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(entry.path()) else { continue };
        let Ok(parsed) = serde_yaml::from_str::<TestFile>(&text) else { continue };
        let fname = entry.path().file_name().unwrap().to_string_lossy().to_string();

        for t in &parsed.tests {
            for stage in &t.stages {
                let Some(log) = &stage.output.log else {
                    skipped += 1;
                    continue;
                };
                if stage.input.encoded_request.is_some()
                    || (log.expect_ids.is_empty() && log.no_expect_ids.is_empty())
                {
                    skipped += 1;
                    continue;
                }

                let got = run_stage(&m, &stage.input);
                let mut ok = true;
                for id in log.expect_ids.iter().map(scalar) {
                    if !got.contains(&id) {
                        ok = false;
                        *missing.entry(id).or_default() += 1;
                    }
                }
                for id in log.no_expect_ids.iter().map(scalar) {
                    if got.contains(&id) {
                        ok = false;
                        *spurious.entry(id).or_default() += 1;
                    }
                }
                if ok {
                    pass += 1;
                } else {
                    fail += 1;
                    *by_file.entry(fname.clone()).or_default() += 1;
                }
            }
        }
    }

    let total = pass + fail;
    println!("\nCRS regression corpus: {pass}/{total} passing ({:.1}%), {skipped} skipped",
             100.0 * f64::from(pass) / f64::from(total));

    let mut worst: Vec<_> = by_file.into_iter().collect();
    worst.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    if !worst.is_empty() {
        println!("\nfailing files:");
        for (f, n) in worst.iter().take(15) {
            println!("  {n:>4}  {f}");
        }
    }
    let top = |label: &str, m: BTreeMap<String, u32>| {
        let mut v: Vec<_> = m.into_iter().collect();
        v.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        if !v.is_empty() {
            println!("\n{label}:");
            for (id, n) in v.iter().take(15) {
                println!("  {n:>4}  {id}");
            }
        }
    };
    top("rules that should have fired", missing);
    top("rules that fired but must not", spurious);

    assert!(
        skipped <= EXPECTED_SKIPS_MAX,
        "{skipped} corpus stages were skipped, more than the {EXPECTED_SKIPS_MAX} expected. \
         Silently skipping cases reads as coverage that is not there — find out what changed."
    );
    assert!(
        pass >= MIN_PASSING,
        "CRS conformance regressed: {pass} passing, expected at least {MIN_PASSING}. \
         The lists above name the rules. If this is a deliberate trade, say which \
         rules regressed and why, then lower MIN_PASSING in the same commit."
    );
    if pass > MIN_PASSING {
        println!(
            "\nMIN_PASSING is {MIN_PASSING} but {pass} pass — raise it to {pass} \
             so the gain cannot be lost silently."
        );
    }
}

// --- the half the corpus cannot see ----------------------------------------

#[test]
#[ignore = "fails against this engine until zentinelproxy/zentinel-modsec#30 lands: \
CRS 920100 denies every request because REQUEST_LINE is unimplemented and its negated \
regex inverts. Remove this attribute with that fix."]
fn stock_crs_blocks_attacks_and_passes_ordinary_traffic() {
    // Real blocking mode, default paranoia — the configuration an operator
    // actually deploys, and the one the corpus above is blind to.
    let Some(dir) = crs_dir() else { return };
    let m = load(&dir, "");

    let ue = "application/x-www-form-urlencoded";
    let xml = "application/xml";
    // name, should_block, method, uri, content-type, body
    type Case = (&'static str, bool, &'static str, &'static str, &'static str, &'static [u8]);
    let cases: &[Case] = &[
        ("GET /", false, "GET", "/", "", b""),
        ("static page", false, "GET", "/index.html", "", b""),
        ("health check", false, "GET", "/api/v1/health", "", b""),
        ("pdf download", false, "GET", "/docs/report.pdf", "", b""),
        ("ordinary query", false, "GET", "/search?q=blue+widgets&page=2", "", b""),
        ("form post", false, "POST", "/api/orders", ue, b"item=widget&qty=3"),
        ("xml post", false, "POST", "/api/orders", xml, br#"<order><item id="7">widget</item></order>"#),
        ("SQLi in query", true, "GET", "/u?id=1'+UNION+SELECT+password+FROM+users--+", "", b""),
        ("SQLi in form", true, "POST", "/u", ue, b"q=1' UNION SELECT password FROM users-- "),
        ("SQLi in XML", true, "POST", "/u", xml, br#"<o><q>1' UNION SELECT password FROM users-- </q></o>"#),
        ("XSS in query", true, "GET", "/s?q=%3Cscript%3Ealert(1)%3C/script%3E", "", b""),
        ("LFI in query", true, "GET", "/f?p=../../../../etc/passwd", "", b""),
    ];

    let mut wrong = Vec::new();
    for (name, should_block, method, uri, ct, body) in cases {
        let mut tx = m.new_transaction();
        tx.process_uri(uri, method, "HTTP/1.1").unwrap();
        tx.add_request_header("Host", "example.com").unwrap();
        tx.add_request_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0")
            .unwrap();
        tx.add_request_header("Accept", "text/html,application/xhtml+xml").unwrap();
        tx.add_request_header("Accept-Language", "en-US,en;q=0.9").unwrap();
        tx.add_request_header("Accept-Encoding", "gzip, deflate").unwrap();
        tx.add_request_header("Connection", "keep-alive").unwrap();
        if !ct.is_empty() {
            tx.add_request_header("Content-Type", ct).unwrap();
            tx.add_request_header("Content-Length", &body.len().to_string()).unwrap();
        }
        tx.process_request_headers().unwrap();
        if !body.is_empty() {
            tx.append_request_body(body).unwrap();
        }
        tx.process_request_body().unwrap();

        let blocked = tx.has_intervention();
        let ids = tx.intervention().map(|i| i.rule_ids.clone()).unwrap_or_default();
        println!("{name:<18} blocked={blocked:<6} {ids:?}");
        if blocked != *should_block {
            wrong.push(format!(
                "{name}: expected {}, got {blocked} {ids:?}",
                if *should_block { "a block" } else { "no block" }
            ));
        }
    }
    assert!(wrong.is_empty(), "stock CRS behaved wrongly:\n  {}", wrong.join("\n  "));
}
