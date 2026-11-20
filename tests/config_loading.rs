use std::fs;
use std::io;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;
use zentinel_modsec::ModSecurity;

/// Collects formatted log output so a test can assert on load-time warnings.
#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl io::Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for LogBuffer {
    type Writer = Self;

    fn make_writer(&self) -> Self {
        self.clone()
    }
}

#[test]
fn continued_loading_after_comments_and_indented_lines() {
    let first = r#"SecAction "id:701,phase:1,pass""#;
    let last = r#"SecAction "id:702,phase:1,pass""#;
    for middle in [
        "SecComponentSignature sample # component metadata\r\n",
        "SecFutureOption value # an ignored directive\n# another comment\n",
        "# a full-line comment\n",
    ] {
        let engine = ModSecurity::from_string(&format!("{first}\n{middle}{last}")).unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(tx.matched_rules(), ["701", "702"], "{middle:?}");
    }
}

#[test]
fn sibling_includes_are_not_limited() {
    let dir = tempfile::tempdir().unwrap();
    let entry = dir.path().join("entry.conf");
    for vhost in 0..150 {
        fs::write(
            dir.path().join(format!("vhost-{vhost}.conf")),
            format!(r#"SecAction "id:{},phase:1,pass""#, 1000 + vhost),
        )
        .unwrap();
    }
    let includes: String = (0..150)
        .map(|vhost| format!("Include vhost-{vhost}.conf\n"))
        .collect();
    fs::write(&entry, includes).unwrap();
    let engine = ModSecurity::from_file(entry.to_str().unwrap()).unwrap();
    assert_eq!(engine.rule_count(), 150);
}

#[test]
fn include_nesting_is_limited_to_100_levels() {
    use zentinel_modsec::parser::Parser;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("level-0.conf");
    for level in 0..100 {
        fs::write(
            dir.path().join(format!("level-{level}.conf")),
            format!("Include level-{}.conf", level + 1),
        )
        .unwrap();
    }
    let leaf = dir.path().join("level-100.conf");
    fs::write(&leaf, "# end").unwrap();
    fs::write(dir.path().join("level-101.conf"), "# too deep").unwrap();
    let mut parser = Parser::new();
    parser.parse_file(&root).unwrap();

    fs::write(&leaf, "Include level-101.conf").unwrap();
    let error = parser.parse_file(&root).expect_err("nesting limit");
    assert!(error.to_string().contains("level-100.conf:1"), "{error}");
    assert!(error.to_string().contains("100 levels"), "{error}");

    // The failed load leaves no nesting behind.
    fs::write(&leaf, "# end").unwrap();
    parser.parse_file(&root).unwrap();
}

#[test]
fn include_cycles_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    let entry = dir.path().join("entry.conf");
    fs::write(&entry, "Include entry.conf").unwrap();
    let error = ModSecurity::from_file(entry.to_str().unwrap()).expect_err("self include");
    assert!(error.to_string().contains("cycle"), "{error}");
    assert!(error.to_string().contains("entry.conf:1"), "{error}");

    // Two files that both include every sibling fan out at each level, so the
    // cycle has to be caught before the nesting limit is reached.
    fs::write(&entry, "Include *.conf").unwrap();
    fs::write(dir.path().join("other.conf"), "Include *.conf").unwrap();
    let error = ModSecurity::from_file(entry.to_str().unwrap()).expect_err("glob cycle");
    assert!(error.to_string().contains("cycle"), "{error}");
}

#[test]
fn relative_includes_try_the_working_directory_before_the_declaring_directory() {
    // Tests share the process working directory, so place the fixtures below
    // it instead of changing it.
    let cwd = std::env::current_dir().unwrap();
    let below_cwd = tempfile::tempdir_in(&cwd).unwrap();
    let given = below_cwd.path().strip_prefix(&cwd).unwrap();
    let conf = below_cwd.path().join("conf");
    let beside = conf.join(given);
    fs::create_dir_all(&beside).unwrap();
    let rule = |id: u32| format!(r#"SecAction "id:{id},phase:1,pass""#);
    fs::write(below_cwd.path().join("cwd-only.conf"), rule(901)).unwrap();
    fs::write(below_cwd.path().join("both.conf"), rule(902)).unwrap();
    fs::write(beside.join("both.conf"), rule(903)).unwrap();
    fs::write(beside.join("beside-only.conf"), rule(904)).unwrap();
    fs::write(below_cwd.path().join("cwd-glob-1.conf"), rule(905)).unwrap();
    fs::write(beside.join("cwd-glob-2.conf"), rule(906)).unwrap();
    fs::write(beside.join("beside-glob-1.conf"), rule(907)).unwrap();

    let entry = conf.join("entry.conf");
    let includes: String = [
        "cwd-only.conf",
        "both.conf",
        "beside-only.conf",
        "cwd-glob-*.conf",
        "beside-glob-*.conf",
    ]
    .iter()
    .map(|name| format!("Include {}\n", given.join(name).display()))
    .collect();
    fs::write(&entry, includes).unwrap();

    let engine = ModSecurity::from_file(entry.to_str().unwrap()).unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["901", "902", "904", "905", "907"]);
}

#[test]
fn missing_literal_include_fails_the_load() {
    let dir = tempfile::tempdir().unwrap();
    let entry = dir.path().join("entry.conf");
    fs::write(&entry, "Include removed.conf").unwrap();
    let error = ModSecurity::from_file(entry.to_str().unwrap()).expect_err("missing include");
    assert!(error.to_string().contains("removed.conf"), "{error}");
}

#[cfg(unix)]
#[test]
fn glob_match_with_an_unavailable_target_is_skipped_with_a_warning() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("entry");
    fs::write(&root, "Include *.conf").unwrap();
    fs::write(
        dir.path().join("present.conf"),
        r#"SecAction "id:811,phase:1,pass""#,
    )
    .unwrap();
    let link = dir.path().join("active.conf");
    std::os::unix::fs::symlink(dir.path().join("removed"), &link).unwrap();

    let log = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(log.clone())
        .with_ansi(false)
        .finish();
    let engine = tracing::subscriber::with_default(subscriber, || {
        ModSecurity::from_file(root.to_str().unwrap())
    })
    .unwrap();

    assert_eq!(engine.rule_count(), 1);
    let log = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert!(log.contains("WARN"), "{log}");
    assert!(log.contains(link.to_str().unwrap()), "{log}");
}

#[test]
fn relative_globs_treat_the_declaring_directory_as_literal() {
    let dir = tempfile::tempdir().unwrap();
    let literal = dir.path().join("tenant-[12]");
    let sibling = dir.path().join("tenant-1");
    for (parent, id) in [(&literal, 17), (&sibling, 18)] {
        fs::create_dir(parent).unwrap();
        fs::write(
            parent.join("active.conf"),
            format!(r#"SecAction "id:{id},phase:1,pass""#),
        )
        .unwrap();
    }
    let root = literal.join("entry");
    fs::write(&root, "Include *.conf").unwrap();
    let engine = ModSecurity::from_file(root.to_str().unwrap()).unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["17"]);
}

#[test]
fn failed_glob_append_restores_prior_rules_and_defaults() {
    use zentinel_modsec::{engine::CompiledRuleset, parser::Parser};
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("leaf"), "# shared settings").unwrap();
    fs::write(
        dir.path().join("a.conf"),
        "Include leaf\nSecDefaultAction \"phase:1,deny,status:410\"\nSecAction \"id:802,phase:1,pass\"",
    )
    .unwrap();
    fs::write(dir.path().join("b.conf"), "Include missing").unwrap();
    let mut parser = Parser::new();
    parser
        .parse("SecDefaultAction \"phase:1,pass\"\nSecAction \"id:801,phase:1,pass\"")
        .unwrap();
    let previous = parser.directives().len();
    assert!(parser
        .parse_glob(dir.path().join("*.conf").to_str().unwrap())
        .is_err());
    assert_eq!(parser.directives().len(), previous);
    parser
        .parse_with_location(
            "Include leaf\nSecRule REQUEST_METHOD \"@streq GET\" \"id:803,phase:1,block\"",
            Some(&dir.path().join("fixed.conf")),
        )
        .unwrap();
    let engine = ModSecurity::new(CompiledRuleset::compile(parser.into_directives()).unwrap());
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["801", "803"]);
    assert!(tx.intervention().is_none());
}
