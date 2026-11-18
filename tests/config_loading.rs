use std::fs;
use zentinel_modsec::ModSecurity;

#[test]
fn continued_loading_after_comments_and_indented_lines() {
    let first = r#"SecAction "id:701,phase:1,pass""#;
    let last = r#"SecAction "id:702,phase:1,pass""#;
    for middle in [
        "SecComponentSignature sample # component metadata\r\n",
        "SecFutureOption value # an ignored directive\n# another comment\n",
        "# a full-line comment\n",
        "\u{2003}",
        "\x0c",
        "\u{a0}",
    ] {
        let engine = ModSecurity::from_string(&format!("{first}\n{middle}{last}")).unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(tx.matched_rules(), ["701", "702"], "{middle:?}");
    }
}

#[test]
fn include_budget_counts_directives_across_sibling_files() {
    let dir = tempfile::tempdir().unwrap();
    let entry = dir.path().join("entry.conf");
    fs::write(dir.path().join("leaf.conf"), "# shared metadata\n").unwrap();
    let line = "Include leaf.conf\n";
    fs::write(&entry, line.repeat(100)).unwrap();
    ModSecurity::from_file(entry.to_str().unwrap()).unwrap();
    fs::write(&entry, line.repeat(101)).unwrap();
    let error = ModSecurity::from_file(entry.to_str().unwrap()).expect_err("include budget");
    assert!(error.to_string().contains("100"), "{error}");
    assert!(error.to_string().contains("entry.conf:101"), "{error}");
}

#[test]
fn include_budget_covers_nested_files_and_treats_a_glob_as_one_directive() {
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
    ModSecurity::from_file(root.to_str().unwrap()).unwrap();
    fs::write(leaf, "Include one-more.conf").unwrap();
    let error = ModSecurity::from_file(root.to_str().unwrap()).expect_err("nested include budget");
    assert!(error.to_string().contains("level-100.conf:1"), "{error}");
    assert!(error.to_string().contains("100 Include"), "{error}");

    let fragments = dir.path().join("fragments");
    fs::create_dir(&fragments).unwrap();
    for id in 1..=101 {
        fs::write(
            fragments.join(format!("rule-{id}.conf")),
            format!(r#"SecAction "id:{id},phase:1,pass""#),
        )
        .unwrap();
    }
    fs::write(&root, "Include fragments/*.conf").unwrap();
    let engine = ModSecurity::from_file(root.to_str().unwrap()).unwrap();
    assert_eq!(engine.rule_count(), 101);
}

#[cfg(unix)]
#[test]
fn matched_include_with_an_unavailable_target_reports_its_path() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("entry");
    fs::write(&root, "Include *.conf").unwrap();
    let link = dir.path().join("active.conf");
    std::os::unix::fs::symlink(dir.path().join("removed"), &link).unwrap();
    let error = ModSecurity::from_file(root.to_str().unwrap()).expect_err("missing include");
    assert!(
        error.to_string().contains(link.to_str().unwrap()),
        "{error}"
    );
    fs::remove_file(link).unwrap();
    assert_eq!(
        ModSecurity::from_file(root.to_str().unwrap())
            .unwrap()
            .rule_count(),
        0
    );
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
fn failed_glob_append_restores_prior_rules_defaults_and_include_budget() {
    use zentinel_modsec::{engine::CompiledRuleset, parser::Parser};
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("leaf"), "# shared settings").unwrap();
    fs::write(
        dir.path().join("a.conf"),
        format!(
            "{}SecDefaultAction \"phase:1,deny,status:410\"\nSecAction \"id:802,phase:1,pass\"",
            "Include leaf\n".repeat(100)
        ),
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
