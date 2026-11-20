use zentinel_modsec::ModSecurity;

/// IDs of the rules that fire for `GET /` in phase 1.
fn matched(rules: &str) -> Vec<String> {
    let engine = ModSecurity::from_string(rules).unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.matched_rules().to_vec()
}

#[test]
fn static_exclusions_match_chain_starters_and_actions() {
    let rules = r#"SecRuleEngine On
SecRuleRemoveById 14
SecRule REQUEST_METHOD "@streq GET" "id:10,phase:1,deny,chain,tag:local"
SecRule REQUEST_URI "@streq /"
SecAction "id:11,phase:1,deny,msg:'local  policy'"
SecRuleRemoveByTag local
SecRuleRemoveByMsg "local  policy"
SecAction "id:12,phase:1,pass,tag:Local"
SecAction "id:13,phase:1,pass,msg:'local policy'"
SecAction "id:14,phase:1,pass"
SecRule REQUEST_METHOD "@streq GET" "id:15,phase:1,pass,chain"
SecRule REQUEST_URI "@streq /" "tag:child"
SecRuleRemoveByTag child"#;
    assert_eq!(matched(rules), ["12", "13", "15"]);
}

/// ModSecurity v3 consults exclusions when a rule is evaluated, so a setup
/// file may declare them before the `Include` that brings in the rules.
#[test]
fn exclusions_apply_to_rules_declared_after_them() {
    let rules = r#"SecRuleEngine On
SecRuleRemoveById 920350 20-29
SecRuleRemoveByTag attack-sqli
SecRuleRemoveByMsg "Host header is a numeric IP address"
SecAction "id:920350,phase:1,deny"
SecRule REQUEST_METHOD "@streq GET" "id:25,phase:1,deny,chain"
SecRule REQUEST_URI "@streq /"
SecAction "id:30,phase:1,deny,tag:attack-sqli"
SecAction "id:31,phase:1,deny,msg:'Host header is a numeric IP address'"
SecAction "id:32,phase:1,pass""#;
    assert_eq!(matched(rules), ["32"]);
}

#[test]
fn single_quoted_exclusion_value_is_unquoted() {
    let rules = r#"SecRuleEngine On
SecRuleRemoveByTag 'attack-sqli'
SecRuleRemoveByMsg 'local policy'
SecAction "id:1,phase:1,deny,tag:attack-sqli"
SecAction "id:2,phase:1,deny,msg:'local policy'"
SecAction "id:3,phase:1,pass""#;
    assert_eq!(matched(rules), ["3"]);
}

#[test]
fn blank_line_ends_a_continued_exclusion_value() {
    for ending in ["\n", "\r\n"] {
        let rules = [
            "SecRuleEngine On",
            "SecRuleRemoveByTag local \\",
            "",
            r#"SecAction "id:1,phase:1,pass,tag:other""#,
            r#"SecAction "id:2,phase:1,pass,tag:local""#,
        ]
        .join(ending);
        assert_eq!(matched(&rules), ["1"]);
    }
}

#[test]
fn missing_exclusion_argument_is_a_load_error() {
    assert!(ModSecurity::from_string("SecRuleRemoveByMsg\nSecAction \"id:1,pass\"").is_err());
}

#[test]
fn continued_literal_retains_spaces_and_inline_hashes() {
    let lines = [
        r#"SecAction "id:1,phase:1,deny,msg:'two  words #now'""#,
        "SecRuleRemoveByMsg two  \\",
        "  # comment",
        "  words #now",
    ];
    for ending in ["\n", "\r\n"] {
        assert_eq!(
            ModSecurity::from_string(&lines.join(ending))
                .unwrap()
                .rule_count(),
            0
        );
    }
}
