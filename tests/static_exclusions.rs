use zentinel_modsec::ModSecurity;

#[test]
fn static_exclusions_match_prior_chain_starters_and_actions() {
    let engine = ModSecurity::from_string(
        r#"SecRuleEngine On
SecRuleRemoveById 14
SecRuleRemoveByTag local
SecRule REQUEST_METHOD "@streq GET" "id:10,phase:1,deny,chain,tag:local"
SecRule REQUEST_URI "@streq /"
SecAction "id:11,phase:1,deny,msg:'local  policy'"
SecRuleRemoveByTag local
SecRuleRemoveByMsg "local  policy"
SecAction "id:12,phase:1,pass,tag:Local"
SecAction "id:14,phase:1,pass,tag:local"
SecRule REQUEST_METHOD "@streq GET" "id:15,phase:1,deny,chain"
SecRule REQUEST_URI "@streq /" "tag:child"
SecRuleRemoveByTag child"#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["12", "14", "15"]);
    assert!(tx.has_intervention());
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
