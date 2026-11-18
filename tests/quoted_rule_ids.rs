use zentinel_modsec::parser::{parse_actions, Action, MetadataAction};
use zentinel_modsec::ModSecurity;

#[test]
fn quoted_numeric_ids_load_and_execute_without_rewriting_config() {
    let engine = ModSecurity::from_string(
        r#"SecAction "id:'200000',phase:1,pass"
SecRule REQUEST_METHOD "@streq GET" "id:'200001',phase:1,pass""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["200000", "200001"]);
    let actions = parse_actions(r#"id:"200002",phase:1,pass"#).unwrap();
    assert!(matches!(
        actions[0],
        Action::Metadata(MetadataAction::Id(200002))
    ));
}

#[test]
fn malformed_or_overflowing_quoted_ids_remain_load_errors() {
    for action in [
        "id:''",
        "id:'200000",
        "id:200000'",
        "id:'not-a-number'",
        "id:'-1'",
        "id:'18446744073709551616'",
        "id:''200000''",
    ] {
        assert!(parse_actions(action).is_err(), "accepted {action}");
    }
}
