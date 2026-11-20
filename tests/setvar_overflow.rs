//! `setvar` arithmetic that leaves the signed 64-bit range wraps around
//! instead of overflowing.
//!
//! libmodsecurity adds and subtracts plain `int`s (`actions/set_var.cc`), where
//! overflow is undefined and in practice wraps. The engine keeps 64-bit
//! values, and used `+` and unary `-` on them: a build with overflow checks
//! panicked in the middle of a request.

use zentinel_modsec::engine::{SetVarChange, Transaction};
use zentinel_modsec::variables::{Collection, HashMapCollection, MutableCollection, TxCollection};
use zentinel_modsec::ModSecurity;

/// Run `rules` against `GET <uri>`, recording what each `setvar` did.
fn run(rules: &str, uri: &str) -> Transaction {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.set_record_setvar_effects(true);
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx
}

fn tx_var(tx: &Transaction, name: &str) -> String {
    tx.tx()
        .get(name)
        .and_then(|v| v.first().map(|s| s.to_string()))
        .unwrap_or_else(|| "-".to_string())
}

#[test]
fn adding_past_the_maximum_wraps() {
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,setvar:tx.n=+9223372036854775807\"\n\
         SecAction \"id:2,phase:1,pass,nolog,setvar:tx.n=+9223372036854775807\"";
    let tx = run(rules, "/");
    assert_eq!(tx.matched_rules(), ["1", "2"]);
    assert_eq!(tx_var(&tx, "n"), "-2");
}

#[test]
fn subtracting_past_the_minimum_wraps() {
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,setvar:tx.n=-9223372036854775807\"\n\
         SecAction \"id:2,phase:1,pass,nolog,setvar:tx.n=-2\"";
    assert_eq!(tx_var(&run(rules, "/"), "n"), "9223372036854775807");
}

#[test]
fn subtracting_the_minimum_wraps_and_is_recorded_as_written() {
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,setvar:tx.n=--9223372036854775808\"";
    let tx = run(rules, "/");
    assert_eq!(tx_var(&tx, "n"), "-9223372036854775808");
    assert_eq!(tx.setvar_effects()[0].op, SetVarChange::Decrement(i64::MIN));
}

#[test]
fn an_operand_from_the_request_wraps_too() {
    // The operand is expanded from a capture, so the client chooses it.
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,setvar:tx.up=9223372036854775807,setvar:tx.down=-2\"\n\
         SecRule ARGS:n \"@rx ^(.*)$\" \"id:2,phase:1,pass,nolog,capture,\
         setvar:tx.up=+%{tx.1},setvar:tx.down=-%{tx.1},setvar:tx.negated=-%{tx.1}\"";

    let tx = run(rules, "/?n=9223372036854775807");
    assert_eq!(tx.matched_rules(), ["1", "2"]);
    assert_eq!(tx_var(&tx, "up"), "-2");
    assert_eq!(tx_var(&tx, "down"), "9223372036854775807");

    let tx = run(rules, "/?n=-9223372036854775808");
    assert_eq!(tx.matched_rules(), ["1", "2"]);
    assert_eq!(tx_var(&tx, "up"), "-1");
    assert_eq!(tx_var(&tx, "negated"), "-9223372036854775808");
    assert_eq!(
        tx.setvar_effects().last().unwrap().op,
        SetVarChange::Decrement(i64::MIN)
    );
}

fn wraps_at_both_ends<C: MutableCollection>(mut collection: C) {
    collection.set("n".into(), i64::MAX.to_string());
    collection.increment("n", 1);
    assert_eq!(collection.get("n"), Some(vec!["-9223372036854775808"]));
    collection.decrement("n", 1);
    assert_eq!(collection.get("n"), Some(vec!["9223372036854775807"]));
    collection.set("n".into(), "0".into());
    collection.decrement("n", i64::MIN);
    assert_eq!(collection.get("n"), Some(vec!["-9223372036854775808"]));
}

#[test]
fn collections_wrap_at_both_ends() {
    wraps_at_both_ends(HashMapCollection::new());
    wraps_at_both_ends(TxCollection::new());
}
