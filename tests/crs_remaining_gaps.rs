//! `UNIQUE_ID`, `FILES_SIZES`, `FILES_COMBINED_SIZE` and
//! `ctl:forceRequestBodyVariable`: the last gaps reported when loading the CRS
//! request rules.
//!
//! - `UNIQUE_ID` resolved to nothing, so CRS rule 901410 never set
//!   `TX:sampling_rnd100` and the sampling mode could not be used.
//! - `FILES_COMBINED_SIZE` resolved to nothing, so the upload limit of CRS
//!   rule 920410 was never enforced once `tx.combined_file_sizes` was set.
//! - `ctl:forceRequestBodyVariable` was reported as unrecognised although
//!   `REQUEST_BODY` is always populated here.

use std::collections::HashSet;

use zentinel_modsec::ModSecurity;

fn engine(rules: &str) -> ModSecurity {
    ModSecurity::from_string(rules).expect("rules should load")
}

fn blocked_get(msc: &ModSecurity, unique_id: Option<&str>) -> bool {
    let mut tx = msc.new_transaction();
    if let Some(id) = unique_id {
        tx.set_unique_id(id);
    }
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

fn blocked_post(rules: &str, content_type: &str, body: &[u8]) -> bool {
    let msc = engine(rules);
    let mut tx = msc.new_transaction();
    tx.process_uri("/upload", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.add_request_header("Content-Type", content_type).unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(body).unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

// ---------------------------------------------------------------------------
// UNIQUE_ID
// ---------------------------------------------------------------------------

#[test]
fn every_transaction_gets_a_distinct_unique_id() {
    let msc = engine("SecRuleEngine On");
    let ids: HashSet<String> = (0..1000)
        .map(|_| msc.new_transaction().unique_id().to_string())
        .collect();
    assert_eq!(ids.len(), 1000);
    assert!(ids.iter().all(|id| !id.is_empty()));
}

#[test]
fn unique_id_is_visible_to_rules() {
    let msc = engine(
        "SecRuleEngine On\n\
         SecRule UNIQUE_ID \"@rx .\" \"id:1,phase:1,deny\"",
    );
    assert!(blocked_get(&msc, None));
}

#[test]
fn the_application_can_supply_its_own_unique_id() {
    let msc = engine(
        "SecRuleEngine On\n\
         SecRule UNIQUE_ID \"@streq req-42\" \"id:1,phase:1,deny\"",
    );
    assert!(blocked_get(&msc, Some("req-42")));
    assert!(!blocked_get(&msc, Some("req-43")));
    // An empty ID is ignored rather than leaving UNIQUE_ID empty.
    let mut tx = msc.new_transaction();
    tx.set_unique_id("");
    assert!(!tx.unique_id().is_empty());
}

/// CRS sampling mode: 901410 derives a number in 0..100 from `UNIQUE_ID`, and
/// 901450 removes every CRS rule when it falls outside
/// `tx.sampling_percentage`.
fn sampling_rules(percentage: u32) -> String {
    format!(
        r#"
SecRuleEngine On
SecAction "id:900400,phase:1,pass,nolog,setvar:tx.sampling_percentage={percentage}"
SecRule UNIQUE_ID "@rx ^[a-f]*([0-9])[a-f]*([0-9])" "id:901410,phase:1,pass,capture,t:sha1,t:hexEncode,nolog,setvar:'TX.sampling_rnd100=%{{TX.1}}%{{TX.2}}'"
SecRule TX:sampling_rnd100 "!@lt %{{tx.sampling_percentage}}" "id:901450,phase:1,pass,nolog,tag:'OWASP_CRS',ctl:ruleRemoveByTag=OWASP_CRS"
SecRule REQUEST_URI "@contains /" "id:2,phase:1,deny,tag:'OWASP_CRS'"
"#
    )
}

#[test]
fn sampling_mode_skips_part_of_the_traffic() {
    let msc = engine(&sampling_rules(50));
    let inspected = (0..400).filter(|_| blocked_get(&msc, None)).count();
    // Roughly half; the bounds are loose enough never to fail by chance.
    assert!(
        (100..=300).contains(&inspected),
        "{inspected} of 400 requests inspected at 50% sampling"
    );
}

#[test]
fn sampling_at_100_percent_inspects_everything() {
    let msc = engine(&sampling_rules(100));
    assert!((0..200).all(|_| blocked_get(&msc, None)));
}

// ---------------------------------------------------------------------------
// FILES_SIZES / FILES_COMBINED_SIZE
// ---------------------------------------------------------------------------

const MULTIPART: &str = "multipart/form-data; boundary=X";

/// Two files of 8 and 5 bytes, and a form field that is not a file.
const TWO_FILES: &[u8] = b"--X\r\n\
Content-Disposition: form-data; name=\"a\"; filename=\"a.txt\"\r\n\
\r\n\
12345678\r\n\
--X\r\n\
Content-Disposition: form-data; name=\"b\"; filename=\"b.txt\"\r\n\
\r\n\
12345\r\n\
--X\r\n\
Content-Disposition: form-data; name=\"field\"\r\n\
\r\n\
not a file, not counted\r\n\
--X--\r\n";

/// CRS 920410, with the limit an operator sets in `crs-setup.conf`.
fn upload_limit_rules(limit: u64) -> String {
    format!(
        r#"
SecRuleEngine On
SecAction "id:900350,phase:1,pass,nolog,setvar:tx.combined_file_sizes={limit}"
SecRule &TX:COMBINED_FILE_SIZES "@eq 1" "id:920410,phase:2,deny,chain"
    SecRule FILES_COMBINED_SIZE "@gt %{{tx.combined_file_sizes}}" ""
"#
    )
}

#[test]
fn combined_upload_size_limit_is_enforced() {
    assert!(blocked_post(&upload_limit_rules(12), MULTIPART, TWO_FILES));
    assert!(!blocked_post(&upload_limit_rules(13), MULTIPART, TWO_FILES));
}

#[test]
fn each_file_size_is_reported_by_part_name() {
    let rules = "SecRuleEngine On\n\
         SecRule FILES_SIZES:a \"@eq 8\" \"id:1,phase:2,deny,chain\"\n\
             SecRule FILES_SIZES:b \"@eq 5\" \"\"";
    assert!(blocked_post(rules, MULTIPART, TWO_FILES));
    // The form field has no size entry.
    let rules = "SecRuleEngine On\n\
         SecRule &FILES_SIZES:field \"@gt 0\" \"id:1,phase:2,deny\"";
    assert!(!blocked_post(rules, MULTIPART, TWO_FILES));
}

#[test]
fn a_binary_file_is_measured_in_bytes() {
    // Four bytes that are not valid UTF-8: a lossy conversion would turn them
    // into replacement characters and report a larger size.
    let mut body = b"--X\r\n\
Content-Disposition: form-data; name=\"bin\"; filename=\"x.bin\"\r\n\
\r\n"
        .to_vec();
    body.extend_from_slice(&[0xff, 0xfe, 0x00, 0x80]);
    body.extend_from_slice(b"\r\n--X--\r\n");

    let rules = "SecRuleEngine On\n\
         SecRule FILES_COMBINED_SIZE \"@eq 4\" \"id:1,phase:2,deny\"";
    assert!(blocked_post(rules, MULTIPART, &body));
}

#[test]
fn combined_size_is_zero_without_uploads() {
    let rules = "SecRuleEngine On\n\
         SecRule FILES_COMBINED_SIZE \"@eq 0\" \"id:1,phase:2,deny\"";
    assert!(blocked_post(
        rules,
        "application/x-www-form-urlencoded",
        b"a=1"
    ));
}

#[test]
fn form_fields_are_unchanged_by_byte_level_parsing() {
    let rules = "SecRuleEngine On\n\
         SecRule ARGS_POST:field \"@streq not a file, not counted\" \"id:1,phase:2,deny\"";
    assert!(blocked_post(rules, MULTIPART, TWO_FILES));
}

// ---------------------------------------------------------------------------
// ctl:forceRequestBodyVariable
// ---------------------------------------------------------------------------

#[test]
fn force_request_body_variable_is_accepted_and_request_body_is_populated() {
    // The shape of CRS 901340: a body no processor handles is still
    // inspected through REQUEST_BODY.
    let rules = r#"
SecRuleEngine On
SecRule REQBODY_PROCESSOR "!@rx (?:URLENCODED|MULTIPART|XML|JSON)" "id:901340,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On"
SecRule REQUEST_BODY "@contains attack" "id:2,phase:2,deny"
"#;
    assert!(blocked_post(rules, "text/plain", b"an attack payload"));
    assert!(!blocked_post(rules, "text/plain", b"harmless"));
}
