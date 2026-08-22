//! Duplicate-preserving JSON parsing for the request body processor.
//!
//! `serde_json::Value` stores objects in a map, so `{"a":1,"a":2}` collapses
//! to a single entry and the *last* value wins. For a WAF that is an evasion:
//!
//! ```text
//! {"a":"<payload>","a":"safe"}
//! ```
//!
//! collapses to `a = safe`, so the rules never see the payload — while an
//! origin application whose parser keeps the first occurrence receives it.
//! Whether a given application keeps the first or the last is not knowable
//! from here, so the only safe reading is to inspect *every* value that was
//! sent and let the rules decide.
//!
//! [`JsonNode`] therefore stores objects as an ordered list of pairs, keeping
//! duplicates and document order.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

/// A parsed JSON document that preserves duplicate object keys.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonNode {
    /// `null`
    Null,
    /// `true` / `false`
    Bool(bool),
    /// A number, kept in its textual form so no precision is lost on the way
    /// to the string comparison a rule will do.
    Number(String),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<JsonNode>),
    /// An object, as an ordered list of key/value pairs including duplicates.
    Object(Vec<(String, JsonNode)>),
}

struct JsonNodeVisitor;

impl<'de> Visitor<'de> for JsonNodeVisitor {
    type Value = JsonNode;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any valid JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<JsonNode, E> {
        Ok(JsonNode::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<JsonNode, E> {
        Ok(JsonNode::Null)
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<JsonNode, E> {
        Ok(JsonNode::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<JsonNode, E> {
        Ok(JsonNode::Number(v.to_string()))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<JsonNode, E> {
        Ok(JsonNode::Number(v.to_string()))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<JsonNode, E> {
        Ok(JsonNode::Number(v.to_string()))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<JsonNode, E> {
        Ok(JsonNode::String(v.to_string()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<JsonNode, E> {
        Ok(JsonNode::String(v))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<JsonNode, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(JsonNode::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<JsonNode, A::Error> {
        // MapAccess is a stream, so duplicate keys arrive as separate entries
        // and are all kept. This is the whole reason for this type.
        let mut entries = Vec::new();
        while let Some((key, value)) = map.next_entry::<String, JsonNode>()? {
            entries.push((key, value));
        }
        Ok(JsonNode::Object(entries))
    }
}

impl<'de> Deserialize<'de> for JsonNode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonNodeVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> JsonNode {
        serde_json::from_str(s).expect("valid JSON")
    }

    #[test]
    fn duplicate_keys_are_all_preserved() {
        let node = parse(r#"{"a":"first","a":"second"}"#);
        let JsonNode::Object(entries) = node else {
            panic!("expected object");
        };
        assert_eq!(
            entries,
            vec![
                ("a".to_string(), JsonNode::String("first".to_string())),
                ("a".to_string(), JsonNode::String("second".to_string())),
            ],
            "both values must survive; keeping only one is a parser-differential evasion"
        );
    }

    #[test]
    fn object_order_is_preserved() {
        let JsonNode::Object(entries) = parse(r#"{"z":1,"a":2}"#) else {
            panic!("expected object");
        };
        let keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["z", "a"]);
    }

    #[test]
    fn scalars_round_trip() {
        assert_eq!(parse("null"), JsonNode::Null);
        assert_eq!(parse("true"), JsonNode::Bool(true));
        assert_eq!(parse(r#""s""#), JsonNode::String("s".to_string()));
        assert_eq!(parse("42"), JsonNode::Number("42".to_string()));
    }

    #[test]
    fn large_integers_keep_their_exact_value() {
        // Going through f64 would round this; the textual form must survive
        // so a rule comparing it sees what was sent.
        assert_eq!(
            parse("9007199254740993"),
            JsonNode::Number("9007199254740993".to_string())
        );
    }

    #[test]
    fn nested_structures_parse() {
        assert_eq!(
            parse(r#"{"a":[1,{"b":null}]}"#),
            JsonNode::Object(vec![(
                "a".to_string(),
                JsonNode::Array(vec![
                    JsonNode::Number("1".to_string()),
                    JsonNode::Object(vec![("b".to_string(), JsonNode::Null)]),
                ])
            )])
        );
    }
}
