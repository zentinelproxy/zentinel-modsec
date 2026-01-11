//! Data actions (setvar, capture).

use super::{SetVarOp, SetVarOperation};
use crate::variables::{Collection, MutableCollection};

/// Apply a setvar operation to a collection.
pub fn apply_setvar<C: MutableCollection>(collection: &mut C, op: &SetVarOp) {
    match &op.operation {
        SetVarOperation::Set(value) => {
            collection.set(op.name.clone(), value.clone());
        }
        SetVarOperation::Increment(delta) => {
            collection.increment(&op.name, *delta);
        }
        SetVarOperation::Decrement(delta) => {
            collection.decrement(&op.name, *delta);
        }
        SetVarOperation::Delete => {
            collection.delete(&op.name);
        }
    }
}

/// Expand macro variables in a value.
///
/// Supported macros:
/// - %{TX.varname} - Transaction variable
/// - %{MATCHED_VAR} - The matched variable value
/// - %{MATCHED_VAR_NAME} - The matched variable name
pub fn expand_macros(
    value: &str,
    tx: &impl Collection,
    matched_var: Option<&str>,
    matched_var_name: Option<&str>,
) -> String {
    let mut result = value.to_string();

    // Expand %{TX.varname}
    let tx_re = regex::Regex::new(r"%\{TX\.([^}]+)\}").unwrap();
    result = tx_re
        .replace_all(&result, |caps: &regex::Captures| {
            let var_name = &caps[1];
            tx.get(var_name)
                .and_then(|v| v.first().map(|s| s.to_string()))
                .unwrap_or_default()
        })
        .into_owned();

    // Expand %{MATCHED_VAR}
    if let Some(mv) = matched_var {
        result = result.replace("%{MATCHED_VAR}", mv);
    }

    // Expand %{MATCHED_VAR_NAME}
    if let Some(mvn) = matched_var_name {
        result = result.replace("%{MATCHED_VAR_NAME}", mvn);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::variables::HashMapCollection;

    #[test]
    fn test_setvar_set() {
        let mut tx = HashMapCollection::new();
        let op = SetVarOp {
            collection: "TX".to_string(),
            name: "score".to_string(),
            operation: SetVarOperation::Set("5".to_string()),
        };
        apply_setvar(&mut tx, &op);
        let values = tx.get("score");
        assert_eq!(values.and_then(|v| v.first().map(|s| *s)), Some("5"));
    }

    #[test]
    fn test_setvar_increment() {
        let mut tx = HashMapCollection::new();
        tx.set("score".to_string(), "10".to_string());
        let op = SetVarOp {
            collection: "TX".to_string(),
            name: "score".to_string(),
            operation: SetVarOperation::Increment(5),
        };
        apply_setvar(&mut tx, &op);
        let values = tx.get("score");
        assert_eq!(values.and_then(|v| v.first().map(|s| *s)), Some("15"));
    }

    #[test]
    fn test_setvar_decrement() {
        let mut tx = HashMapCollection::new();
        tx.set("score".to_string(), "10".to_string());
        let op = SetVarOp {
            collection: "TX".to_string(),
            name: "score".to_string(),
            operation: SetVarOperation::Decrement(3),
        };
        apply_setvar(&mut tx, &op);
        let values = tx.get("score");
        assert_eq!(values.and_then(|v| v.first().map(|s| *s)), Some("7"));
    }

    #[test]
    fn test_macro_expansion() {
        let mut tx = HashMapCollection::new();
        tx.set("anomaly_score".to_string(), "25".to_string());

        let value = "Score is %{TX.anomaly_score}, matched %{MATCHED_VAR}";
        let expanded = expand_macros(value, &tx, Some("<script>"), None);
        assert_eq!(expanded, "Score is 25, matched <script>");
    }
}
