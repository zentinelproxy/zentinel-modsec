//! TX (transaction) collection.

use super::collection::{Collection, HashMapCollection, MutableCollection};
use regex::Regex;
use std::borrow::Cow;

/// Transaction collection for storing intermediate values.
///
/// Keys are **case-insensitive**, as they are in ModSecurity. The OWASP CRS
/// depends on this: it writes `setvar:'tx.blocking_paranoia_level=1'` and reads
/// `TX:BLOCKING_PARANOIA_LEVEL`, and its anomaly scoring never accumulates if
/// those are treated as two different keys. Normalising here rather than at the
/// call sites keeps the guarantee in one place -- every read and write in the
/// engine goes through this type -- and leaves case-sensitive collections such
/// as `ARGS` untouched.
#[derive(Debug, Clone, Default)]
pub struct TxCollection {
    data: HashMapCollection,
}

/// Lowercase a key only when it actually contains uppercase, so the common path
/// (CRS writes and reads lowercase) does not allocate.
fn normalize(key: &str) -> Cow<'_, str> {
    if key.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(key.to_ascii_lowercase())
    } else {
        Cow::Borrowed(key)
    }
}

impl TxCollection {
    /// Create a new TX collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear all data.
    pub fn clear(&mut self) {
        self.data.clear();
    }
}

impl Collection for TxCollection {
    fn all(&self) -> Vec<(&str, &str)> {
        self.data.all()
    }

    fn get(&self, key: &str) -> Option<Vec<&str>> {
        self.data.get(&normalize(key))
    }

    /// Regex selection (`TX:/^foo/`) matches against the stored, lowercased
    /// key, so a pattern anchored on uppercase will not match.
    fn get_regex(&self, pattern: &Regex) -> Vec<(&str, &str)> {
        self.data.get_regex(pattern)
    }

    fn count(&self) -> usize {
        self.data.count()
    }

    fn count_key(&self, key: &str) -> usize {
        self.data.count_key(&normalize(key))
    }
}

impl MutableCollection for TxCollection {
    fn set(&mut self, key: String, value: String) {
        match normalize(&key) {
            Cow::Borrowed(_) => self.data.set(key, value),
            Cow::Owned(lower) => self.data.set(lower, value),
        }
    }

    fn delete(&mut self, key: &str) {
        self.data.delete(&normalize(key));
    }

    fn increment(&mut self, key: &str, amount: i64) {
        self.data.increment(&normalize(key), amount);
    }

    fn decrement(&mut self, key: &str, amount: i64) {
        self.data.decrement(&normalize(key), amount);
    }
}
