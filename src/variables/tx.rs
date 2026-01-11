//! TX (transaction) collection.

use super::collection::{HashMapCollection, MutableCollection, Collection};
use regex::Regex;

/// Transaction collection for storing intermediate values.
#[derive(Debug, Clone, Default)]
pub struct TxCollection {
    data: HashMapCollection,
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
        self.data.get(key)
    }

    fn get_regex(&self, pattern: &Regex) -> Vec<(&str, &str)> {
        self.data.get_regex(pattern)
    }

    fn count(&self) -> usize {
        self.data.count()
    }

    fn count_key(&self, key: &str) -> usize {
        self.data.count_key(key)
    }
}

impl MutableCollection for TxCollection {
    fn set(&mut self, key: String, value: String) {
        self.data.set(key, value);
    }

    fn delete(&mut self, key: &str) {
        self.data.delete(key);
    }

    fn increment(&mut self, key: &str, amount: i64) {
        self.data.increment(key, amount);
    }

    fn decrement(&mut self, key: &str, amount: i64) {
        self.data.decrement(key, amount);
    }
}
