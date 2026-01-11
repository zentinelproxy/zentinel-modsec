//! Collection trait and implementations.

use regex::Regex;
use std::collections::HashMap;

/// A collection of key-value pairs.
pub trait Collection: Send + Sync {
    /// Get all key-value pairs.
    fn all(&self) -> Vec<(&str, &str)>;

    /// Get values by key.
    fn get(&self, key: &str) -> Option<Vec<&str>>;

    /// Get values matching a regex pattern.
    fn get_regex(&self, pattern: &Regex) -> Vec<(&str, &str)>;

    /// Count items.
    fn count(&self) -> usize;

    /// Count items with specific key.
    fn count_key(&self, key: &str) -> usize;
}

/// A mutable collection (TX, SESSION, etc.).
pub trait MutableCollection: Collection {
    /// Set a value.
    fn set(&mut self, key: String, value: String);

    /// Delete a key.
    fn delete(&mut self, key: &str);

    /// Increment a numeric value.
    fn increment(&mut self, key: &str, amount: i64);

    /// Decrement a numeric value.
    fn decrement(&mut self, key: &str, amount: i64);
}

/// Simple hash map based collection.
#[derive(Debug, Clone, Default)]
pub struct HashMapCollection {
    data: HashMap<String, Vec<String>>,
}

impl HashMapCollection {
    /// Create a new empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a value to a key.
    pub fn add(&mut self, key: String, value: String) {
        self.data.entry(key).or_default().push(value);
    }

    /// Clear all data.
    pub fn clear(&mut self) {
        self.data.clear();
    }
}

impl Collection for HashMapCollection {
    fn all(&self) -> Vec<(&str, &str)> {
        self.data
            .iter()
            .flat_map(|(k, vs)| vs.iter().map(move |v| (k.as_str(), v.as_str())))
            .collect()
    }

    fn get(&self, key: &str) -> Option<Vec<&str>> {
        self.data
            .get(key)
            .map(|vs| vs.iter().map(|s| s.as_str()).collect())
    }

    fn get_regex(&self, pattern: &Regex) -> Vec<(&str, &str)> {
        self.data
            .iter()
            .filter(|(k, _)| pattern.is_match(k))
            .flat_map(|(k, vs)| vs.iter().map(move |v| (k.as_str(), v.as_str())))
            .collect()
    }

    fn count(&self) -> usize {
        self.data.values().map(|v| v.len()).sum()
    }

    fn count_key(&self, key: &str) -> usize {
        self.data.get(key).map(|v| v.len()).unwrap_or(0)
    }
}

impl MutableCollection for HashMapCollection {
    fn set(&mut self, key: String, value: String) {
        self.data.insert(key, vec![value]);
    }

    fn delete(&mut self, key: &str) {
        self.data.remove(key);
    }

    fn increment(&mut self, key: &str, amount: i64) {
        let current: i64 = self
            .data
            .get(key)
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        self.set(key.to_string(), (current + amount).to_string());
    }

    fn decrement(&mut self, key: &str, amount: i64) {
        self.increment(key, -amount);
    }
}
