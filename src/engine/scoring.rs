//! Anomaly scoring system.

use crate::variables::MutableCollection;

/// Standard anomaly score variable names (CRS).
pub const ANOMALY_SCORE: &str = "anomaly_score";
pub const INBOUND_ANOMALY_SCORE_THRESHOLD: &str = "inbound_anomaly_score_threshold";
pub const OUTBOUND_ANOMALY_SCORE_THRESHOLD: &str = "outbound_anomaly_score_threshold";
pub const SQL_INJECTION_SCORE: &str = "sql_injection_score";
pub const XSS_SCORE: &str = "xss_score";
pub const RFI_SCORE: &str = "rfi_score";
pub const LFI_SCORE: &str = "lfi_score";
pub const RCE_SCORE: &str = "rce_score";
pub const PHP_INJECTION_SCORE: &str = "php_injection_score";
pub const SESSION_FIXATION_SCORE: &str = "session_fixation_score";

/// Default CRS thresholds by paranoia level.
#[derive(Debug, Clone)]
pub struct ScoringConfig {
    /// Paranoia level (1-4).
    pub paranoia_level: u8,
    /// Inbound anomaly score threshold.
    pub inbound_threshold: i32,
    /// Outbound anomaly score threshold.
    pub outbound_threshold: i32,
    /// Critical severity score.
    pub critical_score: i32,
    /// Error severity score.
    pub error_score: i32,
    /// Warning severity score.
    pub warning_score: i32,
    /// Notice severity score.
    pub notice_score: i32,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            paranoia_level: 1,
            inbound_threshold: 5,
            outbound_threshold: 4,
            critical_score: 5,
            error_score: 4,
            warning_score: 3,
            notice_score: 2,
        }
    }
}

impl ScoringConfig {
    /// Create config for paranoia level.
    pub fn for_paranoia_level(level: u8) -> Self {
        match level {
            1 => Self::default(),
            2 => Self {
                paranoia_level: 2,
                inbound_threshold: 10,
                outbound_threshold: 8,
                ..Default::default()
            },
            3 => Self {
                paranoia_level: 3,
                inbound_threshold: 15,
                outbound_threshold: 12,
                ..Default::default()
            },
            _ => Self {
                paranoia_level: 4,
                inbound_threshold: 20,
                outbound_threshold: 16,
                ..Default::default()
            },
        }
    }

    /// Get score for severity level.
    pub fn score_for_severity(&self, severity: u8) -> i32 {
        match severity {
            0 | 1 | 2 => self.critical_score,
            3 => self.error_score,
            4 => self.warning_score,
            5 => self.notice_score,
            _ => 0,
        }
    }
}

/// Anomaly score tracker.
#[derive(Debug, Clone, Default)]
pub struct AnomalyScore {
    /// Total inbound score.
    pub inbound: i32,
    /// Total outbound score.
    pub outbound: i32,
    /// SQL injection specific score.
    pub sqli: i32,
    /// XSS specific score.
    pub xss: i32,
    /// RFI specific score.
    pub rfi: i32,
    /// LFI specific score.
    pub lfi: i32,
    /// RCE specific score.
    pub rce: i32,
    /// PHP injection specific score.
    pub php: i32,
    /// Session fixation specific score.
    pub session_fixation: i32,
}

impl AnomalyScore {
    /// Create a new anomaly score tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add to inbound score.
    pub fn add_inbound(&mut self, score: i32) {
        self.inbound += score;
    }

    /// Add to outbound score.
    pub fn add_outbound(&mut self, score: i32) {
        self.outbound += score;
    }

    /// Check if inbound threshold exceeded.
    pub fn inbound_exceeded(&self, threshold: i32) -> bool {
        self.inbound >= threshold
    }

    /// Check if outbound threshold exceeded.
    pub fn outbound_exceeded(&self, threshold: i32) -> bool {
        self.outbound >= threshold
    }

    /// Sync scores to TX collection.
    pub fn sync_to_tx<C: MutableCollection>(&self, tx: &mut C) {
        tx.set(ANOMALY_SCORE.to_string(), self.inbound.to_string());
        tx.set(SQL_INJECTION_SCORE.to_string(), self.sqli.to_string());
        tx.set(XSS_SCORE.to_string(), self.xss.to_string());
        tx.set(RFI_SCORE.to_string(), self.rfi.to_string());
        tx.set(LFI_SCORE.to_string(), self.lfi.to_string());
        tx.set(RCE_SCORE.to_string(), self.rce.to_string());
        tx.set(PHP_INJECTION_SCORE.to_string(), self.php.to_string());
        tx.set(SESSION_FIXATION_SCORE.to_string(), self.session_fixation.to_string());
    }

    /// Load scores from TX collection.
    pub fn sync_from_tx<C: crate::variables::Collection>(&mut self, tx: &C) {
        if let Some(values) = tx.get(ANOMALY_SCORE) {
            if let Some(v) = values.first() {
                self.inbound = v.parse().unwrap_or(0);
            }
        }
        if let Some(values) = tx.get(SQL_INJECTION_SCORE) {
            if let Some(v) = values.first() {
                self.sqli = v.parse().unwrap_or(0);
            }
        }
        if let Some(values) = tx.get(XSS_SCORE) {
            if let Some(v) = values.first() {
                self.xss = v.parse().unwrap_or(0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::variables::{Collection, HashMapCollection};

    #[test]
    fn test_scoring_config() {
        let config = ScoringConfig::default();
        assert_eq!(config.score_for_severity(2), 5); // Critical
        assert_eq!(config.score_for_severity(3), 4); // Error
        assert_eq!(config.score_for_severity(4), 3); // Warning
    }

    #[test]
    fn test_anomaly_score() {
        let mut score = AnomalyScore::new();
        score.add_inbound(5);
        score.add_inbound(3);
        assert_eq!(score.inbound, 8);
        assert!(score.inbound_exceeded(5));
        assert!(!score.inbound_exceeded(10));
    }

    #[test]
    fn test_sync_to_tx() {
        let mut score = AnomalyScore::new();
        score.inbound = 15;
        score.sqli = 10;

        let mut tx = HashMapCollection::new();
        score.sync_to_tx(&mut tx);

        let anomaly_val = tx.get(ANOMALY_SCORE).and_then(|v| v.first().map(|s| s.to_string()));
        let sqli_val = tx.get(SQL_INJECTION_SCORE).and_then(|v| v.first().map(|s| s.to_string()));
        assert_eq!(anomaly_val, Some("15".to_string()));
        assert_eq!(sqli_val, Some("10".to_string()));
    }
}
