//! Intervention tracking for blocked requests.

use super::phase::Phase;
use crate::actions::RuleMetadata;

/// An intervention (blocking decision) from rule processing.
#[derive(Debug, Clone)]
pub struct Intervention {
    /// HTTP status code to return.
    pub status: u16,
    /// Redirect URL (if applicable).
    pub url: Option<String>,
    /// Log message.
    pub log: Option<String>,
    /// Rule IDs that triggered the intervention.
    pub rule_ids: Vec<String>,
    /// Phase in which intervention occurred.
    pub phase: Phase,
    /// Whether to drop the connection.
    pub drop_connection: bool,
    /// Matched rule metadata.
    pub metadata: Vec<RuleMetadata>,
}

impl Intervention {
    /// Create a new intervention.
    pub fn new(status: u16, phase: Phase) -> Self {
        Self {
            status,
            url: None,
            log: None,
            rule_ids: Vec::new(),
            phase,
            drop_connection: false,
            metadata: Vec::new(),
        }
    }

    /// Create a deny intervention.
    pub fn deny(status: u16, phase: Phase, rule_id: Option<String>) -> Self {
        let mut intervention = Self::new(status, phase);
        if let Some(id) = rule_id {
            intervention.rule_ids.push(id);
        }
        intervention
    }

    /// Create a redirect intervention.
    pub fn redirect(url: String, phase: Phase, rule_id: Option<String>) -> Self {
        let mut intervention = Self::new(302, phase);
        intervention.url = Some(url);
        if let Some(id) = rule_id {
            intervention.rule_ids.push(id);
        }
        intervention
    }

    /// Create a drop intervention.
    pub fn drop(phase: Phase, rule_id: Option<String>) -> Self {
        let mut intervention = Self::new(444, phase);
        intervention.drop_connection = true;
        if let Some(id) = rule_id {
            intervention.rule_ids.push(id);
        }
        intervention
    }

    /// Add a rule ID.
    pub fn add_rule_id(&mut self, id: String) {
        self.rule_ids.push(id);
    }

    /// Add metadata from a matched rule.
    pub fn add_metadata(&mut self, metadata: RuleMetadata) {
        if let Some(ref id) = metadata.id {
            self.rule_ids.push(id.clone());
        }
        if let Some(ref msg) = metadata.msg {
            if self.log.is_none() {
                self.log = Some(msg.clone());
            }
        }
        self.metadata.push(metadata);
    }

    /// Set log message.
    pub fn set_log(&mut self, log: String) {
        self.log = Some(log);
    }

    /// Format as a log entry.
    pub fn format_log(&self) -> String {
        let mut parts = vec![format!("[status {}]", self.status)];

        if !self.rule_ids.is_empty() {
            parts.push(format!("[rule_ids: {}]", self.rule_ids.join(", ")));
        }

        if let Some(ref log) = self.log {
            parts.push(format!("[msg: {}]", log));
        }

        if let Some(ref url) = self.url {
            parts.push(format!("[redirect: {}]", url));
        }

        parts.push(format!("[phase: {}]", self.phase.name()));

        parts.join(" ")
    }
}

impl Default for Intervention {
    fn default() -> Self {
        Self::new(403, Phase::RequestHeaders)
    }
}

/// Builder for creating interventions.
#[derive(Debug, Clone)]
pub struct InterventionBuilder {
    intervention: Intervention,
}

impl InterventionBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            intervention: Intervention::default(),
        }
    }

    /// Set status code.
    pub fn status(mut self, status: u16) -> Self {
        self.intervention.status = status;
        self
    }

    /// Set phase.
    pub fn phase(mut self, phase: Phase) -> Self {
        self.intervention.phase = phase;
        self
    }

    /// Set redirect URL.
    pub fn redirect(mut self, url: String) -> Self {
        self.intervention.status = 302;
        self.intervention.url = Some(url);
        self
    }

    /// Set drop connection flag.
    pub fn drop_connection(mut self) -> Self {
        self.intervention.drop_connection = true;
        self.intervention.status = 444;
        self
    }

    /// Add rule ID.
    pub fn rule_id(mut self, id: String) -> Self {
        self.intervention.rule_ids.push(id);
        self
    }

    /// Set log message.
    pub fn log(mut self, msg: String) -> Self {
        self.intervention.log = Some(msg);
        self
    }

    /// Build the intervention.
    pub fn build(self) -> Intervention {
        self.intervention
    }
}

impl Default for InterventionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deny_intervention() {
        let intervention = Intervention::deny(403, Phase::RequestHeaders, Some("12345".to_string()));
        assert_eq!(intervention.status, 403);
        assert_eq!(intervention.rule_ids, vec!["12345".to_string()]);
        assert!(!intervention.drop_connection);
    }

    #[test]
    fn test_redirect_intervention() {
        let intervention = Intervention::redirect(
            "https://example.com/blocked".to_string(),
            Phase::RequestHeaders,
            Some("12345".to_string()),
        );
        assert_eq!(intervention.status, 302);
        assert_eq!(
            intervention.url,
            Some("https://example.com/blocked".to_string())
        );
    }

    #[test]
    fn test_builder() {
        let intervention = InterventionBuilder::new()
            .status(403)
            .phase(Phase::RequestBody)
            .rule_id("100".to_string())
            .log("SQL Injection detected".to_string())
            .build();

        assert_eq!(intervention.status, 403);
        assert_eq!(intervention.phase, Phase::RequestBody);
        assert_eq!(intervention.rule_ids, vec!["100".to_string()]);
    }

    #[test]
    fn test_format_log() {
        let intervention = Intervention::deny(403, Phase::RequestHeaders, Some("942100".to_string()));
        let log = intervention.format_log();
        assert!(log.contains("[status 403]"));
        assert!(log.contains("942100"));
    }
}
