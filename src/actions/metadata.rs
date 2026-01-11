//! Metadata actions (id, msg, severity, tag, etc.).

use super::RuleMetadata;

/// Severity levels as defined in ModSecurity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Severity {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl From<u8> for Severity {
    fn from(value: u8) -> Self {
        match value {
            0 => Severity::Emergency,
            1 => Severity::Alert,
            2 => Severity::Critical,
            3 => Severity::Error,
            4 => Severity::Warning,
            5 => Severity::Notice,
            6 => Severity::Info,
            _ => Severity::Debug,
        }
    }
}

impl Severity {
    /// Get severity name.
    pub fn name(&self) -> &'static str {
        match self {
            Severity::Emergency => "EMERGENCY",
            Severity::Alert => "ALERT",
            Severity::Critical => "CRITICAL",
            Severity::Error => "ERROR",
            Severity::Warning => "WARNING",
            Severity::Notice => "NOTICE",
            Severity::Info => "INFO",
            Severity::Debug => "DEBUG",
        }
    }
}

impl RuleMetadata {
    /// Get severity as enum.
    pub fn severity_level(&self) -> Option<Severity> {
        self.severity.map(Severity::from)
    }

    /// Format as log message.
    pub fn format_log(&self) -> String {
        let mut parts = Vec::new();

        if let Some(ref id) = self.id {
            parts.push(format!("[id \"{}\"]", id));
        }

        if let Some(ref msg) = self.msg {
            parts.push(format!("[msg \"{}\"]", msg));
        }

        if let Some(sev) = self.severity {
            parts.push(format!("[severity \"{}\"]", Severity::from(sev).name()));
        }

        for tag in &self.tags {
            parts.push(format!("[tag \"{}\"]", tag));
        }

        if let Some(ref rev) = self.rev {
            parts.push(format!("[rev \"{}\"]", rev));
        }

        if let Some(ref ver) = self.ver {
            parts.push(format!("[ver \"{}\"]", ver));
        }

        parts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_u8() {
        assert_eq!(Severity::from(0), Severity::Emergency);
        assert_eq!(Severity::from(2), Severity::Critical);
        assert_eq!(Severity::from(4), Severity::Warning);
        assert_eq!(Severity::from(99), Severity::Debug);
    }

    #[test]
    fn test_format_log() {
        let meta = RuleMetadata {
            id: Some("942100".to_string()),
            msg: Some("SQL Injection Attack".to_string()),
            severity: Some(2),
            tags: vec!["attack-sqli".to_string(), "OWASP_CRS".to_string()],
            ..Default::default()
        };

        let log = meta.format_log();
        assert!(log.contains("[id \"942100\"]"));
        assert!(log.contains("[msg \"SQL Injection Attack\"]"));
        assert!(log.contains("[severity \"CRITICAL\"]"));
        assert!(log.contains("[tag \"attack-sqli\"]"));
    }
}
