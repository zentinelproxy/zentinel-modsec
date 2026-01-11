//! Request processing phases.

/// ModSecurity processing phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Phase {
    /// Phase 1: Request headers
    RequestHeaders = 1,
    /// Phase 2: Request body
    RequestBody = 2,
    /// Phase 3: Response headers
    ResponseHeaders = 3,
    /// Phase 4: Response body
    ResponseBody = 4,
    /// Phase 5: Logging
    Logging = 5,
}

impl Phase {
    /// Get the phase number.
    pub fn number(&self) -> u8 {
        *self as u8
    }

    /// Get phase name.
    pub fn name(&self) -> &'static str {
        match self {
            Phase::RequestHeaders => "REQUEST_HEADERS",
            Phase::RequestBody => "REQUEST_BODY",
            Phase::ResponseHeaders => "RESPONSE_HEADERS",
            Phase::ResponseBody => "RESPONSE_BODY",
            Phase::Logging => "LOGGING",
        }
    }

    /// Create from phase number.
    pub fn from_number(n: u8) -> Option<Self> {
        match n {
            1 => Some(Phase::RequestHeaders),
            2 => Some(Phase::RequestBody),
            3 => Some(Phase::ResponseHeaders),
            4 => Some(Phase::ResponseBody),
            5 => Some(Phase::Logging),
            _ => None,
        }
    }

    /// Get all phases in order.
    pub fn all() -> &'static [Phase] {
        &[
            Phase::RequestHeaders,
            Phase::RequestBody,
            Phase::ResponseHeaders,
            Phase::ResponseBody,
            Phase::Logging,
        ]
    }

    /// Check if this is a request phase.
    pub fn is_request_phase(&self) -> bool {
        matches!(self, Phase::RequestHeaders | Phase::RequestBody)
    }

    /// Check if this is a response phase.
    pub fn is_response_phase(&self) -> bool {
        matches!(self, Phase::ResponseHeaders | Phase::ResponseBody)
    }
}

impl Default for Phase {
    fn default() -> Self {
        Phase::RequestHeaders
    }
}

impl TryFrom<u8> for Phase {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Phase::from_number(value).ok_or(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase_number() {
        assert_eq!(Phase::RequestHeaders.number(), 1);
        assert_eq!(Phase::RequestBody.number(), 2);
        assert_eq!(Phase::ResponseHeaders.number(), 3);
        assert_eq!(Phase::ResponseBody.number(), 4);
        assert_eq!(Phase::Logging.number(), 5);
    }

    #[test]
    fn test_phase_from_number() {
        assert_eq!(Phase::from_number(1), Some(Phase::RequestHeaders));
        assert_eq!(Phase::from_number(2), Some(Phase::RequestBody));
        assert_eq!(Phase::from_number(6), None);
    }

    #[test]
    fn test_is_request_phase() {
        assert!(Phase::RequestHeaders.is_request_phase());
        assert!(Phase::RequestBody.is_request_phase());
        assert!(!Phase::ResponseHeaders.is_request_phase());
    }
}
