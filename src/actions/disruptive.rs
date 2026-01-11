//! Disruptive actions (deny, block, pass, allow, redirect).

use super::DisruptiveOutcome;

/// Determine the final HTTP status code for a disruptive action.
pub fn status_for_outcome(outcome: &DisruptiveOutcome, default_status: u16) -> u16 {
    match outcome {
        DisruptiveOutcome::Deny(status) => *status,
        DisruptiveOutcome::Block => default_status,
        DisruptiveOutcome::Allow => 200,
        DisruptiveOutcome::Redirect(_) => 302,
        DisruptiveOutcome::Pass => 200,
        DisruptiveOutcome::Drop => 444, // nginx-style connection drop
    }
}

/// Check if the outcome should terminate the request.
pub fn is_terminal(outcome: &DisruptiveOutcome) -> bool {
    matches!(
        outcome,
        DisruptiveOutcome::Deny(_)
            | DisruptiveOutcome::Block
            | DisruptiveOutcome::Drop
            | DisruptiveOutcome::Redirect(_)
    )
}

/// Check if the outcome is an allow (should skip further rules).
pub fn is_allow(outcome: &DisruptiveOutcome) -> bool {
    matches!(outcome, DisruptiveOutcome::Allow)
}
