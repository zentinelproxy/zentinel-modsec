//! Flow control actions (chain, skip, skipAfter).

use super::FlowOutcome;

/// Check if the outcome indicates chaining.
pub fn is_chain(outcome: &FlowOutcome) -> bool {
    matches!(outcome, FlowOutcome::Chain)
}

/// Get skip count if applicable.
pub fn skip_count(outcome: &FlowOutcome) -> Option<u32> {
    match outcome {
        FlowOutcome::Skip(n) => Some(*n),
        _ => None,
    }
}

/// Get skip-after marker if applicable.
pub fn skip_after_marker(outcome: &FlowOutcome) -> Option<&str> {
    match outcome {
        FlowOutcome::SkipAfter(marker) => Some(marker),
        _ => None,
    }
}
