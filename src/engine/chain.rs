//! Rule chaining logic.

use super::ruleset::CompiledRule;

/// Track chain state during rule execution.
#[derive(Debug, Clone)]
pub struct ChainState {
    /// Whether we're currently in a chain.
    pub in_chain: bool,
    /// Whether the current chain has matched so far.
    pub chain_matched: bool,
    /// Accumulated captures from chain.
    pub captures: Vec<String>,
    /// Starting rule index of current chain.
    pub chain_start: Option<usize>,
}

impl ChainState {
    /// Create a new chain state.
    pub fn new() -> Self {
        Self {
            in_chain: false,
            chain_matched: false,
            captures: Vec::new(),
            chain_start: None,
        }
    }

    /// Start a new chain.
    pub fn start_chain(&mut self, rule_idx: usize) {
        self.in_chain = true;
        self.chain_matched = true;
        self.chain_start = Some(rule_idx);
        self.captures.clear();
    }

    /// Continue chain with match result.
    pub fn continue_chain(&mut self, matched: bool, captures: &[String]) {
        if matched {
            self.captures.extend(captures.iter().cloned());
        } else {
            self.chain_matched = false;
        }
    }

    /// End the current chain.
    pub fn end_chain(&mut self) -> bool {
        let matched = self.chain_matched;
        self.in_chain = false;
        self.chain_matched = false;
        self.chain_start = None;
        self.captures.clear();
        matched
    }

    /// Reset chain state (on match failure).
    pub fn reset(&mut self) {
        self.in_chain = false;
        self.chain_matched = false;
        self.chain_start = None;
        self.captures.clear();
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

/// Evaluate a chain of rules.
pub fn evaluate_chain<F>(
    rules: &[CompiledRule],
    start_idx: usize,
    mut eval_rule: F,
) -> Option<(bool, Vec<String>)>
where
    F: FnMut(&CompiledRule) -> Option<(bool, Vec<String>)>,
{
    let mut state = ChainState::new();
    let mut idx = start_idx;
    let mut all_captures = Vec::new();

    loop {
        if idx >= rules.len() {
            break;
        }

        let rule = &rules[idx];

        // Evaluate the rule
        match eval_rule(rule) {
            Some((matched, captures)) => {
                if matched {
                    all_captures.extend(captures);
                    if rule.is_chain {
                        if let Some(next_idx) = rule.chain_next {
                            idx = next_idx;
                            continue;
                        }
                    }
                    // Chain complete and matched
                    return Some((true, all_captures));
                } else {
                    // Chain broken
                    return Some((false, Vec::new()));
                }
            }
            None => {
                // Rule evaluation error
                return None;
            }
        }
    }

    Some((false, Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_state() {
        let mut state = ChainState::new();
        assert!(!state.in_chain);

        state.start_chain(0);
        assert!(state.in_chain);
        assert!(state.chain_matched);

        state.continue_chain(true, &["test".to_string()]);
        assert!(state.chain_matched);
        assert_eq!(state.captures.len(), 1);

        state.continue_chain(false, &[]);
        assert!(!state.chain_matched);

        let matched = state.end_chain();
        assert!(!matched);
        assert!(!state.in_chain);
    }
}
