# Reviewing changes to zentinel-modsec

What to check on every PR, in roughly the order problems have turned up in
past reviews. The background for each point is in `../CLAUDE.md`.

## Semantics

- [ ] **Reference cited.** A claim that the new behavior matches ModSecurity
      names the v3 source file (`owasp-modsecurity/ModSecurity`, `v3/master`).
      Coraza or v2 behavior alone is not enough. Check the claim against the
      v3 source yourself when it decides the review.
- [ ] **Divergence recorded.** Where the change stays different from v3 on
      purpose, there is a code comment saying so and a row in
      `docs/v3-compatibility.md`.
- [ ] **Loud, not silent.** Input v3 would reject or ignore is either rejected
      or accepted with a load-time warning, deduplicated with a count. Nothing
      is dropped, reinterpreted or skipped without a log line.
- [ ] **Configs that load today still load,** or the PR says which ones stop
      and why, and `CHANGELOG.md` has the entry.
- [ ] **Failure direction.** A rule that cannot be evaluated as written ends up
      never matching, not matching everything. Look at negated operators
      (`!@rx`, `!@within`, `!@eq`) in particular: "no value" or "unresolvable"
      inverted by `!` has blocked all traffic before.
- [ ] **Request-controlled arithmetic saturates.** Any value expanded from
      request data (`%{tx.1}`, `MATCHED_VAR`, header values) that feeds a
      number cannot overflow, panic, or wrap a score below a threshold.
- [ ] **Exclusion scope.** Removals and target exclusions are no wider than
      written: exact tags, case-sensitive argument names, header names
      case-insensitive. A broader match is a bypass.

## CRS gate

- [ ] `MIN_PASSING` in `tests/crs_conformance.rs` equals the count the change
      produces against the pinned CRS commit, measured after rebasing on the
      current `main`.
- [ ] If another merged PR moved the count since this branch was cut, the
      number was re-measured, not added up from two PR descriptions.
- [ ] A lower count names the regressed rules and gives the reason.
- [ ] A bump of the CRS commit in `.github/workflows/ci.yml` comes with the new
      `MIN_PASSING`, the README conformance table, and the comment above
      `MIN_PASSING`.
- [ ] Changes to blocking behavior are checked by
      `stock_crs_blocks_attacks_and_passes_ordinary_traffic` as well: the
      corpus runs in `DetectionOnly` and cannot see decisions.

## Code

- [ ] No `unsafe`, no FFI, no C or C++ build dependency. New crates are
      justified in a `Cargo.toml` comment.
- [ ] No regex (or Aho-Corasick automaton) built per request. Rule-text
      patterns compile at load or once through a cache.
- [ ] Nothing new allocates per rule on the hot path when the feature is not in
      use (compare `is_rule_removed_by_tag`, which returns early on an empty
      list).
- [ ] Collections keep insertion order. No `HashMap` iteration where order
      reaches a result.
- [ ] Public API changes are additive, or called out in `CHANGELOG.md` with a
      migration note. `missing_docs` stays clean.

## Tests

- [ ] Every semantic change has a test that fails without it.
- [ ] Warning assertions use `common::capture_log` from `tests/common/mod.rs`,
      never a subscriber scoped to the test thread.
- [ ] Edge cases from v3 are covered: empty values, missing variables, negated
      operators, chains (the starter and each link), and both LF and CRLF rule
      files where the lexer is involved.

## Documentation

- [ ] `CHANGELOG.md` `Unreleased` lists every change to what rules match, what
      loads, or what the public API offers.
- [ ] README facts touched by the change (supported directives, operators,
      conformance figure) are still true.
- [ ] `docs/` updated when the pipeline, the gate, or a v3 divergence changed.
