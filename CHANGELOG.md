# Changelog

Notable changes to `zentinel-modsec`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate uses
[Semantic Versioning](https://semver.org/).

CRS figures are passing cases of the regression corpus at the CRS commit CI
pins (see [`docs/conformance.md`](docs/conformance.md)).

## [Unreleased]

CRS conformance: 4,949 to 4,952 of 5,184 runnable cases.

### Behavior changes

- **`@detectSQLi` gives libinjection's verdict.** It used to be a set of
  regular expressions and a small fingerprint list, which matched ordinary
  crawler User-Agents (AhrefsBot, PetalBot, `meta-externalagent`, ...) under
  CRS 942100 and missed some injections. It is now a port of libinjection
  v4.0.2's SQLi detector: the same tokenizer, folding, fingerprint list and
  false-positive filter, so the verdict and the reported fingerprint (`TX:0`)
  match C libinjection. Some inputs that matched before no longer do, and some
  that did not now do. (#84)
- **Rules after a form feed, vertical tab or Unicode space are loaded.** Any
  whitespace character other than space, tab or carriage return between
  directives used to end the configuration silently, dropping every directive
  after it. Those characters now separate tokens, and U+0085, U+2028 and
  U+2029 end a line or a comment. v3 accepts none of them, so the load logs
  one warning per distinct character with its position. Content that used to
  be dropped is now parsed, so an error in it surfaces at load. (#79)
- **An unquoted argument keeps a leading backslash.** `SecRule REQUEST_URI
  \.php$` compiled `.php$` and now compiles `\.php$`; `Include
  \\server\share\rules.conf` and `SecMarker \name` keep theirs too. A stray
  backslash outside a word is still ignored, now with a warning. (#79)
- **A numeric operator with a bare macro name never matches.** `@gt
  %{REMOTE_PORT}` was expanded as `tx.REMOTE_PORT` and compared against 0. v3
  reads a bare name as the variable, which the engine cannot resolve in an
  operand, so `@eq`, `@gt`, `@lt`, `@ge` and `@le` with a bare name other than
  `MATCHED_VAR` or `MATCHED_VAR_NAME` are handled like a macro on an
  unresolvable collection: no match, and one load warning per macro. Other
  operators and `setvar` still read a bare name from TX. (#87)

### Performance

- `@rx` answers a value that does not match without allocating capture
  slots. (#91)
- A rule's message, tags and other metadata are collected when it
  intervenes, not copied on every match. (#92)
- `%{...}` macros in operands and `setvar` are expanded without running a
  regex, and whether an operand holds one is decided at load. (#93)

## [0.7.0] - 2026-11-21

CRS conformance: 4,900 to 4,949 of 5,184 runnable cases.

### Behavior changes

Changes that alter what loads or what rules match. Read these before
upgrading.

- **A missing literal `Include` is a load error.** It used to be skipped
  silently. A glob with no matches is still allowed. A relative path is now
  tried as given (relative to the working directory) first and beside the
  declaring file second, as in ModSecurity v3; 0.6.0 tried the other order, so
  a config where both files exist can now load the other one. The limit of 100
  `Include` directives is replaced by a nesting limit of 100 levels, and a file
  that includes itself is reported as a cycle. A glob match that cannot be
  inspected, such as a dangling symlink, is skipped with a warning.
  Configuration includes load atomically: a failed load leaves the previous
  configuration in place. (#76)
- **`SecRuleRemoveByTag` and `SecRuleRemoveByMsg` are supported.** They were
  previously logged and skipped, so the rules they name ran. Like
  `SecRuleRemoveById`, they apply to the whole ruleset wherever they are
  declared, and remove a chain with its starter. Tags and messages are
  compared exactly against the rule text. (#77)
- **The engine no longer writes TX score variables.** At the end of every
  phase it used to overwrite `tx.anomaly_score` and seven per-category scores
  (`tx.sql_injection_score`, `tx.xss_score`, ...) from an internal tracker, so
  a score a rule set in one phase read 0 in the next, and those variables
  existed even when no rule had set them. TX is now left to the rules, and
  `Transaction::anomaly_score()` reads `TX:anomaly_score`. The public
  `AnomalyScore` type remains but the engine no longer uses it. (#81)
- **Literal TX assignments keep their spelling.** `setvar:tx.code=007` stored
  `7`; it now stores `007`, so a later string comparison sees what the rule
  wrote. (#78)
- **`setvar` into a collection other than TX is skipped, with a warning.**
  Writes to `ip.`, `session.`, `user.`, `global.` or `resource.` used to land in
  TX under the same member name, so `setvar:ip.score=1` overwrote `TX:score`.
  They are now removed when the rules load, with one warning per collection,
  and the rest of the rule still runs. (#78)
- **CRS rules gated on `ctl:ruleRemoveByTag` take effect.** CRS sampling mode
  (901410, 901450) and the 905110 exception for Apache's internal dummy
  connection now work. Embedders must pass the real client address
  (`Transaction::set_client_addr`); a loopback `REMOTE_ADDR` with a matching
  request skips the CRS. 905100 stays inert (see
  [`docs/v3-compatibility.md`](docs/v3-compatibility.md)). (#67)
- **`setvar` arithmetic saturates** at `i64::MIN` and `i64::MAX`. An operand
  outside the range, including one expanded from request data
  (`=+%{tx.1}`), used to panic in builds with overflow checks; it can no
  longer crash a transaction or wrap a score below a blocking threshold. (#82)
- **Numeric operators compare empty and non-numeric operands as 0.** `@eq`,
  `@gt`, `@lt`, `@ge` and `@le` read both sides as v3 does (`atoll`/`stoi`):
  leading whitespace skipped, an optional sign, digits up to the first other
  byte, 0 if there are none. Previously such an operand was a no-match, and a
  negated rule (`!@eq 0`) then matched: the recommended configuration's
  request body checks (200002, 200003) denied requests whose value was empty.
  An argument using a macro on a collection the engine cannot resolve
  (`%{env.MAX_LEN}`) is the exception: the rule never matches, and the load
  logs one warning per macro with the number of rules affected. (#80)
- **`t:urlDecodeUni` folds full-width ASCII escapes** (`%uFF01`..`%uFF5E`) to
  the ASCII characters they stand for, so `%uFF1C` decodes to `<`. Literal
  full-width characters in the input are left as they are. (#71)

### Added

- `ctl:ruleRemoveByTag` and `ctl:ruleRemoveTargetByTag`. Tags match exactly
  and case-sensitively; removals accumulate and affect rules evaluated
  afterwards. (#67)
- `UNIQUE_ID`: each transaction gets a distinct, unpredictable identifier.
  `Transaction::set_unique_id` replaces it with the application's own request
  ID, which must not be client-controlled. (#67)
- `FILES_SIZES` and `FILES_COMBINED_SIZE`, measured in bytes by the multipart
  processor, which now splits the body as bytes. CRS 920410's upload limit is
  enforced. (#67)
- `ctl:forceRequestBodyVariable` is accepted. It has nothing to do:
  `REQUEST_BODY` always holds the raw body. (#67)
- A benchmark of request latency against the full OWASP CRS 4.25.0, with
  setup in `benches/README.md`. (#69)

### Fixed

- `t:normalizePathWin` emits forward slashes, and converts backslashes before
  resolving path components. (#70)
- `t:utf8toUnicode` encodes non-ASCII code points in the IIS `%u` form. (#72)
- Rule IDs in balanced quotes (`id:'942100'`) parse, with the same range checks
  as unquoted IDs. (#73)
- `@ipMatch` matches IPv4-mapped IPv6 addresses against the masked network
  number, for inline and file-based lists. (#74)
- A single-quoted `SecRuleRemoveByTag` or `SecRuleRemoveByMsg` value is
  unquoted, and a trailing `\` followed by a blank line no longer pulls the
  next directive into the value. (#77)
- When an unknown directive is skipped, the line after it is no longer
  swallowed if the directive ends in a comment. (#76)

### Performance

- Phase rules are borrowed from the compiled ruleset instead of copied for
  every request. (#75)
- Multipart bodies are split with `memchr::memmem`. (#67)

## Earlier releases

0.1.2 through 0.6.0 are tagged in Git (`v0.1.2` ... `v0.6.0`); see the tags
and the commit history for what each contains.

[Unreleased]: https://github.com/zentinelproxy/zentinel-modsec/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/zentinelproxy/zentinel-modsec/compare/v0.6.0...v0.7.0
