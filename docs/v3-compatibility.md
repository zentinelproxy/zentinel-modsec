# ModSecurity v3 compatibility

## The reference

Behavior is measured against libmodsecurity, the C++ ModSecurity v3, at
[`owasp-modsecurity/ModSecurity`](https://github.com/owasp-modsecurity/ModSecurity)
branch `v3/master`. When the engine and v3 disagree, v3 is right unless this
page lists the difference as deliberate.

- Cite the v3 source file when claiming parity, as the code comments do
  (`operators/rx.cc`, `actions/set_var.cc`, `seclang-scanner.ll`,
  `rule_with_operator.cc`). A claim without a source is a guess.
- Coraza and ModSecurity v2 are not the reference. Where they differ from v3,
  follow v3.
- Where this engine accepts something v3 rejects or ignores, it logs a warning
  when the rules load. Where it cannot do what v3 does, it says so at load and
  fails toward "the rule does not match", never toward "the rule matches
  everything".

## Known divergences and gaps

Each row is either deliberate (a decision with a reason) or a gap (to be
closed). A new divergence gets a row in the change that introduces it.

### Parsing and loading

| Area | This engine | ModSecurity v3 | Kind |
|---|---|---|---|
| Lone `\r` in a rule file | Treated as whitespace anywhere between tokens, without a warning (`skip_whitespace` in `src/parser/lexer.rs`). | The scanner accepts `\n` and `\r\n` as line ends and `[ \t]` as whitespace. | Deliberate, no warning yet |
| `Include` nesting | Limited to 100 levels; a file that includes itself is an error. | No depth limit. | Deliberate |
| `Include` resolution | A relative path is tried as given, then beside the declaring file (v3's `find_resource` order). A missing literal path is a load error (since #76). A glob with no matches is allowed; a glob match that cannot be inspected (dangling symlink) is skipped with a warning; one that exists but cannot be read fails the load. | Same search order. Error handling for unreadable glob matches not compared in detail. | Matches for the search order |
| Unknown directives | Logged and skipped. This includes `SecRequestBodyLimit`, `SecResponseBodyLimit` and `SecRuleUpdateActionById`, which v3 implements. | Implemented or rejected. | Gap |
| `SecRuleRemoveByTag` / `SecRuleRemoveByMsg` | Compared exactly against the tag or message as written in the rule, once at load. | Compared per transaction against the macro-expanded tag or message (`RuleWithActions::containsTag`, `containsMsg`, used in `src/rules_set.cc`). A rule with `tag:'%{tx.foo}'` differs. | Deliberate |

### Variables and collections

| Area | This engine | ModSecurity v3 | Kind |
|---|---|---|---|
| Regex key selections (`ARGS:/.../`, `TX:/.../`, `!ARGS:/.../`) | Keys are compared case-sensitively. CRS 922110 reads `TX:/MULTIPART_HEADERS_CONTENT_TYPES_*/` against lowercased TX keys and so never fires. Pending fix: PR #83. With #83, the `regex` crate folds case across Unicode (`ſession` matches `^session`). | Built case-insensitively (`VariableRegex`, `KeyExclusionRegex` in `src/variables/variable.h` pass `ignoreCase`), compiled without PCRE's UTF flag, so only ASCII letters fold (`src/utils/regex.cc`). | Gap (case); after #83, Unicode folding is a known difference accepted in review |
| `REQUEST_LINE` | Always built as `METHOD URI PROTOCOL`. An HTTP/0.9 line (`GET /`, no protocol) is never produced, so CRS 905100 is inert. 905110 works. | Built from the request as received. | Gap, low impact |
| Persistent collections (`IP`, `SESSION`, `USER`, `GLOBAL`, `RESOURCE`) | Not implemented. A `setvar` into one is removed when the rules load, with one warning per collection (since #78). | Persistent, stored across transactions. | Gap |
| `%{...}` on collections other than TX and `REQUEST_HEADERS` (`ENV`, `IP`, ...) | Not resolved in operator arguments (`MATCHED_VAR` and `MATCHED_VAR_NAME` are); expands to an empty string. In a numeric operator the rule never matches, with a load warning (#80). | Resolved. | Gap |
| `XML:` targets | No XPath. `XML:/*` and `XML://@*` resolve against the flattened body; other expressions are reported at load. | XPath via libxml2. | Gap |
| Capture slots `TX:0`..`TX:9` | All ten are cleared before a capturing match stores its groups (`store_captures` in `src/engine/transaction.rs`). | Each capture is stored on its own and nothing is removed (`operators/rx.cc`), so a stale higher slot can survive. | Deliberate |

### Operators and macros

| Area | This engine | ModSecurity v3 | Kind |
|---|---|---|---|
| Bare `%{NAME}` in an operator argument | Looked up as `TX:NAME` (`OperandMacro::parse` in `src/engine/operand_macro.rs`). `@gt %{REMOTE_PORT}` compares against a missing TX member, which is 0. | A bare name is a variable (`REMOTE_PORT`), never TX. Follow-up to #80: treat bare names other than `MATCHED_VAR` and `MATCHED_VAR_NAME` as unresolvable in the numeric-operand load check. | Gap |
| Numeric operand macro on an unresolvable collection | Rule never matches; one load warning per macro with a count (#80). | Resolves the macro. | Deliberate fallback for a gap |
| Mixed macro operand (`@gt %{tx.a}%{env.b}`) | Treated as unresolvable as a whole. | Resolves both. | Deliberate |
| Numeric operator width | 64-bit, saturating (`leading_integer` in `src/operators/comparison.rs`). | `atoll` for `@gt`/`@lt`/`@ge`/`@le`; `stoi` (32-bit, 0 on overflow) for `@eq`. | Deliberate |
| `@containsWord` | Approximated by `@contains`, so it also matches inside a longer word. | Requires word boundaries around the match. | Gap |
| `@strmatch` | Implemented as `@contains`. | Plain substring search after macro expansion (`operators/str_match.cc`), so the result is the same for a literal argument. | Matches for literal arguments |
| `@verifyCC`, `@verifySSN`, `@verifyCPF`, `@validateHash`, `@validateDTD`, `@validateSchema`, `@rbl`, `@geoLookup`, `@gsbLookup`, `@inspectFile`, `@fuzzyHash`, `@rsub` | Parse, never match. | Implemented (some need build options or external data). | Gap |
| Invalid `@rx` pattern | Rule never matches, with a warning; a `!` on it is dropped so it cannot match everything. | Load error (`Rx::init` in `operators/rx.cc`). | Deliberate: `regex` rejects some valid PCRE (lookaround, backreferences), and refusing the whole ruleset for one such rule would leave nothing loaded |
| `@detectSQLi` | Pure Rust port. Flags some ordinary crawler User-Agents that C libinjection does not (issue #84). | C libinjection. | Gap |

### Actions and `ctl:`

| Area | This engine | ModSecurity v3 | Kind |
|---|---|---|---|
| `setvar` arithmetic | 64-bit, saturating at `i64::MIN`/`i64::MAX` (#82). | `int` via `stoi` (`actions/set_var.cc`). | Deliberate |
| `block` with no `SecDefaultAction` | Denies. | Inherits the built-in default, which passes. | Deliberate: a hand-written `block` is not silently downgraded. CRS always sets a default. |
| `allow:phase`, `allow:request` | Behave like plain `allow`: no further rules run in any phase, including phase 5. | `allow` skips all phases except logging; `allow:request` skips only the request phases (`src/rules_set.cc`). | Gap |
| `ctl:ruleRemoveTargetById` / `ctl:ruleRemoveTargetByTag` | The target is parsed like a rule variable. A keyed target compares the key exactly for arguments and ASCII case-insensitively for header names; a regex target (`ARGS:/.../`) is refused and removes nothing (`target_matches_resolved` in `src/engine/control.rs`). | Compares the target string with the variable's name ASCII case-insensitively at the collection level, and exactly against `COLLECTION:key` per value (`src/rule_with_operator.cc`). | Deliberate |
| `ctl:ruleRemoveByTag` | Exact, case-sensitive tag comparison. | Compared through `containsTag`, macro-expanded. | Deliberate; every CRS use is a literal tag |
| `ctl:auditEngine`, `ctl:auditLogParts` | Accepted, no effect, reported once at load. | Control the audit log. | Gap (no audit log) |
| `ctl:forceRequestBodyVariable` | Accepted, no effect: `REQUEST_BODY` always holds the raw body. | Not among the `ctl:` actions in `src/actions/ctl/` on `v3/master`. | Deliberate: CRS uses it |

## Matching v3 more closely

Closing a gap is a normal change: cite the v3 file, add a test, record the CRS
count (`conformance.md`), add a `CHANGELOG.md` entry, and delete the row here.
