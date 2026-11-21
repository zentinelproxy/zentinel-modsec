# Architecture

How a rule file becomes a decision about a request. The engine follows
ModSecurity v3's model (phases, collections, actions); where it differs on
purpose, `v3-compatibility.md` says so.

## Pipeline

```
 rule files ──► Parser ──► Vec<Directive> ──► CompiledRuleset ──► ModSecurity
 (.conf,        lexer,      SecRule,           rules per phase,     (Arc, shared,
  Include)      includes,   SecAction,         chains, markers,      Send + Sync)
                defaults    removals, ...      load-time warnings        │
                                                                         │ new_transaction()
                                                                         ▼
 request ──► process_uri / add_request_header ──► Transaction (one per request)
             process_request_headers   phase 1        │
             append_request_body                      │ for each rule in the phase:
             process_request_body      phase 2        │   resolve variables
             process_response_headers  phase 3        │   apply t: pipeline
             process_response_body     phase 4        │   run operator per value
             process_logging           phase 5        │   run actions per match
                                                      ▼
                                       intervention(), matched_rules(),
                                       matched_data(), anomaly_score()
```

Load once, evaluate many times: everything expensive (parsing, operator
construction, regex validation, transformation lookup) happens before the
first request. A `Transaction` holds only per-request state and borrows the
compiled rules through an `Arc`.

## Load

**Parse** (`src/parser/`). The lexer turns SecLang into tokens, joining `\`
continuations and treating CRLF like LF. `Parser` dispatches on the directive
name (case-insensitive) and produces `Directive` values. It also:

- resolves `Include` (a relative path is tried as given, then beside the
  declaring file; globs; nesting limited to 100 levels; cycles are errors);
- merges `SecDefaultAction`, which is per phase, into each rule's actions;
- logs and skips directives it does not know;
- keeps the configuration it held before a call that fails, so a parse error
  leaves no half-loaded state.

**Compile** (`CompiledRuleset::compile` in `src/engine/ruleset.rs`). Directives
become `CompiledRule`s grouped by phase, in declaration order:

- `SecRuleRemoveById`, `SecRuleRemoveByTag` and `SecRuleRemoveByMsg` are
  resolved against the whole ruleset wherever they appear; removed rules are
  never compiled. `SecRuleUpdateTargetById` is applied after every rule exists.
- A chain is a run of rules: each link points at the next (`chain_next`) and
  inherits the starter's phase.
- `SecMarker` positions are recorded in every phase for `skipAfter`.
- Operators are constructed once. `@rx` validates its pattern at load and
  builds the automaton on first use; an invalid pattern turns the rule into one
  that never matches, with a warning, and drops a `!` so it cannot match
  everything.
- Things the engine cannot honor are reported once per ruleset, with counts:
  unsupported `ctl:` values, `setvar` into collections other than TX (removed
  from the rule), numeric-operator arguments using macros it cannot resolve
  (those rules never match), unimplemented variables.

## Evaluate

**Transaction.** `ModSecurity::new_transaction()` creates one per request with
a fresh `UNIQUE_ID` and an empty TX collection. Each `process_*` call runs one
phase. Phase 2 first runs a request body processor: multipart, XML or JSON by
`Content-Type`, otherwise form decoding, unless `ctl:requestBodyProcessor`
forced one or `ctl:requestBodyAccess=Off` turned it off. `REQUEST_BODY` always
holds the raw body.

**A phase** (`Transaction::run_phase`) walks the phase's rules in order. It
stops early when the transaction already has an intervention or was allowed,
or when the effective engine mode is `Off`. It honors `skip`, `skipAfter`
(never backwards), and the per-transaction removals set by `ctl:`.

**A rule** (`evaluate_rule`):

1. The `VariableResolver` (`src/variables/resolver.rs`) turns each target into
   `(name, value)` pairs: whole collections, `:key` and `:/regex/` selections,
   `&COLLECTION` counts, minus `!` exclusions and `ctl:` target removals.
2. A target that resolves to nothing does not run the operator, so a negated
   operator does not match on absence. A rule with no targets (`SecAction`)
   runs once against the empty string.
3. The `t:` pipeline (`src/transformations/`) runs on each value.
4. The operator runs on each transformed value. An argument containing
   `%{...}` is expanded against the transaction (`operand_macro.rs`) first.
5. Each matching value is one match. `capture` (into `TX:0`..`TX:9`) and
   `setvar` run once per match, in order, as v3 does.

**Chains.** The starter's disruptive and logging actions are held until every
link has matched; a chain that fails part-way leaves nothing in
`matched_rules()` or `matched_data()`. Each link's own `setvar` runs when that
link matches.

**Disruptive actions.** `block` takes the disruptive action of the
`SecDefaultAction` for the rule's phase (CRS sets `pass`, so its rules score
and 949110 decides); with no default configured it denies. Under
`SecRuleEngine On`, `deny`, `drop` and `redirect` set an `Intervention` and end
the phase. Under `DetectionOnly` rules match and run their non-disruptive
actions, but nothing intervenes. `allow` stops further evaluation.

## Collections

- **TX** (`src/variables/tx.rs`) is the only writable collection. Keys are
  case-insensitive (stored lowercased), values are strings, and arithmetic in
  `setvar` saturates at the 64-bit bounds. The engine does not write scores of
  its own; `anomaly_score()` reads `TX:anomaly_score`.
- **Request and response collections** (`ARGS`, `REQUEST_HEADERS`, `FILES`,
  `XML`, ...) are built from what the application passed in and from the body
  processors. Header names are looked up case-insensitively, argument names are
  case-sensitive.
- All collections iterate in insertion order (`indexmap`). Which value matches
  first decides `MATCHED_VAR` and captures, so order is part of the result and
  the CRS gate depends on it.
- IP, SESSION, USER, GLOBAL and RESOURCE are not implemented.

## Extension points

Each kind of rule element is a name-to-implementation table:

| Element | Trait | Registry | Parsed in |
|---|---|---|---|
| Operator | `operators::Operator` (`execute(&str) -> OperatorResult`) | `compile_operator` in `src/operators/mod.rs` | `src/parser/operator.rs` (`OperatorName`) |
| Transformation | `transformations::Transformation` | `create_transformation` in `src/transformations/mod.rs` | `t:` in `src/parser/action.rs` |
| Action | `parser::Action` enum | `execute_actions` in `src/actions/mod.rs`; `setvar`, `capture`, flow and disruptive outcomes are applied in `transaction.rs` | `src/parser/action.rs` |
| `ctl:` | `CtlDirective` | `CtlDirective::parse` in `src/engine/control.rs` | as an action |
| Variable | `parser::VariableName` | `VariableResolver` in `src/variables/resolver.rs` | `src/parser/variable.rs` |

Adding one means: the name in the parser, the implementation, the registry
entry, a test in `tests/`, the README's supported list, and a `CHANGELOG.md`
entry. If it changes the CRS count, set `MIN_PASSING` (see `conformance.md`).
